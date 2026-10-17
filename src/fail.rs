//! v0.4 失败归因（DESIGN.md §13）。
//!
//! 这一层回答的问题只有一个：**这次工具调用失败在哪一层？**
//!
//! 四层（DESIGN.md §13.1），从"根本没跑到命令"到"跑到了但系统拒绝了"：
//!
//! | 层 | 现象 | 内核足迹 |
//! |----|------|----------|
//! | agent | bwrap/沙箱初始化失败，命令从未运行 | **无**（连 fork 都没有） |
//! | exec | `command not found`，bash 自己报 127 | **无 execve**（只有 bash 的内部错误） |
//! | runtime | exec 成功，进程以非零码退出 | 有 `proc.exec` + `proc.exit` |
//! | infra | 跑起来了，但 openat/connect 被拒 | 有失败的 `file.open` / `net.connect` |
//!
//! 四层里只有第一层**永远不会**在内核里留下任何东西 —— 这正是这个功能存在的理由：
//! 光看时间线你分不清"命令没跑"和"命令跑了没留下痕迹"，而这两件事的排查方向完全相反。
//!
//! # 铁律（与整个项目同源，这里单独再说一遍，因为它最容易破）
//!
//! **派生出来的原因只能命名 trace 里真实存在的证据。**
//!
//! - 没有 execve，就说"没有 execve"，不许说"沙箱拒绝了它"——除非结果文本里写着
//!   bwrap（那是 agent 层的自述，不是我们猜的）。
//! - 内核源没开的时候（纯 `-S` 回放），"内核里没有 X"这句话**不成立** ——
//!   字符串里必须带上"这一轮没有采集内核"，否则读的人会以为我们看着内核说的。
//! - PATH 探测产生的 `exec_fail ENOENT`（glibc 对每个 PATH 项试一次）**不是失败**：
//!   同一个 basename 后来 exec 成功了，那 13 条 ENOENT 就是它成功的代价。
//!   把它们报成"最深失败点"是本模块最容易犯、也最像那么回事的错误。
//!
//! # 位置
//!
//! ```text
//! merger → binder → collapser → [fail attribution] → renderer
//! ```
//!
//! 在 binder **之后**：内核行要带上 `corr.tool_use_id` 才谈得上"这条调用挂住的子树"。
//! 在 collapser **之后**：折叠行是原始行的无损摘要，读者在屏幕上看到的是折叠后的
//! 世界，归因必须解释同一个世界（`-v` / `--output json` 下折叠关闭，看到的就是原始行）。
//!
//! # 什么时候下结论（v0.4.1，实测逼出来的）
//!
//! `tool.result` 行**不代表内核证据已经到齐**。两条实测（§13.5）：
//! transcript 是事后写的、bpftrace 按 perf buffer 批量投递，于是"结果先到、它所
//! 解释的那次 exec 后到"是常态而不是异常 —— 一次 `claude -p` 实测里，`ls` 的
//! `tool.result` 在第 9 行，它的 `execve`+`openat ENOENT` 在第 368 行才出现，
//! 而两者的时间戳只差 40ms。
//!
//! 所以归因**不在读到结果时就下结论**：先挂起（[`Pending`]），等下面三者之一：
//!
//! 1. **证据到了** —— 这条调用挂上了内核事件，立刻按最深失败点出结论；
//! 2. **内核水位线越过结果 + 重排窗口** —— 合并器的契约是"ts 早于水位线 − 窗口的
//!    内核事件都已放出"，此刻再说"内核里没有"才是老实话（窗口由 `--merge-window`
//!    给出，见 [`FailCfg::settle_ns`]）；
//! 3. **流结束** —— 兜底，此时看到的已是全部。
//!
//! 这一轮没有内核源（`--source agent`）时不需要等：永远不会有内核行到来，
//! 立刻按"这一轮没采集内核"的口径出结论。
//!
//! 代价要写清楚：`XX` 行因此在流里**晚于**那条 `tool.result` 出现（跟在它引用的
//! 内核证据后面），这正是想要的顺序 —— 先证据，后结论。而 `tool.result` 本身
//! 照旧立即输出，agent 层永远不阻塞时间线（merger §2.4）。

use crate::event::{Binding, Event, Kind, Layer, Payload, errno_label, one_line};
use crate::lineage::{self, ClaimVsKernel, Facts, Lineage};
use std::collections::{HashMap, HashSet, VecDeque};

/// 一个进程里同时挂着的未定论调用数上限。病态输入（几千条 tool.call 而一条 result
/// 都没有）时丢最老的 —— 与 `exact.rs` 的 `MAX_PENDING_CALLS` 同一个理由：
/// 宁可少归因几条，也不能让内存无界增长。
const MAX_PENDING_CALLS: usize = 4096;

/// 每类候选证据各留最近几条。我们只需要"最深的那一条"，但保留几条便于
/// `-v` 与后续扩展；上限保证一次 `find /` 不会把内存吃光。
const MAX_CANDIDATES: usize = 8;

/// 一次失败**最深**落在哪一层。进 json 的 `payload.class`。
///
/// 字符串而不是 enum 是为了 json 稳定：下游按字符串过滤，加新类别不会破坏旧脚本。
pub const CLASS_BEFORE_EXEC: &str = "before-exec";
pub const CLASS_KERNEL: &str = "kernel";
pub const CLASS_BOUND_NO_EVIDENCE: &str = "bound-no-evidence";
pub const CLASS_UNBOUND: &str = "unbound";
pub const CLASS_NO_KERNEL_SOURCE: &str = "no-kernel-source";
/// v0.6：transcript 说它成功了，内核说没有这回事（§14.2 的楔子）。
///
/// 它和上面四类的区别是**方向**：四类是"这次调用为什么失败"，这一类是
/// "这次调用根本没失败 —— 失败的是它的自述"。所以它挂在一条 `ok` 的结果上。
/// 因此它只可能由 [`lineage::evaluate`] 的门槛通过时产出：没有内核源、
/// 或者这条调用没被连上，这条结论**不成立**，那个调用会安静地什么也不产出。
pub const CLASS_CLAIM: &str = "claim-mismatch";

/// 结论是在什么条件下下的。进 `XX` 行的 notes（不进 payload）—— 它解释的是
/// "我们凭什么现在说这句话"，是审计信息，不是渲染素材。
const SETTLE_LINKED: &str = "kernel events for this call arrived after its result";
const SETTLE_NO_SOURCE: &str = "no kernel source in this run, so there was nothing to wait for";
const SETTLE_EOS: &str = "the stream ended without any kernel event linked to this call";
const SETTLE_WATERMARK: &str = "the kernel stream moved past this result without linking anything to it";

/// `--failures-only` 与外层知识的汇合点。
#[derive(Debug, Clone, Copy, Default)]
pub struct FailCfg {
    /// `--failures-only`：只放行失败链（失败调用 + 它的绑定子树 + 归因行）。
    pub only: bool,
    /// 这一轮有没有内核源（`-p` / `-C`）。决定"内核里没有 X"这句话能不能说。
    pub kernel_available: bool,
    /// 挂起一条失败后，等内核证据等到什么时候。
    ///
    /// 取 `--merge-window`：合并器的契约是"ts 比已放出的水位线早一个窗口以上的
    /// 内核事件都已放出"，所以水位线越过 `结果 ts + 这个值` 之后，再说"内核里
    /// 没有这条调用的足迹"才不是抢答。见文件头的"什么时候下结论"。
    pub settle_ns: u64,
    /// 会话级 pid 绑定是不是 exact/heuristic —— **只用于解释，不再是核对门槛**。
    ///
    /// v0.6 曾把它当第二个门：调用没被 argv 绑定时，只要它落在我们看着的进程树里
    /// 就说"内核里没有这次写入"。**这是错的**（2026-10-17 审计）：事实集
    /// （`Evidence::kb`）只由带 join key 的内核行填充，没绑定的调用手上是空集，
    /// 于是这句话实际是"我们没连上"，不是"它没发生"。`Read` 这类根本不 exec 的
    /// 工具、heredoc / env 前缀这类 binder 合法漏配的命令都会因此被误报成
    /// `!! claim-mismatch`。现在它只用于把"没内核源"和"看了但没连上"分开计数
    /// （见 [`FailAttributor::claims_unverified_unlinked`]）。
    pub pid_linked: bool,
}

/// 一次失败的人读记录（footer 的 `--- failures (N)` 与 json 的 `extra.failures`）。
///
/// 刻意与 `Payload::Fail` 分开：payload 是**行**（渲染用），这个是**账**（收尾用）。
/// 两者字段高度重叠，但用法不同 —— 合并会逼着 footer 去解析渲染后的字符串。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub ts_wall_ns: u64,
    pub ts_ns: u64,
    pub tool: String,
    pub cmd: String,
    /// 结果侧的行首（`exit 2` / `BEFORE exec: ...`）。
    pub head: String,
    /// 内核侧最深失败点。
    pub deepest: Option<String>,
    /// `before-exec` …（见上面的常量）。
    pub class: String,
    /// 失败是**怎么被判定**的（`status=Failure` / `text: Exit code 127`）。
    /// footer 不显示它，json 里有 —— 审"这算不算失败"时要能查到依据。
    pub detected_by: String,
    pub tool_use_id: Option<String>,
    /// 挂在这条调用上的内核事件数（0 = 内核侧一条都没连上）。
    pub kernel_events: u64,
    /// 这是 transcript 里的第几次 `tool.call`（v0.6 血缘用的步号）。
    ///
    /// **只用于引用**（`└─ input X produced by step 3 fetch_pdf`），不是身份：
    /// 它是本条流里 `tool.call` 的出现次序，与 adapter 有没有 `tool_use_id` 无关，
    /// 也与内核事件无关。
    pub step: u64,
    /// 血缘行（v0.6 §14.1）。空 = 这条链上没有可说的引用关系。
    ///
    /// 每行都是**用户态推断**：依据是"另一条 `tool.call` 提到过同一个字符串"。
    /// 行文里带着 `produced by step N`，而不是"这个文件是第 N 步写的"。
    pub lineage: Vec<String>,
    /// claim vs kernel 的并排对账行（v0.6 §14.2）。空 = 没有可核对的 claim，
    /// 或者核对门槛不满足（两者在 `-v` 的计数里分开报）。
    ///
    /// 第一行如果是 `mismatch`，它就是这条失败记录的 `head`（进 `XX` 行）。
    pub claims: Vec<ClaimVsKernel>,
    /// 内容嗅探结论（v0.6 §14.3）。**用户态启发式，不是内核证据** ——
    /// 句子里必须带 `userspace heuristic` 这几个字（由 [`lineage::sniff`] 保证）。
    pub sniff: Vec<String>,
}

/// 一条未定论的 `tool.call`。
#[derive(Debug, Clone)]
struct Call {
    /// 事件上的 `corr.tool_use_id`；缺失时为 `None`（此时它在 `calls` 里的键
    /// 是合成的 `#<序号>` —— 没有 join key 的 adapter 也要能被跟着，
    /// 只是它挂不上任何内核行）。
    id: Option<String>,
    tool: String,
    cmd: String,
    /// `tool.call` 的单调钟 ts（排序主键，见 src/event.rs 文件头）。
    ts_ns: u64,
    /// 同一条 `tool.call` 的**墙钟**（CLOCK_REALTIME 纳秒）。
    ///
    /// `ts_ns` 是单调钟，而观测窗口的左沿 `kernel_first_wall` 是从内核事件的
    /// `ts_wall_ns` 来的 —— 两个不同钟源直接比大小恒为假，所以"这条调用在不在
    /// 窗口里"必须拿墙钟比墙钟（见 [`FailAttributor::window_ok`]）。
    ts_wall_ns: u64,
    resolved: bool,
    /// transcript 里的第几次 `tool.call`（见 [`Failure::step`]）。
    step: u64,
}

/// 一条**已判定失败、但还不到下结论的时候**的调用（见文件头"什么时候下结论"）。
///
/// 三样东西要一起活到结论那一刻：那条 `tool.result`（`XX` 行的 ts/corr/notes 都从
/// 它继承）、判定依据（`detected_by` 与原文）、以及调用本身（工具名、命令行）。
/// 内核证据不在这里 —— 它继续按 `corr.tool_use_id` 累加进 `ev`。
#[derive(Debug, Clone)]
struct Pending {
    key: String,
    src: Event,
    text: String,
    detected_by: String,
    call: Call,
    kind: PendingKind,
}

/// 挂起的是哪种结论。两者的等待条件一样（证据到齐 / 水位线 / 流尾），
/// 但放出来的东西完全不同：一个说"它失败了"，另一个说"它说自己成功了，
/// 内核不认"。分开建模而不是塞进一个 `Option`，是为了让"成功调用也会挂起"
/// 这件事在类型上看得见。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    /// 结果说这次调用失败了（v0.4 的四层归因）。
    Fail,
    /// 结果说成功了，但 transcript 里的话可以被内核核对（v0.6 §14.2）。
    Claim,
}

/// 一条调用挂住的内核证据。全部**有界**（每类留最近 `MAX_CANDIDATES` 条）。
#[derive(Debug, Default, Clone)]
struct Evidence {
    /// 最深的一类：openat 失败 / connect 失败 / policy.deny。
    ///
    /// 存 `(失败对象, 渲染好的整句)` 两半：对象留着和 argv 对账（见
    /// [`asked_for`]），整句是最终要打给人看的。对账放在 [`Evidence::deepest`]
    /// 里而不是入队时做 —— argv 那条 exec 行有可能比它引发的失败**后**到。
    deep: VecDeque<(String, String)>,
    /// exec_fail。**必须**与 `ok_basenames` 对账之后才可用（见文件头铁律）。
    exec_fail: VecDeque<(String, String)>,
    /// 非零退出。它是"症状"不是"根因"，排在最深类的后面。
    exits: VecDeque<String>,
    /// 子树里**成功** exec 过的 basename。用来剔除 PATH 探测的假失败。
    ok_basenames: HashSet<String>,
    /// 子树里被认领的那次 exec 的可执行文件（"via ..."）。
    exec_file: Option<String>,
    /// 被认领的那次 exec 的 argv 操作数（含 argv[0] 与可执行文件路径）。
    argv_tokens: HashSet<String>,
    /// 挂在这条调用上的内核事件数（含折叠行）。
    kernel_events: u64,
    /// v0.6 §14.2：这条调用子树里的写-open / 连接对端 / exec，供 claim 对账。
    ///
    /// 放在 `Evidence` 里而不是另开一张表：它的生命周期与 `Evidence` **逐字相同**
    /// （同样的插入点、同样的移除点：结论落定那一刻）。多一张表就多一份
    /// "什么时候删"的重复答案，而那种重复一定会漂移。
    kb: lineage::KernelFacts,
}

impl Evidence {
    /// 最深失败点。优先级：
    ///
    /// 1. **命令被要求处理的东西**失败了（argv 操作数，见 [`asked_for`]）—— 病因；
    /// 2. 没能跑起来的那次 exec（PATH 探测的假失败已排除）—— 也是病因；
    /// 3. 非零退出 —— 是**结果**，但它至少确实是**这条调用**的结果；
    /// 4. 兜底：只剩一堆和命令行无关的失败 open/connect，此时它是唯一能命名的事实。
    ///
    /// 为什么 1 要单独拎出来：一次正常的 `ls` 在内核里就有几十条失败的 openat ——
    /// 动态链接器找 `ld.so.cache`、glibc 按十几个 locale 目录逐个试 `.mo`。它们
    /// **确实**是失败（内核真的拒绝了），但它们不是这次调用为什么失败。实测
    /// （§13.6）：不加这一条，`ls /nonexistent-dir-abc` 的"最深失败点"会报成
    /// `/usr/share/locale-langpack/en/LC_MESSAGES/libc.mo ENOENT`。
    ///
    /// 为什么 3 排在 4 前面（哪怕退出码是"症状"）：把一条**和这条命令行毫无关系**
    /// 的失败 open 说成病因，是**猜**；说"它以 2 退出"是**陈述**。同一个实测里
    /// `ls` 用的是 `stat`，我们根本没采到那个 ENOENT —— 那时宁可少说一句。
    fn deepest(&self) -> Option<String> {
        let via = |s: String| match &self.exec_file {
            Some(f) if !f.is_empty() => format!("{} via {}", s, f),
            _ => s,
        };
        if let Some((_, s)) = self
            .deep
            .iter()
            .rev()
            .find(|(subj, _)| asked_for(subj, &self.argv_tokens))
        {
            return Some(via(s.clone()));
        }
        // PATH 探测的 ENOENT 只在"这个 basename 从来没有 exec 成功过"时才算失败。
        for (base, ev) in self.exec_fail.iter().rev() {
            if !self.ok_basenames.contains(base) {
                return Some(via(ev.clone()));
            }
        }
        if let Some(e) = self.exits.back() {
            return Some(via(e.clone()));
        }
        self.deep.back().map(|(_, s)| via(s.clone()))
    }
}

/// `observe` 对一条事件的裁决。`--failures-only` 的路由完全依赖它，
/// 所以三种"新信息"必须分开报：开了链、结了链（成功）、结了链（失败）。
enum Resolution {
    /// 只是流里的一条普通事件（内核行 / 模型行）：归到 `belongs` 说的那条链上。
    None,
    /// 这条是 `tool.call`，它**开了**一条新链（键由归因器分配，见 `call_key`）。
    ///
    /// 单独一个分支而不是复用 `None`：链头属于哪条链，只有 `on_call` 知道
    /// （带 `tool_use_id` 时是那个 id，不带时是合成的 `#<序号>`）。
    /// 让调用点去猜这个键，就等于把"怎么算键"这件事写了两遍。
    Opened(String),
    /// 结果说这次调用成功了，而且它没有任何可核对的 claim —— 无事发生。
    Clean,
    /// 结果说这次调用失败了 —— 但**还没有归因行**：结论要等内核证据到齐（文件头）。
    Failed,
    /// 结果说成功了，但文本里有能被内核核对的话（v0.6 §14.2）。
    ///
    /// 它**不是**失败 —— 但它同样不能当场下结论：`ok` 是不是真的，要看这条调用
    /// 挂住的内核事件里有没有那笔写入。所以它走和 `Failed` 一样的等待路径，
    /// 只是放出来的东西不同（对上了就什么都放不出）。
    ClaimPending,
}

pub struct FailAttributor {
    cfg: FailCfg,
    calls: HashMap<String, Call>,
    /// FIFO：给没有 `tool_use_id` 的结果按"同工具、最早未定论"配对。
    order: VecDeque<String>,
    ev: HashMap<String, Evidence>,
    /// 已判定失败、在等内核证据的调用（FIFO：按结果出现的顺序下结论）。
    pending: VecDeque<Pending>,
    /// `--failures-only` 的按链缓冲：key → 这条链已经流过的事件。
    chains: HashMap<String, Vec<Event>>,
    /// 已放出的内核事件的最大墙钟（合并器水位线在本层的影子）。
    /// 只由内核事件推进 —— agent 行的时间戳可能来自另一只钟，拿它当水位线
    /// 会让"内核已经走过这里了"这句话失去意义。
    kernel_watermark: u64,
    seq: u64,
    /// 整条流的最小墙钟（`time_origin` 的口径）—— `--failures-only` 下时间线被剪枝，
    /// 渲染器不能从"第一条打印出来的事件"定原点，否则 `4.995s` 会变成 `0.000s`。
    origin_wall: Option<u64>,
    /// 整条流的最大墙钟。同样只在剪枝模式下有意义：那时 `Summary` 的
    /// `last_wall` 是**剩下的行**里最晚的一条，用它画的 span 会和失败时间对不上。
    end_wall: Option<u64>,
    pub failures: Vec<Failure>,
    /// 本 run 实际收到过内核事件吗（用于 `-v` 与 json 的诚实说明）。
    pub kernel_events_seen: u64,
    /// v0.6 §14.1：全会话的产物提到表。**不随调用结束而释放** ——
    /// 血缘是"第 12 步引用第 3 步的产物"，第 3 步的账必须还在。
    /// 每条 `tool.call` 一项（几个产物字符串），量级小于 transcript 本身。
    lineage: Lineage,
    /// 第一条内核事件的墙钟 —— 观测窗口的左沿（见 [`lineage::Facts::in_window`]）。
    kernel_first_wall: Option<u64>,
    /// v0.6 §14.2 的计数。**必须先分清"核对过没问题"和"没资格核对"**，
    /// 否则"没有 `!!`"会被读成"一切正常"。
    pub claims_seen: u64,
    pub claims_checked: u64,
    pub claims_unverified: u64,
    /// 其中"在看内核、但这条调用没有 join key"的条数（与 `no kernel source`
    /// 分开计数：前者是 join key 的缺口，后者是压根没看）。
    pub claims_unverified_unlinked: u64,
    /// 最近一次"没资格核对"的**明确原因**（`-v` / JSON 可查；见
    /// [`lineage::Facts::unverified_reason`]）。
    pub claims_unverified_reason: Option<&'static str>,
    /// 找不到归属的 `tool.result` 数（显式 id 已 resolved/未知，或没有 id 且没有
    /// 可配对的同工具调用）。以前这类结果会被 FIFO 猜给别的调用，现在是计数。
    pub unmatched_results: u64,
    pub claims_mismatched: u64,
}

impl FailAttributor {
    pub fn new(cfg: FailCfg) -> Self {
        FailAttributor {
            cfg,
            calls: HashMap::new(),
            order: VecDeque::new(),
            ev: HashMap::new(),
            pending: VecDeque::new(),
            chains: HashMap::new(),
            kernel_watermark: 0,
            seq: 0,
            origin_wall: None,
            end_wall: None,
            failures: Vec::new(),
            kernel_events_seen: 0,
            lineage: Lineage::new(),
            kernel_first_wall: None,
            claims_seen: 0,
            claims_checked: 0,
            claims_unverified: 0,
            claims_unverified_unlinked: 0,
            claims_unverified_reason: None,
            unmatched_results: 0,
            claims_mismatched: 0,
        }
    }

    /// v0.6 血缘的账（进 `-v` 与 `--output json`）。
    pub fn lineage_stats(&self) -> lineage::LineageStats {
        self.lineage.stats()
    }

    /// 会话起点 / 终点（全流的最小、最大墙钟）。
    ///
    /// 剪枝模式下这两个值**不等于** `Summary` 的 `first_wall`/`last_wall`
    /// （后者只统计活下来的行）。收尾段和时间线都必须用这一对，
    /// 否则同一次失败会在两个地方显示两个时间。
    pub fn origin_wall(&self) -> Option<u64> {
        self.origin_wall
    }

    pub fn end_wall(&self) -> Option<u64> {
        self.end_wall
    }

    /// 一条事件的流入口。输入的事件原样（或按 `--failures-only` 过滤后）进入输出；
    /// 本层**追加**的行（`XX` 归因行）在批次末尾放出 —— 见文件头"什么时候下结论"。
    pub fn process(&mut self, events: Vec<Event>) -> Vec<Event> {
        let mut out = Vec::with_capacity(events.len() + 1);
        for ev in events {
            // 顺序要紧：**先**问"这条事件属不属于某个未定论的链"，**再** observe。
            // observe 会把 `tool.result` 那条链标记成已定论，问晚了就永远问不到。
            let belongs = self.key_for_event(&ev);
            self.note_origin(&ev);
            let res = self.observe(&ev);
            // 挂起的两条路（失败归因、claim 核对）都要问一句"现在能下结论了吗"。
            let failed = matches!(res, Resolution::Failed | Resolution::ClaimPending);
            if self.cfg.only {
                self.route_filtered(ev, belongs, res);
            } else {
                // agent 行照旧立即输出（merger §2.4：agent 层永不阻塞时间线）。
                out.push(ev);
            }
            if failed {
                self.settle_latest(&mut out);
            }
        }
        self.settle(false, &mut out);
        out
    }

    /// 刚挂上的那条失败，如果答案已经不会再变，就**紧跟着结果**出结论。
    ///
    /// 答案不会再变的两种场合：这一轮没有内核源（永远不会有内核行），或者证据在
    /// 结果到达之前就已经挂上了。这两种情况下等待只会把 `XX` 行推到批次末尾 ——
    /// 离线回放（整份 transcript 一个批次）里就是推到**整个会话末尾**，白白丢掉
    /// "跟在失败调用旁边"这个唯一的排列收益。
    ///
    /// 真正值得等的只有一种：内核在看着，而这条调用还没挂上任何内核行。
    fn settle_latest(&mut self, out: &mut Vec<Event>) {
        let Some(p) = self.pending.back() else { return };
        if !self.decided_now(p) {
            return;
        }
        let why = if self.cfg.kernel_available {
            SETTLE_LINKED
        } else {
            SETTLE_NO_SOURCE
        };
        let p = self.pending.pop_back().unwrap();
        self.flush_failure(p, why, out);
    }

    /// 这条挂起的结论，答案还会变吗。
    ///
    /// 这条挂起的结论，答案还会变吗。
    ///
    /// 真失败：内核里已经有挂到这条调用上的东西了，病因就不会再变 —— 可以立刻说。
    ///
    /// **对账（claim）不能照抄这一条**，这是 v0.6 在真实会话里踩到的坑：claim 的
    /// 否定结论（`no write open observed`）说的不是"这条调用身上发生了什么"，而是
    /// "整段内核流里都没有"。而**写经常发生在结果之后** —— curl 先收完响应头、
    /// 再落盘，实测落盘比 `tool.result` 晚 20~60ms；exec/fork 却早就在结果之前挂上
    /// 了。于是"已有内核事件挂上"在这条路上恰恰是**最不能下结论**的时刻：它会把
    /// 每一次真写都喊成"没写"（真机复现见 V06_RUN.log 的 acceptance #4）。
    /// 所以它必须等水印走过 `结果时刻 + settle 窗口`。
    fn decided_now(&self, p: &Pending) -> bool {
        if !self.cfg.kernel_available {
            return true;
        }
        match p.kind {
            PendingKind::Fail => self.ev.get(&p.key).is_some_and(|e| e.kernel_events > 0),
            PendingKind::Claim => self.kernel_watermark > p.src.ts_wall_ns.saturating_add(self.cfg.settle_ns),
        }
    }

    /// 流结束。这里做两件事：
    ///
    /// - 把还挂着的失败全部下结论（兜底：不会再有任何证据了）；
    /// - `--failures-only` 下没有结果的调用链（dangling）不算失败，直接丢掉。
    pub fn finish(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        self.settle(true, &mut out);
        self.chains.clear();
        self.refresh_lineage();
        out
    }

    /// v0.6 §14.1：把血缘的**完整**答案补进失败账。
    ///
    /// 为什么非要在流尾补一次：时间线上那条 `XX` 行是在证据到齐那一刻放出的
    /// （§13.5），而"后面还有哪一步用了这个产物"当时**还没发生**。正向的血缘
    ///（`output X referenced later by step 12 display_pdf`）只有整个会话都读完了
    /// 才谈得上。失败账（footer 的 `--- failures` 与 json 的 `extra.failures`）
    /// 本来就是回顾性的，所以它在流尾补齐 —— 时间线上已经渲染过的行一个字节
    /// 都不动（那是"当时知道什么"的忠实记录）。
    fn refresh_lineage(&mut self) {
        for f in self.failures.iter_mut() {
            let Some(key) = self.lineage.key_of_step(f.step).map(|s| s.to_string()) else {
                continue;
            };
            for l in self.lineage.chain(&key) {
                if !f.lineage.contains(&l) {
                    f.lineage.push(l);
                }
            }
        }
    }

    /// 批次末尾的定夺：能下结论的挂起失败在这里放出归因行。
    ///
    /// 三种可以下结论的时机见文件头。注意 `final_pass`（流结束）一定通过 ——
    /// 宁可早说一句"没连上"，也不能到收尾还欠着一行。
    fn settle(&mut self, final_pass: bool, out: &mut Vec<Event>) {
        let wm = self.kernel_watermark;
        let win = self.cfg.settle_ns;
        let mut i = 0;
        while i < self.pending.len() {
            let (ready, why) = {
                let p = &self.pending[i];
                let linked = self.ev.get(&p.key).map(|e| e.kernel_events).unwrap_or(0);
                // 真失败：内核侧一挂上东西，病因就在手里了。
                // 对账要等水印 —— 理由见 [`FailAttributor::decided_now`]。
                let linked_is_enough = linked > 0 && p.kind == PendingKind::Fail;
                if linked_is_enough {
                    (true, SETTLE_LINKED)
                } else if !self.cfg.kernel_available {
                    (true, SETTLE_NO_SOURCE)
                } else if final_pass {
                    (true, SETTLE_EOS)
                } else if wm > p.src.ts_wall_ns.saturating_add(win) {
                    (true, SETTLE_WATERMARK)
                } else {
                    (false, "")
                }
            };
            if ready {
                let p = self.pending.remove(i).unwrap();
                self.flush_failure(p, why, out);
            } else {
                i += 1;
            }
        }
    }

    /// 下结论：算出归因行，`--failures-only` 下顺带把整条链放出去。
    fn flush_failure(&mut self, p: Pending, why: &str, out: &mut Vec<Event>) {
        match p.kind {
            PendingKind::Fail => self.flush_failed_call(p, why, out),
            PendingKind::Claim => self.flush_claim_check(p, why, out),
        }
    }

    /// 一条真失败（结果自己说失败了）的归因。
    fn flush_failed_call(&mut self, p: Pending, why: &str, out: &mut Vec<Event>) {
        let evidence = self.ev.remove(&p.key).unwrap_or_default();
        let mut f = self.build_failure(&p.src, &p.call, &p.text, p.detected_by, &evidence);
        self.attach_lineage(&p.key, &mut f);
        let row = fail_event(&p.src, &p.call, &f, why);
        self.failures.push(f);
        // 定论之后这条调用不再收内核行 —— 归因行已经写死了它的结论。
        self.calls.remove(&p.key);
        if self.cfg.only
            && let Some(mut chain) = self.chains.remove(&p.key)
        {
            out.append(&mut chain);
        }
        out.push(row);
    }

    /// 一条 `ok` 结果的对账（v0.6 §14.2）。
    ///
    /// 三种出口，必须分清：
    ///
    /// 1. **对上了**（或门槛不满足）—— **一行都不产出**。这里是有意的：把
    ///    "核对通过"也打出来，等于给每一次成功调用都加一行噪音，而失败视图的
    ///    全部价值就在于"屏幕上出现的每一行都值得看"。核实过的条数进 `-v` 的计数。
    /// 2. **对不上** —— 这条调用被**提升成一条失败记录**（class
    ///    [`CLASS_CLAIM`]），走和真失败完全相同的收尾路径：进 `--failures-only`
    ///    的链、进 footer 的 `--- failures`、进 json 的 `extra.failures`。
    ///    不新开一条"警告"通道是刻意的 —— 下游要过滤的东西越少越好。
    /// 3. **门槛不满足** —— 只记数（`claims_unverified`），什么都不说。
    ///    我们没资格核对的东西，绝不说成"没问题"。
    fn flush_claim_check(&mut self, p: Pending, why: &str, out: &mut Vec<Event>) {
        let evidence = self.ev.remove(&p.key).unwrap_or_default();
        let facts = self.facts_for(&p.key, &p.call, &evidence);
        let claims = self.lineage.claims_of(&p.key);
        self.claims_seen += claims.len() as u64;
        // 门槛先于对账：**明确记下"为什么没核对"**。没连上的调用手上没有内核事实
        // （`Evidence::kb` 只由 join-key 行填充），它的"没看见"不构成任何结论；
        // 会话级绑定单独不够格（见 `lineage::Facts::can_speak`）。
        if let Some(reason) = facts.unverified_reason() {
            if !claims.is_empty() {
                self.claims_unverified += claims.len() as u64;
                if self.cfg.kernel_available {
                    // 和"这一轮压根没看内核"分开计数：这是 join key 的缺口。
                    self.claims_unverified_unlinked += claims.len() as u64;
                }
            }
            self.calls.remove(&p.key);
            if self.cfg.only {
                // `--failures-only`：这条链没有任何结论，整条丢掉。
                self.chains.remove(&p.key);
            }
            // 审计信息：原因必须在 `-v`/JSON 里查得到（main.rs 的 summary 段）。
            self.claims_unverified_reason = Some(reason);
            return;
        }
        let rows = lineage::evaluate(&claims, &facts);
        debug_assert!(
            claims.is_empty() || !rows.is_empty(),
            "can_speak() passed but evaluate() produced no rows (claims={})",
            claims.len()
        );
        if rows.is_empty() {
            // 没有 claim：无事可对。
            self.calls.remove(&p.key);
            if self.cfg.only {
                self.chains.remove(&p.key);
            }
            return;
        }
        let mismatched = rows.iter().filter(|r| r.mismatch).count() as u64;
        self.claims_checked += rows.len() as u64;
        self.claims_mismatched += mismatched;
        if mismatched == 0 {
            // 核对通过：安静。这条链在 --failures-only 下不该留下来。
            self.calls.remove(&p.key);
            if self.cfg.only {
                self.chains.remove(&p.key);
            }
            return;
        }

        // 对不上：把它当成一条失败来收尾。`head` 就是那两列 —— 这是 §14.2 的
        // 全部意思：读者在 `XX` 行上同时看到 transcript 的自我陈述和内核的原话。
        let first = rows.iter().find(|r| r.mismatch).expect("mismatched > 0");
        // 先按"结果说它成功了"建一条记录（`head` 由下面覆盖），这样失败记录里
        // 的每一个字段（工具、命令行、步号、ts、内核事件数）都来自同一条调用。
        let mut f = self.build_failure(&p.src, &p.call, &p.text, String::new(), &evidence);
        f.class = CLASS_CLAIM.to_string();
        f.head = first.render();
        f.detected_by = "text: claim not confirmed by the kernel events bound to this call".into();
        // `deepest` 是"四层归因"里的概念（这次调用失败最深落在哪一层）。这条
        // 调用根本没失败 —— 把它的子树里某次无关的失败 openat 摆进这一行，
        // 读者会以为那是病因。内核侧的话已经在那两列里了。
        f.deepest = None;
        f.claims = rows;
        self.attach_lineage(&p.key, &mut f);
        let mut row = fail_event(&p.src, &p.call, &f, why);
        // `XX` 行说的是"这一步有问题"，两列已经写在 head 里；多余的对账列
        // （同一条结果里既说写了文件又说下了 URL）另起 `derived.claim` 行 ——
        // 它们**不是**失败，只是同一笔对账的其余几列。
        let extra: Vec<Event> = f
            .claims
            .iter()
            .skip(1)
            .map(|c| claim_event(&p.src, &p.call, c))
            .collect();
        let chain = if self.cfg.only {
            self.chains.remove(&p.key)
        } else {
            None
        };
        self.failures.push(f);
        self.calls.remove(&p.key);
        row.notes.push(format!(
            "claim vs kernel: {}; see the two columns in the head of this row",
            if mismatched == 1 {
                "1 mismatch".to_string()
            } else {
                format!("{} mismatches", mismatched)
            }
        ));
        if let Some(mut chain) = chain {
            out.append(&mut chain);
        }
        out.push(row);
        out.extend(extra);
    }

    /// 这条调用在内核侧的事实（§14.2 对账的输入）。
    fn facts_for<'a>(&self, key: &str, call: &Call, e: &'a Evidence) -> Facts<'a> {
        Facts {
            kernel_available: self.cfg.kernel_available,
            linked: e.kernel_events > 0,
            session_linked: self.cfg.pid_linked,
            in_window: self.window_ok(key, call),
            write_paths: &e.kb.write_paths,
            net_targets: &e.kb.net_targets,
            exec_seen: e.kb.exec_seen,
        }
    }

    /// 这条调用落没落在内核观测窗口里（见 [`lineage::Facts::in_window`]）。
    ///
    /// 两个满足条件之一：调用发生在采集开始之后（`tool.call` 的 ts 晚于第一条
    /// 内核事件），或者这条调用本来就挂上了内核事件（那它当然在窗口里）。
    ///
    /// 比的是**墙钟**：`kernel_first_wall` 来自内核事件的 `ts_wall_ns`，而
    /// `call.ts_ns` 是单调钟 —— 拿单调钟去比 epoch 恒为假，窗口判定会永远失败，
    /// 于是没挂上内核事件的调用一律被当成"没资格核对"。
    fn window_ok(&self, key: &str, call: &Call) -> bool {
        if self.ev.get(key).is_some_and(|e| e.kernel_events > 0) {
            return true;
        }
        match self.kernel_first_wall {
            Some(k) => call.ts_wall_ns >= k,
            // 一条内核行都没看见过：窗口是空的，"在窗口内"不成立。
            None => false,
        }
    }

    /// 血缘行与内容嗅探（v0.6 §14.1/§14.3），挂在一条已经成形的失败记录上。
    fn attach_lineage(&mut self, key: &str, f: &mut Failure) {
        f.lineage = self.lineage.chain(key);
        for p in self.lineage.paths_of(key).iter().take(lineage::MAX_SNIFF) {
            if let Some(v) = lineage::sniff(p) {
                f.sniff.push(v);
            }
        }
    }

    /// 这条调用的链还"活着"吗 —— 未定论，或者已判定失败但还在等证据。
    ///
    /// 后一半是关键：`tool.result` 一到就把调用标成 resolved，若只看这一个标志，
    /// 晚到的内核证据会被当成"没有意义的迟到行"丢掉，等待就白等了。
    fn live(&self, key: &str) -> bool {
        match self.calls.get(key) {
            Some(c) if !c.resolved => true,
            Some(_) => self.pending.iter().any(|p| p.key == key),
            None => false,
        }
    }

    /// `--failures-only` 的分流：只放行失败链，其余丢弃。
    ///
    /// 缓冲是**必须**的：链头的 `tool.call` 与链尾的 `tool.result` 之间隔着整棵绑定
    /// 子树，而"这条链要不要"只有读到结果才知道。代价是这一模式下内存正比于
    /// **单条调用**的子树大小（不是整个会话），因为链一有结论就立刻放行、立刻释放。
    ///
    /// 这里**不产出**任何行：放行统一发生在 [`Self::flush_failure`]（结论那一刻），
    /// 所以归因行永远跟着它引用的证据，而不是跟着结果。
    fn route_filtered(&mut self, ev: Event, belongs: Option<String>, res: Resolution) {
        match res {
            // 链头自带键 —— 不用问 `belongs`（那时这条调用还没进表）。
            Resolution::Opened(key) => {
                let mut buf = self.chains.remove(&key).unwrap_or_default();
                buf.push(ev);
                self.chains.insert(key, buf);
            }
            Resolution::Clean => {
                // 成功的调用不该出现在 --failures-only 里：把整条链丢掉。
                if let Some(key) = belongs {
                    self.chains.remove(&key);
                }
            }
            Resolution::Failed | Resolution::ClaimPending => {
                // 结果进链缓冲，整条链**等结论一起放**：归因行还没算出来，
                // 先放链头/子树就等于给读者一段没有结论的片段。
                //
                // claim 核对走同一条路是刻意的：它的结论也可能是"这条链有问题"
                // （§14.2 的对不上），而那正是读者要看见的整条链。
                if let Some(key) = belongs {
                    self.chains.entry(key).or_default().push(ev);
                }
            }
            Resolution::None => {
                // 内核行/模型行的归属由 `belongs`（binder 盖的 join key）说了算。
                if let Some(key) = belongs {
                    self.chains.entry(key).or_default().push(ev);
                }
            }
        }
    }

    fn note_origin(&mut self, ev: &Event) {
        if ev.ts_wall_ns > 0 {
            self.origin_wall = Some(match self.origin_wall {
                Some(w) => w.min(ev.ts_wall_ns),
                None => ev.ts_wall_ns,
            });
            self.end_wall = Some(match self.end_wall {
                Some(w) => w.max(ev.ts_wall_ns),
                None => ev.ts_wall_ns,
            });
        }
        if ev.produced_by_kernel_collector() || ev.is_collapse() {
            self.kernel_events_seen += 1;
            self.kernel_watermark = self.kernel_watermark.max(ev.ts_wall_ns);
            if ev.ts_wall_ns > 0 {
                // 观测窗口的左沿（§14.2 的门槛之一）。
                self.kernel_first_wall = Some(match self.kernel_first_wall {
                    Some(k) => k.min(ev.ts_wall_ns),
                    None => ev.ts_wall_ns,
                });
            }
        }
    }

    /// 这条事件属于哪条**未定论**的调用链。
    ///
    /// 首选 `corr.tool_use_id`（binder 盖的 join key）；**显式 id 只做精确查表**，
    /// 查不到就是查不到 —— 绝不退到 FIFO 猜配（2026-10-17 审计：迟到的重复结果
    /// 会把另一条同工具调用坐实，XX 行里拼进别人的 cmd）。没有 id 的 adapter
    /// （openshell fixture / 不带 id 的 jsonl）才走"同工具、最早未定论"的 FIFO。
    fn key_for_event(&self, ev: &Event) -> Option<String> {
        if let Some(id) = ev.corr.tool_use_id.as_deref() {
            return self.live(id).then(|| id.to_string());
        }
        if ev.kind != Kind::AgentToolResult {
            return None;
        }
        let tool = match &ev.payload {
            Payload::ToolResult { tool, .. } => tool.as_deref(),
            _ => None,
        };
        self.order
            .iter()
            .find(|k| self.live(k) && self.calls.get(*k).is_some_and(|c| tool.is_none_or(|t| c.tool == t)))
            .cloned()
    }

    fn observe(&mut self, ev: &Event) -> Resolution {
        match &ev.payload {
            Payload::ToolCall {
                tool,
                input_preview,
                bash_cmd,
                ..
            } => {
                let key = self.on_call(ev, tool, bash_cmd.as_deref().unwrap_or(input_preview));
                Resolution::Opened(key)
            }
            Payload::ToolResult {
                tool,
                status,
                result_preview,
            } => self.on_result(ev, tool.as_deref(), status, result_preview),
            _ => {
                self.on_kernel(ev);
                Resolution::None
            }
        }
    }

    fn on_call(&mut self, ev: &Event, tool: &str, cmd: &str) -> String {
        self.seq += 1;
        let id = ev.corr.tool_use_id.clone();
        let key = call_key(&id, self.seq);
        if self.calls.len() >= MAX_PENDING_CALLS
            && let Some(old) = self.order.pop_front()
        {
            self.calls.remove(&old);
            self.ev.remove(&old);
            self.chains.remove(&old);
            // 挂起中的也要丢：这条路径是为了给病态输入兜底，而不是为了
            // 攒住几千条没结果的调用。
            self.pending.retain(|p| p.key != old);
        }
        // v0.6 §14.1：每一次 `tool.call` 都在血缘表里占一步 —— 包括成功的那些，
        // 因为"第 12 步引用了第 3 步的产物"里的第 3 步，往往是一次成功的调用。
        // 命令行与输入预览都要喂进去：产物既可能写在 `Bash` 的 cmd 里，
        // 也可能写在 `Read` 的 input 里（`{"file_path": "/tmp/report.pdf"}`）。
        // `bash_cmd` 单独传：血缘靠它判断这次调用有没有**写意图**（`> file`、
        // `curl -o file`），从而区分"产出者"与"只是提到过这个路径的消费者"。
        let (args, bash_cmd) = match &ev.payload {
            Payload::ToolCall {
                input_preview,
                bash_cmd,
                ..
            } => (
                format!("{} {}", input_preview, bash_cmd.as_deref().unwrap_or("")),
                bash_cmd.as_deref(),
            ),
            _ => (cmd.to_string(), None),
        };
        let step = self.lineage.on_call(&key, tool, &args, bash_cmd, ev.ts_wall_ns);
        self.calls.insert(
            key.clone(),
            Call {
                id,
                tool: tool.to_string(),
                cmd: one_line(cmd),
                ts_ns: ev.ts_ns,
                ts_wall_ns: ev.ts_wall_ns,
                resolved: false,
                step,
            },
        );
        self.order.push_back(key.clone());
        key
    }

    /// 内核行：如果它带着某条**还在等**的调用的 join key，就记进那条调用的证据里。
    ///
    /// 已经下过结论的调用不再收：归因行写死了它的结论，事后再改会让时间线上
    /// 出现两句话。挂起中的（`live`）照收 —— 那正是这个模块等待的东西。
    fn on_kernel(&mut self, ev: &Event) {
        let Some(id) = ev.corr.tool_use_id.as_deref() else {
            return;
        };
        if !self.live(id) {
            return;
        }
        let e = self.ev.entry(id.to_string()).or_default();
        e.kernel_events += 1;
        // v0.6 §14.2：写-open / connect 对端 / exec 三件事顺路记下来。
        // 用的是**同一条**内核事件、同一份 join key —— claim 核对没有第二条
        // 证据通道，它只能看这条调用挂住的东西。
        e.kb.observe(ev);
        match &ev.payload {
            Payload::ProcExec { filename, argv, .. } => {
                e.exec_file = Some(filename.clone());
                e.argv_tokens.insert(filename.clone());
                for a in argv {
                    if !a.is_empty() {
                        e.argv_tokens.insert(a.clone());
                    }
                }
                if let Some(b) = basename(argv.first().map(String::as_str).unwrap_or(filename)) {
                    e.ok_basenames.insert(b);
                }
            }
            Payload::ProcExecFail { filename, errno, .. } => {
                let base = basename(filename).unwrap_or_default();
                push_capped(
                    &mut e.exec_fail,
                    (base, format!("exec {} {}", filename, errno_str(*errno))),
                );
            }
            Payload::FileOpen {
                path, ok: false, errno, ..
            } => {
                let s = if *errno == 0 {
                    // v0.4 之前的 fixture 没有 errno —— 不编造名字。
                    format!("openat {} failed (errno not captured)", path)
                } else {
                    format!("openat {} {}", path, errno_str(*errno))
                };
                push_capped(&mut e.deep, (path.clone(), s));
            }
            Payload::NetConnect {
                addr,
                port,
                ok: false,
                pending: false,
                ..
            } => {
                // connect 的 payload 里没有 errno（§1.2 只留了 ok/pending），
                // 所以这里**不写** ECONNREFUSED —— 那会是一句我们没证据的话。
                let target = match port {
                    Some(p) => format!("{}:{}", addr, p),
                    None => addr.clone(),
                };
                let s = format!("connect {} failed (errno not captured)", target);
                push_capped(&mut e.deep, (target, s));
            }
            Payload::PolicyDeny {
                syscall, target, errno, ..
            } => {
                let s = format!("{} {} {}", syscall, target, errno_str(*errno));
                push_capped(&mut e.deep, (target.clone(), s));
            }
            Payload::ProcExit { exit_code } if *exit_code != 0 => {
                push_capped(
                    &mut e.exits,
                    format!(
                        "exit({}) at pid {}",
                        exit_code,
                        ev.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into())
                    ),
                );
            }
            _ => {}
        }
    }

    fn on_result(&mut self, ev: &Event, tool: Option<&str>, status: &str, text: &str) -> Resolution {
        let Some(key) = self.key_for_result(ev, tool) else {
            // 查不到归属的结果**必须计数**（DESIGN：不许静默丢失）。显式 id 查不到
            // 时尤其不能退到 FIFO：那会把这条结果的 corr 和另一条调用的 cmd 拼进
            // 同一条 XX 行 —— 一个比"没结论"更糟的结论。
            self.unmatched_results += 1;
            return Resolution::None;
        };
        let (verdict, detected_by) = judge(status, text);
        let call = match self.calls.get_mut(&key) {
            Some(c) => {
                c.resolved = true;
                c.clone()
            }
            None => return Resolution::None,
        };
        // v0.6 §14.1：结果文本是血缘的第二半 —— 消费关系（"第 12 步引用了 X"）
        // 大多写在结果里（`read /tmp/report.pdf`、`loaded /tmp/x.json`）。
        self.lineage.on_result(&key, !verdict, lineage::error_note(text), text);
        if !verdict {
            // 结果说它成功了。这里面有没有能被内核核对的话？（§14.2）
            //
            // 只有**有 claim** 才挂起：绝大多数成功调用没有任何 claim，
            // 为它们各留一条待定记录会让 `pending` 变成一条长尾，
            // 而它唯一的作用是几毫秒后自己把自己删掉。
            if self.lineage.claims_of(&key).is_empty() {
                self.ev.remove(&key);
                return Resolution::Clean;
            }
            self.pending.push_back(Pending {
                key,
                src: ev.clone(),
                text: text.to_string(),
                detected_by,
                call,
                kind: PendingKind::Claim,
            });
            return Resolution::ClaimPending;
        }

        // 不下结论，只挂起：证据可能还在内核流里（文件头"什么时候下结论"）。
        // 证据留在 `self.ev` 里继续累加 —— 所以这里**不能** remove。
        self.pending.push_back(Pending {
            key,
            src: ev.clone(),
            text: text.to_string(),
            detected_by,
            call,
            kind: PendingKind::Fail,
        });
        Resolution::Failed
    }

    /// 给结果找调用。带 id 的只做精确查表；不带的按 FIFO 同工具配对（见 `key_for_event`）。
    ///
    /// 显式 id 查不到（已 resolved / 调用行丢失 / 未知 id）时返回 `None`，由调用方
    /// 记入 `unmatched_results` —— 以前的"退到 FIFO"会把结果配给另一条同工具调用。
    fn key_for_result(&self, ev: &Event, tool: Option<&str>) -> Option<String> {
        if let Some(id) = ev.corr.tool_use_id.as_deref() {
            return self.calls.get(id).filter(|c| !c.resolved).map(|_| id.to_string());
        }
        self.order
            .iter()
            .find(|k| {
                self.calls
                    .get(*k)
                    .is_some_and(|c| !c.resolved && tool.is_none_or(|t| c.tool == t))
            })
            .cloned()
    }

    fn build_failure(&self, ev: &Event, call: &Call, text: &str, detected_by: String, e: &Evidence) -> Failure {
        let exit_code = exit_code_from_text(text);
        let sandbox = is_sandbox_init_error(text);
        let notfound = text.contains("command not found");
        let kernel_on = self.cfg.kernel_available;

        let (class, head, deepest);
        if kernel_on && e.kernel_events == 0 {
            // 内核在看着，而这条调用一条内核事件都没有：命令压根没跑起来。
            match (sandbox, notfound) {
                (true, _) => {
                    class = CLASS_BEFORE_EXEC;
                    head = "BEFORE exec: sandbox init failed (no kernel event)".to_string();
                }
                (_, true) => {
                    class = CLASS_BEFORE_EXEC;
                    head = "BEFORE exec: command not found (no execve)".to_string();
                }
                _ => {
                    class = CLASS_UNBOUND;
                    head = unbound_head(exit_code, "no kernel events linked to this call");
                }
            }
            deepest = None;
        } else if kernel_on {
            match e.deepest() {
                Some(d) => {
                    class = CLASS_KERNEL;
                    head = exit_head(exit_code);
                    deepest = Some(d);
                }
                None => {
                    class = CLASS_BOUND_NO_EVIDENCE;
                    head = unbound_head(exit_code, "bound subtree has no failing kernel event");
                    deepest = None;
                }
            }
        } else {
            // 这一轮没有内核源。**"内核里没有 X"这句话不成立** —— 我们没在看。
            match (sandbox, notfound) {
                (true, _) => {
                    class = CLASS_BEFORE_EXEC;
                    head = "BEFORE exec: sandbox init failed (no kernel event; this run had no kernel capture)"
                        .to_string();
                }
                (_, true) => {
                    class = CLASS_BEFORE_EXEC;
                    head = "BEFORE exec: command not found (no execve; this run had no kernel capture)".to_string();
                }
                _ => {
                    class = CLASS_NO_KERNEL_SOURCE;
                    head = unbound_head(exit_code, "no kernel source this run (-p/-C not given)");
                }
            }
            deepest = None;
        }

        Failure {
            ts_wall_ns: ev.ts_wall_ns,
            ts_ns: ev.ts_ns,
            tool: call.tool.clone(),
            cmd: call.cmd.clone(),
            head,
            deepest,
            class: class.to_string(),
            detected_by,
            tool_use_id: call.id.clone(),
            kernel_events: e.kernel_events,
            step: call.step,
            // 下面三项由调用方补（`attach_lineage` / `flush_claim_check`）：
            // 它们要读 `self.lineage`，而这里只借到了 `&Evidence`。
            lineage: Vec::new(),
            claims: Vec::new(),
            sniff: Vec::new(),
        }
    }
}

/// 结果文本 → (是否失败, 判定依据)。
///
/// **状态字段优先**：`is_error` 是 harness 自己的裁决，我们的文本解析没资格推翻它。
/// 只有状态不可解读（既不是成功词也不是失败词）时才退到文本 —— 那时它是唯一证据。
fn judge(status: &str, text: &str) -> (bool, String) {
    let t = status.trim().to_ascii_lowercase();
    if matches!(t.as_str(), "failure" | "failed" | "fail" | "error" | "err") {
        return (true, format!("status={}", status.trim()));
    }
    if matches!(t.as_str(), "success" | "ok" | "succeeded" | "pass" | "passed") {
        return (false, String::new());
    }
    if let Some(sig) = text_failure(text) {
        return (true, sig);
    }
    (false, String::new())
}

/// 文本里的失败信号（只用于状态字段不可解读的 adapter）。
///
/// 刻意收得很紧：**任何一个成功的 Bash 结果里都可能出现 "Error"**（命令的输出），
/// 所以这里只认 harness 自己会印的、且语义明确的三种形状。
fn text_failure(text: &str) -> Option<String> {
    if let Some(n) = exit_code_from_text(text)
        && n != 0
    {
        return Some(format!("text: Exit code {}", n));
    }
    if text.contains("command not found") {
        return Some("text: command not found".into());
    }
    if is_sandbox_init_error(text) {
        return Some("text: sandbox init error".into());
    }
    None
}

/// `Exit code 1` / `Exit code: 127` / `[exit code: 2]` → 1 / 127 / 2。
///
/// 只认 `exit code` + 可选冒号 + 数字的**字面协议**（大小写不敏感：DSH 的
/// shell 工具用全小写的 `[exit code: N]`，Claude Code 用 `Error: Exit code N`）。
/// 命令自己的输出（`exit=7`、`exit(2)`）**绝不能**被吃进来 —— 那会把一个成功的
/// `curl ... ; echo "exit=$?"` 读成失败（实测：那一行的结果正是 `stdout: exit=7`）。
pub fn exit_code_from_text(text: &str) -> Option<i64> {
    // `to_ascii_lowercase` 保持字节布局不变（ASCII 大小写映射等长，非 ASCII
    // 字节原样保留），所以下面的字节下标可以同时安全地切原文。
    let lower = text.to_ascii_lowercase();
    let needle = "exit code";
    let mut from = 0usize;
    while let Some(i) = lower[from..].find(needle) {
        let idx = from + i;
        let after = &text[idx + needle.len()..];
        let after = after.trim_start();
        let after = after.strip_prefix(':').unwrap_or(after).trim_start();
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return digits.parse::<i64>().ok();
        }
        from = idx + needle.len();
    }
    None
}

/// 沙箱/agent 层的初始化失败。这些命令**从未 fork/exec**，所以内核里什么都没有。
fn is_sandbox_init_error(text: &str) -> bool {
    let l = text.to_ascii_lowercase();
    l.contains("bwrap") || l.contains("bubblewrap") || (l.contains("sandbox") && l.contains("failed"))
}

fn exit_head(code: Option<i64>) -> String {
    match code {
        Some(n) => format!("exit {}", n),
        None => "failed".to_string(),
    }
}

fn unbound_head(code: Option<i64>, why: &str) -> String {
    format!("{}; {}", exit_head(code), why)
}

fn errno_str(e: i64) -> String {
    let n = errno_label(e);
    if n == "?" { format!("ERRNO({})", e) } else { n }
}

/// 一条 `tool.call` 在归因器内部的键。
///
/// 有 `corr.tool_use_id` 就用它 —— 那是 binder 盖在所有绑定内核行上的同一个
/// join key，用它当键，"这条调用挂住了哪些内核行"就退化成一次查表。
/// 没有 id 的 adapter（openshell fixture）用 `#<序号>`：仍然能被跟着、
/// 仍然能进 `--failures-only`，只是永远挂不上内核行（它没有 join key）。
fn call_key(id: &Option<String>, seq: u64) -> String {
    match id {
        Some(i) => i.clone(),
        None => format!("#{}", seq),
    }
}

/// 这个失败对象是不是命令**被明确要求**去处理的东西。
///
/// 判据只有一条：它是不是这次 exec 的 argv 操作数（或其一部分 —— `curl
/// http://127.0.0.1:9/` 的 argv 里是整个 URL，而 connect 记的是 `127.0.0.1:9`）。
///
/// 这条判据的目标是**良性探测**：locale 目录、`ld.so.cache`、PATH 里不存在的
/// 目录 —— 它们在内核里都是货真价实的失败，但它们是程序在试探，不是这次调用
/// 失败的原因。而"命令要它开的东西打不开"才是。
///
/// 它不猜因果：命中的那条 openat 仍然是内核里真实存在的一次失败，我们只是
/// 在两堆都是真话的证据里，挑了和这条命令行相关的那一堆。
fn asked_for(subject: &str, argv: &HashSet<String>) -> bool {
    if subject.is_empty() {
        return false;
    }
    argv.iter()
        .any(|t| t == subject || (subject.len() >= 4 && t.contains(subject)))
}

fn basename(p: &str) -> Option<String> {
    let b = p.rsplit('/').next().unwrap_or(p);
    if b.is_empty() { None } else { Some(b.to_string()) }
}

fn push_capped<T>(q: &mut VecDeque<T>, v: T) {
    if q.len() >= MAX_CANDIDATES {
        q.pop_front();
    }
    q.push_back(v);
}

/// 构造 `XX` 归因行。
///
/// ts/pid/comm 继承那条 `tool.result`（派生行必须落在它解释的事实的时间位置上；
/// 用 `tool.call` 的 ts 会让时间倒流 —— 结果永远晚于调用）。
/// corr 也继承结果：`tool_use_id` 因此挂在这一行上，`--failures-only` 的 jq
/// 配方才能用它把整条链捞出来。
fn fail_event(src: &Event, call: &Call, f: &Failure, settle_note: &str) -> Event {
    let mut notes = vec![format!(
        "failure attribution: class={}; detected by {}; {} kernel event(s) linked to this call",
        f.class, f.detected_by, f.kernel_events
    )];
    notes.push(format!(
        "tool.call at ts_ns={} ({} ns before the result)",
        call.ts_ns,
        src.ts_ns.saturating_sub(call.ts_ns)
    ));
    // 这条说明"我们等到了什么才敢下结论" —— 审计一句 `XX` 时最先要看的就是它。
    notes.push(format!("conclusion deferred until: {}", settle_note));
    // v0.6：血缘与内容嗅探的每一行都在这里留档 —— 它们是**用户态推断**，
    // 屏幕上的行文已经这么说了，json 里也必须留着同一句话。
    for l in &f.lineage {
        notes.push(format!("lineage (userspace inference, no kernel evidence): {}", l));
    }
    for s in &f.sniff {
        notes.push(format!(
            "content sniff (userspace heuristic, not kernel evidence): {}",
            s
        ));
    }
    Event {
        seq: 0,
        ts_ns: src.ts_ns,
        ts_wall_ns: src.ts_wall_ns,
        ts_src: src.ts_src,
        layer: Layer::Derived,
        kind: Kind::DerivedFail,
        source: "fail".into(),
        pid: None,
        tid: None,
        ppid: None,
        comm: None,
        cgroup_id: None,
        corr: src.corr.clone(),
        payload: Payload::Fail {
            step: f.step,
            tool: f.tool.clone(),
            cmd_preview: f.cmd.clone(),
            class: f.class.clone(),
            head: f.head.clone(),
            deepest: f.deepest.clone(),
            kernel_events: f.kernel_events,
        },
        trunc: Vec::new(),
        notes,
        late: false,
        watch: false,
        binding: Binding::None,
        retry: false,
    }
}

/// 构造一条 `derived.claim` 行：claim vs kernel 的**其余**几列。
///
/// 为什么要另一种 kind 而不是把几列都塞进 `XX` 行：一条 `tool.result` 里可能同时
/// 有"写了 /tmp/x.pdf"和"下了 https://…"两句话，它们是**两笔**对账。第一笔
/// （不一致的那些）说了算 `XX` 行，其余各占一行。它们渲染成 `derived`（不是
/// 红色 `XX`）是准确的 —— 只有不一致才是问题，对上的那笔只是核实过的事实。
fn claim_event(src: &Event, call: &Call, c: &ClaimVsKernel) -> Event {
    Event {
        seq: 0,
        ts_ns: src.ts_ns,
        ts_wall_ns: src.ts_wall_ns,
        ts_src: src.ts_src,
        layer: Layer::Derived,
        kind: Kind::DerivedClaim,
        source: "lineage".into(),
        pid: None,
        tid: None,
        ppid: None,
        comm: None,
        cgroup_id: None,
        corr: src.corr.clone(),
        payload: Payload::Claim {
            claim: c.claim.clone(),
            kernel: c.kernel.clone(),
            mismatch: c.mismatch,
        },
        trunc: Vec::new(),
        notes: vec![format!(
            "claim vs kernel for tool.call {} step {}: extracted from the tool.result text \
             (userspace) and checked against the kernel events bound to this call",
            call.tool, call.step
        )],
        late: false,
        watch: false,
        binding: Binding::None,
        retry: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Corr, TsSource};

    const S: u64 = 1_000_000_000;
    const T0: u64 = 1_700_000_000_000_000_000;

    fn base(ts: u64, kind: Kind, layer: Layer, payload: Payload) -> Event {
        Event {
            seq: 0,
            ts_ns: ts,
            ts_wall_ns: T0 + ts,
            ts_src: TsSource::Kernel,
            layer,
            kind,
            source: "t".into(),
            pid: None,
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr::default(),
            payload,
            trunc: vec![],
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        }
    }

    fn call(ts: u64, id: &str, tool: &str, cmd: &str) -> Event {
        let mut e = base(
            ts,
            Kind::AgentToolCall,
            Layer::Agent,
            Payload::ToolCall {
                tool: tool.into(),
                input_preview: cmd.into(),
                input_bytes: cmd.len(),
                via_mcp: false,
                bash_cmd: Some(cmd.into()),
            },
        );
        e.corr.tool_use_id = Some(id.into());
        e.ts_src = TsSource::WallOnly;
        e
    }

    fn result(ts: u64, id: &str, tool: &str, status: &str, text: &str) -> Event {
        let mut e = base(
            ts,
            Kind::AgentToolResult,
            Layer::Agent,
            Payload::ToolResult {
                tool: Some(tool.into()),
                status: status.into(),
                result_preview: text.into(),
            },
        );
        e.corr.tool_use_id = Some(id.into());
        e.ts_src = TsSource::WallOnly;
        e
    }

    /// 一条挂了 join key 的内核行。
    fn kernel(ts: u64, id: &str, pid: u32, payload: Payload) -> Event {
        let mut e = base(ts, Kind::RuntimeProcExec, Layer::Runtime, payload);
        e.corr.tool_use_id = Some(id.into());
        e.pid = Some(pid);
        e
    }

    fn exec_ok(ts: u64, id: &str, pid: u32, file: &str) -> Event {
        exec_argv(ts, id, pid, file, &[file])
    }

    /// 带真实 argv 的 exec —— 真实抓包里的 argv 就是命令自己写下的那些操作数。
    fn exec_argv(ts: u64, id: &str, pid: u32, file: &str, argv: &[&str]) -> Event {
        let mut e = kernel(
            ts,
            id,
            pid,
            Payload::ProcExec {
                filename: file.into(),
                argv: argv.iter().map(|s| (*s).to_string()).collect(),
                argc_total: None,
            },
        );
        e.kind = Kind::RuntimeProcExec;
        e
    }

    fn open_fail(ts: u64, id: &str, pid: u32, path: &str, errno: i64) -> Event {
        let mut e = kernel(
            ts,
            id,
            pid,
            Payload::FileOpen {
                path: path.into(),
                flags: 0,
                dirfd: -100,
                path_is_relative: false,
                ok: false,
                errno,
            },
        );
        e.kind = Kind::InfraFileOpen;
        e.layer = Layer::Infra;
        e
    }

    /// 一条**写意图** open（真机上的 `curl -o x` 就是这个形状：0x241 = W|CREAT|TRUNC）。
    /// 路径按内核原样给：`openat` 记的是**原始实参**，通常相对 cwd。
    fn open_write(ts: u64, id: &str, pid: u32, path: &str) -> Event {
        let mut e = kernel(
            ts,
            id,
            pid,
            Payload::FileOpen {
                path: path.into(),
                flags: 0x241,
                dirfd: -100,
                path_is_relative: true,
                ok: true,
                errno: 0,
            },
        );
        e.kind = Kind::InfraFileOpen;
        e.layer = Layer::Infra;
        e
    }

    fn exit_code(ts: u64, id: &str, pid: u32, code: i64) -> Event {
        let mut e = kernel(ts, id, pid, Payload::ProcExit { exit_code: code });
        e.kind = Kind::RuntimeProcExit;
        e
    }

    fn run(cfg: FailCfg, evs: Vec<Event>) -> (Vec<Event>, Vec<Failure>) {
        let mut a = FailAttributor::new(cfg);
        let mut out = a.process(evs);
        out.extend(a.finish());
        (out, a.failures)
    }

    fn kernel_on() -> FailCfg {
        FailCfg {
            only: false,
            kernel_available: true,
            settle_ns: 0,
            pid_linked: false,
        }
    }

    #[test]
    fn before_exec_when_the_kernel_saw_nothing() {
        let (_, f) = run(
            kernel_on(),
            vec![
                call(S, "t1", "Bash", "curl http://127.0.0.1:9/"),
                result(
                    2 * S,
                    "t1",
                    "Bash",
                    "Failure",
                    "Error: Exit code 1\nbwrap: loopback: Failed RTM_NEWADDR",
                ),
            ],
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class, CLASS_BEFORE_EXEC);
        assert_eq!(f[0].head, "BEFORE exec: sandbox init failed (no kernel event)");
        assert!(f[0].deepest.is_none());
    }

    #[test]
    fn command_not_found_is_named_as_such() {
        let (_, f) = run(
            kernel_on(),
            vec![
                call(S, "t1", "Bash", "foobarxyz123"),
                result(
                    2 * S,
                    "t1",
                    "Bash",
                    "Failure",
                    "Error: Exit code 127\n/bin/bash: line 1: foobarxyz123: command not found",
                ),
            ],
        );
        assert_eq!(f[0].class, CLASS_BEFORE_EXEC);
        assert_eq!(f[0].head, "BEFORE exec: command not found (no execve)");
    }

    #[test]
    fn deepest_infra_failure_beats_the_exit_symptom() {
        // `cat` 真的会 openat 它的操作数（`ls` 用的是 stat，见下一条测试）。
        let (out, f) = run(
            kernel_on(),
            vec![
                call(S, "t1", "Bash", "cat /nonexistent-dir-abc"),
                exec_argv(2 * S, "t1", 42, "/usr/bin/cat", &["cat", "/nonexistent-dir-abc"]),
                open_fail(3 * S, "t1", 42, "/nonexistent-dir-abc", -2),
                exit_code(4 * S, "t1", 42, 2),
                result(5 * S, "t1", "Bash", "Failure", "Error: Exit code 2\ncat: cannot access"),
            ],
        );
        assert_eq!(f[0].class, CLASS_KERNEL);
        assert_eq!(f[0].head, "exit 2");
        assert_eq!(
            f[0].deepest.as_deref(),
            Some("openat /nonexistent-dir-abc ENOENT via /usr/bin/cat")
        );
        // 归因行紧跟在 tool.result 之后，且带 XX 语义的 kind。
        assert_eq!(out.len(), 6);
        assert_eq!(out[5].kind, Kind::DerivedFail);
        assert_eq!(out[4].kind, Kind::AgentToolResult);
    }

    /// PATH 探测的 ENOENT 不是失败：同一个 basename 后来 exec 成功了。
    #[test]
    fn path_probe_enoints_are_not_a_failure_cause() {
        let mut evs = vec![call(S, "t1", "Bash", "git rev-parse HEAD")];
        for (i, p) in ["/home/v/.cargo/bin/git", "/home/v/.nvm/git", "/home/v/.bun/bin/git"]
            .iter()
            .enumerate()
        {
            let mut e = kernel(
                2 * S + i as u64,
                "t1",
                42,
                Payload::ProcExecFail {
                    filename: (*p).into(),
                    errno: -2,
                    errno_name: "ENOENT".into(),
                    argv: vec!["git".into()],
                },
            );
            e.kind = Kind::RuntimeProcExecFail;
            evs.push(e);
        }
        evs.push(exec_ok(2 * S + 100, "t1", 42, "/usr/bin/git"));
        // 不在 git 仓库里 -> git 自己以 128 退出。这是**唯一**的真实失败点。
        evs.push(exit_code(3 * S, "t1", 42, 128));
        evs.push(result(
            4 * S,
            "t1",
            "Bash",
            "Failure",
            "Error: Exit code 128\nfatal: not a git repository",
        ));
        let (_, f) = run(kernel_on(), evs);
        assert_eq!(f[0].class, CLASS_KERNEL);
        assert_eq!(
            f[0].deepest.as_deref(),
            Some("exit(128) at pid 42 via /usr/bin/git"),
            "探测用的 ENOENT 被当成了失败点"
        );
    }

    /// **实测回归**（真实的 `ls /nonexistent-dir-abc` 抓包，§13.6）：一次正常的
    /// `ls` 会产出几十条良性 ENOENT（locale 目录、`ld.so.cache`）。最深失败点必须是
    /// 命令**被要求**打开的那个目录，而不是这批探测里最后失败的那条。
    #[test]
    fn benign_probes_do_not_become_the_cause() {
        let mut e = kernel(
            2 * S,
            "t1",
            42,
            Payload::ProcExec {
                filename: "/usr/bin/ls".into(),
                argv: vec!["ls".into(), "/nonexistent-dir-abc".into()],
                argc_total: None,
            },
        );
        e.kind = Kind::RuntimeProcExec;
        let evs = vec![
            call(S, "t1", "Bash", "ls /nonexistent-dir-abc"),
            e,
            open_fail(3 * S, "t1", 42, "/etc/ld.so.cache", -2),
            open_fail(4 * S, "t1", 42, "/nonexistent-dir-abc", -2),
            // 这些在真实抓包里排在病因**之后**：光"取最后一条"会挑中它们。
            open_fail(5 * S, "t1", 42, "/usr/lib/locale/locale-archive", -2),
            open_fail(6 * S, "t1", 42, "/usr/share/locale-langpack/en/LC_MESSAGES/libc.mo", -2),
            exit_code(7 * S, "t1", 42, 2),
            result(8 * S, "t1", "Bash", "Failure", "Error: Exit code 2\nls: cannot access"),
        ];
        let (_, f) = run(kernel_on(), evs);
        assert_eq!(f[0].class, CLASS_KERNEL);
        assert_eq!(
            f[0].deepest.as_deref(),
            Some("openat /nonexistent-dir-abc ENOENT via /usr/bin/ls"),
            "把良性探测当成了病因"
        );
    }

    /// **实测回归**（§13.6）：`ls` 用 `stat` 看参数，不用 `openat` —— 所以内核里
    /// **没有**那个 ENOENT。此时子树里只剩 23 条 glibc 找 locale 的良性失败。
    ///
    /// 把它们里的任何一条说成"最深失败点"都是猜。宁可只说"它以 2 退出"。
    #[test]
    fn an_unrelated_failing_open_is_not_named_as_the_cause() {
        let evs = vec![
            call(S, "t1", "Bash", "ls /nonexistent-dir-abc"),
            exec_argv(2 * S, "t1", 42, "/usr/bin/ls", &["ls", "/nonexistent-dir-abc"]),
            open_fail(3 * S, "t1", 42, "/etc/ld.so.cache", -2),
            open_fail(4 * S, "t1", 42, "/usr/share/locale/en/LC_MESSAGES/libc.mo", -2),
            exit_code(5 * S, "t1", 42, 2),
            result(6 * S, "t1", "Bash", "Failure", "Error: Exit code 2\nls: cannot access"),
        ];
        let (_, f) = run(kernel_on(), evs);
        assert_eq!(f[0].class, CLASS_KERNEL, "子树是绑上的，只是里面没有病因");
        assert_eq!(
            f[0].deepest.as_deref(),
            Some("exit(2) at pid 42 via /usr/bin/ls"),
            "把和命令行无关的失败 open 说成了病因"
        );
    }

    /// 真正没跑起来的命令：exec_fail 之后**没有**成功的同 basename exec。
    #[test]
    fn exec_fail_without_a_successful_exec_is_a_cause() {
        let mut evs = vec![call(S, "t1", "Bash", "sh -c 'nosuchbinary'")];
        let mut e = kernel(
            2 * S,
            "t1",
            42,
            Payload::ProcExecFail {
                filename: "/usr/bin/nosuchbinary".into(),
                errno: -2,
                errno_name: "ENOENT".into(),
                argv: vec!["nosuchbinary".into()],
            },
        );
        e.kind = Kind::RuntimeProcExecFail;
        evs.push(e);
        evs.push(exit_code(3 * S, "t1", 42, 127));
        evs.push(result(4 * S, "t1", "Bash", "Failure", "Error: Exit code 127"));
        let (_, f) = run(kernel_on(), evs);
        assert_eq!(f[0].class, CLASS_KERNEL);
        assert_eq!(f[0].deepest.as_deref(), Some("exec /usr/bin/nosuchbinary ENOENT"));
    }

    #[test]
    fn successful_calls_never_get_a_row() {
        let (out, f) = run(
            kernel_on(),
            vec![
                call(S, "t1", "Bash", "echo hi"),
                exec_ok(2 * S, "t1", 42, "/usr/bin/echo"),
                exit_code(3 * S, "t1", 42, 0),
                result(4 * S, "t1", "Bash", "Success", "stdout: hi"),
            ],
        );
        assert!(f.is_empty());
        assert!(out.iter().all(|e| e.kind != Kind::DerivedFail));
    }

    /// **实测回归**（一次真实 `claude -p` 抓包，见 V06_RUN.log acceptance #4）。
    ///
    /// 结果文本说 `Saved to /tmp/…/work/q3.pdf`，而 curl 的**落盘 open 晚于**
    /// `tool.result` 到来；exec/fork 却早就在结果之前挂上了这条调用。修复前
    /// `settle` 的判据是"已经有内核事件挂上了 → 可以下结论"，于是那一刻就写出
    /// `no write open observed !!` —— 把一次真写真成了没写（真机上复现了两次）。
    ///
    /// 对账必须等水印越过 `结果时刻 + settle 窗口`：它说的是"整段流里都没有"，
    /// 而"整段流"在结果到达时还没走完。
    #[test]
    fn a_write_landing_after_the_result_is_not_reported_as_missing() {
        let cfg = FailCfg {
            only: false,
            kernel_available: true,
            settle_ns: 100 * 1_000_000, // 100ms，与 main.rs 的 merge-window 默认值同量级
            pid_linked: false,
        };
        let mut a = FailAttributor::new(cfg);
        // exec 先到（curl 起进程），结果随后 —— 这正是真实顺序。
        let out = a.process(vec![
            call(
                S,
                "t1",
                "Bash",
                "curl -s -o work/q3.pdf https://example.com/q3-revenue.pdf",
            ),
            exec_argv(S, "t1", 42, "/usr/bin/curl", &["curl", "-s", "-o", "work/q3.pdf"]),
            result(
                2 * S,
                "t1",
                "Bash",
                "Success",
                "stdout: Saved to /tmp/v06demo2/work/q3.pdf",
            ),
        ]);
        assert!(
            a.failures.is_empty(),
            "结果一到、内核只挂上了 exec 就抢答了: {:?}",
            a.failures
        );
        assert!(out.iter().all(|e| e.kind != Kind::DerivedFail), "抢在落盘前写了归因行");

        // 30ms 后 curl 才落盘：内核看到的是**相对**路径（openat 的原始实参）。
        let _ = a.process(vec![open_write(2 * S + 30_000_000, "t1", 42, "work/q3.pdf")]);
        assert!(
            a.failures.is_empty(),
            "一次真写被喊成了没写: {:?}",
            a.failures.iter().map(|f| &f.head).collect::<Vec<_>>()
        );
        assert_eq!(a.claims_mismatched, 0);
    }

    /// 反过来：落盘**始终没来**时，这句话照样要说，而且要等到水印走过后再说。
    #[test]
    fn a_claim_with_no_write_at_all_is_still_reported_after_the_watermark() {
        let cfg = FailCfg {
            only: false,
            kernel_available: true,
            settle_ns: 100 * 1_000_000,
            pid_linked: false,
        };
        let mut a = FailAttributor::new(cfg);
        a.process(vec![
            call(
                S,
                "t1",
                "Bash",
                "curl -s -o work/gone.pdf http://127.0.0.1:9/gone.pdf ; echo Saved",
            ),
            exec_argv(S, "t1", 42, "/usr/bin/curl", &["curl", "-s", "-o", "work/gone.pdf"]),
            result(
                2 * S,
                "t1",
                "Bash",
                "Success",
                "stdout: Saved to /tmp/v06demo2/work/gone.pdf",
            ),
        ]);
        assert!(a.failures.is_empty(), "还没等水印就下结论了");
        // 一条**别处**的内核行把水印推过 结果+窗口：现在可以说了。
        a.process(vec![exec_ok(3 * S, "t9", 99, "/usr/bin/true")]);
        assert_eq!(a.failures.len(), 1, "水印走过后仍然没有对账");
        assert!(
            a.failures[0].head.contains("no write open observed"),
            "{}",
            a.failures[0].head
        );
        assert!(a.failures[0].head.ends_with("!!"));
        assert_eq!(a.claims_mismatched, 1);
    }

    /// **钟源回归**：一条没挂上任何内核事件、但落在观测窗口内的调用，
    /// `in_window` 必须为真。
    ///
    /// 修复前这里比的是 `call.ts_ns`（CLOCK_MONOTONIC）与 `kernel_first_wall`
    /// （CLOCK_REALTIME epoch，来自内核事件的 `ts_wall_ns`）—— 单调钟要追平
    /// epoch 得跑几百年，比较恒为假，于是窗口判定永远不成立。
    #[test]
    fn a_call_in_the_window_with_no_kernel_events_is_in_window() {
        let cfg = FailCfg {
            only: false,
            kernel_available: true,
            settle_ns: 0,
            pid_linked: true,
        };
        let mut a = FailAttributor::new(cfg);
        // 一条别处调用的内核行先把窗口左沿立起来。它挂着 t9，而 t9 不是
        // 在等着的调用，所以不会给 t1 留下任何证据。
        a.process(vec![exec_ok(S, "t9", 99, "/usr/bin/true")]);
        // t1 在左沿**之后**才发起，且全程零内核事件。
        a.process(vec![call(2 * S, "t1", "Bash", "echo hi")]);

        let c = a.calls.get("t1").expect("调用该在表里");
        assert_eq!(
            a.ev.get("t1").map(|e| e.kernel_events).unwrap_or(0),
            0,
            "这条调用不该有内核事件"
        );
        assert!(
            a.window_ok("t1", c),
            "窗口内、零内核事件的调用被判成了不在窗口里（钟源比错了）"
        );
        let ev = Evidence::default();
        let facts = a.facts_for("t1", c, &ev);
        assert!(facts.in_window);
    }

    /// 上一条的**诚实边界**（2026-10-17 审计后收紧）：调用落在观测窗口内、会话级
    /// pid 绑定也成立，但它**没有 join key** —— 这时事实集为空，不能说"内核里没有"。
    /// v0.6 的第二个门曾把这种调用报成 `!! claim-mismatch`（把 `Read` 结果里的
    /// "Saved to …"、heredoc 里没绑上的真写真写成"agent 撒谎"）。现在必须只记
    /// `claims_unverified`，并单独记录"看了内核但没连上"这一类。
    #[test]
    fn an_unlinked_call_in_the_window_is_unverified_not_mismatched() {
        let cfg = FailCfg {
            only: false,
            kernel_available: true,
            settle_ns: 0,
            pid_linked: true,
        };
        let mut a = FailAttributor::new(cfg);
        let out = a.process(vec![
            // 窗口左沿：属于别的调用，不挂在 t1 上。
            exec_ok(S, "t9", 99, "/usr/bin/true"),
            // t1 在窗口内发起；它说自己写了盘，内核侧却一条事件都没有。
            call(
                2 * S,
                "t1",
                "Bash",
                "curl -s -o work/gone.pdf http://127.0.0.1:9/gone.pdf",
            ),
            result(
                3 * S,
                "t1",
                "Bash",
                "Success",
                "stdout: Saved to /tmp/v06demo2/work/gone.pdf",
            ),
        ]);
        let tail = a.finish();
        let all: Vec<&Event> = out.iter().chain(tail.iter()).collect();
        assert!(
            all.iter()
                .all(|e| e.kind != Kind::DerivedFail && e.kind != Kind::DerivedClaim),
            "没 join key 的调用不许产出 claim 对账行: {:?}",
            all.iter().map(|e| e.kind).collect::<Vec<_>>()
        );
        assert_eq!(a.claims_mismatched, 0, "没连上却说了'内核里没有'");
        assert!(a.failures.is_empty());
        assert_eq!(a.claims_unverified, 1);
        assert_eq!(a.claims_unverified_unlinked, 1, "必须和'压根没看内核'分开计数");
        assert!(
            a.claims_unverified_reason.is_some_and(|r| r.contains("join key")),
            "没资格核对时必须留下明确原因: {:?}",
            a.claims_unverified_reason
        );
    }

    /// 窗口**之外**的调用（发起于第一条内核事件之前）仍然不许核对 ——
    /// 修复不能把这道门槛整个拆掉。
    #[test]
    fn a_call_before_the_window_is_not_eligible_even_with_no_kernel_events() {
        let cfg = FailCfg {
            only: false,
            kernel_available: true,
            settle_ns: 0,
            pid_linked: true,
        };
        let mut a = FailAttributor::new(cfg);
        a.process(vec![
            // t1 先发起（采集器还没 attach）。
            call(S, "t1", "Bash", "curl -s -o work/gone.pdf http://127.0.0.1:9/gone.pdf"),
            // 窗口左沿随后才立起来。
            exec_ok(2 * S, "t9", 99, "/usr/bin/true"),
            result(
                3 * S,
                "t1",
                "Bash",
                "Success",
                "stdout: Saved to /tmp/v06demo2/work/gone.pdf",
            ),
        ]);
        a.finish();

        assert_eq!(a.claims_mismatched, 0, "采集前的那一段不该被拿来核对");
        assert_eq!(a.claims_unverified, 1, "没资格核对的 claim 必须只记数、不说话");
        assert!(a.failures.is_empty());
    }

    /// 成功的结果文本里出现 `exit=7` 之类的字面量，**不能**被读成失败。
    #[test]
    fn shell_exit_literals_in_a_success_result_are_not_failures() {
        let (out, f) = run(
            FailCfg {
                only: false,
                kernel_available: false,
                settle_ns: 0,
                pid_linked: false,
            },
            vec![
                call(S, "t1", "Bash", "curl -s -m 3 http://127.0.0.1:9/ ; echo \"exit=$?\""),
                result(2 * S, "t1", "Bash", "Success", "stdout: exit=7"),
            ],
        );
        assert!(f.is_empty(), "成功结果被误判成失败: {:?}", f);
        assert!(out.iter().all(|e| e.kind != Kind::DerivedFail));
    }

    /// 没有内核源时不许说"内核里没有"。
    #[test]
    fn without_a_kernel_source_the_claim_is_qualified() {
        let (_, f) = run(
            FailCfg {
                only: false,
                kernel_available: false,
                settle_ns: 0,
                pid_linked: false,
            },
            vec![
                call(S, "t1", "Bash", "ls /x"),
                result(2 * S, "t1", "Bash", "Failure", "Error: Exit code 2"),
            ],
        );
        assert_eq!(f[0].class, CLASS_NO_KERNEL_SOURCE);
        assert!(
            f[0].head.contains("no kernel source this run"),
            "没有内核源却断言了内核: {}",
            f[0].head
        );
    }

    /// 内核在看着、命令也跑了，但子树里没有任何失败事件 —— 不许编一个。
    #[test]
    fn bound_subtree_without_a_failing_event_says_so() {
        let (_, f) = run(
            kernel_on(),
            vec![
                call(S, "t1", "Bash", "true"),
                exec_ok(2 * S, "t1", 42, "/usr/bin/true"),
                exit_code(3 * S, "t1", 42, 0),
                result(4 * S, "t1", "Bash", "Failure", "Error: Exit code 2"),
            ],
        );
        assert_eq!(f[0].class, CLASS_BOUND_NO_EVIDENCE);
        assert!(f[0].deepest.is_none(), "编出了一个内核原因: {:?}", f[0].deepest);
    }

    #[test]
    fn failures_only_keeps_the_chain_and_drops_the_rest() {
        let cfg = FailCfg {
            only: true,
            kernel_available: true,
            settle_ns: 0,
            pid_linked: false,
        };
        let evs = vec![
            // 一条与失败无关的模型行：必须被丢掉
            base(
                S,
                Kind::AgentModelRequest,
                Layer::Agent,
                Payload::ModelRequest {
                    model: Some("m".into()),
                    input_tokens: None,
                    detail_preview: None,
                },
            ),
            call(2 * S, "t1", "Bash", "ls /x"),
            exec_ok(3 * S, "t1", 42, "/usr/bin/ls"),
            open_fail(4 * S, "t1", 42, "/x", -2),
            result(5 * S, "t1", "Bash", "Failure", "Error: Exit code 2"),
            // 一次成功的调用：整条链都要被丢掉
            call(6 * S, "t2", "Bash", "echo hi"),
            exec_ok(7 * S, "t2", 43, "/usr/bin/echo"),
            result(8 * S, "t2", "Bash", "Success", "stdout: hi"),
        ];
        let (out, f) = run(cfg, evs);
        assert_eq!(f.len(), 1);
        let kinds: Vec<Kind> = out.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                Kind::AgentToolCall,
                Kind::RuntimeProcExec,
                Kind::InfraFileOpen,
                Kind::AgentToolResult,
                Kind::DerivedFail,
            ],
            "过滤模式漏进或漏掉了不该有的行"
        );
        assert!(out.iter().all(|e| e.corr.tool_use_id.as_deref() == Some("t1")));
    }

    #[test]
    fn failures_only_keeps_a_before_exec_chain_too() {
        let cfg = FailCfg {
            only: true,
            kernel_available: true,
            settle_ns: 0,
            pid_linked: false,
        };
        let (out, f) = run(
            cfg,
            vec![
                call(S, "t1", "Bash", "foobarxyz123"),
                result(
                    2 * S,
                    "t1",
                    "Bash",
                    "Failure",
                    "Error: Exit code 127\ncommand not found",
                ),
            ],
        );
        assert_eq!(f.len(), 1);
        assert_eq!(out.len(), 3, "链头、结果、归因行");
    }

    #[test]
    fn origin_is_the_session_start_not_the_first_failure() {
        let a = {
            let mut a = FailAttributor::new(kernel_on());
            let _ = a.process(vec![
                base(
                    S,
                    Kind::AgentModelRequest,
                    Layer::Agent,
                    Payload::ModelRequest {
                        model: Some("m".into()),
                        input_tokens: None,
                        detail_preview: None,
                    },
                ),
                call(2 * S, "t1", "Bash", "x"),
                result(3 * S, "t1", "Bash", "Failure", "Error: Exit code 1"),
            ]);
            a
        };
        assert_eq!(a.origin_wall(), Some(T0 + S));
    }

    #[test]
    fn results_without_a_tool_use_id_still_pair_by_order() {
        let mut c = call(S, "t1", "Bash", "ls /x");
        c.corr.tool_use_id = None;
        let mut r = result(2 * S, "t1", "Bash", "Failure", "Error: Exit code 2");
        r.corr.tool_use_id = None;
        let (_, f) = run(kernel_on(), vec![c, r]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].tool, "Bash");
        assert!(f[0].tool_use_id.is_none());
    }

    /// 显式 id 的结果**只做精确查表**：重复/迟到/未知 id 不许退到 FIFO，把另一条
    /// 同工具调用坐实（XX 行里会拼进别人的 cmd 和 corr）。2026-10-17 审计修复。
    #[test]
    fn late_duplicate_result_never_resolves_another_call() {
        let mut a = FailAttributor::new(kernel_on());
        let out = a.process(vec![
            call(S, "c1", "Bash", "echo one"),
            result(2 * S, "c1", "Bash", "Success", "stdout: one"),
            call(3 * S, "c2", "Bash", "echo two"),
            // c1 已经 resolved，这条**同一个 id** 的重复结果以前会配给 c2。
            result(4 * S, "c1", "Bash", "Failure", "Error: Exit code 1"),
        ]);
        let tail = a.finish();
        let all: Vec<&Event> = out.iter().chain(tail.iter()).collect();
        assert!(
            all.iter().all(|e| e.kind != Kind::DerivedFail),
            "重复结果被配给了另一条调用: {:?}",
            all.iter().map(|e| e.kind).collect::<Vec<_>>()
        );
        assert!(a.failures.is_empty());
        assert_eq!(a.unmatched_results, 1, "查不到归属的结果必须计数");
    }

    /// **实测回归**（一次 `claude -p` 抓包，§13.5）：`tool.result` 先到，
    /// 它解释的 `execve` + `openat ENOENT` 后到。
    ///
    /// 修复前这一刻就下了结论，于是最深失败点被写成"内核里没有" —— 而内核明明
    /// 记着那次 ENOENT。结论必须等到证据到齐。
    #[test]
    fn evidence_arriving_after_the_result_still_wins() {
        let (out, f) = run(
            kernel_on(),
            vec![
                call(S, "t1", "Bash", "cat /nonexistent-dir-abc"),
                result(2 * S, "t1", "Bash", "Failure", "Error: Exit code 2\ncat: cannot access"),
                // ↓ 结果之后才流出来的内核证据（真实顺序就是如此）
                exec_argv(3 * S, "t1", 42, "/usr/bin/cat", &["cat", "/nonexistent-dir-abc"]),
                open_fail(4 * S, "t1", 42, "/nonexistent-dir-abc", -2),
                exit_code(5 * S, "t1", 42, 2),
            ],
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class, CLASS_KERNEL, "晚到的内核证据没有被采纳: {:?}", f[0]);
        assert_eq!(
            f[0].deepest.as_deref(),
            Some("openat /nonexistent-dir-abc ENOENT via /usr/bin/cat")
        );
        // 结论行跟着它引用的证据走：排在 exec 之后，而不是排在结果后面抢答。
        let fail_at = out.iter().position(|e| e.kind == Kind::DerivedFail).unwrap();
        let exec_at = out.iter().position(|e| e.kind == Kind::RuntimeProcExec).unwrap();
        assert!(fail_at > exec_at, "归因行抢在内核证据前面出现了");
    }

    /// 只有结果、没有证据时**不许**抢答：要等流尾（或水位线越过）才落笔，
    /// 而且落笔时说的是它当时知道的全部。
    #[test]
    fn a_lonely_result_waits_until_the_stream_is_settled() {
        let mut a = FailAttributor::new(kernel_on());
        let out = a.process(vec![
            call(S, "t1", "Bash", "ls /x"),
            result(2 * S, "t1", "Bash", "Failure", "Error: Exit code 2"),
        ]);
        assert!(
            out.iter().all(|e| e.kind != Kind::DerivedFail),
            "证据还没到齐就已经下结论了"
        );
        assert!(a.failures.is_empty(), "账也已经记上了，说明结论下早了");

        let tail = a.finish();
        assert_eq!(tail.len(), 1, "流尾没有补上欠着的那一行");
        assert_eq!(tail[0].kind, Kind::DerivedFail);
        assert_eq!(a.failures.len(), 1);
        assert_eq!(a.failures[0].class, CLASS_UNBOUND);
        assert!(
            tail[0].notes.iter().any(|n| n.contains("stream ended")),
            "没有交代结论是在什么条件下下的: {:?}",
            tail[0].notes
        );
    }

    /// 内核水位线越过结果之后就可以定论，不必等到流尾 —— 否则实时 tail 要等到
    /// 会话结束才看得见 `XX`。
    #[test]
    fn a_moving_kernel_watermark_settles_the_question() {
        let cfg = FailCfg {
            only: false,
            kernel_available: true,
            settle_ns: 100 * 1_000_000, // 100ms
            pid_linked: false,
        };
        let mut a = FailAttributor::new(cfg);
        let first = a.process(vec![
            call(S, "t1", "Bash", "ls /x"),
            result(2 * S, "t1", "Bash", "Failure", "Error: Exit code 2"),
        ]);
        assert!(a.failures.is_empty(), "水位线还没动就下结论了: {first:?}");

        // 一条与本次调用无关的内核行，时间戳越过 结果+窗口 → 内核流已经走过这里了
        let out = a.process(vec![exec_ok(3 * S, "t9", 99, "/usr/bin/true")]);
        assert_eq!(a.failures.len(), 1, "水位线越过后没有定论");
        assert_eq!(out.len(), 2, "那条内核行 + 补出的归因行");
        assert_eq!(out[1].kind, Kind::DerivedFail);
        assert!(
            out[1].notes.iter().any(|n| n.contains("kernel stream moved past")),
            "没有交代结论是在什么条件下下的: {:?}",
            out[1].notes
        );
    }

    #[test]
    fn exit_code_parsing_only_takes_the_harness_protocol() {
        assert_eq!(exit_code_from_text("Error: Exit code 1\nboom"), Some(1));
        assert_eq!(exit_code_from_text("Error: Exit code: 127"), Some(127));
        assert_eq!(exit_code_from_text("stdout: exit=7"), None);
        assert_eq!(exit_code_from_text("exit(0)"), None);
        assert_eq!(exit_code_from_text("Exit code 0"), Some(0));
        // DeepSeek Harness shell tools append the marker in lower case:
        // `...output...\n[exit code: 2]`.
        assert_eq!(exit_code_from_text("no such file\n[exit code: 2]"), Some(2));
        assert_eq!(exit_code_from_text("[exit code: 0]"), Some(0));
        assert_eq!(exit_code_from_text("note: exit code: 130"), Some(130));
        // Still not a shell literal.
        assert_eq!(exit_code_from_text("exit_code=5"), None);
    }

    #[test]
    fn sandbox_detection_is_narrow() {
        assert!(is_sandbox_init_error("bwrap: loopback: Failed RTM_NEWADDR"));
        assert!(is_sandbox_init_error("bubblewrap: no such file"));
        assert!(is_sandbox_init_error("sandbox failed to start"));
        assert!(!is_sandbox_init_error("stdout: hello"));
        assert!(!is_sandbox_init_error("sandbox is a nice word"));
    }
}
