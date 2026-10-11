//! v0.2：逻辑调用折叠（derived events）。
//!
//! 内核给的是**地面真相**，但它按"每发生一次系统调用"计数，而不是按"这个程序
//! 想干一件事"计数。真实会话里两处最刺眼的落差：
//!
//! - 一次 `execvp("git")` = glibc 按 PATH 逐个目录 `execve`，每个失败的目录产出
//!   一条 `exec_fail ENOENT` —— 实测 14 条裸行说的是同一件事；
//! - 一次 worker-pool 派生 = 7 条 `fork` 挤在 150µs 内。
//!
//! 于是"这是什么、它想干什么"被淹没在"它调用了哪些系统调用"里，用户只能自己
//! 去数、自己去 grep —— 而工具存在的意义恰恰是**替用户回答这个问题**。
//!
//! 本模块把这类**原始行**折叠成一条派生行，同时守住两条底线：
//!
//! 1. **一行原始行都没丢。** 折叠是显示层的摘要：`-v` 下原始行照常出现，
//!    `--output json` 永远只输出原始事件（见 `CollapseCfg::enabled` 的说明）。
//! 2. **只折叠能自证的形态。** 只有"同一个 pid、同一个 basename、连续的 ENOENT
//!    探测、随后 2s 内成功 exec"这一种能被证明是 PATH 搜索；EACCES/EPERM 一律保留
//!    裸行 —— 它们本身是"找到了但没权限"这个**结论**，折叠掉就把结论也折叠了。
//!
//! 折叠发生在 merger **之后**：merger 负责把事件排成近似时间序，本模块在这条
//! 有序流上做分组。分组需要"往后看"（等成功 exec / 等 10ms 窗口关闭），所以
//! 一个未决分组会把它**之后**的事件一起压住 —— 保持输出仍是时间序，
//! 代价见 `hold` 的说明。

use crate::event::{Event, Kind, Layer, Payload, one_line};
use std::collections::{HashMap, VecDeque};

/// 判定为一次 execvp 搜索所需的最少 ENOENT 探测数（K >= 2）。
pub const MIN_PROBES: usize = 2;
/// 成功 exec 必须落在首次探测之后的这个窗口内，才算同一次逻辑调用。
pub const EXEC_RESOLVE_NS: u64 = 2_000_000_000;
/// 判定为一次 fork 突发所需的最少子进程数。
pub const MIN_FORK_BURST: usize = 5;
/// fork 突发的统计窗口。
pub const FORK_BURST_NS: u64 = 10_000_000;
/// 两个**等价**的折叠行（同 basename、同落点、同探测数）在这个窗口内就合并成一行。
pub const MERGE_NS: u64 = 2_000_000_000;
/// 锚行背后最多允许积压多少行 —— 超过就不再等合并（见 `Pending`）。
///
/// 合并窗口按**事件时间**算（`MERGE_NS`），所以它不可能被"投递慢"拖长；但它也
/// 不会因为"没人再来"而提前结束。真要紧的是**内存**：锚行背后的行全部扣在
/// `buf` 里，`--file-all` 这类洪流下 2s 事件时间可能是几十万行。到这个数就放手 ——
/// 宁可多打一行摘要，也不能为了排版把内存吃光。
pub const HOLD_MAX_ITEMS: usize = 4096;
/// 父进程身份提示（`<= "..."`）的显示列上限。
///
/// 定这个数是为了让后缀**完整地**留在行内：前缀列是 50（`13+2+8+1+9+1+15+1`），
/// 正文 `fork -> 1234567 (python3)` 约 24–29 列，加上 `  <= ""` 的 7 列，
/// 留给命令行的余量约 36 列。取 32 留出 pid/comm 变长的余地 ——
/// 让 120 列的截断把 `"` 收尾吃掉、读者不知道提示在哪结束，等于没有这个功能。
/// 真超了也不会静默：渲染层照常截断并补 `~`。
const CMDLINE_HINT_COLS: usize = 32;
/// 身份提示在内存里的存储上限（显示列）。命令行可以很长，不设上限等于把
/// 每个进程的完整 argv 常驻内存。
const CMDLINE_STORE_COLS: usize = 200;

#[derive(Debug, Clone, Copy)]
pub struct CollapseCfg {
    /// 是否产出折叠行。
    ///
    /// `--no-collapse` 关掉它；**`--output json` 也关掉它** —— json 是给下游用的
    /// 无损流，"折叠"是一种呈现选择，不该出现在里面（铁律：json 永远只有原始事件）。
    pub enabled: bool,
    /// `-v`：原始行与折叠行**同时**出现（折叠行跟在它概括的那组之后）。
    pub verbose: bool,
    /// 是否给 fork 行补父进程身份（§v0.2 #3）。与 `enabled` 独立：它是给一条
    /// 原始行**加**信息，不是把多条原始行合成一条。
    pub identity: bool,
    /// 流的时间戳比墙钟落后多少（= merger 的重排窗口）。
    ///
    /// **分组窗口必须用流自己的钟来判**，不能用 `clock_gettime`：merger 交出来的
    /// 事件固定落后墙钟一个重排窗口（默认 200ms），拿墙钟去比"这条 fork 是不是
    /// 10ms 内的"——答案永远是"早就过期了"，于是 fork 突发永远攒不起来。
    /// 实测：第一版就是这么错的，7 条 fork 一条都没折。
    ///
    /// 反过来，光靠"最后一条事件的 ts"也不行：流闲下来的时候（复现里 python
    /// 跑完到 sleep 结束有 5s 没有事件）未决分组会一直扣着时间线。
    /// 所以取两者的大者：既知道流至少走到了哪，也知道墙钟证明了哪一段不会再有事件。
    pub stream_lag_ns: u64,
}

impl Default for CollapseCfg {
    fn default() -> Self {
        CollapseCfg {
            enabled: true,
            verbose: false,
            identity: true,
            stream_lag_ns: 200_000_000,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CollapseStats {
    /// 折叠成 `x -> /path (N PATH probes)` 的次数。
    pub execvp_resolved: u64,
    /// 折叠成 `x -> NOT FOUND (N probes)` 的次数。
    pub execvp_not_found: u64,
    /// 额外并入既有折叠行的等价调用数（合并是"少说一遍"，不是"丢一条"）。
    pub execvp_merged: u64,
    pub fork_bursts: u64,
    /// 被折叠掉的原始行总数 —— 用户据此核对"到底少看了多少行"。
    pub raw_events_replaced: u64,
    /// 拿到父进程命令行的 fork 行数。
    pub identity_hits: u64,
}

// ---------------------------------------------------------------
// 进程身份表：回答"这是哪个 python？"
// ---------------------------------------------------------------

/// pid → 命令行。两个来源：
/// - **attach 时的 /proc 扫描**（`seed`）：进程在 attach 之前就已经 exec 完了，
///   内核不会再把那次 exec 报给我们，只能从 /proc 补一条"合成记录"；
/// - **本次运行观察到的 exec/fork**：exec 给全量 argv，fork 让子进程继承父进程的
///   命令行（fork 不改变 cmdline，这是事实而不是猜测，直到它 exec 为止）。
#[derive(Debug, Default)]
pub struct ProcTable {
    cmdline: HashMap<u32, String>,
}

impl ProcTable {
    /// 从 /proc 读一批进程的命令行（`-p` 模式的种子集合）。
    pub fn seed(&mut self, pids: &[u32]) {
        for p in pids {
            if let Some(info) = crate::binding::read_proc(*p) {
                let s = info.cmdline_str();
                if !s.is_empty() {
                    self.set(*p, &s);
                }
            }
        }
    }

    fn set(&mut self, pid: u32, cmdline: &str) {
        let s = one_line(cmdline);
        let (cut, _) = crate::render::truncate_display(&s, CMDLINE_STORE_COLS);
        self.cmdline.insert(pid, cut);
    }

    /// 给渲染用的紧凑提示；过长时以 `...` 收尾（**看得见**地截断）。
    ///
    /// 刻意**不**写进 `trunc`：`trunc` 的含义是"这条内核证据的某个字段不完整"，
    /// 而这个字段根本不是采集来的证据，是我们从 /proc 读来的一行提示。
    /// 把它记成截断会让每个 fork 行都挂上 `~`，而 `~` 一旦变成噪声，
    /// 真正被截断的那些行就没人看了。
    pub fn hint(&self, pid: u32) -> Option<String> {
        let s = self.cmdline.get(&pid)?;
        let (cut, truncated) = crate::render::truncate_display(s, CMDLINE_HINT_COLS);
        Some(if truncated { format!("{}...", cut) } else { cut })
    }

    /// 用刚看到的事件更新表。**在给这一行做标注之后调用** ——
    /// exec 会覆盖旧命令行，fork 让子进程继承当前命令行。
    pub fn observe(&mut self, ev: &Event) {
        let Some(pid) = ev.pid else { return };
        match &ev.payload {
            Payload::ProcExec { filename, argv, .. } => {
                let s = if argv.is_empty() {
                    filename.clone()
                } else {
                    argv.join(" ")
                };
                if !s.is_empty() {
                    self.set(pid, &s);
                }
            }
            Payload::ProcFork { child_pid, .. } => {
                if let Some(parent) = self.cmdline.get(&pid).cloned() {
                    self.cmdline.insert(*child_pid, parent);
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------
// 折叠器
// ---------------------------------------------------------------

/// 缓冲里的一个位置：要么是自由行，要么属于某个分组。
enum BufItem {
    Raw(Event),
    Grouped(Event, u64),
}

enum GroupState {
    /// 还在等判定依据（成功 exec / 窗口关闭）。
    Open,
    /// 判定为**不可折叠**：原始行照常输出。
    Passthrough,
    /// 已折叠，派生行已就绪（放在组内第一条原始行的位置）。
    Collapsed(Event),
}

struct Group {
    /// 第一条原始行的事件，用来给派生行提供 ts / pid / comm / corr。
    template: Event,
    first_ts: u64,
    last_ts: u64,
    /// 还在缓冲里的本组行数（减到 0 就可以把组从表里删掉）。
    remaining: usize,
    state: GroupState,
    /// 非 `-v` 下派生行只输出一次（否则每弹一条原始行就重复一遍摘要）。
    emitted: bool,
    // ---- exec ----
    basename: String,
    /// ENOENT 探测次数（不含最终成功的那次 exec）。
    probes: usize,
    /// 成功 exec 的文件名。
    target: Option<String>,
    // ---- fork burst ----
    children: usize,
}

/// 一条等合并的折叠行（见 `push_derived`）。
struct Pending {
    /// 合并键 = 已经格式化好的摘要正文。两行**逐字相同**才合并：
    /// "看起来差不多"不是合并的理由，"说的是一回事"才是。
    key: String,
    ev: Event,
    /// 合并资格窗口的终点 = 锚行 ts + `MERGE_NS`，用**事件自己的钟**表示。
    ///
    /// 这里曾经是墙钟的"持有限期"（now + 50ms），实测证明那是错的：merger 的
    /// 投递节奏不是均匀的，复现脚本里 7 个子进程的 execvp 明明只差 2.6ms，却有
    /// 一个批次整整晚了 5s 才被投递上来（`lag_ms=5002`），50ms 的墙钟窗口早就过期，
    /// 屏幕上于是出现 3 条一模一样的摘要行。**"这两行说的是不是同一件事"是事件
    /// 时间上的问题，就该用事件时间回答**：只要来者的 ts 还在窗口内，它就有资格
    /// 并进来，中间隔了多少墙钟秒无关紧要。
    until: u64,
}

/// 一条**已经落盘**、但仍在合并窗口内的锚行。
///
/// 为什么需要它：锚行被事件时间的超时推出去之后，压在它后头的行才开始放，
/// 而同一批 worker 的摘要可能就在这批行里 —— 它的落点排在锚行**之后**
/// （中间隔着别的 pid 的原始行）。此时 `pending` 已经空了，摘要于是又开一条
/// 新锚行，屏幕上重新出现两条一模一样的行。实测复现：7 个子进程里有 6 个的
/// fork 挤在 2.6ms 内、第 7 个晚到，超时正好落在两者之间，输出是
/// `x6 calls` + 一条裸摘要 —— 正是合并要消灭的那个毛病。
///
/// `idx` 是**本批次** `out` 里的下标：锚行推出去之后 `out` 只增不改，所以这个
/// 下标在同一次调用内一直指向那一行。跨调用失效 —— `process` / `finish` 开头
/// 会清掉它，下标绝不会被带到另一个 `Vec` 上。
struct Emitted {
    key: String,
    until: u64,
    idx: usize,
}

/// 分组为什么结束。决定它变成折叠行还是原始行。
enum ExecClose {
    /// 等到了同 basename 的成功 exec。
    Resolved,
    /// 没有等到（超时 / 被别的 basename 打断 / 遇到别的 errno）。
    NoSuccess,
    /// 被同 pid 的无关事件打断 —— 不猜，原样输出。
    Interrupted,
    /// 流结束。`early` = 2s 窗口还没到就走到了流的尽头。
    Eof { early: bool },
}

pub struct Collapser {
    cfg: CollapseCfg,
    buf: VecDeque<BufItem>,
    groups: HashMap<u64, Group>,
    next_gid: u64,
    /// pid → 未决的 exec 探测组。
    exec_open: HashMap<u32, u64>,
    /// 父 pid → 未决的 fork 突发组。
    burst_open: HashMap<u32, u64>,
    pub proc: ProcTable,
    /// 一条还没放出去、还在等"有没有等价的调用"的折叠行。
    pending: Option<Pending>,
    /// 一条已经放出去、但还在窗口内的锚行（见 `Emitted`）。
    emitted: Option<Emitted>,
    /// 流已经结束（`finish`）：不再开新的合并窗口，所有行直接落盘。
    draining: bool,
    /// 至今见过的最大事件 ts（流自己的钟，见 `CollapseCfg::stream_lag_ns`）。
    last_ts: u64,
    stats: CollapseStats,
}

impl Collapser {
    pub fn new(cfg: CollapseCfg) -> Self {
        Collapser {
            cfg,
            buf: VecDeque::new(),
            groups: HashMap::new(),
            next_gid: 1,
            exec_open: HashMap::new(),
            burst_open: HashMap::new(),
            proc: ProcTable::default(),
            pending: None,
            emitted: None,
            draining: false,
            last_ts: 0,
            stats: CollapseStats::default(),
        }
    }

    pub fn stats(&self) -> CollapseStats {
        self.stats
    }

    /// `-p` 模式的种子集合：这些进程在 attach 之前就存在了，内核不会再报它们的
    /// exec，但它们的 fork 行同样需要"这是谁"。
    pub fn seed_procs(&mut self, pids: &[u32]) {
        if self.cfg.identity {
            self.proc.seed(pids);
        }
    }

    /// 处理一批事件，返回这一批应该输出的行（已保持时间序）。
    ///
    /// `now_ns` 与 merger 用同一个钟（CLOCK_MONOTONIC）。用**墙钟现在**而不是
    /// "最后一条事件的 ts"来判超时：真实运行里可能 2s 内一条事件都没有，
    /// 用事件 ts 的话未决分组永远不会超时，时间线就一直被压住。
    pub fn process(&mut self, events: Vec<Event>, now_ns: u64) -> Vec<Event> {
        let mut out = Vec::new();
        // 上一条"已落盘锚行"的下标说的是上一批的 `out`，到这一批就作废了。
        self.emitted = None;
        for ev in events {
            self.last_ts = self.last_ts.max(ev.ts_ns);
            // 锚行的合并窗口按**事件时间**判，见 `Pending::until`。
            self.flush_pending_if_past(&mut out, ev.ts_ns);
            // 分组窗口反过来用**流自己的钟**判，见 `CollapseCfg::stream_lag_ns`。
            self.expire(self.stream_now(now_ns));
            self.release(&mut out);
            self.on_event(ev);
            self.release(&mut out);
            self.check_hold_limit(&mut out);
        }
        // 批次末尾：merger 已经保证"ts 早于 now−窗口 的事件不会再来了"，
        // 所以这一次 expire 的判定是确定的 —— 攒不够成员的分组在这里定型。
        // 这一句同时是"流闲下来了"的唯一出口（没有新事件时循环体不执行）——
        // 墙钟兜底在这里把冻住的原始行放出去。
        self.expire(self.stream_now(now_ns));
        self.release(&mut out);
        self.check_hold_limit(&mut out);
        out
    }

    /// 锚行背后的积压到了上限就不再等合并 —— 见 `HOLD_MAX_ITEMS`。
    fn check_hold_limit(&mut self, out: &mut Vec<Event>) {
        if self.pending.is_some() && self.buf.len() >= HOLD_MAX_ITEMS {
            if let Some(p) = self.pending.take() {
                self.emit_anchor(out, p);
            }
            self.release(out);
        }
    }

    /// 把一条锚行推进 `out`，并记下它的位置 —— 同一次调用里随即被放出来的等价行
    /// 还要并回这一行（见 `Emitted`）。
    fn emit_anchor(&mut self, out: &mut Vec<Event>, p: Pending) {
        let idx = out.len();
        if let Some(key) = collapse_detail(&p.ev) {
            self.emitted = Some(Emitted {
                key,
                until: p.until,
                idx,
            });
        }
        out.push(p.ev);
    }

    /// 流自己的钟：见 `CollapseCfg::stream_lag_ns`。
    fn stream_now(&self, wall_now_ns: u64) -> u64 {
        self.last_ts.max(wall_now_ns.saturating_sub(self.cfg.stream_lag_ns))
    }

    /// 流结束：把所有未决分组收掉再输出。
    pub fn finish(&mut self, now_ns: u64) -> Vec<Event> {
        let mut out = Vec::new();
        // 流的尽头：合并窗口到此为止。锚行先落盘 —— 它的 ts 比后面所有未决分组
        // 都早，顺序不能乱。
        self.draining = true;
        if let Some(p) = self.pending.take() {
            out.push(p.ev);
        }
        // 未等到成功 exec 的探测组在这里定格。若 2s 窗口还没走完就到了流的尽头，
        // 结论同样成立（这段捕获里确实没有成功 exec），但必须让用户能看出
        // "这是流结束"与"这是等满 2s 的判定"不是一回事 —— 见 finish 的 note。
        let open: Vec<u32> = self.exec_open.keys().copied().collect();
        let stream_now = self.stream_now(now_ns);
        for pid in open {
            let early = self
                .groups
                .get(&self.exec_open[&pid])
                .map(|g| stream_now.saturating_sub(g.first_ts) < EXEC_RESOLVE_NS)
                .unwrap_or(false);
            self.close_exec(pid, ExecClose::Eof { early });
        }
        let bursts: Vec<u32> = self.burst_open.keys().copied().collect();
        for pid in bursts {
            self.close_burst(pid);
        }
        // 锚行已经落盘（`draining` 也不再开新窗口），剩下的行全部放出来。
        self.release(&mut out);
        out
    }

    // ---------------- 事件分派 ----------------

    fn on_event(&mut self, mut ev: Event) {
        // 身份标注必须在更新身份表**之前**：fork 行要显示的是"fork 的那一刻
        // 父进程在跑什么"，而不是这一行本身带来的新信息。
        let mut identity_hit = false;
        if self.cfg.identity && ev.kind == Kind::RuntimeProcFork {
            if let Some(pid) = ev.pid {
                if let Some(hint) = self.proc.hint(pid) {
                    if let Payload::ProcFork { parent_argv, .. } = &mut ev.payload {
                        *parent_argv = Some(hint);
                        identity_hit = true;
                    }
                }
            }
        }
        if identity_hit {
            self.stats.identity_hits += 1;
        }

        let group = if self.cfg.enabled {
            match ev.kind {
                Kind::RuntimeProcExecFail => self.on_exec_fail(&ev),
                Kind::RuntimeProcExec => self.on_exec_ok(&ev),
                Kind::RuntimeProcFork => self.on_fork(&ev),
                _ => {
                    // 同 pid 的**无关**事件 = 这次 PATH 搜索已经结束（execvp 的探测
                    // 之间不会有别的系统调用）。不猜它成没成，原样输出。
                    if let Some(pid) = ev.pid {
                        self.close_exec(pid, ExecClose::Interrupted);
                    }
                    None
                }
            }
        } else {
            None
        };

        self.proc.observe(&ev);

        match group {
            Some(gid) => {
                if let Some(g) = self.groups.get_mut(&gid) {
                    g.remaining += 1;
                    g.last_ts = g.last_ts.max(ev.ts_ns);
                }
                self.buf.push_back(BufItem::Grouped(ev, gid));
            }
            None => self.buf.push_back(BufItem::Raw(ev)),
        }
    }

    /// 一条 ENOENT 的 exec_fail。返回它归属的分组（新开的或既有的）。
    fn on_exec_fail(&mut self, ev: &Event) -> Option<u64> {
        let pid = ev.pid?;
        let Payload::ProcExecFail { errno, .. } = &ev.payload else {
            return None;
        };
        if *errno != -2 {
            // EACCES / EPERM / 其他：这些行本身是**结论**（找到了但进不去），
            // 折叠掉就等于把结论折叠了。它们同时意味着这次 PATH 搜索已经走到头。
            self.close_exec(pid, ExecClose::NoSuccess);
            return None;
        }
        let base = exec_basename(ev)?;
        if let Some(gid) = self.exec_open.get(&pid).copied() {
            let same_run = self
                .groups
                .get(&gid)
                .map(|g| g.basename == base && ev.ts_ns <= g.first_ts.saturating_add(EXEC_RESOLVE_NS))
                .unwrap_or(false);
            if same_run {
                if let Some(g) = self.groups.get_mut(&gid) {
                    g.probes += 1;
                }
                return Some(gid);
            }
            // basename 换了（不是同一次搜索），或窗口已经过期 —— 先给旧组收尾。
            self.close_exec(pid, ExecClose::NoSuccess);
        }
        Some(self.new_exec_group(pid, base, ev))
    }

    /// 一次成功的 exec。它可能是某个未决探测组的终点。
    fn on_exec_ok(&mut self, ev: &Event) -> Option<u64> {
        let pid = ev.pid?;
        let base = exec_basename(ev)?;
        let Some(gid) = self.exec_open.get(&pid).copied() else {
            return None;
        };
        let matched = self
            .groups
            .get(&gid)
            .map(|g| g.basename == base && ev.ts_ns <= g.first_ts.saturating_add(EXEC_RESOLVE_NS))
            .unwrap_or(false);
        if !matched {
            self.close_exec(pid, ExecClose::NoSuccess);
            return None;
        }
        // watchlist 命中过的 exec **绝不折叠**。安全视图的价值全在"这一行会被看见"，
        // 把它折进一条摘要行，等于让告警失效 —— 宁可多几行噪声。
        if ev.watch {
            self.close_exec(pid, ExecClose::Interrupted);
            return None;
        }
        if let Some(g) = self.groups.get_mut(&gid) {
            g.target = match &ev.payload {
                Payload::ProcExec { filename, .. } => Some(filename.clone()),
                _ => None,
            };
        }
        self.close_exec(pid, ExecClose::Resolved);
        // 成功的那次 exec 也属于这一组：默认模式下它被摘要行取代（信息没丢，
        // `git -> /usr/bin/git` 就是它），`-v` 下照常出现。
        Some(gid)
    }

    fn on_fork(&mut self, ev: &Event) -> Option<u64> {
        let parent = ev.pid?;
        if let Some(gid) = self.burst_open.get(&parent).copied() {
            let within = self
                .groups
                .get(&gid)
                .map(|g| ev.ts_ns <= g.first_ts.saturating_add(FORK_BURST_NS))
                .unwrap_or(false);
            if within {
                if let Some(g) = self.groups.get_mut(&gid) {
                    g.children += 1;
                }
                return Some(gid);
            }
            self.close_burst(parent);
        }
        Some(self.new_burst_group(parent, ev))
    }

    // ---------------- 分组的建立与收尾 ----------------

    fn new_group(&mut self, ev: &Event) -> u64 {
        let gid = self.next_gid;
        self.next_gid += 1;
        self.groups.insert(
            gid,
            Group {
                template: ev.clone(),
                first_ts: ev.ts_ns,
                last_ts: ev.ts_ns,
                remaining: 0,
                state: GroupState::Open,
                emitted: false,
                basename: String::new(),
                probes: 0,
                target: None,
                children: 0,
            },
        );
        gid
    }

    fn new_exec_group(&mut self, pid: u32, base: String, ev: &Event) -> u64 {
        let gid = self.new_group(ev);
        if let Some(g) = self.groups.get_mut(&gid) {
            g.basename = base;
            g.probes = 1;
        }
        self.exec_open.insert(pid, gid);
        gid
    }

    fn new_burst_group(&mut self, parent: u32, ev: &Event) -> u64 {
        let gid = self.new_group(ev);
        if let Some(g) = self.groups.get_mut(&gid) {
            g.children = 1;
        }
        self.burst_open.insert(parent, gid);
        gid
    }

    fn close_exec(&mut self, pid: u32, reason: ExecClose) {
        let Some(gid) = self.exec_open.remove(&pid) else {
            return;
        };
        let (probes, base, target, template) = match self.groups.get(&gid) {
            Some(g) => (g.probes, g.basename.clone(), g.target.clone(), g.template.clone()),
            None => return,
        };
        let collapsed = match reason {
            ExecClose::Resolved => {
                // 只有 >=2 次探测才值得折叠：1 次探测 + 1 次成功就是一次普通执行，
                // 折起来反而把"它执行了 /usr/bin/git"这条原始信息藏了。
                if probes >= MIN_PROBES {
                    if let Some(t) = &target {
                        let raw = (probes + 1) as u64;
                        self.stats.execvp_resolved += 1;
                        self.stats.raw_events_replaced += raw;
                        Some(collapse_event(
                            &template,
                            Kind::DerivedExecvp,
                            "execvp",
                            format!("{} -> {} ({} PATH probes)", base, t, probes),
                            raw,
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            ExecClose::NoSuccess | ExecClose::Eof { .. } => {
                if probes >= MIN_PROBES {
                    let raw = probes as u64;
                    self.stats.execvp_not_found += 1;
                    self.stats.raw_events_replaced += raw;
                    let mut e = collapse_event(
                        &template,
                        Kind::DerivedExecvp,
                        "execvp",
                        format!("{} -> NOT FOUND ({} probes)", base, probes),
                        raw,
                    );
                    if let ExecClose::Eof { early: true } = reason {
                        // 说清楚这个结论的边界：不是"等满了 2s 确认没有"，
                        // 而是"捕获到这里就结束了"。两者都成立，但读者有权知道是哪种。
                        e.notes.push(
                            "capture ended before the 2s window elapsed; a successful exec after \
                             this point would not have been in the capture"
                                .into(),
                        );
                    }
                    Some(e)
                } else {
                    None
                }
            }
            ExecClose::Interrupted => None,
        };
        self.set_group_outcome(gid, collapsed);
    }

    fn close_burst(&mut self, parent: u32) {
        let Some(gid) = self.burst_open.remove(&parent) else {
            return;
        };
        let (children, first, last, template) = match self.groups.get(&gid) {
            Some(g) => (g.children, g.first_ts, g.last_ts, g.template.clone()),
            None => return,
        };
        let collapsed = if children >= MIN_FORK_BURST {
            self.stats.fork_bursts += 1;
            self.stats.raw_events_replaced += children as u64;
            let span_ms = last.saturating_sub(first) as f64 / 1e6;
            Some(collapse_event(
                &template,
                Kind::DerivedForkBurst,
                "fork-burst",
                format!("{} forks in {:.1}ms", children, span_ms),
                children as u64,
            ))
        } else {
            None
        };
        self.set_group_outcome(gid, collapsed);
    }

    fn set_group_outcome(&mut self, gid: u64, collapsed: Option<Event>) {
        if let Some(g) = self.groups.get_mut(&gid) {
            g.state = match collapsed {
                Some(e) => GroupState::Collapsed(e),
                None => GroupState::Passthrough,
            };
        }
    }

    // ---------------- 超时 ----------------

    fn expire(&mut self, now: u64) {
        let exec_due: Vec<u32> = self
            .exec_open
            .iter()
            .filter(|(_, gid)| {
                self.groups
                    .get(gid)
                    .map(|g| now.saturating_sub(g.first_ts) > EXEC_RESOLVE_NS)
                    .unwrap_or(true)
            })
            .map(|(p, _)| *p)
            .collect();
        for pid in exec_due {
            self.close_exec(pid, ExecClose::NoSuccess);
        }

        let burst_due: Vec<u32> = self
            .burst_open
            .iter()
            .filter(|(_, gid)| {
                self.groups
                    .get(gid)
                    .map(|g| now.saturating_sub(g.first_ts) > FORK_BURST_NS)
                    .unwrap_or(true)
            })
            .map(|(p, _)| *p)
            .collect();
        for pid in burst_due {
            self.close_burst(pid);
        }
    }

    // ---------------- 输出 ----------------

    /// 把缓冲里**已经定案**的前缀放出去。
    ///
    /// 遇到未决分组就停下：它后面的事件必须等它 —— 否则折叠行（时间戳更早）
    /// 会排到它后面那些事件的后头，时间线出现倒序。代价是未决分组会**压住**
    /// 整条流水线：一次 PATH 探测通常几十微秒，压住的时间可以忽略；
    /// 但"命令不存在"要等满 2s 的超时窗口，这 2s 内时间线是停的。
    /// 这是为了让"execvp foo -> NOT FOUND"这个结论能成立而付的钱，写在 DESIGN §11。
    ///
    /// 另外还有一次等待：一条还没定案的合并锚行（`Pending`）同样会压住它后面的行，
    /// 直到事件时间走过 `MERGE_NS`，或积压到 `HOLD_MAX_ITEMS`。
    /// 用事件时间而不是墙钟判合并资格的理由写在 `Pending::until` 上。
    fn release(&mut self, out: &mut Vec<Event>) {
        enum Act {
            Hold,
            Raw(u64),
            /// (gid, derived row, this is the group's last buffered row, already emitted)
            Collapsed(u64, Event, bool, bool),
        }
        loop {
            // 扣着锚行时，**会产出原始行**的东西一律等 —— 否则那些行会先于锚行
            // 落到屏幕上，而锚行的 ts 更早，时间线出现倒序。
            let holding = self.pending.is_some();
            let act = match self.buf.front() {
                None => break,
                Some(BufItem::Raw(_)) => {
                    if holding {
                        break;
                    }
                    Act::Raw(0)
                }
                Some(BufItem::Grouped(_, gid)) => {
                    let gid = *gid;
                    match self.groups.get(&gid) {
                        Some(g) if g.remaining > 0 => match &g.state {
                            GroupState::Open => Act::Hold,
                            GroupState::Passthrough => {
                                if holding {
                                    break;
                                }
                                Act::Raw(gid)
                            }
                            GroupState::Collapsed(d) => {
                                // 例外：非 `-v` 下已定案的组只产出**一条派生行**，
                                // 它要么并进锚行、要么让锚行先落盘，两种都保持时间序。
                                // 必须放它过 —— 同一批 worker 的落点经常分散在两个
                                // drain 批次里（实测 6 个在第一批、第 7 个晚 2.6ms），
                                // 拦在这里就并不成一行了。
                                if holding && self.cfg.verbose {
                                    break;
                                }
                                Act::Collapsed(gid, d.clone(), g.remaining == 1, g.emitted)
                            }
                        },
                        // 组已经不在了（不该发生）：宁可当原始行放出去，也不吞掉。
                        _ => {
                            if holding {
                                break;
                            }
                            Act::Raw(gid)
                        }
                    }
                }
            };
            match act {
                Act::Hold => break,
                Act::Raw(gid) => {
                    let Some(item) = self.buf.pop_front() else {
                        break;
                    };
                    let ev = match item {
                        BufItem::Raw(e) => e,
                        BufItem::Grouped(e, _) => e,
                    };
                    if gid != 0 {
                        self.dec_group(gid);
                    }
                    out.push(ev);
                }
                Act::Collapsed(gid, d, is_last, already) => {
                    let Some(item) = self.buf.pop_front() else {
                        break;
                    };
                    let ev = match item {
                        BufItem::Raw(e) => e,
                        BufItem::Grouped(e, _) => e,
                    };
                    if !already {
                        // 摘要占住组内**第一条**原始行的位置 —— 两种模式都是。
                        //（少了这个判断就会每弹一条原始行重复输出一遍摘要：
                        // 7 次探测会打出 8 条一模一样的 execvp 行，比不折叠还吵。）
                        //
                        // 为什么不在 `-v` 下把它挪到组尾当"结论"：那样摘要行的 ts
                        // 会比它上面几行的 ts 还早，时间线上出现一次倒退 ——
                        // 而倒退在这套工具里是有专属记号（`(late)`）的严重信号，
                        // 不该被一个排版选择借用。默认模式下的位置也正是 spec 里
                        // 那行样例的位置。
                        self.push_derived(out, d);
                        if let Some(g) = self.groups.get_mut(&gid) {
                            g.emitted = true;
                        }
                    }
                    if self.cfg.verbose && self.pending.is_some() {
                        // `-v` 下摘要行和它概括的原始行都要打，而摘要刚被扣下 ——
                        // 这一条原始行不能先跑出去，否则摘要落在它后面，ts 倒退。
                        // 放回队首：这一条还没消费过，`remaining` 不动（早先这里多加了
                        // 1，于是 8 条缓冲行把 `remaining` 顶到 9，组永远删不掉）；
                        // `emitted` 已经置位，下次弹出来不会再产一遍摘要。
                        //
                        // 非 `-v` 的组不进这个分支：那一组的原始行本来就不输出，
                        // 直接消费掉才能走到后面的组 —— 拦在这里，同一批 worker
                        // 分散在两个 drain 批次时就并不成一行。
                        self.buf.push_front(BufItem::Grouped(ev, gid));
                        break;
                    }
                    if self.cfg.verbose {
                        // `-v`：原始行一条不少，跟在摘要后面。
                        out.push(ev);
                    }
                    self.dec_group(gid);
                    if is_last {
                        self.groups.remove(&gid);
                    }
                }
            }
        }
    }

    fn dec_group(&mut self, gid: u64) {
        if let Some(g) = self.groups.get_mut(&gid) {
            g.remaining = g.remaining.saturating_sub(1);
        }
    }

    /// 输出一条折叠行，并在可能时与**上一条等价**的折叠行合并。
    ///
    /// 为什么要合并：7 个 worker 同时 `execvp("git")` 是 7 次逻辑调用，
    /// 但它们说的是同一件事（同一个 basename、同一个落点、同样的探测数）。
    /// 打 7 行几乎相同的内容，正是"要我抓"的那个毛病本身 —— 用户得逐行比对
    /// 才能确认它们真的一样。合并成一行并**明写次数**，信息量不减而噪声归零。
    ///
    /// 实现是"扣住一条锚行等一会儿"而不是"往回改已经输出的行"：同一批 worker
    /// 的落点经常落在**不同的 drain 批次**里（实测复现：7 个子进程有 6 个在同一批
    /// 完成，第 7 个晚了 2.6ms），只在本批内合并的话屏幕上会出现两条一模一样的行。
    /// 扣住的代价（时间线跟着停 ≤ `MERGE_NS` 事件时间）写在 `Pending::until` 上。
    fn push_derived(&mut self, out: &mut Vec<Event>, d: Event) {
        let key = collapse_detail(&d);
        // 1) 能并进手里的锚行吗？
        if d.kind == Kind::DerivedExecvp {
            if let (Some(k), Some(p)) = (key.as_ref(), self.pending.as_mut()) {
                if *k == p.key && d.ts_ns <= p.until {
                    merge_into(&mut p.ev, &d);
                    // 原始行数在 `close_exec` 定案时已经记过 —— 并进来的是**行数**
                    // 不是新事件，再记一次就把"替掉多少行"翻倍（那是给用户核对的数）。
                    self.stats.execvp_merged += 1;
                    return;
                }
            }
            // 1b) 手里的锚行已经因为超时落盘了，但窗口还没过 —— 它就在这一批的
            //     `out` 里，位置记在 `Emitted` 上（见那里的注释）。
            //     只在默认模式下走这条路：`-v` 的契约是"每个组一条摘要 + 它自己的
            //     原始行"，合并掉一条摘要会让原始行失去归属。
            if !self.cfg.verbose {
                if let (Some(k), Some(e)) = (key.as_ref(), self.emitted.as_ref()) {
                    if *k == e.key && d.ts_ns <= e.until && e.idx < out.len() {
                        let idx = e.idx;
                        merge_into(&mut out[idx], &d);
                        self.stats.execvp_merged += 1;
                        return;
                    }
                }
            }
        }
        // 2) 并不上：手里的锚行定格，先落盘。
        //    这里不记 `emitted`：紧跟着就要放一条**不等价**的派生行，隔着它再回头
        //    合并会破坏"相邻的两条才合并"。
        if let Some(p) = self.pending.take() {
            out.push(p.ev);
        }
        // 3) 这条自己要不要开一个合并窗口？收尾阶段（`draining`）不再开 ——
        //    流的尽头没有"后面还有没有等价的"这个问题了。
        if d.kind == Kind::DerivedExecvp && !self.draining {
            if let Some(k) = key {
                self.pending = Some(Pending {
                    key: k,
                    until: d.ts_ns.saturating_add(MERGE_NS),
                    ev: d,
                });
                return;
            }
        }
        out.push(d);
    }

    /// 事件时间走过合并窗口就把锚行放出去；还在窗口内就继续扣着。
    ///
    /// 判据是**来者的 ts**，所以"锚行永远出不来"只可能发生在流真的停住的时候 ——
    /// 而那时候它背后也没有任何东西被压着，用户并没有少看到什么，剩下的半行会在
    /// `finish` 落盘（`--duration` / EOF / Ctrl-C 都会走到那里）。
    fn flush_pending_if_past(&mut self, out: &mut Vec<Event>, ts: u64) {
        let past = self.pending.as_ref().map(|p| ts > p.until).unwrap_or(false);
        if past {
            if let Some(p) = self.pending.take() {
                self.emit_anchor(out, p);
            }
        }
    }
}

fn collapse_detail(ev: &Event) -> Option<String> {
    match &ev.payload {
        Payload::Collapse { detail, .. } => Some(detail.clone()),
        _ => None,
    }
}

/// 把一条等价摘要并进锚行：只加**次数**和**它替掉的行数**，正文一个字不动。
/// 正文相同是合并的前提（见 `Pending::key`），所以这里不需要再拼字符串。
fn merge_into(anchor: &mut Event, d: &Event) {
    if let Payload::Collapse { raw_events, calls, .. } = &mut anchor.payload {
        *calls += 1;
        *raw_events += collapse_raw(d);
    }
}

fn collapse_raw(ev: &Event) -> u64 {
    match &ev.payload {
        Payload::Collapse { raw_events, .. } => *raw_events,
        _ => 0,
    }
}

/// 一条 exec 事件属于哪个"命令名"。优先 argv[0]（execvp 传的就是用户写的那个名字），
/// 拿不到 argv 就退到文件名的 basename —— 探测行的 filename 是 PATH 拼出来的路径，
/// 但它的 basename 与最终成功的那个 basename 相同，这正是分组要的。
fn exec_basename(ev: &Event) -> Option<String> {
    let (filename, argv) = match &ev.payload {
        Payload::ProcExec { filename, argv, .. } => (filename, argv),
        Payload::ProcExecFail { filename, argv, .. } => (filename, argv),
        _ => return None,
    };
    let src = argv
        .first()
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(filename.as_str());
    let base = src.rsplit('/').next().unwrap_or(src);
    if base.is_empty() { None } else { Some(base.to_string()) }
}

/// 构造一条折叠行。ts / pid / comm / corr 全部继承组内第一条原始行 ——
/// 派生行必须落在它概括的那组**所在的时间位置**上，否则时间线就错位了。
fn collapse_event(src: &Event, kind: Kind, form: &str, detail: String, raw: u64) -> Event {
    Event {
        seq: 0,
        ts_ns: src.ts_ns,
        ts_wall_ns: src.ts_wall_ns,
        ts_src: src.ts_src,
        layer: Layer::Derived,
        kind,
        source: "collapse".into(),
        pid: src.pid,
        tid: None,
        ppid: None,
        comm: src.comm.clone(),
        cgroup_id: None,
        corr: src.corr.clone(),
        payload: Payload::Collapse {
            form: form.to_string(),
            detail,
            raw_events: raw,
            calls: 1,
        },
        trunc: Vec::new(),
        notes: Vec::new(),
        late: false,
        watch: false,
        // v0.3：折叠的是**同一批内核行**，它们的 `binding` 是同一个值（按 pid 判定），
        // 所以继承组内第一条的即可。丢了这个字段，一次被精确绑定的 execvp 会被
        // 摘要行抹掉 `=` —— 摘要把"这条链属于哪次 tool.call"一起摘没了。
        binding: src.binding,
        retry: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Binding, Corr, TsSource};

    fn base(ts: u64, pid: u32, kind: Kind, payload: Payload) -> Event {
        Event {
            seq: ts,
            ts_ns: ts,
            ts_wall_ns: 1_700_000_000_000_000_000 + ts,
            ts_src: TsSource::Kernel,
            layer: Layer::Runtime,
            kind,
            source: "kernel".into(),
            pid: Some(pid),
            tid: None,
            ppid: None,
            comm: Some("prog".into()),
            cgroup_id: None,
            corr: Corr::default(),
            payload,
            trunc: Vec::new(),
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        }
    }

    fn basename(p: &str) -> String {
        p.rsplit('/').next().unwrap_or(p).to_string()
    }

    /// 一次 ENOENT 探测行。真实形态：`execvp("git", ...)` 让 glibc 拿 argv[0] 去拼
    /// 每个 PATH 目录，所以 filename 是拼出来的完整路径、argv[0] 还是用户写的名字，
    /// 两者的 basename 相同。`probe_named` 是那个"不同"的例外，专门用来验证
    /// 分组认的是 argv[0] 而不是路径。
    fn probe(ts: u64, pid: u32, path: &str) -> Event {
        probe_named(ts, pid, path, &basename(path))
    }

    fn probe_named(ts: u64, pid: u32, path: &str, argv0: &str) -> Event {
        base(
            ts,
            pid,
            Kind::RuntimeProcExecFail,
            Payload::ProcExecFail {
                filename: path.into(),
                errno: -2,
                errno_name: "ENOENT".into(),
                argv: vec![argv0.into(), "rev-parse".into()],
            },
        )
    }

    fn exec_ok(ts: u64, pid: u32, path: &str) -> Event {
        exec_ok_named(ts, pid, path, &basename(path))
    }

    fn exec_ok_named(ts: u64, pid: u32, path: &str, argv0: &str) -> Event {
        base(
            ts,
            pid,
            Kind::RuntimeProcExec,
            Payload::ProcExec {
                filename: path.into(),
                argv: vec![argv0.into(), "rev-parse".into()],
                argc_total: Some(2),
            },
        )
    }

    /// 走完一条完整的流：`process` 之后再 `finish` —— 未决分组（比如"还在等
    /// 成功 exec"）只有到流的尽头才能定案，这一步不能省。
    fn run(c: &mut Collapser, evs: Vec<Event>, now: u64) -> Vec<Event> {
        let mut out = c.process(evs, now);
        out.extend(c.finish(now));
        out
    }

    fn fork(ts: u64, parent: u32, child: u32) -> Event {
        base(
            ts,
            parent,
            Kind::RuntimeProcFork,
            Payload::ProcFork {
                child_pid: child,
                child_comm: "prog".into(),
                parent_argv: None,
            },
        )
    }

    fn detail_of(ev: &Event) -> String {
        match &ev.payload {
            Payload::Collapse { detail, .. } => detail.clone(),
            other => panic!("not a collapse row: {:?}", other),
        }
    }

    fn calls_of(ev: &Event) -> u64 {
        match &ev.payload {
            Payload::Collapse { calls, .. } => *calls,
            _ => 0,
        }
    }

    /// 7 次 PATH 探测 + 1 次成功 exec = 一条派生行。
    #[test]
    fn execvp_collapses_path_probes() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![];
        for (i, dir) in [
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local/bin",
            "/snap/bin",
            "/opt/bin",
        ]
        .iter()
        .enumerate()
        {
            evs.push(probe(1_000 + i as u64 * 10, 42, &format!("{}/git", dir)));
        }
        evs.push(exec_ok(1_100, 42, "/usr/bin/git"));
        let out = run(&mut c, evs, 1_200);
        assert_eq!(out.len(), 1, "expected one derived row, got {:?}", out);
        assert_eq!(out[0].kind, Kind::DerivedExecvp);
        assert_eq!(detail_of(&out[0]), "git -> /usr/bin/git (7 PATH probes)");
        assert_eq!(out[0].layer, Layer::Derived);
        assert_eq!(out[0].ts_ns, 1_000, "the derived row must sit at the group's first ts");
        assert_eq!(c.stats().execvp_resolved, 1);
        assert_eq!(c.stats().raw_events_replaced, 8);
    }

    /// 每次探测的 filename basename 不同也要能分组 —— 分组用的是 argv[0]。
    #[test]
    fn grouping_uses_argv0_not_the_probe_path() {
        let mut c = Collapser::new(CollapseCfg::default());
        let out = run(
            &mut c,
            vec![
                // PATH 里装的是带版本号的名字，argv[0] 仍是 `git`
                probe_named(1, 42, "/usr/local/bin/git-2.43", "git"),
                probe_named(2, 42, "/usr/bin/git-2.39", "git"),
                exec_ok_named(3, 42, "/usr/bin/git-2.39", "git"),
            ],
            10,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(detail_of(&out[0]), "git -> /usr/bin/git-2.39 (2 PATH probes)");
    }

    /// 单次探测 + 成功 = 普通执行，不折叠（折了反而藏起原始信息）。
    #[test]
    fn a_single_probe_is_not_a_path_search() {
        let mut c = Collapser::new(CollapseCfg::default());
        let out = run(
            &mut c,
            vec![probe(1, 42, "/opt/x/git"), exec_ok(2, 42, "/opt/x/git")],
            10,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, Kind::RuntimeProcExecFail);
        assert_eq!(out[1].kind, Kind::RuntimeProcExec);
        assert_eq!(c.stats().execvp_resolved, 0);
    }

    /// 没有成功 exec：等满 2s 后给 `NOT FOUND`，而不是无限压着时间线。
    #[test]
    fn not_found_after_the_window() {
        let mut c = Collapser::new(CollapseCfg::default());
        let held = c.process(vec![probe(1, 42, "/usr/bin/nope"), probe(2, 42, "/bin/nope")], 3);
        assert!(held.is_empty(), "must still be undecided inside the window");
        // 注意用**墙钟**推进：流已经闲下来了，流的钟（`stream_now`）靠墙钟 − 重排窗口
        // 继续走，所以窗口到期点比事件 ts 晚一个窗口。
        let still = c.process(vec![], 2_000_000_002 + 300_000_000);
        assert!(still.is_empty(), "the summary becomes an anchor of its own");
        // 定了案的摘要行自己也是锚行，同样要等一等**等价**的调用（另一个进程也没
        // 找到 `nope` 说的是同一件事）。窗口按事件时间算，所以下面这条 ts 走出
        // `MERGE_NS` 的无关事件就是"等完了"的那个信号 —— 它一到，锚行先落盘。
        let out = c.process(vec![probe(3_000_000_000, 77, "/usr/bin/other")], 3_100_000_000);
        assert_eq!(out.len(), 1, "{:?}", out);
        assert_eq!(detail_of(&out[0]), "nope -> NOT FOUND (2 probes)");
        assert_eq!(detail_of(&out[0]), "nope -> NOT FOUND (2 probes)");
        assert_eq!(c.stats().execvp_not_found, 1);
    }

    /// 流在窗口走完之前就结束了：结论照下，但必须说清"这是捕获到头了"。
    #[test]
    fn not_found_at_eof_says_so() {
        let mut c = Collapser::new(CollapseCfg::default());
        let _ = c.process(vec![probe(1, 42, "/usr/bin/nope"), probe(2, 42, "/bin/nope")], 3);
        let out = c.finish(4);
        assert_eq!(out.len(), 1);
        assert_eq!(detail_of(&out[0]), "nope -> NOT FOUND (2 probes)");
        assert_eq!(out[0].notes.len(), 1, "the early-EOF caveat must be attached");
        // 等满窗口之后再 EOF 就不是"提前结束"，不该有这条注记。
        let mut c2 = Collapser::new(CollapseCfg::default());
        let _ = c2.process(vec![probe(1, 42, "/usr/bin/nope"), probe(2, 42, "/bin/nope")], 3);
        let out2 = c2.finish(EXEC_RESOLVE_NS + 300_000_000);
        assert!(out2[0].notes.is_empty());
    }

    /// EACCES 保留原始行，而且它终结了这次 PATH 搜索。
    #[test]
    fn eacces_stays_raw() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![probe(1, 42, "/usr/bin/x"), probe(2, 42, "/bin/x")];
        evs.push(base(
            3,
            42,
            Kind::RuntimeProcExecFail,
            Payload::ProcExecFail {
                filename: "/root/x".into(),
                errno: -13,
                errno_name: "EACCES".into(),
                argv: vec!["x".into()],
            },
        ));
        let out = run(&mut c, evs, 10);
        // 折叠行（那 2 次 ENOENT 探测）+ EACCES 原始行
        assert_eq!(out.len(), 2, "{:?}", out);
        assert_eq!(out[0].kind, Kind::DerivedExecvp);
        assert_eq!(out[1].kind, Kind::RuntimeProcExecFail);
    }

    /// 同 pid 的无关事件打断探测组 —— 不猜，原样输出。
    #[test]
    fn an_unrelated_event_breaks_the_guess() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![probe(1, 42, "/usr/bin/x"), probe(2, 42, "/bin/x")];
        evs.push(base(
            3,
            42,
            Kind::InfraFileOpen,
            Payload::FileOpen {
                path: "/tmp/z".into(),
                flags: 1,
                dirfd: -100,
                path_is_relative: false,
                ok: true,
                errno: 0,
            },
        ));
        let out = c.process(evs, 10);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|e| !e.is_collapse()));
    }

    /// 7 次 fork 挤在 10ms 内 = 一条派生行；父进程身份来自 /proc 种子。
    #[test]
    fn fork_burst_collapses_and_identifies_the_parent() {
        // 身份由 `identity_comes_from_the_proc_seed` 单独验证；这里只看折叠本身。
        let mut c = Collapser::new(CollapseCfg::default());
        // 20µs 一个：7 个挤在 120µs 内，正是 worker-pool 派生的形态。
        let mut evs = vec![fork(1_000, 42, 100)];
        for i in 1..7u32 {
            evs.push(fork(1_000 + i as u64 * 20_000, 42, 100 + i));
        }
        let out = run(&mut c, evs, 2_000);
        assert_eq!(out.len(), 1, "{:?}", out);
        assert_eq!(out[0].kind, Kind::DerivedForkBurst);
        assert_eq!(detail_of(&out[0]), "7 forks in 0.1ms");
        assert_eq!(c.stats().fork_bursts, 1);
    }

    /// 5 次以下不折叠；10ms 以外不折叠。
    #[test]
    fn fork_burst_needs_five_inside_the_window() {
        let mut c = Collapser::new(CollapseCfg::default());
        let evs: Vec<Event> = (0..4u32).map(|i| fork(1_000 + i as u64, 42, 100 + i)).collect();
        let out = run(&mut c, evs, 1_000_000_000);
        assert_eq!(out.len(), 4);
        assert!(out.iter().all(|e| !e.is_collapse()));

        let mut c2 = Collapser::new(CollapseCfg::default());
        let evs: Vec<Event> = (0..6u32)
            .map(|i| fork(1_000 + i as u64 * 20_000_000, 42, 100 + i))
            .collect();
        let out2 = run(&mut c2, evs, 200_000_000);
        assert_eq!(out2.len(), 6, "forks spread over 100ms are not a burst");
    }

    /// `--no-collapse`：一条原始行都不动。
    #[test]
    fn disabled_passes_everything_through() {
        let mut c = Collapser::new(CollapseCfg {
            enabled: false,
            identity: false,
            ..CollapseCfg::default()
        });
        let mut evs = vec![probe(1, 42, "/usr/bin/git"), probe(2, 42, "/bin/git")];
        evs.push(exec_ok(3, 42, "/usr/bin/git"));
        let out = c.process(evs, 10);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|e| !e.is_collapse()));
    }

    /// `-v`：摘要照常出现，原始行一条不少跟在它后面。
    #[test]
    fn verbose_keeps_the_raw_rows_next_to_the_summary() {
        let mut c = Collapser::new(CollapseCfg {
            verbose: true,
            ..CollapseCfg::default()
        });
        let mut evs = vec![probe(1, 42, "/usr/bin/git"), probe(2, 42, "/bin/git")];
        evs.push(exec_ok(3, 42, "/usr/bin/git"));
        let out = run(&mut c, evs, 10);
        assert_eq!(out.len(), 4, "{:?}", out);
        assert_eq!(
            out[0].kind,
            Kind::DerivedExecvp,
            "the summary keeps the group's position"
        );
        assert_eq!(
            out[1].kind,
            Kind::RuntimeProcExecFail,
            "raw rows are kept, not replaced"
        );
        assert_eq!(out[2].kind, Kind::RuntimeProcExecFail);
        assert_eq!(out[3].kind, Kind::RuntimeProcExec);
        // 时间戳必须仍然单调：摘要在前、原始行在后，`-v` 下也不能出现倒退。
        for w in out.windows(2) {
            assert!(w[0].ts_ns <= w[1].ts_ns, "ts went backwards: {:?}", out);
        }
    }

    /// 并入的等价调用明写次数 —— 7 行摘要合成 1 行，但次数看得见。
    #[test]
    fn equivalent_calls_merge_and_are_counted() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![];
        for child in 0..7u32 {
            let pid = 100 + child;
            evs.push(probe(1_000, pid, "/usr/bin/git"));
            evs.push(probe(1_010, pid, "/bin/git"));
            evs.push(exec_ok(1_020, pid, "/usr/bin/git"));
        }
        let out = run(&mut c, evs, 2_000);
        assert_eq!(out.len(), 1, "{:?}", out);
        assert_eq!(calls_of(&out[0]), 7);
        assert_eq!(out[0].ts_ns, 1_000);
        assert_eq!(c.stats().execvp_merged, 6);
    }

    /// 跨 drain 批次的合并：同一批 worker 的落点经常分散在两个批次里
    /// （实测复现：7 个子进程 6 个在第一批，第 7 个晚了 2.6ms）。
    /// 只在本批内合并的话，屏幕上会出现两条一模一样的 execvp 行 —— 那正是
    /// "为什么要我抓"的那个毛病：读者得逐字比对才知道它们说的是同一件事。
    #[test]
    fn equivalent_calls_merge_across_drain_batches() {
        let mut c = Collapser::new(CollapseCfg::default());
        let first = c.process(
            vec![
                probe(1_000, 100, "/bin/git"),
                probe(1_010, 100, "/bin/git"),
                exec_ok(1_020, 100, "/bin/git"),
                probe(1_030, 101, "/bin/git"),
                probe(1_040, 101, "/bin/git"),
                exec_ok(1_050, 101, "/bin/git"),
            ],
            2_000,
        );
        assert!(first.is_empty(), "the anchor is held open for more equivalent calls");
        let second = c.process(
            vec![
                probe(3_600, 102, "/bin/git"),
                probe(3_610, 102, "/bin/git"),
                exec_ok(3_620, 102, "/bin/git"),
            ],
            4_000,
        );
        assert!(second.is_empty(), "still inside the hold window");
        let tail = c.finish(4_000);
        assert_eq!(tail.len(), 1, "{:?}", tail);
        assert_eq!(calls_of(&tail[0]), 3);
        assert_eq!(collapse_raw(&tail[0]), 9, "9 raw lines replaced, counted once each");
    }

    /// 持有是**有界**的：没有等价的调用来，锚行也必须到点就走。
    /// 否则一个不断产生折叠行的进程会让整条时间线停在那儿。
    ///
    /// 这个界是**事件时间**上的（锚行 ts + `MERGE_NS`），不是墙钟 —— 复现脚本里
    /// 第 7 个子进程的落点整整晚了 5s 才投递上来（merger 的投递节奏不均），墙钟
    /// 窗口会在它到达之前就把锚行放走，屏幕上于是出现 3 条一模一样的摘要行。
    #[test]
    fn the_merge_hold_is_bounded() {
        let mut c = Collapser::new(CollapseCfg::default());
        let first = c.process(
            vec![
                probe(1_000, 100, "/bin/git"),
                probe(1_010, 100, "/bin/git"),
                exec_ok(1_020, 100, "/bin/git"),
            ],
            2_000,
        );
        assert!(first.is_empty());
        // 摘要行的 ts 是它那一组**第一条**原始行的 ts（1_000），窗口从那里算。
        let until = 1_000 + MERGE_NS;
        // 墙钟走多远都不算数：事件时间没动，锚行就该继续等。
        let held = c.process(vec![], 2_000 + 60_000_000_000);
        assert!(held.is_empty(), "wall-clock time passing is not a reason to give up");
        // ……而**整组**都落在窗口内的等价调用还并得进来（窗口是闭区间）。
        let edge = c.process(
            vec![
                probe(until - 2, 200, "/bin/git"),
                probe(until - 1, 200, "/bin/git"),
                exec_ok(until, 200, "/bin/git"),
            ],
            until + 100,
        );
        assert!(
            edge.is_empty(),
            "an equivalent call landing inside the window still merges"
        );
        // 再晚一步就不行了：来者的 ts 一走出窗口，锚行立刻落盘（带着两次调用），
        // 后面那次等价调用只能自己另起一行 —— 这正是"有界"的含义。
        let out = c.process(
            vec![
                probe(until + 1, 300, "/bin/git"),
                probe(until + 2, 300, "/bin/git"),
                exec_ok(until + 3, 300, "/bin/git"),
            ],
            until + 200,
        );
        assert_eq!(out.len(), 1, "{:?}", out);
        assert_eq!(calls_of(&out[0]), 2, "the anchor lands with both merged calls");
        let tail = c.finish(until + 300);
        assert_eq!(tail.len(), 1, "{:?}", tail);
        assert_eq!(calls_of(&tail[0]), 1, "the late call gets its own summary");
        assert_eq!(detail_of(&tail[0]), detail_of(&out[0]), "same words, two logical calls");
    }

    /// 锚行因为超时落盘之后，压在它后面、仍在窗口内的等价摘要必须并回**那一行**。
    ///
    /// 这是实测抓到的第二种形态（第一种是 5s 投递停顿）：7 个子进程里 6 个的
    /// fork 挤在 2.6ms 内、第 7 个晚到，投递批次正好把"锚行超时"和"第 7 条摘要"
    /// 分在窗口边界两侧 —— 超时先把锚行推出去，同一批里跟在后面的第 7 条摘要
    /// 此时 `pending` 已空，于是又开一条新锚行，屏幕上成了
    /// `x6 calls` + 一条裸摘要。合并必须能在**已经落盘的那一行**上继续。
    #[test]
    fn equivalents_still_merge_after_the_anchor_times_out() {
        let mut c = Collapser::new(CollapseCfg::default());
        // 第一批：两组等价的探测。中间那条别的 pid 的原始行会把第二组的摘要
        // 堵在锚行后头（锚行没落盘，原始行就不许先走）。
        let first = c.process(
            vec![
                probe(1_000, 1, "/bin/git"),
                probe(1_010, 1, "/usr/bin/git"),
                exec_ok(1_020, 1, "/usr/bin/git"),
                base(
                    1_030,
                    3,
                    Kind::InfraFileOpen,
                    Payload::FileOpen {
                        path: "/tmp/a".into(),
                        flags: 1,
                        dirfd: -100,
                        path_is_relative: false,
                        ok: true,
                        errno: 0,
                    },
                ),
                probe(1_200, 2, "/bin/git"),
                probe(1_210, 2, "/usr/bin/git"),
                exec_ok(1_220, 2, "/usr/bin/git"),
            ],
            1_300,
        );
        assert!(first.is_empty(), "the anchor is still held; nothing may pass it");

        // 第二批：一条 ts 走出窗口的事件把锚行推出去，压着的行随之放出 ——
        // 第二组的摘要就在这批行里，它必须并回刚落盘的那一行。
        let mut out = c.process(
            vec![base(
                2_100_000_000,
                9,
                Kind::InfraFileOpen,
                Payload::FileOpen {
                    path: "/tmp/b".into(),
                    flags: 1,
                    dirfd: -100,
                    path_is_relative: false,
                    ok: true,
                    errno: 0,
                },
            )],
            2_100_000_000,
        );
        out.extend(c.finish(2_100_000_100));

        let summaries: Vec<&Event> = out.iter().filter(|e| e.kind == Kind::DerivedExecvp).collect();
        assert_eq!(summaries.len(), 1, "one summary, not two: {:?}", out);
        assert_eq!(
            calls_of(summaries[0]),
            2,
            "the equivalent call merged into the emitted anchor"
        );
        assert_eq!(detail_of(summaries[0]), "git -> /usr/bin/git (2 PATH probes)");
        assert_eq!(
            summaries[0].ts_ns, 1_000,
            "the merged row keeps the first call's position"
        );
        assert_eq!(c.stats().execvp_merged, 1);
    }

    /// 锚行挡住的是**原始行**，不是已经定案的组：遇到不等价的摘要时
    /// 锚行先落盘，顺序不乱。
    #[test]
    fn a_different_summary_flushes_the_anchor_first() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![
            probe(1_000, 100, "/bin/git"),
            probe(1_010, 100, "/bin/git"),
            exec_ok(1_020, 100, "/bin/git"),
        ];
        evs.push(probe(2_000, 200, "/bin/ls"));
        evs.push(probe(2_010, 200, "/bin/ls"));
        evs.push(exec_ok(2_020, 200, "/bin/ls"));
        // 第二条摘要自己也会开一个合并窗口，所以要看全量得走完流。
        let out = run(&mut c, evs, 3_000);
        assert_eq!(out.len(), 2, "{:?}", out);
        assert_eq!(out[0].ts_ns, 1_000);
        assert_eq!(out[1].ts_ns, 2_000);
        assert!(out[0].ts_ns <= out[1].ts_ns);
    }

    /// 不同落点不合并 —— "一样"才合并，像但不一样是两件事。
    #[test]
    fn different_targets_do_not_merge() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![];
        for (pid, path) in [(1u32, "/usr/bin/git"), (2u32, "/usr/local/bin/git")] {
            evs.push(probe(1_000, pid, "/bin/git"));
            evs.push(probe(1_010, pid, "/bin/git"));
            evs.push(exec_ok(1_020, pid, path));
        }
        let out = run(&mut c, evs, 2_000);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|e| calls_of(e) == 1));
    }

    /// 输出必须保持时间序：派生行落在它那组的位置上，不会被推到组后面的事件之后。
    #[test]
    fn output_stays_in_time_order() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![probe(100, 42, "/bin/git"), probe(110, 42, "/bin/git")];
        evs.push(exec_ok(120, 42, "/bin/git"));
        evs.push(base(
            130,
            77,
            Kind::InfraFileOpen,
            Payload::FileOpen {
                path: "/tmp/a".into(),
                flags: 1,
                dirfd: -100,
                path_is_relative: false,
                ok: true,
                errno: 0,
            },
        ));
        let out = run(&mut c, evs, 200);
        assert_eq!(out.len(), 2);
        assert!(out[0].ts_ns <= out[1].ts_ns, "ts went backwards: {:?}", out);
        assert_eq!(out[0].kind, Kind::DerivedExecvp);
    }

    /// 未决分组会压住它后面的行 —— 这是"结论需要往后看"必然的代价，
    /// 但压住的行一条都不能丢。
    #[test]
    fn nothing_is_lost_while_a_group_is_pending() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![probe(100, 42, "/bin/git"), probe(110, 42, "/bin/git")];
        evs.push(base(
            120,
            77,
            Kind::InfraFileOpen,
            Payload::FileOpen {
                path: "/tmp/a".into(),
                flags: 1,
                dirfd: -100,
                path_is_relative: false,
                ok: true,
                errno: 0,
            },
        ));
        let first = c.process(evs, 130);
        assert!(first.is_empty(), "the pending probe group holds the tail");
        let mut rest = c.finish(EXEC_RESOLVE_NS + 200);
        assert_eq!(rest.len(), 2, "{:?}", rest);
        assert_eq!(rest[0].kind, Kind::DerivedExecvp);
        assert_eq!(rest[1].kind, Kind::InfraFileOpen);
        rest.clear();
    }

    /// watchlist 命中过的 exec 绝不折叠（§8 ⑤ 的价值全在"这一行会被看见"）。
    #[test]
    fn a_watched_exec_is_never_collapsed() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut ok = exec_ok(120, 42, "/usr/bin/curl");
        ok.watch = true;
        let mut evs = vec![probe(100, 42, "/bin/curl"), probe(110, 42, "/bin/curl")];
        evs.push(ok);
        let out = c.process(evs, 200);
        assert!(out.iter().any(|e| e.watch), "the watched row must survive");
        assert!(out.iter().all(|e| !e.is_collapse()));
    }

    /// 身份：父进程的命令行来自 /proc 种子，过长时以可见的 `...` 收尾。
    #[test]
    fn identity_comes_from_the_proc_seed() {
        let mut c = Collapser::new(CollapseCfg::default());
        c.proc.set(
            42,
            "python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload",
        );
        let out = run(&mut c, vec![fork(1, 42, 100)], 2);
        match &out[0].payload {
            Payload::ProcFork { parent_argv, .. } => {
                let a = parent_argv.as_ref().expect("identity must be attached");
                assert!(a.ends_with("..."), "long cmdlines must show they were cut: {}", a);
                assert!(crate::render::display_width(a) <= CMDLINE_HINT_COLS + 3);
                assert!(a.starts_with("python3 -m uvicorn"));
            }
            other => panic!("{:?}", other),
        }
    }

    /// fork 让子进程继承父进程的命令行（fork 不改 cmdline），于是子进程的
    /// 第一次 fork/exec 也能被认出来。
    #[test]
    fn a_child_inherits_the_parent_cmdline_until_it_execs() {
        let mut c = Collapser::new(CollapseCfg::default());
        c.proc.set(42, "bash".into());
        let _ = c.process(vec![fork(1, 42, 100)], 2);
        let out = run(&mut c, vec![fork(3, 100, 200)], 4);
        // out[0] 是 42 派生的那个子进程，out[1] 才是子进程自己再 fork 的那次。
        match &out[1].payload {
            Payload::ProcFork { parent_argv, .. } => {
                assert_eq!(parent_argv.as_deref(), Some("bash"))
            }
            other => panic!("{:?}", other),
        }
    }

    /// 命令行未知就**安静地**不加后缀 —— 宁可少一条信息，也不要一行噪声。
    #[test]
    fn unknown_identity_adds_no_suffix() {
        let mut c = Collapser::new(CollapseCfg::default());
        let out = run(&mut c, vec![fork(1, 42, 100)], 2);
        match &out[0].payload {
            Payload::ProcFork { parent_argv, .. } => assert!(parent_argv.is_none()),
            other => panic!("{:?}", other),
        }
        assert_eq!(c.stats().identity_hits, 0);
    }

    /// 折叠行是 derived 层但没有 `watch`/`retry` 标记 ——
    /// `!!` 的含义必须是"可疑"，不能因为折叠行也是派生行就被稀释。
    #[test]
    fn collapse_rows_carry_no_suspicion_markers() {
        let mut c = Collapser::new(CollapseCfg::default());
        let mut evs = vec![probe(1, 42, "/bin/x"), probe(2, 42, "/bin/x")];
        evs.push(exec_ok(3, 42, "/bin/x"));
        let out = run(&mut c, evs, 10);
        assert!(!out[0].watch && !out[0].retry && !out[0].late);
        assert_eq!(crate::render::markers(&out[0]), "");
    }
}
