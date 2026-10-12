//! 统一事件 Schema —— DESIGN.md §1 的完整实现。
//!
//! 关键设计约束（来自 DESIGN.md）：
//! - `ts_ns` 是 CLOCK_MONOTONIC 纳秒，**排序主键**；内核事件直接来自 bpftrace `nsecs`。
//! - `pid_binding` 是核心诚实字段，绝不把 Heuristic 呈现为 Exact（§3.5）。
//! - `trunc` 记录一切截断，没有静默丢失（§4.3）。

use serde::{Deserialize, Serialize};
use std::fmt;

/// 证据来自哪一层（§1.2）。`Derived` 是 §8.4/§8.5 派生视图用的伪层，渲染成 `!!`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Agent,
    Runtime,
    Infra,
    Policy,
    /// 派生视图（gap / retry / watchlist）与采集器自身事件（lost_events）。
    /// DESIGN.md §4.2 的时间线示例里已经用 `!!` 作为这一列的值，此处把它正式化。
    Derived,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Agent => "agent",
            Layer::Runtime => "runtime",
            Layer::Infra => "infra",
            Layer::Policy => "policy",
            Layer::Derived => "!!",
        }
    }

    /// 渲染用的定宽列值。`!!` 只有 2 字符，右侧补空格由调用方负责。
    pub fn color(self) -> &'static str {
        match self {
            Layer::Agent => "\x1b[36m",   // 青
            Layer::Runtime => "\x1b[33m", // 黄
            Layer::Infra => "\x1b[34m",   // 蓝
            Layer::Policy => "\x1b[31m",  // 红
            Layer::Derived => "\x1b[35m", // 品红
        }
    }
}

/// 时间戳来源，决定我们对这个 ts 有多信任（§1.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsSource {
    /// 内核 nsecs，CLOCK_MONOTONIC，全系统一致，无需对齐。
    Kernel,
    /// agent 层 wall-clock 经 offset 换算得到。
    Converted,
    /// 只有墙钟，换算失败/不适用（fixture 相对时间兜底）。
    WallOnly,
}

impl TsSource {
    pub fn as_str(self) -> &'static str {
        match self {
            TsSource::Kernel => "kernel",
            TsSource::Converted => "converted",
            TsSource::WallOnly => "wall-only",
        }
    }
}

/// 绑定的可靠性等级（§3.5）。**这是本工具可信度的底线**：
/// 不确定就必须说不知道，不允许把启发式当事实。
///
/// v0.3 起它同时服务于两件事，但语义始终是"这一行被归因到某次 tool.call 的可信度"：
///  - `Corr::pid_binding`：**会话 ↔ 进程树**的绑定等级（一级 `/proc` 精确、二级启发式）；
///  - `Event::binding`：**这一行（每条事件）**的归因等级 —— 内核行由 argv 匹配升级为
///    `exact`（§3.5 三级），agent 行继承会话级等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Binding {
    /// 一级：`/proc/<pid>/cmdline` 里含 `claude --resume <sessionId>` 且 sessionId 相等。
    /// 三级：exec argv 与 tool.call 的 shell 命令按 §3.5 的规则精确匹配上（含子树）。
    Exact,
    /// cwd + 启动时间窗 + comm 推断；多候选时不猜，标歧义。
    /// 三级：只有会话级绑定，没有 tool.call 级证据 —— prompt/model/thinking 就在这一档。
    Heuristic,
    /// 绑不上。时间线仍然输出，但关联只是"时间邻近"不是"因果同一"。
    None,
}

impl Default for Binding {
    fn default() -> Self {
        Binding::None
    }
}

impl Binding {
    pub fn as_str(self) -> &'static str {
        match self {
            Binding::Exact => "exact",
            Binding::Heuristic => "heuristic",
            Binding::None => "none",
        }
    }

    /// §4.2 保真标记：非 Exact 时行尾加 `?`。
    pub fn suffix(self) -> &'static str {
        match self {
            Binding::Exact => "",
            _ => "?",
        }
    }
}

/// 事件类型，点号命名空间（§1.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Kind {
    // ---- agent ----
    #[serde(rename = "agent.prompt")]
    AgentPrompt,
    #[serde(rename = "agent.prompt.queued")]
    AgentPromptQueued,
    #[serde(rename = "agent.model.request")]
    AgentModelRequest,
    #[serde(rename = "agent.model.thinking")]
    AgentModelThinking,
    #[serde(rename = "agent.model.text")]
    AgentModelText,
    #[serde(rename = "agent.model.usage")]
    AgentModelUsage,
    #[serde(rename = "agent.tool.call")]
    AgentToolCall,
    #[serde(rename = "agent.tool.result")]
    AgentToolResult,
    #[serde(rename = "agent.sandbox.disabled")]
    AgentSandboxDisabled,
    /// §5.4 #1：[未验证] —— 纯推测的映射，默认不产出，仅在 `-v` 下提示。
    #[serde(rename = "policy.deny.agent")]
    PolicyDenyAgent,

    // ---- runtime ----
    #[serde(rename = "runtime.proc.fork")]
    RuntimeProcFork,
    #[serde(rename = "runtime.proc.exec")]
    RuntimeProcExec,
    #[serde(rename = "runtime.proc.exec_fail")]
    RuntimeProcExecFail,
    #[serde(rename = "runtime.proc.exit")]
    RuntimeProcExit,

    // ---- infra ----
    #[serde(rename = "infra.file.open")]
    InfraFileOpen,
    #[serde(rename = "infra.net.connect")]
    InfraNetConnect,
    #[serde(rename = "infra.net.sendto")]
    InfraNetSendto,

    // ---- policy ----
    #[serde(rename = "policy.deny")]
    PolicyDeny,

    // ---- 派生的伪事件（§4.2 的 lost_events 行 + §8 的 ④⑤ 视图）----
    /// 丢包必须可见，绝不静默（§4.3）。
    #[serde(rename = "collector.lost_events")]
    CollectorLostEvents,
    /// tool call → result 的大 gap（§8 ④）。
    #[serde(rename = "derived.tool.gap")]
    DerivedToolGap,
    /// 同一 tool + 同一 input 反复出现，疑似静默重试（§8 ④）。
    #[serde(rename = "derived.tool.retry")]
    DerivedToolRetry,
    /// tool.call 到流结束都没等到 tool.result。
    #[serde(rename = "derived.tool.dangling")]
    DerivedToolDangling,
    /// watchlist 命中（§8 ⑤），alert-only。
    #[serde(rename = "derived.watchlist")]
    DerivedWatchlist,
    /// v0.2 折叠：K 次 ENOENT PATH 探测 + 1 次成功 exec = 一次逻辑 execvp。
    #[serde(rename = "derived.execvp")]
    DerivedExecvp,
    /// v0.2 折叠：同一父进程在 10ms 内的 N 次 fork = 一次 worker-pool 派生。
    #[serde(rename = "derived.fork_burst")]
    DerivedForkBurst,
    /// v0.3 §3.5 三级：一次 `tool.call` 与一次内核 `exec` 按 argv 精确连上。
    ///
    /// 与 `Collapse` 一样属于**事实的摘要**而不是 §8 的怀疑视图，渲染成 `derived`。
    /// 一次匹配产出一行 —— 它同时是"这条链是怎么连上的"的**证据**（规则写在行内）
    /// 和"哪条进程被标成了 exact"的**索引**。
    #[serde(rename = "derived.bind")]
    DerivedBind,
    /// v0.4 §13：一次失败的 `tool.call` 的**归因行**。
    ///
    /// 与 `Collapse`/`Bind` 同属"事实的摘要"（不是 §8 的怀疑），但渲染成 `XX` ——
    /// 因为这一列在时间线上是给人**扫**的：一眼看出哪几行是失败，以及失败发生在
    /// 四层里的哪一层。行内的 `-> ...` 后面的每一个词都必须指向 trace 里真实存在的
    /// 证据（见 fail.rs 的铁律注释）。
    #[serde(rename = "derived.fail")]
    DerivedFail,
    /// v0.6 §14：**产物血缘**的一行 —— "这条调用的输入，是第几步产出的、那一步成没成"。
    ///
    /// 与 `DerivedFail` 一起出现（紧跟在那条 `XX` 后面），只在失败视图里产出：
    /// 正常时间线上加这一行只会把时间线撑长，而它的全部价值都建立在
    /// "有个下游调用正在为这个产物收拾残局"之上。
    ///
    /// 它是**用户态推断**，不是内核证据：依据是 transcript 里前后两次提到同一个
    /// 绝对路径/URL。这一点写在行首的 `└─ ` 与 `notes` 里，`-v` 与 json 都能查到。
    #[serde(rename = "derived.lineage")]
    DerivedLineage,
    /// v0.6 §14：**claim vs kernel** 的一行 —— transcript 说的事，和内核看到的事，
    /// 并排放在一行里。
    ///
    /// 这是 v0.6 的楔子：`tool.result` 说"下载好了"，而内核里那条调用的子树**没有**
    /// 任何一次写意图 open。两边都是**事实**，矛盾才是信息。
    ///
    /// 两列里，`claim:` 侧来自 transcript 文本（启发式），`kernel:` 侧来自内核事件
    /// （实测）。不一致时行尾有 `!!`；一致时也照打 —— 只打不一致的话，读者无法
    /// 区分"核对过、一致"和"根本没核对"。
    #[serde(rename = "derived.claim")]
    DerivedClaim,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::AgentPrompt => "agent.prompt",
            Kind::AgentPromptQueued => "agent.prompt.queued",
            Kind::AgentModelRequest => "agent.model.request",
            Kind::AgentModelThinking => "agent.model.thinking",
            Kind::AgentModelText => "agent.model.text",
            Kind::AgentModelUsage => "agent.model.usage",
            Kind::AgentToolCall => "agent.tool.call",
            Kind::AgentToolResult => "agent.tool.result",
            Kind::AgentSandboxDisabled => "agent.sandbox.disabled",
            Kind::PolicyDenyAgent => "policy.deny.agent",
            Kind::RuntimeProcFork => "runtime.proc.fork",
            Kind::RuntimeProcExec => "runtime.proc.exec",
            Kind::RuntimeProcExecFail => "runtime.proc.exec_fail",
            Kind::RuntimeProcExit => "runtime.proc.exit",
            Kind::InfraFileOpen => "infra.file.open",
            Kind::InfraNetConnect => "infra.net.connect",
            Kind::InfraNetSendto => "infra.net.sendto",
            Kind::PolicyDeny => "policy.deny",
            Kind::CollectorLostEvents => "collector.lost_events",
            Kind::DerivedToolGap => "derived.tool.gap",
            Kind::DerivedToolRetry => "derived.tool.retry",
            Kind::DerivedToolDangling => "derived.tool.dangling",
            Kind::DerivedWatchlist => "derived.watchlist",
            Kind::DerivedExecvp => "derived.execvp",
            Kind::DerivedForkBurst => "derived.fork_burst",
            Kind::DerivedBind => "derived.bind",
            Kind::DerivedFail => "derived.fail",
            Kind::DerivedLineage => "derived.lineage",
            Kind::DerivedClaim => "derived.claim",
        }
    }

    /// 时间线上显示的短名（§4.2 的 `kind` 列，定宽 15）。
    /// 去掉 layer 前缀，让纵向扫读更紧凑：`agent.tool.call` → `tool.call`。
    pub fn short(self) -> &'static str {
        // v0.2 折叠行的名字是给用户看的短标签（`execvp` / `fork-burst`），
        // 不按前缀规则推导 —— `derived.fork_burst` 去掉前缀会留下下划线，
        // 而这一列是 strace 式的短标签，连字符更贴近命令行里的写法。
        match self {
            Kind::DerivedExecvp => return "execvp",
            Kind::DerivedForkBurst => return "fork-burst",
            Kind::DerivedBind => return "bind",
            // `derived.fail` 去掉前缀只剩 `fail`，但它是 v0.4 唯一一条**默认刷红**的
            // 摘要行，短名直接写死，免得将来加前缀规则时把它改成别的词。
            Kind::DerivedFail => return "fail",
            Kind::DerivedLineage => return "lineage",
            Kind::DerivedClaim => return "claim",
            _ => {}
        }
        let s = self.as_str();
        for p in [
            "agent.",
            "runtime.proc.",
            "infra.file.",
            "infra.net.",
            "derived.tool.",
            "derived.",
            "collector.",
        ] {
            if let Some(rest) = s.strip_prefix(p) {
                return rest;
            }
        }
        match self {
            Kind::RuntimeProcFork => "proc.fork",
            Kind::RuntimeProcExec => "proc.exec",
            Kind::RuntimeProcExecFail => "proc.exec_fail",
            Kind::RuntimeProcExit => "proc.exit",
            Kind::InfraFileOpen => "file.open",
            Kind::InfraNetConnect => "net.connect",
            Kind::InfraNetSendto => "net.sendto",
            Kind::PolicyDeny => "deny",
            Kind::PolicyDenyAgent => "deny.agent",
            Kind::AgentSandboxDisabled => "sandbox.disabled",
            _ => s,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 关联 key（§1.3）。每一项都标注了可靠性，代码里不做超出该可靠性的推断。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Corr {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_uuid: Option<String>,
    /// `--pid` 指定的根进程（或 `-C` 模式下的第一个种子）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_root: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_binding: Option<Binding>,
    /// `isSidechain=true` 标记子 agent（§1.3，近似）。
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub sidechain: bool,
}

/// 一条被截断的字段的记录。`trunc` 非空 → 渲染时加 `~` 标记并在 `-v` 下展开。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncNote {
    pub field: String,
    /// 原始字节数；内核侧 64 字节硬截断时无法得知，为 `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orig_bytes: Option<usize>,
    pub kept_bytes: usize,
    /// 人类可读的补充说明（例如"内核侧 64 字节硬上限，无法得知原始长度"）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl TruncNote {
    pub fn new(field: impl Into<String>, orig: Option<usize>, kept: usize) -> Self {
        TruncNote {
            field: field.into(),
            orig_bytes: orig,
            kept_bytes: kept,
            note: None,
        }
    }
    pub fn with_note(mut self, n: impl Into<String>) -> Self {
        self.note = Some(n.into());
        self
    }
}

/// 事件载荷。变体由 `kind` 决定。
///
/// 约定（§3.2）：所有可能很长的字符串字段都以 `_preview` 结尾，且**绝不包含未转义换行**。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Payload {
    // ---- agent ----
    Prompt {
        text_preview: String,
        chars: usize,
    },
    PromptQueued {
        text_preview: String,
    },
    ModelRequest {
        model: Option<String>,
        input_tokens: Option<u64>,
        /// 源里关于这次调用的自由文本说明（openshell fixture 的 `status_detail`）。
        ///
        /// DESIGN.md §1.2 只列了 `model`/`input_tokens`，但 fixture 里
        /// `llm.call` 的 `status_detail`（如 `plan: search docs`）是**唯一**能说明
        /// "这一轮模型在干什么"的字段。丢掉它时间线上就只剩一个光秃秃的
        /// `model.request`，属于 §4.3 禁止的静默丢失。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail_preview: Option<String>,
    },
    Thinking {
        preview: String,
        duration_ms: Option<u64>,
    },
    ModelText {
        preview: String,
    },
    ModelUsage {
        model: Option<String>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cache_read: Option<u64>,
        cost_usd: Option<f64>,
    },
    ToolCall {
        tool: String,
        input_preview: String,
        input_bytes: usize,
        /// MCP 工具（`mcp__server__tool` 形式，§8 ②）。
        via_mcp: bool,
        /// Bash 的 `input.command`，用更大的上限单独提取（§3.3）。
        #[serde(skip_serializing_if = "Option::is_none")]
        bash_cmd: Option<String>,
    },
    ToolResult {
        tool: Option<String>,
        status: String,
        result_preview: String,
    },
    SandboxDisabled {
        disabled: bool,
    },

    // ---- runtime ----
    ProcFork {
        child_pid: u32,
        child_comm: String,
        /// v0.2：父进程的命令行，用于回答"这是哪个 python？"。
        ///
        /// 内核的 `sched_process_fork` 只给得出 `comm`（15 字符、被截断的进程名），
        /// 而"fork -> 1234 (python)"对排查毫无用处 —— python 脚本、`python -m uvicorn`
        /// 和 REPL 都是 `python`。这个字段由 `/proc` 侧补齐（见 collapse.rs 的 ProcTable）：
        /// 既包括 attach 时扫描到的既有进程，也包括本次运行里观察到的 exec。
        /// 拿不到就是 `None`，渲染时**静默省略**（不编造、不留下空壳引号）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_argv: Option<String>,
    },
    ProcExec {
        filename: String,
        argv: Vec<String>,
        argc_total: Option<usize>,
    },
    ProcExecFail {
        filename: String,
        errno: i64,
        errno_name: String,
        /// execve 失败时**同样**要给出 argv。
        ///
        /// DESIGN.md §1.2 的 payload 关键字段只列了 `filename`/`errno`，但内核侧
        /// 的 argv stash 对失败路径一样有效（`sys_enter_execve` 已经存了），
        /// 而且"它想执行什么、带了什么参数、失败了"恰恰是排查时最想知道的一件事。
        /// 丢掉它属于 §4.3 禁止的静默丢失，所以这里**加字段而不是丢数据**。
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        argv: Vec<String>,
    },
    ProcExit {
        exit_code: i64,
    },

    // ---- infra ----
    FileOpen {
        path: String,
        flags: u64,
        dirfd: i64,
        /// 路径相对 `dirfd` 解析，无法还原成绝对路径（§5.2 #2）。不猜。
        path_is_relative: bool,
        ok: bool,
        /// v0.4：openat 的原始返回值（成功时为非负，失败时为负 errno）。
        ///
        /// v0 只留了 `ok: bool`，渲染时写死 `=failed (errno not captured)` —— 而
        /// 内核**一直在报**这个数字（`agtrace.bt` 的 OPEN 行第 9 个字段就是 `ret`），
        /// 采集器也解析了它（`ok = ret >= 0`），只是没有往下传。失败归因要给
        /// "最深失败点"命名（`openat /x ENOENT`），没有 errno 就只能写"failed"，
        /// 属于让事实在管道里蒸发。`0` 表示成功（或旧 fixture 没有这个字段）。
        #[serde(default)]
        errno: i64,
    },
    NetConnect {
        family: u16,
        family_name: String,
        addr: String,
        port: Option<u16>,
        ok: bool,
        /// 非阻塞 connect 返回 `EINPROGRESS(-115)`：连接**正在建立**，是正常返回。
        ///
        /// §1.2 只给了 `ok: bool`，但 connect 实际是三态：成功 / 进行中 / 失败。
        /// 把进行中压进 `ok=false` 会让时间线对着 curl 的每一次正常外连说"失败"。
        /// 和 `ProcExecFail.argv`、`ModelRequest.detail_preview` 一样，这是为了让
        /// 事实不被二元字段挤掉而做的加法，不是随手扩 schema。
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        pending: bool,
    },
    NetSendto {
        fd: i64,
        len: u64,
        /// v0.4.2：该 fd 最近一次 connect 的对端（`addr` 或 `addr:port`）。
        /// fd 号会被复用，所以这是启发式归因（most-recent connect），不是因果保证；
        /// UDP 等无连接的 sendto 没有 connect 事件，peer 为 None。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer: Option<String>,
    },

    // ---- policy ----
    PolicyDeny {
        syscall: String,
        target: String,
        errno: i64,
        errno_name: String,
        /// `kernel`（errno 判定）或 `agent`（transcript 文本匹配，[未验证]）。
        decided_by: String,
    },

    // ---- 派生 / 采集器自身 ----
    LostEvents {
        count: u64,
    },
    Derived {
        label: String,
        detail: String,
        count: u64,
    },
    /// v0.2：把 K 条原始行折叠成的一次逻辑操作（见 collapse.rs）。
    ///
    /// 与 `Derived`（§8 的**怀疑**类视图）在渲染上刻意分开：这一行不是怀疑，
    /// 而是**原始行的无损摘要** —— 原始行在 `-v` 与 `--output json` 下一条不少。
    Collapse {
        /// `execvp` | `fork-burst`。
        form: String,
        /// 已经格式化好的人读摘要，例如 `git -> /usr/bin/git (13 PATH probes)`。
        /// 合并多个等价调用时**不改这个字段**（否则摘要里会嵌套次数），
        /// 次数单独放在 `calls` 里，由渲染层追加。
        detail: String,
        /// 这一行替换掉了多少条原始行（不是逻辑调用数）。
        raw_events: u64,
        /// 合并了几个等价的逻辑调用（同一进程内的 K 次探测算 1 次）。
        calls: u64,
    },
    /// v0.3 §3.5 三级：一次 argv 级匹配的**证据行**。
    ///
    /// 这一行不是怀疑（不是 `!!`），也不是原始行的折叠（不是 `execvp`），
    /// 而是"intent（tool.call 的命令行）与 reality（内核 exec 的 argv）是同一条"
    /// 这个**判断本身**。规则必须写在行里：用户要能一眼看出这是精确子串还是
    /// 模糊 token 重叠，绝不允许把模糊匹配说成 exact（V03_PROMPT §3）。
    Bind {
        /// 工具名（当前只有 `Bash` 会进这张表）。
        tool: String,
        /// tool.call 侧的命令行。可能被截断（`trunc` 里有 `bash_cmd` 记录）。
        cmd_preview: String,
        /// 内核侧 `/proc` 报上来的可执行文件路径。
        exec_filename: String,
        /// **实际用上的规则名**，直接进渲染的括号里：
        /// `argv exact`（边界感知的整串子串命中）、`argv overlap NN%`（token 重叠）
        /// 或 `argv prefix NN%`（cmd 被截断，只比了已知 token）。
        ///
        /// 匹配到的 tool.call id **不在这里** —— 它在 `corr.tool_use_id` 上，
        /// 与所有被绑定的内核行共用一个 join key（V03_PROMPT §5）。
        rule: String,
        /// exec 比 tool.call 晚多少毫秒（0 = 同一毫秒）。
        delta_ms: u64,
        /// 命中的进程（子树根）。这一条链上被标 exact 的进程数见 `subtree_pids`。
        pid: u32,
        /// 连这次 exec 在内、一并被标 exact 的进程数（含 `pid` 自己）,
        /// 即"这个 bind 影响了多少行"。
        subtree_pids: u64,
    },
    /// v0.4 §13：一条失败归因行（`XX`）。**每一个字段都是一条可核对的证据**。
    ///
    /// 归因的难点不在"发现失败"（结果文本就会说），而在"失败发生在四层里的哪一层、
    /// 内核侧最深的那条证据是什么"。所以这里把两半分开存：
    /// `head` 是**结果侧**说的（`exit 2` / `BEFORE exec: ...`），`deepest` 是
    /// **内核侧**说的（`openat /x ENOENT via /usr/bin/ls`）。两边都不许猜。
    Fail {
        /// v0.6：这是本次会话的第几次 `tool.call`（从 1 数起，**全部**调用都数 ——
        /// 包括成功的）。血缘链两头的步号就是它，所以两处必须是同一套编号：
        /// 用户在屏幕上数到第 12 条 `tool.call`，`XX` 行上就该写着 12。
        #[serde(default)]
        step: u64,
        /// 工具名（`Bash`）。
        tool: String,
        /// 这次调用要跑的命令行。与 `Bind::cmd_preview` 一样可能被截断。
        cmd_preview: String,
        /// 归因类别，进渲染的括号里做机器可读的那一半：
        /// `before-exec` | `kernel` | `bound-no-evidence` | `unbound` | `no-kernel-source`。
        class: String,
        /// 结果侧的行首。`exit 2`，或 `BEFORE exec: sandbox init failed (no kernel event)`。
        head: String,
        /// 内核侧最深失败点（没有就**不写** —— 空字符串会读成"内核说是空的"）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deepest: Option<String>,
        /// 挂在这条调用上的内核事件数（0 = 内核侧一条都没连上）。
        kernel_events: u64,
    },
    /// v0.6 §14：一条**产物血缘**行（`derived.lineage`）。正文就是给人读的那句话。
    ///
    /// 为什么正文是一个**已经格式化好的字符串**而不是几个字段：这条行是
    /// `└─ input /tmp/report.pdf produced by step 3 fetch_pdf (ERRORED: 404)`
    /// 这种"箭头 + 一句话"的形状，拆成字段后渲染层要把它重新拼一遍，而拼接规则
    /// （哪个库、什么状态、截断到多少列）只属于渲染层。结构化的一半在
    /// `corr.tool_use_id`（这条链属于哪次调用）和 `extra.failures[].lineage` 里。
    Lineage {
        text: String,
    },
    /// v0.6 §14：一条 **claim vs kernel** 行（`derived.claim`）。
    ///
    /// 两列**分开存**，不在这里拼 `|`：渲染层要按终端宽度决定各自的列宽
    /// （并且两边都可能被截断，截断必须在渲染层统一做，否则 json 里的字段
    /// 会是"已经被屏幕宽度裁过"的假值）。
    Claim {
        /// transcript 那一侧说的（`wrote /tmp/report.pdf`）。
        claim: String,
        /// 内核那一侧看到的（`no write open observed`）。
        kernel: String,
        /// 两边是否矛盾。`true` 时渲染行尾 `!!`。
        mismatch: bool,
    },
}

/// 归一化后的统一事件（§1.1）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    // ---- 时间 ----
    /// merger 分配的单调序号，同 ts 时打破平局，保证排序稳定。
    pub seq: u64,
    /// CLOCK_MONOTONIC 纳秒。**排序主键**。
    pub ts_ns: u64,
    /// CLOCK_REALTIME 纳秒，由 ts_ns + offset 换算。仅用于显示与跨层 join。
    pub ts_wall_ns: u64,
    pub ts_src: TsSource,

    // ---- 分类 ----
    pub layer: Layer,
    pub kind: Kind,
    pub source: String,

    // ---- 进程上下文 ----
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_id: Option<u64>,

    // ---- 关联 ----
    pub corr: Corr,

    /// v0.3 §3.5：**这一行**被归因到某次 `tool.call` 的可信度（每条事件都有）。
    ///
    /// 与 `corr.pid_binding` 刻意分开：后者是**会话 ↔ 进程树**的等级，在整条会话上
    /// 恒为同一个值；这个是**事件 ↔ tool.call**。一条 prompt 行可以是
    /// `pid_binding=heuristic` + `binding=heuristic`（会话绑上了，但和哪次 tool.call
    /// 无关）；一条被 argv 匹中的内核 exec/fork/exit 行是 `binding=exact`，
    /// 即使它根本没有 `pid_binding`（内核行不参与会话绑定）。
    ///
    /// 渲染规则（§4.2）：非 Exact 的 **agent 行**打 `?`；Exact 的**内核行**打 `=`。
    #[serde(default)]
    pub binding: Binding,

    // ---- 载荷 ----
    pub payload: Payload,

    // ---- 保真度 ----
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub trunc: Vec<TruncNote>,
    /// 非截断类的告警说明（推导出的时间戳、去重、打码发生等）。
    ///
    /// 与 `trunc` 分开是必须的：`trunc` 非空会让渲染打上 `~` 并计入"含截断"，
    /// 而"这条 ts 是推导的"或"这个 argv 被我们打码了"**没有截断任何内容**。
    /// 混在一起会让 `~` 这个标记说谎 —— 用户看到 `~` 会去找被截掉的部分，
    /// 但那里根本没有东西被截掉。实测：真实 transcript 上 489 条事件里绝大多数
    /// 的 `~` 都来自 model.request 的 ts 推导说明。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,

    /// 渲染态标记：到达时已错过重排窗口（§2.4）。**不参与排序**，只影响显示。
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub late: bool,
    /// 渲染态标记：watchlist 命中（§8 ⑤）。
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub watch: bool,
    /// 渲染态标记：④ 派生视图（疑似重试）。
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub retry: bool,
}

impl Event {
    pub fn is_kernel(&self) -> bool {
        self.ts_src == TsSource::Kernel
    }

    /// 这条事件是不是**由内核采集器产出**的（runtime/infra/policy 三层的实测事实）。
    ///
    /// 与 `is_kernel()` 的区别很重要：`is_kernel()` 说的是"时间戳是内核直采的"，
    /// agent 层事件在本地 tail 时也可能带 Kernel 时间戳。要判断"我们到底有没有在
    /// 看内核"，只能看层，不能看时间戳来源 —— 否则一个纯 `-S` 运行会被误判成
    /// "内核在采"，进而允许做出"内核里没有 X"这种无根据的断言。
    pub fn from_kernel_collector(&self) -> bool {
        matches!(self.layer, Layer::Runtime | Layer::Infra | Layer::Policy)
    }

    /// 这一行是不是 v0.2 的折叠摘要行（execvp / fork-burst）。
    ///
    /// 与 §8 的 `Derived` 视图行分开判断，是因为渲染层对两者的措辞不同：
    /// 视图行是**怀疑**（`!!`），折叠行是**原始行的摘要**（`derived`）。
    pub fn is_collapse(&self) -> bool {
        matches!(self.kind, Kind::DerivedExecvp | Kind::DerivedForkBurst)
    }

    /// 这一行是不是"**事实的摘要**"（渲染成 `derived` 而不是 `!!`）。
    ///
    /// `!!` 在本工具里专指**怀疑**（§8 的视图行、watchlist、丢包）。折叠行与
    /// v0.3 的绑定行不是怀疑 —— 前者是原始行的无损摘要，后者是"intent 与 reality
    /// 是同一条命令"这个判断本身。用同一个 `derived` 标签，是为了让"这一行是
    /// agtrace 推出来的、不是内核直接说的"这件事保持单一含义，
    /// 而 `Kind` 字段承担区分两者（`-v` 与 `--output json` 里都在）。
    pub fn renders_as_derived(&self) -> bool {
        self.is_collapse()
            || matches!(
                self.kind,
                Kind::DerivedBind | Kind::DerivedFail | Kind::DerivedLineage | Kind::DerivedClaim
            )
    }
}

/// 渲染用的 key 列（§4.2）：agent 层用 session_id 前 8 位，内核层用 pid。
pub fn corr_key(layer: Layer, corr: &Corr, pid: Option<u32>) -> String {
    match layer {
        Layer::Agent => corr
            .session_id
            .as_deref()
            .map(|s| s.chars().take(8).collect::<String>())
            .or_else(|| corr.run_id.as_deref().map(|s| s.chars().take(8).collect()))
            .unwrap_or_else(|| "-".to_string()),
        _ => pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
    }
}

/// 按**字符边界**截断，绝不产出非法 UTF-8（§5.5 #8）。
///
/// 返回 (截断后的串, 是否发生了截断, 原始字节数)。
pub fn truncate_chars(s: &str, max_bytes: usize, max_chars: usize) -> (String, bool, usize) {
    let orig = s.len();
    if orig <= max_bytes && s.chars().count() <= max_chars {
        return (s.to_string(), false, orig);
    }
    // 先按字符数切，再确保字节数不超限 —— 两者取更严的。
    let mut end = 0usize;
    let mut nchars = 0usize;
    for (i, c) in s.char_indices() {
        let next = i + c.len_utf8();
        if next > max_bytes || nchars + 1 > max_chars {
            break;
        }
        end = next;
        nchars += 1;
    }
    // 若第一个字符本身就超限，至少保留它 —— 否则会产出空串掩盖信息。
    if end == 0 && !s.is_empty() {
        let c = s.chars().next().unwrap();
        end = c.len_utf8();
    }
    (s[..end].to_string(), true, orig)
}

/// 把字符串压成单行：未转义换行绝不允许进入 payload（§3.2）。
pub fn one_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// errno → 名字。只覆盖 §2.2 Group D 关心 + 常见的一组，未知则 `ERRNO(n)`。
pub fn errno_name(e: i64) -> &'static str {
    match -e {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        5 => "EIO",
        9 => "EBADF",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        30 => "EROFS",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        101 => "ENETUNREACH",
        103 => "ECONNABORTED",
        104 => "ECONNRESET",
        107 => "ENOTCONN",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        113 => "EHOSTUNREACH",
        115 => "EINPROGRESS",
        _ => "?",
    }
}

/// 这个负返回值是不是"其实没出错"。
///
/// `EINPROGRESS`（-115）是非阻塞 socket 上 `connect()` 的**正常**返回：连接正在
/// 建立，完成后 socket 变可写。把它渲染成"失败"是在时间线上写了一句假话 ——
/// 而 curl 用的正是非阻塞 connect，所以只要用户抓一次 curl 就会看到满屏"失败"。
pub fn errno_is_pending(e: i64) -> bool {
    e == -115
}

/// errno → 写进 `Payload::ProcExecFail::errno_name` 的那**一个名字**，不带数字。
///
/// 数字由渲染层补（`render::mod` 的 `ProcExecFail` 分支统一写 `NAME(-N)`）。
/// 早先这里返回的是 `"ENOENT(-2)"`，渲染层又补了一次数字，屏幕上就成了
/// `ENOENT(-2) (-2)` —— 折叠功能让 exec_fail 行只在 `-v` / `--no-collapse` 下出现，
/// 但出现的时候不该是坏的。未知 errno 给 `"?"`，渲染层会写成 `ERRNO(-N)`。
pub fn errno_label(e: i64) -> String {
    errno_name(e).to_string()
}
