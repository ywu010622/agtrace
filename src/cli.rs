//! CLI 参数解析（DESIGN.md §4.1）。
//!
//! 手写解析而不是引 clap：参数不多，而错误信息要能说清"为什么这个组合不行" ——
//! 这正是 §4.1 强调"不给目标就报错退出"的用意。
//!
//! ## 与 DESIGN.md §4.1 的一处**有意偏离**（已记入 BUILD_LOG）
//!
//! §4.1 写的是"目标选择（三选一，v0 互斥）"，但 §7 验收 #3 要求
//! `agtrace -p <pid> -S <session> -f` 输出**合并**时间线。两者不能同时成立。
//! 本实现取的交集是：
//!   - **内核目标** `-p` / `-C` 互斥（都是内核层目标，同时给没有意义）；
//!   - **agent 目标** `-S` 可选，可与内核目标**组合** → 这正是合并时间线；
//!   - 一个目标都不给 → 报错退出（§4.1 的硬要求）。
//! 这样 §4.1 的意图（必须有显式目标、不做全系统跟踪）和 §7 #3 都能满足。

use crate::adapter::openshell::TimeBase;
use crate::collector::bpftrace::SourceFilter;
use crate::redact::RedactMode;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Text,
    Json,
}

pub const DEFAULT_MERGE_WINDOW_MS: u64 = 200;
pub const DEFAULT_RESYNC_SECS: u64 = 30;
pub const DEFAULT_ARGV_MAX: usize = 8;
pub const DEFAULT_TOOL_ARG_MAX: usize = 512;
pub const DEFAULT_BASH_CMD_MAX: usize = 1024;
pub const DEFAULT_GAP_MS: u64 = 5_000;
pub const DEFAULT_RETRY_WINDOW_MS: u64 = 60_000;

#[derive(Debug, Clone)]
pub struct Cli {
    // ---- 目标 ----
    pub pid: Option<u32>,
    pub cgroup: Option<String>,
    pub session: Option<String>,

    // ---- 行为 ----
    pub follow: bool,
    pub adapter: String,
    pub transcript: Option<String>,
    pub time_base: TimeBase,
    /// None = 全部
    pub source: Option<SourceFilter>,
    pub merge_window_ms: u64,
    pub resync_secs: u64,

    // ---- 输出 ----
    pub output: OutputMode,
    pub full: bool,
    pub no_color: bool,
    pub max_events: Option<u64>,
    pub duration_secs: Option<u64>,

    // ---- 保真 / 隐私 ----
    pub redact: RedactMode,
    pub file_all: bool,
    pub argv_max: usize,
    pub tool_arg_max: usize,
    pub bash_cmd_max: usize,
    pub verbose: bool,

    // ---- 派生视图（§8 ④⑤）----
    pub watchlist: Option<String>,
    pub gap_ms: u64,
    pub retry_window_ms: u64,
    pub no_views: bool,

    // ---- 折叠（v0.2 §11）----
    /// 关掉逻辑调用折叠，恢复内核逐行原貌。默认**开**。
    pub no_collapse: bool,

    // ---- 精确绑定（v0.3 §3.5 三级）----
    /// 关掉 argv 级绑定：`?` 全部保留，内核行没有 `=`。
    ///
    /// 存在的理由和 `--no-collapse` 一样：**前后对比要能用一个二进制复现**。
    /// 它也是"怀疑绑定结论"时的一键逃生门 —— 关掉之后时间线上不再有任何
    /// 由 argv 匹配产生的东西。
    pub no_bind: bool,

    // ---- 失败归因（v0.4 §13）----
    /// 只打印失败链：失败的 `tool.call`、它挂住的内核子树、`XX` 归因行、以及
    /// `--- failures (N)` 收尾。
    ///
    /// 与 `--no-collapse` / `--no-bind` 是同一类开关：**选择呈现什么**，不改变
    /// 任何一条被呈现事件的字段。所以它与 `--output json` 也能组合，而且
    /// json 依然逐事件无损 —— 被剪掉的是整条链，不是链里的字段。
    pub failures_only: bool,

    // ---- 采集器（v0.5）----
    /// 内核采集后端。默认 aya（进程内 eBPF），失败时**可见地**退回 bpftrace。
    pub collector: CollectorBackend,

    // ---- v0.6：内核行离线回放 ----
    /// `--kernel-lines <PATH>`：不 attach 任何东西，把一份**已经采到的**内核行
    /// 协议文本当作内核侧喂进流水线。
    ///
    /// 与 `--no-collapse` / `--failures-only` 是同一类开关（选择数据从哪来、
    /// 呈现什么），不改协议、不改任何一行格式。存在的原因是**可复现**：内核采集要
    /// root，而"这条失败应该归因到哪一层"这种问题必须在没有权限的机器上也能被
    /// 逐字复现（见 `tests/inject.rs`）。
    pub kernel_lines: Option<String>,

    // ---- 调试 ----
    pub keep_script: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Cli {
            pid: None,
            cgroup: None,
            session: None,
            follow: false,
            kernel_lines: None,
            adapter: "claude-code".into(),
            transcript: None,
            time_base: TimeBase::Now,
            source: None,
            merge_window_ms: DEFAULT_MERGE_WINDOW_MS,
            resync_secs: DEFAULT_RESYNC_SECS,
            output: OutputMode::Text,
            full: false,
            no_color: false,
            max_events: None,
            duration_secs: None,
            redact: RedactMode::Argv,
            file_all: false,
            argv_max: DEFAULT_ARGV_MAX,
            tool_arg_max: DEFAULT_TOOL_ARG_MAX,
            bash_cmd_max: DEFAULT_BASH_CMD_MAX,
            verbose: false,
            watchlist: None,
            gap_ms: DEFAULT_GAP_MS,
            retry_window_ms: DEFAULT_RETRY_WINDOW_MS,
            no_views: false,
            no_collapse: false,
            no_bind: false,
            failures_only: false,
            collector: CollectorBackend::Aya,
            keep_script: false,
        }
    }
}

/// Which kernel collector to use (`--collector`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorBackend {
    /// In-process eBPF through `aya` (v0.5 default): no external program, so
    /// `cargo install` alone is enough, and attachment is ~ms rather than the
    /// 2-3 s `bpftrace` needs to parse and compile its script.
    Aya,
    /// The v0.4 `sudo bpftrace` subprocess. Kept working, and used automatically
    /// (with a visible note) when aya cannot start on this machine.
    Bpftrace,
}

impl CollectorBackend {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "aya" => Ok(CollectorBackend::Aya),
            "bpftrace" => Ok(CollectorBackend::Bpftrace),
            other => Err(format!(
                "unknown --collector `{}` (available: aya | bpftrace)",
                other
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CollectorBackend::Aya => "aya",
            CollectorBackend::Bpftrace => "bpftrace",
        }
    }
}

pub enum Parsed {
    Run(Box<Cli>),
    Help(String),
    Version,
}

pub fn help() -> String {
    format!(
        r#"agtrace {ver} — make agent behavior debuggable like system calls

Usage:
  agtrace [OPTIONS]

Target (give at least one; -p and -C are mutually exclusive):
  -p, --pid <PID>          follow this process and its descendants (like strace -f)
  -C, --cgroup <PATH>      follow every process in this cgroup (e.g. /sys/fs/cgroup/xxx)
      --kernel-lines <PATH> replay a saved kernel line stream (aya/bpftrace stdout) as the
                           kernel side, without attaching to anything. Offline only
                           (mutually exclusive with -p/-C/-f). The file's `nsecs` come from
                           the machine that captured it, so cross-layer ordering is only
                           trustworthy for a same-boot capture; parsing, binding and
                           attribution are byte-for-byte the live code paths.
  -S, --session <ID|PATH>  follow the agent layer (adapter-specific: Claude Code session id or
                           transcript path; DSH session id, log path, workspace dir, or
                           `auto` = newest session of the current workspace)
                           combine with -p/-C to get a merged timeline
      --transcript <PATH>  alias for -S (agent source path); -S wins if both are given

  With no target, agtrace exits with an error — it never does system-wide tracing,
  which amounts to tracing without a filter.

Behavior:
  -f, --follow             live tail (without it, stop at EOF — for offline fixtures)
      --adapter <NAME>     claude-code | dsh | openshell | jsonl  (default claude-code)
                           dsh: DeepSeek Harness session logs (`session.vN.jsonl.zstd`), which
                           are concatenated Zstandard frames and are tailed frame-by-frame
                           while the harness appends.
      --time-base <MODE>   fixture time anchor: now | wall | epoch   (default now)
      --source <LIST>      comma-separated: exec,file,net,agent      (default all)
      --collector <NAME>   aya | bpftrace  (default aya)
                           aya loads the eBPF programs in-process (no external tool,
                           ~ms to attach). If it cannot start, agtrace says so on
                           stderr and falls back to the bpftrace script.
      --merge-window <MS>  reorder window                            (default {mw})
      --resync-interval <S> clock offset resample, 0=off             (default {ri})

Output:
      --output <text|json> default text (json keeps untruncated fields)
      --full               expand truncation details (it can NOT restore lost data)
      --no-color           disable color (auto-off when stdout is not a tty)
      --max-events <N>     stop after N events
      --duration <SEC>     stop after SEC seconds

Fidelity / privacy:
      --redact <MODE>      off | argv | argv+content           (default argv)
                           argv masks credential-shaped command-line arguments as ***,
                           but leaves agent prompt/thinking/tool text unmasked
                           (pass argv+content to mask that too).
      --file-all           log every openat (default: write intent + sensitive-path reads)
      --argv-max <N>       max argv entries captured                  (default {am})
      --tool-arg-max <N>   truncate tool_use input                    (default {ta})
      --bash-cmd-max <N>   truncate Bash command                      (default {bc})

Derived views (DESIGN.md section 8, dimensions 4/5; they surface signals, never act):
      --watchlist <PATH>   TOML rule file, **appended** after the built-in rules
      --gap-ms <MS>        tool call->result gap treated as abnormal  (default {gm})
      --retry-window-ms <MS> same input seen again within this window = suspected retry (default {rw})
      --no-views           disable the derived views

Logical-call collapsing (DESIGN.md section 11; default ON, text output only):
      --no-collapse        show every kernel line instead of the derived summary.
                           Restores the raw exec_fail PATH probes and every fork row,
                           and drops the /proc-sourced parent identity suffix.
                           (-v is the middle ground: raw lines *and* the summary.)

Exact tool.call <-> exec binding (DESIGN.md section 3.5, 3rd level; default ON):
      --no-bind            disable argv matching. Every agent row keeps its `?`,
                           no kernel row gets `=`, and no `derived bind` line is
                           emitted. Use it when you want the honest "we only know
                           it is *near* this process tree" view, or to reproduce
                           the pre-v0.3 output with the same binary.

Failure attribution (DESIGN.md section 13; always on, one `XX` line per failed call):
      --failures-only      print only failing tool.call chains: the call itself, the
                           kernel subtree bound to it, the derived `XX` row, and the
                           `--- failures (N)` footer. Everything else is dropped.
                           Built for piping into a debug loop; the summary counters
                           then describe the rows that survived the filter.

                           Queries against `--output json` (JSONL: one event per line,
                           the last line is the summary). Every derived row carries the
                           failed call's `corr.tool_use_id`, so a chain is one select:
                             agtrace -S <s> --output json | jq -c 'select(.kind=="derived.fail")'
                             agtrace -S <s> --output json | jq -c 'select(.corr.tool_use_id==$id)' --arg id toolu_01A
                             agtrace -S <s> --output json | jq -r 'select(.kind=="derived.fail")
                               | "\(.ts_wall_ns) \(.payload.class) \(.payload.head) | \(.payload.deepest // "no kernel evidence")"'
                             agtrace -S <s> --output json | jq -s '.[-1].extra.failures.list'
                             agtrace -S <s> --output json | jq -s '.[-1].extra.failures.by_class'
                           `payload.class` is one of before-exec | kernel | bound-no-evidence
                           | unbound | no-kernel-source; fold on it to group a whole
                           session by "which layer did things break in".
                           `extra.failures.kernel_available == false` means this run never
                           watched the kernel, so no `deepest` could be attributed — that
                           is a missing source, not a missing failure.

Debug:
  -v, --verbose            show dropped/unknown events, loss stats, truncation details
      --keep-script        keep the generated bpftrace script (for collector debugging;
                           only meaningful with --collector bpftrace)
  -h, --help               show this help
  -V, --version            show version
"#,
        ver = VERSION,
        mw = DEFAULT_MERGE_WINDOW_MS,
        ri = DEFAULT_RESYNC_SECS,
        am = DEFAULT_ARGV_MAX,
        ta = DEFAULT_TOOL_ARG_MAX,
        bc = DEFAULT_BASH_CMD_MAX,
        gm = DEFAULT_GAP_MS,
        rw = DEFAULT_RETRY_WINDOW_MS,
    )
}

fn parse_u64(name: &str, v: &str) -> Result<u64, String> {
    v.parse::<u64>()
        .map_err(|_| format!("{} needs a non-negative integer, got `{}`", name, v))
}

fn parse_usize(name: &str, v: &str) -> Result<usize, String> {
    v.parse::<usize>()
        .map_err(|_| format!("{} needs a non-negative integer, got `{}`", name, v))
}

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Parsed, String> {
    let mut cli = Cli::default();
    let mut it = args.into_iter().peekable();
    // 跳过 argv[0]
    let _ = it.next();

    while let Some(a) = it.next() {
        // 支持 `--opt=value`
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let take = |it: &mut std::iter::Peekable<_>, name: &str| -> Result<String, String> {
            match inline.clone() {
                Some(v) => Ok(v),
                None => it.next().ok_or_else(|| format!("{} needs a value", name)),
            }
        };

        match name.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help(help())),
            "-V" | "--version" => return Ok(Parsed::Version),

            "-p" | "--pid" => {
                let v = take(&mut it, &name)?;
                let p = v
                    .parse::<u32>()
                    .map_err(|_| format!("--pid needs a process id, got `{}`", v))?;
                if p == 0 {
                    return Err("--pid 0 is not a valid target".into());
                }
                cli.pid = Some(p);
            }
            "-C" | "--cgroup" => cli.cgroup = Some(take(&mut it, &name)?),
            "-S" | "--session" => cli.session = Some(take(&mut it, &name)?),

            "-f" | "--follow" => cli.follow = true,
            "--adapter" => cli.adapter = take(&mut it, &name)?,
            "--transcript" => cli.transcript = Some(take(&mut it, &name)?),
            "--time-base" => cli.time_base = TimeBase::parse(&take(&mut it, &name)?)?,
            "--source" => {
                let v = take(&mut it, &name)?;
                cli.source = Some(SourceFilter::parse(&v)?);
            }
            "--merge-window" => cli.merge_window_ms = parse_u64("--merge-window", &take(&mut it, &name)?)?,
            "--resync-interval" => cli.resync_secs = parse_u64("--resync-interval", &take(&mut it, &name)?)?,

            "--output" => {
                cli.output = match take(&mut it, &name)?.as_str() {
                    "text" => OutputMode::Text,
                    "json" => OutputMode::Json,
                    o => {
                        return Err(format!("unknown --output value `{}` (available: text | json)", o));
                    }
                }
            }
            "--full" => cli.full = true,
            "--no-color" => cli.no_color = true,
            "--max-events" => cli.max_events = Some(parse_u64("--max-events", &take(&mut it, &name)?)?),
            "--duration" => cli.duration_secs = Some(parse_u64("--duration", &take(&mut it, &name)?)?),

            "--collector" => cli.collector = CollectorBackend::parse(&take(&mut it, &name)?)?,
            "--redact" => cli.redact = RedactMode::parse(&take(&mut it, &name)?)?,
            "--file-all" => cli.file_all = true,
            "--argv-max" => cli.argv_max = parse_usize("--argv-max", &take(&mut it, &name)?)?,
            "--tool-arg-max" => cli.tool_arg_max = parse_usize("--tool-arg-max", &take(&mut it, &name)?)?,
            "--bash-cmd-max" => cli.bash_cmd_max = parse_usize("--bash-cmd-max", &take(&mut it, &name)?)?,

            "--watchlist" => cli.watchlist = Some(take(&mut it, &name)?),
            "--gap-ms" => cli.gap_ms = parse_u64("--gap-ms", &take(&mut it, &name)?)?,
            "--retry-window-ms" => cli.retry_window_ms = parse_u64("--retry-window-ms", &take(&mut it, &name)?)?,
            "--no-views" => cli.no_views = true,
            "--no-collapse" => cli.no_collapse = true,
            "--no-bind" => cli.no_bind = true,
            "--failures-only" => cli.failures_only = true,
            "--kernel-lines" => cli.kernel_lines = Some(take(&mut it, &name)?),

            "-v" | "--verbose" => cli.verbose = true,
            "--keep-script" => cli.keep_script = true,

            other => {
                return Err(format!(
                    "unknown argument `{}`\n(`agtrace --help` lists every option)",
                    other
                ));
            }
        }
    }

    // ---- 目标校验（§4.1：不给目标就报错退出）----
    // `--adapter` 的名字在解析期就校验：`--adapter dsh -p 123` 这种"名字打错但
    // 有内核目标所以静默忽略 adapter"的组合，只会让用户以为 agent 层被接上了。
    const ADAPTERS: [&str; 4] = ["claude-code", "dsh", "openshell", "jsonl"];
    if !ADAPTERS.contains(&cli.adapter.as_str()) {
        return Err(format!(
            "unknown --adapter `{}` (available: {})",
            cli.adapter,
            ADAPTERS.join(" | ")
        ));
    }
    if cli.pid.is_some() && cli.cgroup.is_some() {
        return Err(
            "-p/--pid and -C/--cgroup are mutually exclusive: both are kernel-level targets.\n\
             To merge the agent layer, add -S/--session."
                .into(),
        );
    }
    // `--transcript` is an alias for `-S` (§4.1): either one names the agent source.
    if cli.adapter != "claude-code"
        && cli.session.is_none()
        && cli.transcript.is_none()
        && (cli.pid.is_some() || cli.cgroup.is_some())
    {
        return Err(format!(
            "--adapter {} needs an agent source: add -S/--session (or --transcript)",
            cli.adapter
        ));
    }
    // `--kernel-lines` 也是内核源（回放一份已采到的内核行），所以它单独出现时
    // 同样是一个**完整的目标** —— 下面的"回放与实时互斥"校验会接管剩下的规则。
    if cli.pid.is_none()
        && cli.cgroup.is_none()
        && cli.session.is_none()
        && cli.transcript.is_none()
        && cli.kernel_lines.is_none()
    {
        return Err("you must specify a target: -p/--pid, -C/--cgroup, -S/--session \
             (or --transcript), or --kernel-lines.\n\
             agtrace never traces system-wide — an unfiltered openat would drown\n\
             the timeline within seconds."
            .into());
    }
    // ---- v0.6 回放校验 ----
    if cli.kernel_lines.is_some() {
        // 回放和实时内核目标互斥：两者都指向"内核侧"，同时给没有意义
        // （-p 已经 attach 到真进程，再叠一份历史文件只会让时间线自相矛盾）。
        if cli.pid.is_some() || cli.cgroup.is_some() {
            return Err(
                "--kernel-lines replays a saved capture; -p/--pid and -C/--cgroup attach to a live \
                 kernel. Pick one kind of kernel source."
                    .into(),
            );
        }
        // 回放是离线动作：它的行是**一次性**读完的，而 -f 的语义是"还会再来"。
        // 两者组合只会让用户以为自己在看实时数据。
        if cli.follow {
            return Err(
                "--kernel-lines is an offline replay of a saved file; -f/--follow means \"more is \
                 coming\". Drop -f, or capture live with -p/-C."
                    .into(),
            );
        }
    }
    if cli.argv_max == 0 {
        return Err(
            "--argv-max 0 would capture no arguments at all; to turn capture off, use --redact off with --argv-max 1"
                .into(),
        );
    }

    Ok(Parsed::Run(Box::new(cli)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Result<Parsed, String> {
        parse(v.iter().map(|s| s.to_string()))
    }

    #[test]
    fn no_target_is_error() {
        let e = p(&["agtrace"]).err().expect("不给目标必须报错");
        assert!(e.contains("must specify a target"), "{}", e);
    }

    #[test]
    fn pid_and_cgroup_are_exclusive() {
        let e = p(&["agtrace", "-p", "1", "-C", "/x"]).err().unwrap();
        assert!(e.contains("mutually exclusive"), "{}", e);
    }

    /// §7 验收 #3：-p 与 -S 必须能同时给（合并时间线）。
    #[test]
    fn pid_and_session_combine() {
        match p(&["agtrace", "-p", "123", "-S", "abc", "-f"]).unwrap() {
            Parsed::Run(c) => {
                assert_eq!(c.pid, Some(123));
                assert_eq!(c.session.as_deref(), Some("abc"));
                assert!(c.follow);
            }
            _ => panic!("应当解析成 Run"),
        }
    }

    #[test]
    fn session_only_ok() {
        match p(&["agtrace", "-S", "/tmp/t.jsonl"]).unwrap() {
            Parsed::Run(c) => assert_eq!(c.session.as_deref(), Some("/tmp/t.jsonl")),
            _ => panic!(),
        }
    }

    /// `--transcript` 是 `-S` 的别名（v0.6.2）：它曾经解析后被丢弃，
    /// 于是 `agtrace --transcript x` 连目标校验都过不了。
    #[test]
    fn transcript_alone_is_a_valid_target() {
        match p(&["agtrace", "--transcript", "/tmp/t.jsonl"]).unwrap() {
            Parsed::Run(c) => {
                assert_eq!(c.transcript.as_deref(), Some("/tmp/t.jsonl"));
                assert!(c.session.is_none());
            }
            _ => panic!("应当解析成 Run"),
        }
    }

    #[test]
    fn dsh_adapter_accepts_auto_and_session_paths() {
        match p(&["agtrace", "--adapter", "dsh", "-S", "auto", "-f"]).unwrap() {
            Parsed::Run(c) => {
                assert_eq!(c.adapter, "dsh");
                assert_eq!(c.session.as_deref(), Some("auto"));
            }
            _ => panic!(),
        }
        // 会话 id / workspace 目录都在同一个 -S 槽位里。
        assert!(p(&["agtrace", "--adapter", "dsh", "-S", "session-e8694b65"]).is_ok());
        assert!(p(&["agtrace", "--adapter", "dsh", "-S", "C:\\Users\\x\\projects"]).is_ok());
    }

    #[test]
    fn unknown_adapter_is_rejected_at_parse_time() {
        let e = p(&["agtrace", "--adapter", "bogus", "-S", "x"]).err().unwrap();
        assert!(e.contains("unknown --adapter"), "{}", e);
        assert!(e.contains("dsh"), "the error must list the available adapters: {}", e);
    }

    /// 名字打错但恰好有内核目标时，不能静默忽略 adapter。
    #[test]
    fn adapter_without_agent_source_is_rejected() {
        let e = p(&["agtrace", "--adapter", "dsh", "-p", "1"]).err().unwrap();
        assert!(e.contains("needs an agent source"), "{}", e);
        // 默认 adapter 与 -p 组合仍然合法（纯内核跟踪）。
        assert!(p(&["agtrace", "-p", "1"]).is_ok());
    }

    /// `--kernel-lines` 自己就是一个完整目标：离线回放一份已采到的内核行，
    /// 不需要（也不该强制）再给 -S/-p。（`--help` 一直把它列在 Target 一栏。）
    #[test]
    fn kernel_lines_alone_is_a_valid_target() {
        match p(&["agtrace", "--kernel-lines", "/tmp/cap.txt"]).unwrap() {
            Parsed::Run(c) => assert_eq!(c.kernel_lines.as_deref(), Some("/tmp/cap.txt")),
            _ => panic!("应当解析成 Run"),
        }
    }

    #[test]
    fn defaults_match_design() {
        let c = match p(&["agtrace", "-p", "1"]).unwrap() {
            Parsed::Run(c) => c,
            _ => panic!(),
        };
        assert_eq!(c.merge_window_ms, 200);
        assert_eq!(c.resync_secs, 30);
        assert_eq!(c.redact, RedactMode::Argv, "默认必须打码（§5.3 不是可选项）");
        assert_eq!(c.argv_max, 8);
        assert_eq!(c.tool_arg_max, 512);
        assert_eq!(c.bash_cmd_max, 1024);
        assert_eq!(c.adapter, "claude-code");
        assert_eq!(c.output, OutputMode::Text);
        assert!(!c.file_all, "默认只记写意图（§5.1）");
    }

    #[test]
    fn eq_form_and_short_flags() {
        match p(&["agtrace", "-p", "9", "--merge-window=50", "--redact=off"]).unwrap() {
            Parsed::Run(c) => {
                assert_eq!(c.merge_window_ms, 50);
                assert_eq!(c.redact, RedactMode::Off);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn bad_values_are_reported_not_panicked() {
        assert!(p(&["agtrace", "-p", "abc"]).is_err());
        assert!(p(&["agtrace", "-p"]).is_err());
        assert!(p(&["agtrace", "-p", "1", "--output", "xml"]).is_err());
        assert!(p(&["agtrace", "-p", "1", "--redact", "maybe"]).is_err());
        assert!(p(&["agtrace", "-p", "1", "--time-base", "yesterday"]).is_err());
        assert!(p(&["agtrace", "-p", "1", "--source", "cpu"]).is_err());
        assert!(p(&["agtrace", "-p", "1", "--argv-max", "0"]).is_err());
        assert!(p(&["agtrace", "-p", "1", "--nope"]).is_err());
        assert!(p(&["agtrace", "--pid", "0"]).is_err());
    }

    #[test]
    fn failures_only_flag_and_its_json_recipes() {
        let c = match p(&["agtrace", "-S", "s", "--failures-only"]).unwrap() {
            Parsed::Run(c) => c,
            _ => panic!(),
        };
        assert!(c.failures_only);
        assert!(!Cli::default().failures_only, "--failures-only 必须默认关");
        // 帮助里必须给出 json 查询配方 —— 否则 `--output json` 的失败查询
        // 只能靠用户去读源码猜 `derived.fail` 这个名字。
        let h = help();
        assert!(h.contains("--failures-only"));
        assert!(h.contains("select(.kind==\"derived.fail\")"));
        assert!(h.contains("extra.failures"));
    }

    #[test]
    fn help_and_version() {
        assert!(matches!(p(&["agtrace", "--help"]).unwrap(), Parsed::Help(_)));
        assert!(matches!(p(&["agtrace", "-h"]).unwrap(), Parsed::Help(_)));
        assert!(matches!(p(&["agtrace", "--version"]).unwrap(), Parsed::Version));
    }

    #[test]
    fn help_mentions_privacy_and_targets() {
        let h = help();
        assert!(h.contains("--redact"));
        assert!(h.contains("argv+content"));
        assert!(h.contains("-p, --pid"));
        assert!(h.contains("never does system-wide tracing"));
    }
}
