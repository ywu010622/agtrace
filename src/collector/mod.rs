//! Collector 接口 + 内核行协议解析（DESIGN.md §2.5 / §2.2）。
//!
//! 采集器接口约定为**行协议**：启动后在 stdout 上持续输出以 '\n' 结尾的 UTF-8 行，
//! 每行 = 一个内核事件。未来 aya / C+libbpf 实现只需产出同样的行格式，
//! 这里的 parser 与 merger 完全不用改。

pub mod aya;
pub mod bpftrace;
pub mod child;
pub mod replay;

use crate::event::{Binding, Corr, Event, Kind, Layer, Payload, TruncNote, TsSource, errno_label, one_line};
use crate::poll::PollOutcome;
use crate::redact::RedactMode;

/// 一个内核事件采集器。
pub trait Collector: Send {
    fn id(&self) -> &'static str;
    /// 非阻塞拉取。返回本次新增的事件（可能为空）。
    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, CollectorError>;
    /// 优雅关闭。
    fn shutdown(&mut self);
    /// 采集器自报的丢包计数（已通过 `collector.lost_events` 事件呈现，这里只做统计）。
    fn lost_events(&self) -> u64 {
        0
    }
}

/// Either kernel collector, behind the API the main loop already used.
///
/// v0.5 added a second implementation of the same line protocol. An enum rather
/// than `Box<dyn Collector>` because the main loop also reads bpftrace-only
/// diagnostics (`rendered_script`, `keep_script`) that would otherwise force a
/// downcast at every call site; the two variants are known and closed.
pub enum KernelCollector {
    Aya(aya::AyaCollector),
    Bpftrace(bpftrace::BpftraceCollector),
    /// v0.6：回放一份**已经采到的**内核行文件（`--kernel-lines`）。
    ///
    /// 它不是第三个采集后端 —— 它谁也不 attach，只是把同一套行协议重新喂一遍。
    /// 用 `Box` 是因为它比另两个变体大得多（整份文件在内存里），
    /// 而 `KernelCollector` 会被按值放进 `Option<…>` 到处传。
    Replay(Box<replay::KernelReplay>),
}

impl KernelCollector {
    /// Whether the events on this stream are labelled `aya` (for the startup
    /// banner and the "no natural end" note, which name the mechanism).
    pub fn is_aya(&self) -> bool {
        matches!(self, KernelCollector::Aya(_))
    }

    /// v0.6：这一轮的"内核侧"是不是一份回放文件。
    ///
    /// 两个地方要问它：启动时的"内核采集没有自然结尾"注记（回放**有**自然结尾，
    /// 那句话在回放里是假的），以及 target 描述。
    pub fn is_replay(&self) -> bool {
        matches!(self, KernelCollector::Replay(_))
    }

    pub fn exited(&self) -> bool {
        match self {
            KernelCollector::Aya(c) => c.exited(),
            KernelCollector::Bpftrace(c) => c.exited(),
            KernelCollector::Replay(c) => c.exited(),
        }
    }

    /// The collector's own exit status, once it is gone. `None` while it runs.
    ///
    /// The privileged loader exits non-zero when it refuses to do its job (a
    /// tracepoint this kernel does not have, a verifier rejection). Without this,
    /// such a run looks identical from the parent to a clean one that simply
    /// captured nothing — which is the failure mode the whole line protocol
    /// exists to make visible.
    pub fn exit_code(&self) -> Option<i32> {
        match self {
            KernelCollector::Aya(c) => c.exit_code(),
            KernelCollector::Bpftrace(c) => c.exit_code(),
            KernelCollector::Replay(c) => c.exit_code(),
        }
    }

    pub fn redacted_events(&self) -> u64 {
        match self {
            KernelCollector::Aya(c) => c.redacted_events(),
            KernelCollector::Bpftrace(c) => c.redacted_events(),
            KernelCollector::Replay(c) => c.redacted_events(),
        }
    }

    pub fn parse_stats(&self) -> &ParseStats {
        match self {
            KernelCollector::Aya(c) => c.parse_stats(),
            KernelCollector::Bpftrace(c) => c.parse_stats(),
            KernelCollector::Replay(c) => c.parse_stats(),
        }
    }

    pub fn stderr_tail(&self) -> &[String] {
        match self {
            KernelCollector::Aya(c) => c.stderr_tail(),
            KernelCollector::Bpftrace(c) => c.stderr_tail(),
            KernelCollector::Replay(c) => c.stderr_tail(),
        }
    }

    pub fn unfinished_line_bytes(&self) -> usize {
        match self {
            KernelCollector::Aya(c) => c.unfinished_line_bytes(),
            KernelCollector::Bpftrace(c) => c.unfinished_line_bytes(),
            KernelCollector::Replay(c) => c.unfinished_line_bytes(),
        }
    }

    /// The `-v` fingerprint: the expanded script for bpftrace, the attach
    /// configuration for aya.
    pub fn rendered_script(&self) -> &str {
        match self {
            KernelCollector::Aya(c) => &c.rendered_script,
            KernelCollector::Bpftrace(c) => &c.rendered_script,
            KernelCollector::Replay(c) => &c.rendered_script,
        }
    }

    /// `--keep-script` only means something when there is a script.
    pub fn set_keep_script(&mut self, v: bool) {
        if let KernelCollector::Bpftrace(c) = self {
            c.keep_script = v;
        }
    }
}

impl Collector for KernelCollector {
    fn id(&self) -> &'static str {
        match self {
            KernelCollector::Aya(c) => Collector::id(c),
            KernelCollector::Bpftrace(c) => Collector::id(c),
            KernelCollector::Replay(c) => c.id(),
        }
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, CollectorError> {
        match self {
            KernelCollector::Aya(c) => c.poll(out),
            KernelCollector::Bpftrace(c) => c.poll(out),
            KernelCollector::Replay(c) => Collector::poll(c.as_mut(), out),
        }
    }

    fn shutdown(&mut self) {
        match self {
            KernelCollector::Aya(c) => c.shutdown(),
            KernelCollector::Bpftrace(c) => c.shutdown(),
            KernelCollector::Replay(c) => Collector::shutdown(c.as_mut()),
        }
    }

    fn lost_events(&self) -> u64 {
        match self {
            KernelCollector::Aya(c) => c.lost_events(),
            KernelCollector::Bpftrace(c) => c.lost_events(),
            KernelCollector::Replay(c) => c.lost_events(),
        }
    }
}

#[derive(Debug)]
pub enum CollectorError {
    /// 可执行文件不存在 / spawn 失败。
    Spawn(String),
    Io(String),
}

impl std::fmt::Display for CollectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectorError::Spawn(s) => write!(f, "collector spawn failed: {}", s),
            CollectorError::Io(s) => write!(f, "collector io error: {}", s),
        }
    }
}

/// 解析诊断 —— 解析器**绝不 panic**，一切异常都变成这里的计数 + `-v` 可见的说明。
#[derive(Debug, Default, Clone)]
pub struct ParseStats {
    pub lines_total: u64,
    pub lines_unknown_tag: u64,
    /// 字段数不足 / 数字解析失败 —— 半行、被 SIGTERM 截断的行都落这里。
    pub lines_malformed: u64,
    /// bpftrace 自身的非协议输出（Attaching...、map dump 等），静默丢弃。
    pub lines_non_protocol: u64,
    pub ticks: u64,
    pub argv_orphans: u64,
    /// v0.4.2：默认模式下被丢弃的非敏感只读 open（内核已放行，Rust 侧过滤）。
    pub files_dropped_default: u64,
}

/// 内核行协议解析器。
///
/// 关键点：**每行最后一个字段是唯一可能包含 `|` 的字段**，所以一律用 `splitn`，
/// 保证尾字段原样保留。这是把 argv / 路径（可能含 `|`）安全送达 Rust 侧的前提。
/// v0.4.2：默认模式下，只读 open 命中这些路径才保留。
/// 与 views.rs `default_watchlist` 的 File 规则保持一致 —— 改动时两处同步。
const SENSITIVE_FILE_PATTERNS: &[&str] = &[
    "*/.ssh/id_*",
    "*/id_rsa",
    "*/id_ed25519",
    "*/.aws/credentials",
    "*/gcloud/credentials.db",
    "*/.kube/config",
    "*/.netrc",
    "*/.env",
    "/etc/shadow",
    "/etc/sudoers*",
    "*/.docker/config.json",
    "*/.npmrc",
    "*/.git-credentials",
    "/proc/*/environ",
];

/// 敏感路径判断。只对绝对路径做判断；相对路径无法还原（§5.2 #2），不猜。
fn is_sensitive_path(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    SENSITIVE_FILE_PATTERNS
        .iter()
        .any(|p| crate::views::glob_match(p, path))
}

pub struct KernelLineParser {
    /// bpftrace `str()` 的字节上限（由 `BPFTRACE_MAX_STRLEN` 决定），用于判定截断。
    str_limit: usize,
    /// Which collector produced these lines. The parser is shared with the aya
    /// collector (v0.5), so the label is a parameter rather than a constant: an
    /// aya run that reported its events as `source: "bpftrace"` would make `-v`
    /// and `--output json` lie about where the data came from.
    source_label: &'static str,
    /// 凭据打码模式（§5.3）。**默认 argv**：这是设计决策不是可选项 ——
    /// 一个用来做安全调查的工具，若默认把密钥写进输出，它本身就成了新的泄漏面。
    redact: RedactMode,
    /// 有多少个事件因为打码被改动过（`-v` 可见，证明打码确实生效了）。
    pub redacted_events: u64,
    pub stats: ParseStats,
    /// 已看到 EXEC/FAIL、正在等它的 ARGV 行。
    pending: Option<PendingExec>,
    /// 上一个事件产出后，Rust 侧分配 seq 的起始值（merger 会重写）。
    next_seq: u64,
    /// v0.4.2：(pid, fd) → (addr, port)，由 connect 事件填充，供 sendto 做
    /// 对端归因。fd 会被复用，这是 most-recent 启发式，不是因果保证。
    fd_peer: std::collections::HashMap<(u32, i64), (String, Option<u16>)>,
    /// v0.4.2：--file-all 是否开启。关闭时，只读 open 只有敏感路径才保留
    /// （内核侧默认已放行全部 open，过滤在 Rust 侧做 —— bpftrace 里做字符串
    /// 匹配不现实）。
    file_all: bool,
}

struct PendingExec {
    ev: Event,
    /// 期望的 argv 槽位数。
    slots: usize,
    got: Vec<(usize, String)>,
    ts_ns: u64,
}

/// bpftrace 的截断标记：超过 `MAX_STRLEN` 时在尾部打印 `..`。
const TRUNC_MARK: &str = "..";

impl KernelLineParser {
    pub fn with_redact(str_limit: usize, redact: RedactMode) -> Self {
        KernelLineParser {
            str_limit,
            source_label: "bpftrace",
            redact,
            redacted_events: 0,
            stats: ParseStats::default(),
            pending: None,
            next_seq: 0,
            fd_peer: std::collections::HashMap::new(),
            file_all: false,
        }
    }

    /// 设置 --file-all（两个采集器的 spawn 都会调用）。
    pub fn set_file_all(&mut self, v: bool) {
        self.file_all = v;
    }

    /// 标注这批行的来源采集器（`-v` 与 json 输出里可见）。
    pub fn set_source_label(&mut self, label: &'static str) {
        self.source_label = label;
    }

    /// 取下一个 seq。
    fn seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    /// 喂一行（不含结尾 `\n`）。事件会被 push 进 `out`。
    ///
    /// 半行、不完整行、未知 tag 一律降级：计数、丢弃、继续。
    pub fn feed_line(&mut self, line: &str, out: &mut Vec<Event>) {
        self.stats.lines_total += 1;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            self.stats.lines_non_protocol += 1;
            return;
        }

        // 不是我们协议里的 tag → bpftrace 的杂项输出（Attaching N probes...、
        // 退出时的 map dump、警告等）。静默丢弃，但计数。
        let tag = match line.split('|').next() {
            Some(t) => t,
            None => {
                self.stats.lines_non_protocol += 1;
                return;
            }
        };

        // ARGV 行必须紧跟其 EXEC/FAIL —— 先处理它，避免被通用 tag 分派打断。
        if tag == "ARGV" {
            self.handle_argv(line);
            return;
        }

        // 任何非 ARGV 行到来 = 上一条 EXEC/FAIL 的 ARGV 行已经发完（或永远不来）。
        self.flush_pending(out);

        match tag {
            "EXEC" => self.handle_exec(line, false, out),
            "FAIL" => self.handle_exec(line, true, out),
            "FORK" => self.handle_fork(line, out),
            "EXIT" => self.handle_exit(line, out),
            "OPEN" => self.handle_open(line, out),
            "CONN" => self.handle_conn(line, out),
            "SEND" => self.handle_send(line, out),
            "TICK" => {
                self.stats.ticks += 1;
            }
            _ => {
                self.stats.lines_unknown_tag += 1;
            }
        }
    }

    /// 输入流结束（bpftrace 退出 / SIGTERM 截断）时调用：把悬空的 EXEC 吐出来。
    pub fn finish(&mut self, out: &mut Vec<Event>) {
        self.flush_pending(out);
    }

    /// 把上一条 EXEC/FAIL 连同已收集的 ARGV 行产出。
    fn flush_pending(&mut self, out: &mut Vec<Event>) {
        let Some(mut p) = self.pending.take() else {
            return;
        };
        if p.got.len() < p.slots {
            // ARGV 行没来全（例如 bpftrace 被 SIGTERM 打断）。如实记录，不 panic。
            p.ev.trunc.push(
                TruncNote::new("argv", Some(p.slots), p.got.len())
                    .with_note("ARGV lines incomplete (collector ended early or its output was cut)"),
            );
        }
        if let Payload::ProcExec { argv, .. } | Payload::ProcExecFail { argv, .. } = &mut p.ev.payload {
            let raw = summarize_argv(&p.got, p.slots, self.str_limit, &mut p.ev.trunc);
            if self.redact.redacts_argv() {
                let (masked, changed) = crate::redact::redact_argv(&raw);
                let masked_count = raw.iter().zip(masked.iter()).filter(|(a, b)| a != b).count();
                if changed {
                    self.redacted_events += 1;
                    // 打码本身必须留痕：用户要能分辨"这真的是 ***"和"这里被抹掉了"。
                    // 走 notes 而不是 trunc —— 打码**没有截断任何内容**，写进 trunc
                    // 会让这一行被打上 `~`，而 `~` 的含义是"内容被截掉了"。
                    p.ev.notes.push(format!(
                        "{} argv entr(ies) look like credentials and were masked as *** by --redact {}",
                        masked_count,
                        self.redact.as_str()
                    ));
                }
                *argv = masked;
            } else {
                *argv = raw;
            }
        }
        p.ev.ts_ns = p.ts_ns;
        out.push(p.ev);
    }

    fn handle_argv(&mut self, line: &str) {
        // ARGV|<nsecs>|<pid>|<tid>|<idx>|<value>
        let mut it = line.splitn(6, '|');
        let _ = it.next();
        let (_ts, _pid, _tid, idx) = match (it.next(), it.next(), it.next(), it.next()) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => {
                self.stats.lines_malformed += 1;
                return;
            }
        };
        let value = it.next().unwrap_or("");
        let idx: usize = match idx.parse() {
            Ok(v) => v,
            Err(_) => {
                self.stats.lines_malformed += 1;
                return;
            }
        };
        match &mut self.pending {
            Some(p) => p.got.push((idx, value.to_string())),
            None => self.stats.argv_orphans += 1,
        }
    }

    fn handle_exec(&mut self, line: &str, failed: bool, _out: &mut Vec<Event>) {
        // EXEC|<nsecs>|<pid>|<tid>|<ppid>|<cgroup>|<slots>|<comm>|<filename>
        // FAIL|<nsecs>|<pid>|<tid>|<ppid>|<cgroup>|<slots>|<ret>|<comm>|<filename>
        let want = if failed { 10 } else { 9 };
        let f: Vec<&str> = line.splitn(want, '|').collect();
        if f.len() < want {
            self.stats.lines_malformed += 1;
            return;
        }
        let ts_ns = match f[1].parse::<u64>() {
            Ok(v) => v,
            Err(_) => {
                self.stats.lines_malformed += 1;
                return;
            }
        };
        let (pid, tid, ppid, cgroup, slots, comm, filename, retval) = if failed {
            (
                f[2].parse::<u32>().ok(),
                f[3].parse::<u32>().ok(),
                f[4].parse::<u32>().ok(),
                f[5].parse::<u64>().ok(),
                f[6].parse::<usize>().unwrap_or(0),
                f[8].to_string(),
                f[9].to_string(),
                f[7].parse::<i64>().ok(),
            )
        } else {
            (
                f[2].parse::<u32>().ok(),
                f[3].parse::<u32>().ok(),
                f[4].parse::<u32>().ok(),
                f[5].parse::<u64>().ok(),
                f[6].parse::<usize>().unwrap_or(0),
                f[7].to_string(),
                f[8].to_string(),
                None,
            )
        };

        let mut trunc = Vec::new();
        let filename = match check_str_trunc(&filename, self.str_limit) {
            Some(note) => {
                trunc.push(note);
                filename.trim_end_matches(TRUNC_MARK).to_string()
            }
            None => filename,
        };

        let payload = if failed {
            let ret = retval.unwrap_or(0);
            Payload::ProcExecFail {
                filename,
                errno: ret,
                errno_name: errno_label(ret),
                argv: Vec::new(),
            }
        } else {
            Payload::ProcExec {
                filename,
                argv: Vec::new(),
                argc_total: None,
            }
        };

        let ev = Event {
            seq: self.seq(),
            ts_ns,
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Runtime,
            kind: if failed {
                Kind::RuntimeProcExecFail
            } else {
                Kind::RuntimeProcExec
            },
            source: self.source_label.into(),
            pid,
            tid,
            ppid,
            comm: Some(comm),
            cgroup_id: cgroup,
            corr: Corr::default(),
            payload,
            trunc,
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        };
        self.pending = Some(PendingExec {
            ev,
            slots,
            got: Vec::new(),
            ts_ns,
        });
    }

    fn handle_fork(&mut self, line: &str, out: &mut Vec<Event>) {
        // FORK|<nsecs>|<pid>|<ppid>|<cgroup>|<child_pid>|<child_comm>|<parent_comm>
        let f: Vec<&str> = line.splitn(8, '|').collect();
        if f.len() < 8 {
            self.stats.lines_malformed += 1;
            return;
        }
        let (Some(ts_ns), Some(child_pid)) = (f[1].parse::<u64>().ok(), f[5].parse::<u32>().ok()) else {
            self.stats.lines_malformed += 1;
            return;
        };
        let mut trunc = Vec::new();
        let child_comm = clean_str(f[6], self.str_limit, "child_comm", &mut trunc);
        out.push(Event {
            seq: self.seq(),
            ts_ns,
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Runtime,
            kind: Kind::RuntimeProcFork,
            source: self.source_label.into(),
            pid: f[2].parse().ok(),
            tid: None,
            ppid: f[3].parse().ok(),
            comm: Some(clean_str(f[7], self.str_limit, "comm", &mut trunc)),
            cgroup_id: f[4].parse().ok(),
            corr: Corr::default(),
            // v0.2 的父进程身份由 collapse::ProcTable 在管线末端补齐 ——
            // 采集器这一层只搬运内核给的字节，不读 /proc、不做推断。
            payload: Payload::ProcFork {
                child_pid,
                child_comm,
                parent_argv: None,
            },
            trunc,
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        });
    }

    fn handle_exit(&mut self, line: &str, out: &mut Vec<Event>) {
        // EXIT|<nsecs>|<pid>|<ppid>|<cgroup>|<exit_code>|<comm>
        let f: Vec<&str> = line.splitn(7, '|').collect();
        if f.len() < 7 {
            self.stats.lines_malformed += 1;
            return;
        }
        let Some(ts_ns) = f[1].parse::<u64>().ok() else {
            self.stats.lines_malformed += 1;
            return;
        };
        // 进程没了，它的 fd 也就没了：`fd_peer` 里属于这个 pid 的记录全部回收。
        // 不回收就是只增不减 —— `close` 不在追踪范围内（§2.2），唯一的生命周期
        // 信号就是这一行。顺带堵掉 pid 复用：新进程不该继承上一个同号进程的对端。
        let pid: Option<u32> = f[2].parse().ok();
        if let Some(pid) = pid {
            self.fd_peer.retain(|&(p, _), _| p != pid);
        }
        let mut trunc = Vec::new();
        out.push(Event {
            seq: self.seq(),
            ts_ns,
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Runtime,
            kind: Kind::RuntimeProcExit,
            source: self.source_label.into(),
            pid,
            tid: None,
            ppid: f[3].parse().ok(),
            comm: Some(clean_str(f[6], self.str_limit, "comm", &mut trunc)),
            cgroup_id: f[4].parse().ok(),
            corr: Corr::default(),
            payload: Payload::ProcExit {
                exit_code: f[5].parse().unwrap_or(0),
            },
            trunc,
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        });
    }

    fn handle_open(&mut self, line: &str, out: &mut Vec<Event>) {
        // OPEN|<nsecs>|<pid>|<tid>|<ppid>|<cgroup>|<flags_hex>|<dirfd>|<ret>|<path>
        let f: Vec<&str> = line.splitn(10, '|').collect();
        if f.len() < 10 {
            self.stats.lines_malformed += 1;
            return;
        }
        let Some(ts_ns) = f[1].parse::<u64>().ok() else {
            self.stats.lines_malformed += 1;
            return;
        };
        let flags = u64::from_str_radix(f[6], 16).unwrap_or(0);
        let dirfd: i64 = f[7].parse().unwrap_or(-100);
        let ret: i64 = f[8].parse().unwrap_or(-1);
        let ok = ret >= 0;

        let mut trunc = Vec::new();
        let path = clean_str(f[9], self.str_limit, "path", &mut trunc);
        // §5.2 #2：相对路径无法还原成绝对路径 —— 只标记，**不猜**。
        let path_is_relative = !path.starts_with('/') && dirfd != libc::AT_FDCWD as i64;

        // v0.4.2：默认模式下，只读 open 只有敏感路径才保留（写意图的一律保留）。
        // 内核侧默认已放行全部 open（--file-all 的语义不变：全部保留），过滤在这里做。
        if !self.file_all {
            let write_intent = flags & (0x1 | 0x2 | 0x40 | 0x200 | 0x400) != 0;
            if !write_intent && !is_sensitive_path(&path) {
                self.stats.files_dropped_default += 1;
                return;
            }
        }

        let ev = Event {
            seq: self.seq(),
            ts_ns,
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Infra,
            kind: Kind::InfraFileOpen,
            source: self.source_label.into(),
            pid: f[2].parse().ok(),
            tid: f[3].parse().ok(),
            ppid: f[4].parse().ok(),
            comm: None,
            cgroup_id: f[5].parse().ok(),
            corr: Corr::default(),
            payload: Payload::FileOpen {
                path: path.clone(),
                flags,
                dirfd,
                path_is_relative,
                ok,
                // v0.4：把 errno 一路带到渲染层。成功记 0（不是 "无此字段"），
                // 因为 `ok` 已经表达了成败，errno 只在失败时有意义。
                errno: if ok { 0 } else { ret },
            },
            trunc,
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        };

        // §2.2 Group D：v0 的 policy.deny **只从 errno 判定** —— 这是内核已经做出的
        // 真实判定。代价是拿不到"被哪个 LSM/策略拒绝的"。
        if !ok && (ret == -13 || ret == -1) {
            let mut deny = ev.clone();
            deny.seq = self.seq();
            deny.layer = Layer::Policy;
            deny.kind = Kind::PolicyDeny;
            deny.policy_note();
            deny.payload = Payload::PolicyDeny {
                syscall: "openat".into(),
                target: path,
                errno: ret,
                errno_name: errno_label(ret),
                decided_by: "kernel".into(),
            };
            out.push(deny);
        }
        out.push(ev);
    }

    fn handle_conn(&mut self, line: &str, out: &mut Vec<Event>) {
        // CONN|<nsecs>|<pid>|<tid>|<ppid>|<cgroup>|<fd>|<family>|<port>|<ret>|<addr>
        let f: Vec<&str> = line.splitn(11, '|').collect();
        if f.len() < 11 {
            self.stats.lines_malformed += 1;
            return;
        }
        let Some(ts_ns) = f[1].parse::<u64>().ok() else {
            self.stats.lines_malformed += 1;
            return;
        };
        let family: u16 = f[7].parse().unwrap_or(0);
        let port: u16 = f[8].parse().unwrap_or(0);
        let ret: i64 = f[9].parse().unwrap_or(-1);
        let ok = ret == 0;
        let mut trunc = Vec::new();
        let addr = clean_str(f[10], self.str_limit, "addr", &mut trunc);
        let family_name = family_name(family).to_string();

        let ev = Event {
            seq: self.seq(),
            ts_ns,
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Infra,
            kind: Kind::InfraNetConnect,
            source: self.source_label.into(),
            pid: f[2].parse().ok(),
            tid: f[3].parse().ok(),
            ppid: f[4].parse().ok(),
            comm: None,
            cgroup_id: f[5].parse().ok(),
            corr: Corr::default(),
            payload: Payload::NetConnect {
                family,
                family_name: family_name.clone(),
                addr: addr.clone(),
                // AF_UNIX 没有"地址/端口"概念（§2.2）→ 如实标 None，不编造。
                port: if family == 2 || family == 10 { Some(port) } else { None },
                ok,
                pending: crate::event::errno_is_pending(ret),
            },
            trunc,
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        };

        // v0.4.2：记录 (pid, fd) → 对端，供后续 sendto 归因。
        // fd 会被复用，这是 most-recent 启发式；UDP 无连接则无记录。
        if let (Some(pid), Some(fd)) = (f[2].parse::<u32>().ok(), f[6].parse::<i64>().ok()) {
            if !addr.is_empty() {
                let port_opt = if family == 2 || family == 10 { Some(port) } else { None };
                self.fd_peer.insert((pid, fd), (addr.clone(), port_opt));
            }
        }
        // connect 失败 → policy.deny（§2.2 Group D）。
        //
        // §1.2 把 policy.deny 的判定条件写死为 `retval ∈ {EACCES=-13, EPERM=-1}` ——
        // 这是"内核明确拒绝了你"。原来这里写的是 `ret < 0`，于是：
        //   - ENOENT(-2)：路径不存在，是"找不到"，不是"被拒绝"；
        //   - EINPROGRESS(-115)：非阻塞 connect 的**正常**返回，根本不是错误。
        // 两者都被伪造成 policy 层的"权限拒绝"，让 policy 行变得不可信。
        // 与 openat 分支用同一个谓词，语义只有一个来源。
        if !ok && (ret == -13 || ret == -1) {
            let mut deny = ev.clone();
            deny.seq = self.seq();
            deny.layer = Layer::Policy;
            deny.kind = Kind::PolicyDeny;
            deny.policy_note();
            deny.payload = Payload::PolicyDeny {
                syscall: "connect".into(),
                target: if family == 1 {
                    format!("AF_UNIX")
                } else {
                    format!("{}:{}", addr, port)
                },
                errno: ret,
                errno_name: errno_label(ret),
                decided_by: "kernel".into(),
            };
            out.push(deny);
        }
        out.push(ev);
    }

    fn handle_send(&mut self, line: &str, out: &mut Vec<Event>) {
        // SEND|<nsecs>|<pid>|<tid>|<ppid>|<cgroup>|<fd>|<len>
        let f: Vec<&str> = line.splitn(8, '|').collect();
        if f.len() < 8 {
            self.stats.lines_malformed += 1;
            return;
        }
        let Some(ts_ns) = f[1].parse::<u64>().ok() else {
            self.stats.lines_malformed += 1;
            return;
        };
        out.push(Event {
            seq: self.seq(),
            ts_ns,
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Infra,
            kind: Kind::InfraNetSendto,
            source: self.source_label.into(),
            pid: f[2].parse().ok(),
            tid: f[3].parse().ok(),
            ppid: f[4].parse().ok(),
            comm: None,
            cgroup_id: f[5].parse().ok(),
            corr: Corr::default(),
            payload: Payload::NetSendto {
                fd: f[6].parse().unwrap_or(-1),
                len: f[7].parse().unwrap_or(0),
                peer: {
                    let pid: Option<u32> = f[2].parse().ok();
                    let fd: i64 = f[6].parse().unwrap_or(-1);
                    pid.and_then(|p| self.fd_peer.get(&(p, fd))).map(|(a, port)| {
                        match port {
                            Some(pt) => format!("{}:{}", a, pt),
                            None => a.clone(),
                        }
                    })
                },
            },
            trunc: Vec::new(),
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        });
    }
}

impl Event {
    /// 给 `policy.deny` 事件打个可渲染的标记位（复用 `watch` 作为"需要注意"的渲染提示）。
    fn policy_note(&mut self) {
        self.watch = true;
    }
}

/// 把 ARGV 行整理成 argv 列表，并如实记录截断。
///
/// bpftrace 侧无法知道真实 argc（见 agtrace.bt 坑 #11），所以：
/// - 槽位里的空串视为"链表终止"（argv 是 NULL 结尾的，`str()` 对 NULL 返回 ""）。
/// - 若**所有**槽位都非空，说明 argv 至少有 `slots` 个元素，超出部分未捕获 → 记 `trunc`。
fn summarize_argv(got: &[(usize, String)], slots: usize, limit: usize, trunc: &mut Vec<TruncNote>) -> Vec<String> {
    let mut by_idx: Vec<Option<String>> = vec![None; slots];
    for (i, v) in got {
        if *i < slots {
            by_idx[*i] = Some(v.clone());
        }
    }
    let mut argv = Vec::new();
    let mut hit_null = false;
    for item in by_idx.iter() {
        match item {
            Some(v) if v.is_empty() => {
                hit_null = true;
                break;
            }
            Some(v) => {
                if v.ends_with(TRUNC_MARK) {
                    trunc.push(
                        TruncNote::new(format!("argv[{}]", argv.len()), None, limit)
                            .with_note("single argument exceeds MAX_STRLEN, tail marked with `..`"),
                    );
                    argv.push(v.trim_end_matches(TRUNC_MARK).to_string());
                } else {
                    argv.push(v.clone());
                }
            }
            None => {
                hit_null = true;
                break;
            }
        }
    }
    if !hit_null && !argv.is_empty() {
        trunc.push(TruncNote::new("argv", None, slots).with_note(format!(
            "argv has at least {} entries; anything beyond --argv-max was not captured",
            slots
        )));
    }
    argv
}

/// 若字符串以 bpftrace 的截断标记 `..` 结尾，产出一条 `TruncNote`。
fn check_str_trunc(s: &str, limit: usize) -> Option<TruncNote> {
    if s.ends_with(TRUNC_MARK) {
        Some(TruncNote::new("path", None, limit).with_note(format!(
            "truncated at the kernel-side str() cap of {} bytes (original length unknown), tail marked with `..`",
            limit
        )))
    } else {
        None
    }
}

/// 清洗一个可能被截断的字符串字段。
///
/// 两条分支都过 `one_line`：被截断的那条**尤其**需要 —— 截断与否和"里面有没有
/// 控制字符"是两件无关的事，一个超长路径照样可以把 `\r` / `\x1b` 带进来。
/// 原来这里直接 `to_string()`，于是 `..` 成了绕过转义的唯一姿势。
fn clean_str(s: &str, limit: usize, field: &str, trunc: &mut Vec<TruncNote>) -> String {
    if s.ends_with(TRUNC_MARK) {
        trunc.push(TruncNote::new(field, None, limit).with_note(format!(
            "truncated at the kernel-side str() cap of {} bytes (original length unknown)",
            limit
        )));
        one_line(s.trim_end_matches(TRUNC_MARK))
    } else {
        one_line(s)
    }
}

pub fn family_name(f: u16) -> &'static str {
    match f {
        0 => "AF_UNSPEC",
        1 => "AF_UNIX",
        2 => "AF_INET",
        10 => "AF_INET6",
        16 => "AF_NETLINK",
        17 => "AF_PACKET",
        _ => "AF_OTHER",
    }
}

/// 供渲染层复用的辅助：把 argv 渲染成 `["a","b"]` 形式（单行、可读）。

/// 一个简单的 FIFO 行缓冲，负责把 `read()` 出来的任意字节块切成完整的行。
///
/// **必须容忍最后一行不完整**（§2.4 优雅退出）：半行留在缓冲区里等下次，
/// 绝不因为半行而 panic，也绝不把半行当完整行解析。
#[derive(Default)]
pub struct LineBuffer {
    buf: Vec<u8>,
}

impl LineBuffer {
    pub fn new() -> Self {
        LineBuffer {
            buf: Vec::with_capacity(8192),
        }
    }

    /// 追加字节，返回本次切出的完整行（已按 UTF-8 尽力解码）。
    pub fn push(&mut self, data: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(data);
        let mut lines = Vec::new();
        let mut start = 0usize;
        while let Some(pos) = memchr(b'\n', &self.buf[start..]) {
            let end = start + pos;
            lines.push(decode_lossy(&self.buf[start..end]));
            start = end + 1;
        }
        if start > 0 {
            self.buf.drain(..start);
        }
        // 防御：如果对端吐了一条永不结束的巨行，别把内存吃光。
        const MAX_PARTIAL: usize = 1 << 20;
        if self.buf.len() > MAX_PARTIAL {
            let cut = self.buf.len() - MAX_PARTIAL;
            self.buf.drain(..cut);
        }
        lines
    }

    /// 流结束时把残留的半行吐出（标记为可能不完整，由调用方决定是否解析）。
    pub fn take_remainder(&mut self) -> Option<String> {
        if self.buf.is_empty() {
            return None;
        }
        let v = decode_lossy(&self.buf);
        self.buf.clear();
        Some(v)
    }

    pub fn pending_bytes(&self) -> usize {
        self.buf.len()
    }
}

/// bpftrace 的错误信息里可能混入非 UTF-8 字节 —— 用 lossy 解码，绝不 panic。
fn decode_lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// 极小的 memchr，避免为这一个用途引入依赖。
fn memchr(needle: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|&b| b == needle)
}

#[cfg(test)]
mod sensitive_read_tests {
    use super::*;
    use crate::event::Kind;

    fn feed(p: &mut KernelLineParser, line: &str) -> Vec<Event> {
        let mut out = Vec::new();
        p.feed_line(line, &mut out);
        out
    }

    // OPEN|<nsecs>|<pid>|<tid>|<ppid>|<cgroup>|<flags_hex>|<dirfd>|<ret>|<path>
    // flags: 0 = O_RDONLY, 1 = O_WRONLY

    #[test]
    fn default_keeps_sensitive_readonly_open() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        // file_all defaults to false
        let evs = feed(&mut p, "OPEN|1000|1234|1234|1|5|0|-100|3|/etc/shadow");
        assert!(evs.iter().any(|e| e.kind == Kind::InfraFileOpen));
        assert_eq!(p.stats.files_dropped_default, 0);
    }

    #[test]
    fn default_drops_benign_readonly_open() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        let evs = feed(&mut p, "OPEN|1000|1234|1234|1|5|0|-100|3|/usr/lib/locale/en_US/LC_MESSAGES");
        assert!(evs.is_empty());
        assert_eq!(p.stats.files_dropped_default, 1);
    }

    #[test]
    fn default_keeps_write_intent_open() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        let evs = feed(&mut p, "OPEN|1000|1234|1234|1|5|1|-100|3|/tmp/out.txt");
        assert!(evs.iter().any(|e| e.kind == Kind::InfraFileOpen));
    }

    #[test]
    fn file_all_keeps_everything() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        p.set_file_all(true);
        let evs = feed(&mut p, "OPEN|1000|1234|1234|1|5|0|-100|3|/usr/lib/locale/en_US/LC_MESSAGES");
        assert!(evs.iter().any(|e| e.kind == Kind::InfraFileOpen));
        assert_eq!(p.stats.files_dropped_default, 0);
    }

    /// 被内核截断的路径（以 `..` 收尾）照样要过 `one_line`：截断与"里面有没有
    /// 控制字符"无关，而 `..` 曾经是绕过转义的唯一姿势（§3.2 只允许单行 payload）。
    #[test]
    fn truncated_path_is_still_control_escaped() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        // flags=1（写意图），否则这条只读 open 会被默认过滤掉。
        let evs = feed(&mut p, "OPEN|1000|1234|1234|1|5|1|-100|3|/tmp/ev\x1b[31m..");
        let ev = evs.iter().find(|e| e.kind == Kind::InfraFileOpen).unwrap();
        match &ev.payload {
            crate::event::Payload::FileOpen { path, .. } => {
                assert!(!path.contains('\x1b'), "控制字符必须转义: {:?}", path);
                assert!(path.contains("\\x1b"), "转义要看得见: {:?}", path);
                assert!(path.ends_with("[31m"), "`..` 仍要摘掉: {:?}", path);
            }
            other => panic!("unexpected: {:?}", other),
        }
        assert!(!ev.trunc.is_empty(), "截断必须留痕");
    }

    #[test]
    fn relative_sensitive_path_not_guessed() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        // relative path: cannot resolve, do not guess (§5.2 #2)
        let evs = feed(&mut p, "OPEN|1000|1234|1234|1|5|0|42|3|shadow");
        assert!(evs.is_empty());
    }
}

#[cfg(test)]
mod fd_peer_tests {
    use super::*;
    use crate::event::Kind;

    fn feed(p: &mut KernelLineParser, line: &str) -> Vec<Event> {
        let mut out = Vec::new();
        p.feed_line(line, &mut out);
        out
    }

    #[test]
    fn sendto_shows_peer_from_earlier_connect() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        // CONN|<nsecs>|<pid>|<tid>|<ppid>|<cgroup>|<fd>|<family>|<port>|<ret>|<addr>
        let evs = feed(&mut p, "CONN|1000|1234|1234|1|5|7|2|9876|0|127.0.0.1");
        assert!(evs.iter().any(|e| e.kind == Kind::InfraNetConnect));
        let evs = feed(&mut p, "SEND|2000|1234|1234|1|5|7|1");
        let send = evs.iter().find(|e| e.kind == Kind::InfraNetSendto).unwrap();
        match &send.payload {
            crate::event::Payload::NetSendto { peer, .. } => {
                assert_eq!(peer.as_deref(), Some("127.0.0.1:9876"))
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn sendto_without_connect_has_no_peer() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        let evs = feed(&mut p, "SEND|2000|9999|9999|1|5|9|64");
        let send = evs.iter().find(|e| e.kind == Kind::InfraNetSendto).unwrap();
        match &send.payload {
            crate::event::Payload::NetSendto { peer, .. } => assert_eq!(peer, &None),
            other => panic!("unexpected: {:?}", other),
        }
    }

    /// 进程退出 = 它的 (pid, fd) 记录全部作废。表只增不减就是内存泄漏，
    /// 而 pid 复用还会让新进程的 sendto 认错对端。
    #[test]
    fn exit_evicts_that_pids_peer_entries() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        feed(&mut p, "CONN|1000|1234|1234|1|5|7|2|1111|0|10.0.0.1");
        feed(&mut p, "CONN|1000|9999|9999|1|5|7|2|2222|0|10.0.0.2");
        assert_eq!(p.fd_peer.len(), 2);
        // EXIT|<nsecs>|<pid>|<ppid>|<cgroup>|<exit_code>|<comm>
        let evs = feed(&mut p, "EXIT|2000|1234|1|5|0|curl");
        assert!(evs.iter().any(|e| e.kind == Kind::RuntimeProcExit));
        assert_eq!(p.fd_peer.len(), 1, "退出进程的记录必须回收，别人的要留下");
        // 退出之后这个 pid 的 sendto 不该再归因到它生前的对端。
        let evs = feed(&mut p, "SEND|3000|1234|1234|1|5|7|1");
        let send = evs.iter().find(|e| e.kind == Kind::InfraNetSendto).unwrap();
        match &send.payload {
            crate::event::Payload::NetSendto { peer, .. } => assert_eq!(peer, &None),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn fd_reuse_takes_most_recent_connect() {
        let mut p = KernelLineParser::with_redact(4096, crate::redact::RedactMode::Argv);
        feed(&mut p, "CONN|1000|1234|1234|1|5|7|2|1111|0|10.0.0.1");
        feed(&mut p, "CONN|1500|1234|1234|1|5|7|2|2222|0|10.0.0.2");
        let evs = feed(&mut p, "SEND|2000|1234|1234|1|5|7|1");
        let send = evs.iter().find(|e| e.kind == Kind::InfraNetSendto).unwrap();
        match &send.payload {
            crate::event::Payload::NetSendto { peer, .. } => {
                assert_eq!(peer.as_deref(), Some("10.0.0.2:2222"))
            }
            other => panic!("unexpected: {:?}", other),
        }
    }
}

#[cfg(test)]
mod redact_tests {
    use super::*;

    /// 喂一条 `EXEC` + 若干 `ARGV`，再用下一条 `EXEC` 把前面那条挤出去（flush_pending
    /// 是在处理新 EXEC 时对**上一个** EXEC 做的）。返回那条 proc.exec 的 argv。
    ///
    /// 行格式严格照 `.bt` 脚本：`EXEC|<nsecs>|<pid>|<tid>|<ppid>|<cgroup>|<slots>|<comm>|<filename>`
    /// 与 `ARGV|<nsecs>|<pid>|<tid>|<idx>|<value>`。字段数写错会被当成 malformed 静默丢掉，
    /// 测试就会以"没解析出事件"失败 —— 这正是我要的：协议不匹配必须炸出来。
    fn feed(mode: RedactMode, argv: &[&str]) -> Vec<String> {
        let mut p = KernelLineParser::with_redact(4096, mode);
        let mut out = Vec::new();
        let slots = argv.len();
        p.feed_line(
            &format!("EXEC|1000|4242|4242|1|0|{}|curl|/usr/bin/curl", slots),
            &mut out,
        );
        for (i, v) in argv.iter().enumerate() {
            p.feed_line(&format!("ARGV|1000|4242|4242|{}|{}", i, v), &mut out);
        }
        // 第二条 EXEC 触发上一条的 flush。
        p.feed_line("EXEC|2000|4243|4243|1|0|1|bash|/usr/bin/bash", &mut out);
        out.into_iter()
            .find_map(|e| match e.payload {
                Payload::ProcExec { argv, .. } if e.pid == Some(4242) => Some(argv),
                _ => None,
            })
            .expect("没有解析出 pid 4242 的 proc.exec")
    }

    /// **默认行为**：`--redact argv` 下内核 argv 必须被打码。
    /// 这条测试盯的是"argv/命令默认打码"这条铁律有没有真的接上线 ——
    /// `redact_argv` 曾经写好了却没有任何调用点，密钥会原样流进时间线。
    #[test]
    fn kernel_argv_is_redacted_by_default() {
        let argv = feed(
            RedactMode::Argv,
            &["curl", "-H", "Authorization: Bearer sk-live-9f2b7c1d4e6a8b0c2d4f"],
        );
        let joined = argv.join(" ");
        assert!(
            !joined.contains("sk-live-9f2b7c1d4e6a8b0c2d4f"),
            "默认打码下 token 不得出现在时间线里: {:?}",
            argv
        );
        assert!(joined.contains("***"), "应当留下打码痕迹: {:?}", argv);
        // 非敏感部分保留 —— 打码不是把整行抹掉，否则工具就没用了。
        assert_eq!(argv[0], "curl");
        assert_eq!(argv[1], "-H");
    }

    /// `--redact off` 必须真的不打码（用户显式关掉时，工具不该自作主张）。
    #[test]
    fn redact_off_keeps_argv_verbatim() {
        let argv = feed(
            RedactMode::Off,
            &["curl", "-H", "Authorization: Bearer sk-live-9f2b7c1d4e6a8b0c2d4f"],
        );
        assert!(argv.join(" ").contains("sk-live-9f2b7c1d4e6a8b0c2d4f"), "{:?}", argv);
    }

    /// 打码必须留痕（§4.3：不静默 —— 包括不静默地抹掉）。用户要能分辨
    /// "这真的是 `***`" 和 "这里被我们改过"。
    #[test]
    fn redaction_leaves_a_trace() {
        let mut p = KernelLineParser::with_redact(4096, RedactMode::Argv);
        let mut out = Vec::new();
        // 4 个槽位、第 4 个为空 → argv 是 NULL 结尾的正常情况，不产生截断说明。
        // 这样这条测试就只考察"打码"，不会和 trunc 混在一起。
        p.feed_line("EXEC|1000|4242|4242|1|0|4|curl|/usr/bin/curl", &mut out);
        p.feed_line("ARGV|1000|4242|4242|0|curl", &mut out);
        p.feed_line("ARGV|1000|4242|4242|1|--token", &mut out);
        p.feed_line("ARGV|1000|4242|4242|2|hunter2hunter2hunter2", &mut out);
        p.feed_line("ARGV|1000|4242|4242|3|", &mut out);
        p.feed_line("EXEC|2000|4243|4243|1|0|1|bash|/usr/bin/bash", &mut out);
        let ev = out
            .iter()
            .find(|e| e.pid == Some(4242) && e.kind == Kind::RuntimeProcExec)
            .expect("没有解析出 proc.exec");
        assert!(
            ev.notes.iter().any(|n| n.contains("masked")),
            "打码必须留痕（且不能写进 trunc，否则这一行会被误标 `~`）: {:?} / {:?}",
            ev.notes,
            ev.trunc
        );
        assert!(ev.trunc.is_empty(), "打码没有截断任何内容，不得写进 trunc");
        assert_eq!(p.redacted_events, 1, "打码计数应当被记下");
    }
}
