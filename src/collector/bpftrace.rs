//! bpftrace 采集器：spawn + 行协议解析 + 丢包检测（DESIGN.md §2.2 / §2.5）。
//!
//! 两条**必须遵守的操作约束**（§5.5 #6，都是实测踩到的）：
//!  1. `-B none`（否则输出被块缓冲，看起来像卡住）。
//!  2. Rust 必须**直接**持有 bpftrace 的 stdout 句柄逐行读 —— 中间不能夹
//!     `grep`/`head`，否则 grep 的块缓冲会让输出长时间不出现。
//!
//! 非阻塞读取用 `fcntl(O_NONBLOCK)` + `libc::read`，不引入 tokio（§3.1 铁律）。

use super::{Collector, CollectorError, KernelLineParser, LineBuffer};
use crate::event::{Binding, Corr, Event, Kind, Layer, Payload, TsSource};
use crate::poll::PollOutcome;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::{Child, Command, Stdio};

/// 单个内核字符串实际能带回来的字节数（**实测值，不是期望值**）。
///
/// v0.3 曾把这个常量写成 200，并指望 `BPFTRACE_MAX_STRLEN` 环境变量生效 ——
/// v0.3.1 实测证明**它从来没生效过**，真实上限一直是 bpftrace 的默认 64：
///
///   * 坑 #9：`str(ptr, N)` 的 N 参数不能超过 `BPFTRACE_MAX_STRLEN`，加长只能靠环境变量；
///   * 坑 #12：`sudo` 默认 `env_reset`，`Command::env("BPFTRACE_MAX_STRLEN", ...)`
///     根本送不到 bpftrace（`sudo` 会清掉它）。
///   * 而且**送不进去反而是好事**：打印探针里 `--argv-max 8` × 每个字符串
///     ≤512 字节 BPF 栈 ⇒ 8 × 64 = 512 正好顶到上限。把 200 真送进去会被
///     verifier 拒掉：`Looks like the BPF stack limit is exceeded.`
///
/// 所以这里如实写 64：`str_limit` 只会用于**判定截断**，写大了会让 `-v` 的
/// `kept N bytes` 变成一句三倍大的假话。改成 64 后行为逐字节不变（内核本来就在 64 处切），
/// 只是截断说明终于说了实话。
pub const MAX_STRLEN: usize = 64;

/// 采集器的运行模式。
#[derive(Debug, Clone)]
pub enum Target {
    /// `-p/--pid`：跟踪该 pid 及其后代（等价 `strace -f`）。
    PidTree { root: u32, seeds: Vec<u32> },
    /// `-C/--cgroup`：跟踪该 cgroup 下所有进程。最干净（无需共享状态）。
    Cgroup { path: String, id: u64 },
}

pub struct BpftraceCollector {
    child: Child,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    parser: KernelLineParser,
    out_buf: LineBuffer,
    err_buf: LineBuffer,
    /// 从 bpftrace stderr 里抓到的丢包计数（§2.5：`lost_events` / "Lost N events"）。
    lost: u64,
    /// 丢包计数是否已经作为事件上报过（避免重复刷屏）。
    lost_reported: u64,
    eof: bool,
    child_exited: Option<i32>,
    /// 保留展开后的脚本，`-v` 时可打印用于排错。
    pub rendered_script: String,
    pub script_path: Option<std::path::PathBuf>,
    /// `--keep-script`：调试采集问题时保留生成的脚本（否则退出时删除）。
    pub keep_script: bool,
    /// stderr 的原始累积（截断保存），`-v` 时展示。
    pub stderr_tail: Vec<String>,
}

impl BpftraceCollector {
    /// 展开模板并启动 bpftrace。
    ///
    /// `argv_max` 直接决定脚本里 argv 的展开行数（§5.2 #3：提高上限需改脚本）。
    pub fn spawn(
        template: &str,
        target: &Target,
        argv_max: usize,
        file_all: bool,
        sources: &SourceFilter,
        redact: crate::redact::RedactMode,
        keep_script: Option<std::path::PathBuf>,
    ) -> Result<Self, CollectorError> {
        let script = render_script(template, target, argv_max, file_all, sources);

        // 用临时文件而不是 `-e`：报错时能给出有意义的行号，且便于 `-v` 复现。
        let path =
            keep_script.unwrap_or_else(|| std::env::temp_dir().join(format!("agtrace-{}.bt", std::process::id())));
        std::fs::write(&path, &script)
            .map_err(|e| CollectorError::Spawn(format!("failed to write temp script {}: {}", path.display(), e)))?;

        // sudo -n：非交互。本机 passwordless sudo 已确认；若没有会立刻失败而不是挂住。
        //
        // 坑 #12（v0.3.1 实测）：`sudo` 默认 `env_reset`，所以下面这行 `.env(...)`
        // **到不了 bpftrace** —— 内核侧 str() 退回 bpftrace 默认的 64 字节。
        // 试图用 `sudo /usr/bin/env BPFTRACE_MAX_STRLEN=… bpftrace` 绕过是**错的方向**：
        // 打印探针挂着 8 个 `%s`，8 × 200 远超 512 字节 BPF 栈，verifier 直接拒绝
        // （`Looks like the BPF stack limit is exceeded.`）。64 恰好是 512/8。
        // 保留这行不是指望它生效，而是：一旦哪天 target 不再是 sudo，它就该生效。
        let mut cmd = Command::new("sudo");
        cmd.arg("-n")
            .arg("bpftrace")
            .arg("-q") // 抑制 "Attaching N probes..."（map dump 由 END{clear()} 处理）
            .arg("-B")
            .arg("none") // 坑 #6
            .arg(&path)
            .env("BPFTRACE_MAX_STRLEN", MAX_STRLEN.to_string()) // 坑 #9/#12：经 sudo 时到不了，见上
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // 让 bpftrace 自成进程组。**这一步很重要**：`sudo` 在有些配置下会 fork 出
        // 真正的 bpftrace，只 kill sudo 的 pid 会留下一个 **root 权限的 bpftrace
        // 孤儿进程**继续挂着 kprobe 跑。按进程组杀才干净。
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        let child = cmd.spawn().map_err(|e| {
            CollectorError::Spawn(format!(
                "cannot start `sudo -n bpftrace` (needs bpftrace + passwordless sudo): {}",
                e
            ))
        })?;

        let stdout_fd = child.stdout.as_ref().unwrap().as_raw_fd();
        let stderr_fd = child.stderr.as_ref().unwrap().as_raw_fd();
        set_nonblocking(stdout_fd).map_err(|e| CollectorError::Io(e.to_string()))?;
        set_nonblocking(stderr_fd).map_err(|e| CollectorError::Io(e.to_string()))?;

        Ok(BpftraceCollector {
            child,
            stdout_fd,
            stderr_fd,
            parser: KernelLineParser::with_redact(MAX_STRLEN, redact),
            out_buf: LineBuffer::new(),
            err_buf: LineBuffer::new(),
            lost: 0,
            lost_reported: 0,
            eof: false,
            child_exited: None,
            rendered_script: script,
            script_path: Some(path),
            keep_script: false,
            stderr_tail: Vec::new(),
        })
    }

    /// bpftrace 是否已经退出（用于判断"采集结束"）。
    pub fn exited(&self) -> bool {
        self.child_exited.is_some()
    }

    /// 有多少个 exec 事件的 argv 因 `--redact` 被改动过。
    /// 这个数必须是可观测的：默认打码是设计决策，用户有权确认它真的生效了。
    pub fn redacted_events(&self) -> u64 {
        self.parser.redacted_events
    }

    pub fn parse_stats(&self) -> &super::ParseStats {
        &self.parser.stats
    }

    /// 缓冲区里还剩多少字节没凑成完整的一行。
    ///
    /// 采集结束时这个值 > 0 意味着**最后一行被截断了**（bpftrace 被 SIGTERM 打断）。
    /// 那一行不会被解析成事件，所以必须显式告诉用户 —— 否则就是静默丢失（§4.3）。
    pub fn unfinished_line_bytes(&self) -> usize {
        self.out_buf.pending_bytes()
    }

    /// 读取 stderr 并从中提取丢包信号。
    ///
    /// §5.4 #2：`lost_events` 信封的**具体字段结构未验证**（无法可靠触发 perf buffer
    /// 溢出 —— 本次实现又试了一次，`BPFTRACE_PERF_RB_PAGES=1` + 1000+ 事件仍未触发）。
    /// 所以这里做**双路防御**：既认 bpftrace 的 stderr 文本，也认 JSON 信封
    /// （`{"type":"lost_events", ...}` 里的任意数字字段）。哪条路来了都能报出来，
    /// 报不出也不会假装没有 —— 见 BUILD_LOG.md 的诚实说明。
    fn drain_stderr(&mut self) {
        let mut buf = [0u8; 8192];
        loop {
            let n = unsafe { libc::read(self.stderr_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            for line in self.err_buf.push(&buf[..n as usize]) {
                if let Some(c) = parse_lost(&line) {
                    self.lost += c;
                }
                if self.stderr_tail.len() < 64 {
                    self.stderr_tail.push(line);
                }
            }
        }
    }
}

impl Collector for BpftraceCollector {
    fn id(&self) -> &'static str {
        "bpftrace"
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, CollectorError> {
        let mut progress = false;

        // --- stdout：内核事件 ---
        let mut buf = [0u8; 32768];
        loop {
            let n = unsafe { libc::read(self.stdout_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                progress = true;
                for line in self.out_buf.push(&buf[..n as usize]) {
                    self.parser.feed_line(&line, out);
                }
                continue;
            }
            if n == 0 {
                // EOF：bpftrace 退出了。把残留的半行也吐出去（可能被 SIGTERM 截断）。
                self.eof = true;
                if let Some(rest) = self.out_buf.take_remainder() {
                    // 半行**不当作完整事件解析**（§2.4）——只计数。
                    self.parser.stats.lines_malformed += 1;
                    let _ = rest;
                }
                break;
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => break,
                _ => break,
            }
        }

        self.drain_stderr();

        // --- 丢包：必须可见，绝不静默（§4.3）---
        if self.lost > self.lost_reported {
            let delta = self.lost - self.lost_reported;
            self.lost_reported = self.lost;
            out.push(Event {
                seq: 0,
                ts_ns: 0,
                ts_wall_ns: 0,
                ts_src: TsSource::Kernel,
                layer: Layer::Derived,
                kind: Kind::CollectorLostEvents,
                source: "bpftrace".into(),
                pid: None,
                tid: None,
                ppid: None,
                comm: None,
                cgroup_id: None,
                corr: Corr::default(),
                payload: Payload::LostEvents { count: delta },
                trunc: Vec::new(),
                notes: Vec::new(),
                late: false,
                watch: true,
                binding: Binding::None,
                retry: false,
            });
            progress = true;
        }

        // --- 子进程状态 ---
        if self.child_exited.is_none() {
            match self.child.try_wait() {
                Ok(Some(st)) => {
                    self.child_exited = Some(st.code().unwrap_or(-1));
                    // 退出前把解析器里悬空的东西吐出来。
                    self.parser.finish(out);
                    progress = true;
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }

        if progress {
            Ok(PollOutcome::Progress)
        } else if self.eof && self.child_exited.is_some() {
            Ok(PollOutcome::Eof)
        } else {
            Ok(PollOutcome::Idle)
        }
    }

    fn shutdown(&mut self) {
        // 先礼后兵：SIGTERM 整个进程组（负 pid），让 bpftrace 有机会跑 END{} 并
        // detach kprobe；等不到就 SIGKILL。
        let pid = self.child.id() as i32;
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
            libc::kill(pid, libc::SIGTERM);
        }
        for _ in 0..50 {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn lost_events(&self) -> u64 {
        self.lost
    }
}

impl Drop for BpftraceCollector {
    fn drop(&mut self) {
        if self.child_exited.is_none() {
            self.shutdown();
        }
        // 临时脚本不留垃圾；`--keep-script` 时保留，方便 `sudo bpftrace <file>` 手工复现。
        if self.keep_script {
            if let Some(p) = &self.script_path {
                eprintln!("agtrace: kept script {}", p.display());
            }
        } else if let Some(p) = &self.script_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// 从一行 stderr 里提取丢包数。认两种形态：
/// - bpftrace 的文本警告：`Lost 142 events`
/// - JSON 信封：`{"type": "lost_events", "data": {"lost": 142}}`（`[不确定]`，见 §5.4 #2）
fn parse_lost(line: &str) -> Option<u64> {
    let l = line.to_ascii_lowercase();
    if let Some(pos) = l.find("lost") {
        // 取 "lost" 之后第一个连续数字。
        let rest = &line[pos..];
        let mut num = String::new();
        let mut started = false;
        for c in rest.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                started = true;
            } else if started {
                break;
            }
        }
        if let Ok(v) = num.parse::<u64>() {
            return Some(v);
        }
    }
    None
}

/// `--source` 过滤（§4.1：逗号分隔 exec,file,net,agent）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFilter {
    pub exec: bool,
    pub file: bool,
    pub net: bool,
    pub agent: bool,
}

impl Default for SourceFilter {
    fn default() -> Self {
        SourceFilter {
            exec: true,
            file: true,
            net: true,
            agent: true,
        }
    }
}

impl SourceFilter {
    /// 全部打开 —— `--source` 未指定时的默认。
    pub fn all() -> Self {
        SourceFilter::default()
    }

    pub fn any_kernel(&self) -> bool {
        self.exec || self.file || self.net
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let mut f = SourceFilter {
            exec: false,
            file: false,
            net: false,
            agent: false,
        };
        for part in s.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            match p {
                "exec" => f.exec = true,
                "file" => f.file = true,
                "net" => f.net = true,
                "agent" => f.agent = true,
                other => {
                    return Err(format!(
                        "unknown --source value `{}` (available: exec,file,net,agent)",
                        other
                    ));
                }
            }
        }
        if !f.any_kernel() && !f.agent {
            return Err("--source must contain at least one value".into());
        }
        Ok(f)
    }

    /// 该 kind 是否被 --source 允许输出（Rust 侧的兜底过滤，双保险）。
    pub fn allows(&self, k: Kind) -> bool {
        match k {
            Kind::RuntimeProcFork | Kind::RuntimeProcExec | Kind::RuntimeProcExecFail | Kind::RuntimeProcExit => {
                self.exec
            }
            Kind::InfraFileOpen => self.file,
            Kind::InfraNetConnect | Kind::InfraNetSendto => self.net,
            _ => true,
        }
    }
}

/// 把模板展开成可直接交给 bpftrace 的脚本。
pub fn render_script(
    template: &str,
    target: &Target,
    argv_max: usize,
    file_all: bool,
    sources: &SourceFilter,
) -> String {
    let argv_max = argv_max.max(1);

    // --- 种子 / 过滤器 ---
    let (seeds, filter) = match target {
        Target::PidTree { seeds, .. } => {
            let mut s = String::new();
            for p in seeds {
                s.push_str(&format!("    @in_tree[{}] = 1;\n", p));
            }
            if seeds.is_empty() {
                // 理论上不会发生（root 自己至少是一个种子），但绝不生成非法脚本。
                s.push_str("    // (no seeds)\n");
            }
            (s, "@in_tree[pid]".to_string())
        }
        Target::Cgroup { id, .. } => {
            // cgroup 模式无需任何共享状态，最干净（§2.3）。
            (String::new(), format!("cgroup == {}", id))
        }
    };

    // --- argv 展开（坑 #3：unroll 无下标，必须写死常量下标）---
    let mut capture = String::new();
    let mut print = String::new();
    let mut del = String::new();
    for i in 0..argv_max {
        capture.push_str(&format!("    @argv_{}[tid] = str($a[{}], {});\n", i, i, MAX_STRLEN));
        print.push_str(&format!(
            "    printf(\"ARGV|%llu|%d|%d|%d|%s\\n\", nsecs, pid, tid, {}, @argv_{}[tid]);\n",
            i, i
        ));
        del.push_str(&format!("    delete(@argv_{}[tid]);\n", i));
    }

    // --- openat 写意图过滤（§2.2：不过滤会被 openat 淹没）---
    // O_WRONLY=1 O_RDWR=2 O_CREAT=0x40 O_TRUNC=0x200 O_APPEND=0x400
    let file_pred = if file_all {
        "1".to_string()
    } else {
        "(args->flags & 1) || (args->flags & 2) || (args->flags & 0x40) || (args->flags & 0x200) || (args->flags & 0x400)".to_string()
    };

    let tpl = template
        .replacen("@@SEEDS@@", &seeds.trim_end_matches('\n'), 1)
        .replace("@@FILTER@@", &filter)
        .replace("@@ARGV_CAPTURE@@", capture.trim_end_matches('\n'))
        .replace("@@ARGV_PRINT@@", print.trim_end_matches('\n'))
        .replace("@@ARGV_DELETE@@", del.trim_end_matches('\n'))
        .replace("@@ARGV_SLOTS@@", &argv_max.to_string())
        .replace("@@SRC_EXEC@@", if sources.exec { "1" } else { "0" })
        .replace("@@SRC_FILE@@", if sources.file { "1" } else { "0" })
        .replace("@@SRC_NET@@", if sources.net { "1" } else { "0" })
        .replace("@@FILE_PRED@@", &file_pred);
    // 展开后的脚本自带横幅：`--keep-script` 留下的文件必须能自我说明是怎么来的，
    // 否则几天后在 /tmp 里捡到一个 .bt 根本不知道它是什么参数生成的。
    let target_desc = match target {
        Target::PidTree { root, seeds } => format!("pid-tree root={} seeds={}", root, seeds.len()),
        Target::Cgroup { path, id } => format!("cgroup {} (id {})", path, id),
    };
    format!(
        "// === expanded by agtrace from scripts/agtrace.bt ===\n\
         // target={} argv_max={} file_all={} sources(exec={} file={} net={})\n\
         // reproduce: sudo bpftrace -q -B none <this file>\n\
         // note: this file may contain the target pid/cgroup; clean it up as needed.\n{}",
        target_desc, argv_max, file_all, sources.exec as u8, sources.file as u8, sources.net as u8, tpl
    )
}

/// 扫描 `/proc` 找到 `root` 的所有现存后代 —— 用于 `-p` 模式的种子集合。
///
/// §2.3：attach 前已 fork 的子进程如果不预扫就会漏掉。
/// `[近似]` 仍有 attach 前的竞态窗口，诚实地记在 §5.2 #5。
pub fn scan_descendants(root: u32) -> Vec<u32> {
    let mut children: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return vec![root];
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        // /proc/<pid>/stat 的格式：pid (comm) state ppid ...
        // comm 可能含括号和空格 → 从**最后一个** ')' 之后再切。
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) else {
            continue;
        };
        let Some(close) = stat.rfind(')') else {
            continue;
        };
        let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
        if rest.len() < 2 {
            continue;
        }
        let Ok(ppid) = rest[1].parse::<u32>() else {
            continue;
        };
        children.entry(ppid).or_default().push(pid);
    }

    let mut out = vec![root];
    let mut stack = vec![root];
    while let Some(p) = stack.pop() {
        if let Some(kids) = children.get(&p) {
            for k in kids {
                if !out.contains(k) {
                    out.push(*k);
                    stack.push(*k);
                }
            }
        }
    }
    out
}

/// cgroup 路径 → bpftrace `cgroup` 内建值（§5.4 #6 已验证的换算方法）。
///
/// `name_to_handle_at(AT_FDCWD, <cgroup_path>, ...)` 返回的 kernfs handle
/// **前 8 字节按小端解释**就等于 bpftrace 的 `cgroup` 值（根 cgroup 两者都是 1）。
pub fn cgroup_path_to_id(path: &str) -> Result<u64, String> {
    use std::ffi::CString;
    let c = CString::new(path).map_err(|_| "cgroup path contains NUL".to_string())?;
    // struct file_handle 是变长结构：前 4 字节 handle_bytes，第 5 字节是句柄本体。
    let mut buf = vec![0u8; 8 + 64];
    let mut mount_id: libc::c_int = 0;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD,
            c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut mount_id as *mut libc::c_int,
            0,
        )
    };
    if rc != 0 {
        return Err(format!(
            "name_to_handle_at({}) failed: {}",
            path,
            io::Error::last_os_error()
        ));
    }
    let handle_bytes = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if handle_bytes < 8 {
        return Err(format!(
            "kernfs handle for cgroup {} is only {} bytes",
            path, handle_bytes
        ));
    }
    let h = &buf[8..16];
    let id = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_renders_without_placeholders() {
        let tpl = include_str!("../../scripts/agtrace.bt");
        let t = Target::PidTree {
            root: 42,
            seeds: vec![42, 43],
        };
        let s = render_script(tpl, &t, 8, false, &SourceFilter::default());
        assert!(!s.contains("@@"), "模板占位符没有全部展开:\n{}", s);
        assert!(s.contains("@in_tree[42] = 1;"));
        assert!(s.contains("@in_tree[43] = 1;"));
        assert!(s.contains("@argv_7[tid]"));
        assert!(s.contains("@in_tree[pid]"));
    }

    #[test]
    fn cgroup_mode_uses_cgroup_filter() {
        let tpl = include_str!("../../scripts/agtrace.bt");
        let t = Target::Cgroup {
            path: "/x".into(),
            id: 1234,
        };
        let s = render_script(tpl, &t, 2, true, &SourceFilter::default());
        assert!(s.contains("cgroup == 1234"));
        assert!(!s.contains("@@"));
        // --file-all 时谓词退化成 1
        assert!(s.contains("&& (1)"));
    }

    #[test]
    fn source_filter_parsing() {
        let f = SourceFilter::parse("exec,net").unwrap();
        assert!(f.exec && f.net && !f.file && !f.agent);
        assert!(SourceFilter::parse("bogus").is_err());
        assert!(SourceFilter::parse("").is_err());
    }

    #[test]
    fn lost_line_parsing() {
        assert_eq!(parse_lost("Lost 142 events"), Some(142));
        assert_eq!(parse_lost("{\"type\": \"lost_events\", \"lost\": 7}"), Some(7));
        assert_eq!(parse_lost("nothing here"), None);
    }
}
