//! bpftrace 采集器：spawn + 行协议解析 + 丢包检测（DESIGN.md §2.2 / §2.5）。
//!
//! 两条**必须遵守的操作约束**（§5.5 #6，都是实测踩到的）：
//!  1. `-B none`（否则输出被块缓冲，看起来像卡住）。
//!  2. Rust 必须**直接**持有 bpftrace 的 stdout 句柄逐行读 —— 中间不能夹
//!     `grep`/`head`，否则 grep 的块缓冲会让输出长时间不出现。
//!
//! 非阻塞读取用 `fcntl(O_NONBLOCK)` + `libc::read`，不引入 tokio（§3.1 铁律）。
//!
//! v0.5：子进程的读写/收尾逻辑搬到 [`super::child::LineChild`]，与 aya 采集器共用。
//! 这个文件现在只剩 bpftrace 特有的部分：脚本渲染、丢包文本解析的调用方，以及
//! 临时脚本的生命周期。

use super::child::LineChild;
use super::{Collector, CollectorError, KernelLineParser};
use crate::event::{Event, Kind};
use crate::poll::PollOutcome;
use std::io;
use std::process::Command;

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

/// Probe whether bpftrace can actually be run, before committing to it.
///
/// Asking for a collector whose binary is missing used to produce a *silently*
/// empty timeline: `Command::new("sudo")` starts fine, `sudo` then fails to find
/// the program, and the child is gone before anything explains why. The run
/// looked like "the target did nothing" — the one failure mode this tool exists
/// to make impossible. `--version` is enough to tell the two apart, costs a few
/// tens of milliseconds against a collector that takes seconds to attach, and
/// exercises the exact `sudo -n bpftrace` path the real spawn uses (so a sudo
/// policy problem is reported as such rather than as a missing binary).
pub fn precheck() -> Result<(), String> {
    let mut cmd = Command::new("sudo");
    // 同 [`spawn`]：探针也是一次特权 spawn，用户的密钥没理由跟着进去。
    // `PATH` 在白名单里，所以按名字找 `sudo` 这件事不受影响。
    super::child::scrub_env(&mut cmd);
    let out = cmd
        .args(["-n", "bpftrace", "--version"])
        .output()
        .map_err(|e| format!("could not run `sudo -n bpftrace --version`: {}", e))?;
    if out.status.success() {
        return Ok(());
    }
    Err(probe_failure(
        out.status.code(),
        &String::from_utf8_lossy(&out.stderr),
    ))
}

/// Turn a failed probe into a reason that never comes back empty.
///
/// Split out from [`precheck`] because a probe can only be *executed* against a
/// real system, while the thing worth testing is that "failed with no output at
/// all" still yields a sentence the user can act on — an unexplained fallback is
/// the failure this whole path exists to avoid.
pub fn probe_failure(code: Option<i32>, stderr: &str) -> String {
    match stderr.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(l) => l.to_string(),
        None => format!(
            "`sudo -n bpftrace --version` exited with status {:?} and said nothing",
            code
        ),
    }
}

pub struct BpftraceCollector {
    child: LineChild,
    parser: KernelLineParser,
    /// 保留展开后的脚本，`-v` 时可打印用于排错。
    pub rendered_script: String,
    pub script_path: Option<std::path::PathBuf>,
    /// `--keep-script`：调试采集问题时保留生成的脚本（否则退出时删除）。
    pub keep_script: bool,
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
        // 先清环境再设变量：用户的 token 不进特权子进程，而下面的
        // `BPFTRACE_MAX_STRLEN` 照设不误（见 child::scrub_env）。
        super::child::scrub_env(&mut cmd);
        cmd.arg("-n")
            .arg("bpftrace")
            .arg("-q") // 抑制 "Attaching N probes..."（map dump 由 END{clear()} 处理）
            .arg("-B")
            .arg("none") // 坑 #6
            .arg(&path)
            .env("BPFTRACE_MAX_STRLEN", MAX_STRLEN.to_string()); // 坑 #9/#12：经 sudo 时到不了，见上

        // 进程组 / 管道 / 非阻塞读取都由 LineChild 统一处理（见 child.rs）。
        let child = LineChild::spawn(cmd, "bpftrace", "sudo -n bpftrace")?;

        Ok(BpftraceCollector {
            child,
            parser: {
                let mut p = KernelLineParser::with_redact(MAX_STRLEN, redact);
                p.set_file_all(file_all);
                p
            },
            rendered_script: script,
            script_path: Some(path),
            keep_script: false,
        })
    }

    /// bpftrace 是否已经退出（用于判断"采集结束"）。
    pub fn exited(&self) -> bool {
        self.child.exited()
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.child.exit_code()
    }

    /// 有多少个 exec 事件的 argv 因 `--redact` 被改动过。
    /// 这个数必须是可观测的：默认打码是设计决策，用户有权确认它真的生效了。
    pub fn redacted_events(&self) -> u64 {
        self.parser.redacted_events
    }

    pub fn parse_stats(&self) -> &super::ParseStats {
        &self.parser.stats
    }

    /// stderr 原始行（截断保存），`-v` 时展示。
    pub fn stderr_tail(&self) -> &[String] {
        &self.child.stderr_tail
    }

    /// 缓冲区里还剩多少字节没凑成完整的一行。
    ///
    /// 采集结束时这个值 > 0 意味着**最后一行被截断了**（bpftrace 被 SIGTERM 打断）。
    /// 那一行不会被解析成事件，所以必须显式告诉用户 —— 否则就是静默丢失（§4.3）。
    pub fn unfinished_line_bytes(&self) -> usize {
        self.child.unfinished_line_bytes()
    }
}

impl Collector for BpftraceCollector {
    fn id(&self) -> &'static str {
        "bpftrace"
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, CollectorError> {
        self.child.poll_lines(&mut self.parser, out)
    }

    fn shutdown(&mut self) {
        self.child.shutdown();
    }

    fn lost_events(&self) -> u64 {
        self.child.lost_events()
    }
}

impl Drop for BpftraceCollector {
    fn drop(&mut self) {
        // 临时脚本不留垃圾；`--keep-script` 时保留，方便 `sudo bpftrace <file>` 手工复现。
        // 子进程的收尾由 `LineChild` 自己的 `Drop` 负责。
        if self.keep_script {
            if let Some(p) = &self.script_path {
                eprintln!("agtrace: kept script {}", p.display());
            }
        } else if let Some(p) = &self.script_path {
            let _ = std::fs::remove_file(p);
        }
    }
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
    ///
    /// 这里必须把 **agent 层**也显式映射到 `--source agent`：`_ => true` 曾把每个
    /// agent kind 都当成"总是允许"，于是 `--source exec` 的运行仍然打印模型/工具行
    /// （而表头只列 exec）。派生行只描述已经放行的事件，采集器自身的丢包/结束行
    /// 无论选择哪些源都必须可见（§4.3 不静默），它们保持 true。
    pub fn allows(&self, k: Kind) -> bool {
        match k {
            Kind::RuntimeProcFork | Kind::RuntimeProcExec | Kind::RuntimeProcExecFail | Kind::RuntimeProcExit => {
                self.exec
            }
            Kind::InfraFileOpen => self.file,
            Kind::InfraNetConnect | Kind::InfraNetSendto => self.net,
            Kind::AgentPrompt
            | Kind::AgentPromptQueued
            | Kind::AgentModelRequest
            | Kind::AgentModelThinking
            | Kind::AgentModelText
            | Kind::AgentModelUsage
            | Kind::AgentToolCall
            | Kind::AgentToolResult
            | Kind::AgentSandboxDisabled
            | Kind::PolicyDenyAgent => self.agent,
            // Loss/end rows the collector itself produces: always visible.
            Kind::CollectorLostEvents => true,
            // Derived rows are summaries/claims about events that already passed the
            // filter above; they are not a source of their own.
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
    // v0.4.2：内核侧默认放行全部 open，写意图/敏感路径的过滤移到 Rust 侧
    // （KernelLineParser::handle_open）—— bpftrace 里做字符串匹配不现实。
    // --file-all 的语义不变：Rust 侧不过滤。
    let file_pred = "1".to_string();

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
///
/// 这也正是 eBPF 侧 `bpf_get_current_cgroup_id()` 的返回值（`cgrp->kn->id`），
/// 两条路径算出来的 id 因此可以直接比对。
pub fn cgroup_path_to_id(path: &str) -> Result<u64, String> {
    use std::ffi::CString;
    let c = CString::new(path).map_err(|_| "cgroup path contains NUL".to_string())?;

    // struct file_handle 是变长结构：`u32 handle_bytes` + `int handle_type` +
    // 句柄本体，本体从第 8 字节开始。
    //
    // `handle_bytes` 是**入参**：调用前必须写明缓冲区装得下多少字节，内核才知道
    // 填不填得下。留 0（`vec![0u8; ..]` 的默认值）时，内核对**任何**路径都返回
    // EOVERFLOW——它把需要的长度写回 handle_bytes 就退出。于是 `-C` 在每台机器、
    // 每个 cgroup 上都直接报 "Value too large for defined data type"，而错误信息
    // 读起来完全像内核的毛病。（这个 bug 在 aya/bpftrace 两条路径上都存在：换算
    // 发生在选 collector 之前，所以两边报的是同一句话。）
    //
    // 句柄长度随文件系统而异（kernfs 8 字节，ext4/xfs 可达 128），所以先给一个
    // 够用的猜测，内核嫌小就按它回报的长度重试一次，而不是写死一个尺寸。
    let mut handle_len = 64usize;
    let mut buf = vec![0u8; 8 + handle_len];
    let mut mount_id: libc::c_int = 0;
    loop {
        buf[..4].copy_from_slice(&(handle_len as u32).to_ne_bytes());
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
        if rc == 0 {
            break;
        }
        let err = io::Error::last_os_error();
        let need = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        // EOVERFLOW 的意思是"缓冲区不够"，需要的长度就在 handle_bytes 里。
        // 上界 4096 只是不给一个荒谬的返回值分配内存；每轮都会严格变大，必然收敛。
        if err.raw_os_error() == Some(libc::EOVERFLOW) && need > handle_len && need <= 4096 {
            handle_len = need;
            buf = vec![0u8; 8 + handle_len];
            continue;
        }
        return Err(format!(
            "name_to_handle_at({}) failed: {}",
            path, err
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
    fn a_failed_probe_always_explains_itself() {
        // The point of `precheck` is that a missing/broken bpftrace is *said out
        // loud* instead of yielding an empty timeline. So the reason must survive
        // the case where the probe printed nothing at all.
        assert_eq!(
            probe_failure(Some(1), "sudo: bpftrace: command not found\n"),
            "sudo: bpftrace: command not found"
        );
        assert_eq!(
            probe_failure(Some(1), "\n\n   sudo: a password is required   \n"),
            "sudo: a password is required",
            "leading blank lines must be skipped, not reported as the reason"
        );
        let silent = probe_failure(Some(127), "");
        assert!(
            silent.contains("127") && silent.contains("said nothing"),
            "a silent probe still has to say something: {}",
            silent
        );
        assert!(!probe_failure(None, "").is_empty());
    }

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

    /// `--source` 是四个维度共用的过滤器；agent 层必须被**显式**映射，否则
    /// `--source exec` 下 agent 行照常出现、而表头只列 exec。
    #[test]
    fn source_filter_covers_the_agent_layer_explicitly() {
        let f = SourceFilter::parse("exec").unwrap();
        assert!(f.allows(Kind::RuntimeProcExec));
        assert!(!f.allows(Kind::InfraFileOpen));
        assert!(!f.allows(Kind::AgentToolCall));
        assert!(!f.allows(Kind::AgentPrompt));
        assert!(!f.allows(Kind::PolicyDenyAgent));
        // 采集器自身的丢包/结束行无论选择哪些源都必须可见（§4.3 不静默）。
        assert!(f.allows(Kind::CollectorLostEvents));

        let a = SourceFilter::parse("agent").unwrap();
        assert!(a.allows(Kind::AgentModelText));
        assert!(!a.allows(Kind::RuntimeProcExec));
        assert!(a.allows(Kind::CollectorLostEvents));
    }

    /// `/sys/fs/cgroup` 是不是**统一的 v2 根**（kernfs，cgroup id 恒为 1）。
    ///
    /// WSL2 的混合 cgroup 布局里 `/sys/fs/cgroup` 是 tmpfs（v2 挂在
    /// `/sys/fs/cgroup/unified`），`name_to_handle_at` 会返回 inode 句柄而不是
    /// kernfs 根 id —— 在那里断言 id==1 是在测文件系统布局，不是在测代码。
    #[cfg(target_os = "linux")]
    fn is_cgroup2_root(path: &str) -> bool {
        let Ok(c) = std::ffi::CString::new(path) else {
            return false;
        };
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // CGROUP2_SUPER_MAGIC = 0x63677270
        let rc = unsafe { libc::statfs(c.as_ptr(), &mut st) };
        rc == 0 && st.f_type == 0x6367_7270
    }

    #[test]
    fn the_root_cgroup_resolves_to_one() {
        // `-C` 的唯一一个不需要预先准备就能问的 cgroup，也正是上面文档里承诺过的
        // 那个值：根 cgroup 在 bpftrace 和 kernfs 里都是 1。
        //
        // 这个断言同时钉住了**协议**：`handle_bytes` 留 0 时内核对任何路径都返回
        // EOVERFLOW，所以一旦回退到那个写法，这个测试在任何机器上都会失败——而
        // 不是只在某台机器的某个 cgroup 上失败，这正是它当初没被发现的原因。
        if !std::path::Path::new("/sys/fs/cgroup").exists() {
            return; // cgroup v1 主机：没有统一层级，跳过
        }
        #[cfg(target_os = "linux")]
        if !is_cgroup2_root("/sys/fs/cgroup") {
            eprintln!(
                "skipping the_root_cgroup_resolves_to_one: /sys/fs/cgroup is not a cgroup2 mount \
                 (WSL hybrid layout) — kernel cgroup ids are not kernfs ids here"
            );
            return;
        }
        match cgroup_path_to_id("/sys/fs/cgroup") {
            Ok(id) => assert_eq!(id, 1),
            // 句柄长度是文件系统的性质，不是所有 fs 都支持 name_to_handle_at；
            // 那种主机上换算本来就不可用，不该算测试失败。
            Err(e) => assert!(
                e.contains("not supported") || e.contains("Operation not permitted"),
                "root cgroup must resolve to 1, got: {}",
                e
            ),
        }
    }

    #[test]
    fn lost_line_parsing() {
        // `parse_lost` 现在住在 child.rs（两个采集器共用），这里保留 bpftrace 侧的
        // 回归断言：这是它当初为 bpftrace 写下的两种形态。
        assert_eq!(super::super::child::parse_lost("Lost 142 events"), Some(142));
        assert_eq!(
            super::super::child::parse_lost("{\"type\": \"lost_events\", \"lost\": 7}"),
            Some(7)
        );
        assert_eq!(super::super::child::parse_lost("nothing here"), None);
    }
}
