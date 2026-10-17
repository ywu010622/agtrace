//! agent 会话 ↔ OS 进程树的绑定（DESIGN.md §3.5）。
//!
//! **这是本工具可信度的底线**：transcript 里没有任何 pid 字段，而"模型决定 vs
//! 系统实际行为"恰恰要求把两者连起来。连不上时唯一正确的做法是**说连不上**，
//! 而不是把启发式当成事实呈现。
//!
//! 三级降级：`Exact` → `Heuristic` → `None`。多候选时**不猜**。

use crate::event::Binding;

#[derive(Debug, Clone)]
pub struct BindingResult {
    pub level: Binding,
    /// 绑定的 pid（如果绑上了）。
    pub pid: Option<u32>,
    /// 所有候选 pid（Heuristic 歧义时 >1）。
    pub candidates: Vec<u32>,
    /// 给人看的解释 —— 直接进启动横幅，让用户当场知道这个绑定有多可信。
    pub explanation: String,
}

impl BindingResult {
    fn none(why: impl Into<String>) -> Self {
        BindingResult {
            level: Binding::None,
            pid: None,
            candidates: Vec::new(),
            explanation: why.into(),
        }
    }
}

/// 一个 /proc 里的候选进程。
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub comm: String,
    pub cmdline: Vec<String>,
    pub cwd: Option<String>,
    pub start_wall_ns: Option<u64>,
    pub ppid: Option<u32>,
}

impl ProcInfo {
    pub fn cmdline_str(&self) -> String {
        self.cmdline.join(" ")
    }
}

/// 读取一个进程的 /proc 信息。任何一项读不到就是 `None`，**不 panic、不猜测**。
pub fn read_proc(pid: u32) -> Option<ProcInfo> {
    let base = format!("/proc/{}", pid);
    let comm = std::fs::read_to_string(format!("{}/comm", base))
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())?;

    let raw = std::fs::read(format!("{}/cmdline", base)).ok()?;
    // cmdline 是 NUL 分隔的；末尾通常有一个 NUL。
    let cmdline: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();

    let cwd = std::fs::read_link(format!("{}/cwd", base))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    let (ppid, start_ticks) = read_stat(pid, &base);
    let start_wall_ns = start_ticks.and_then(ticks_to_wall_ns);

    Some(ProcInfo {
        pid,
        comm,
        cmdline,
        cwd,
        start_wall_ns,
        ppid,
    })
}

/// 从 `/proc/<pid>/stat` 取 ppid 与 starttime。
///
/// 坑：`comm` 字段被括号包着，**里面可能含空格和右括号**，
/// 所以必须从**最后一个 `)`** 之后开始切分，不能按空白朴素 split。
fn read_stat(_pid: u32, base: &str) -> (Option<u32>, Option<u64>) {
    let s = match std::fs::read_to_string(format!("{}/stat", base)) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };
    let close = match s.rfind(')') {
        Some(i) => i,
        None => return (None, None),
    };
    let rest: Vec<&str> = s[close + 1..].split_whitespace().collect();
    // rest[0] = state（字段 3），ppid 是字段 4 → rest[1]，starttime 是字段 22 → rest[19]。
    let ppid = rest.get(1).and_then(|x| x.parse::<u32>().ok());
    let start = rest.get(19).and_then(|x| x.parse::<u64>().ok());
    (ppid, start)
}

/// `/proc/stat` 的 `btime` + starttime(ticks) → 墙钟纳秒。
fn ticks_to_wall_ns(ticks: u64) -> Option<u64> {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = if hz > 0 { hz as u64 } else { 100 };
    // starttime 只有 tick 粒度（通常 10ms）—— 所以启动时间窗比较必须留足余量。
    let start_secs = ticks / hz;
    let start_ns = (ticks % hz) * (1_000_000_000 / hz);
    let btime = boot_time_secs()?;
    Some(btime * 1_000_000_000 + start_secs * 1_000_000_000 + start_ns)
}

/// `/proc/stat` 里的 `btime <epoch 秒>`（开机墙钟时刻）。
fn boot_time_secs() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

/// 列出所有可读的 /proc/<pid>。
pub fn list_procs() -> Vec<u32> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name();
            if let Some(n) = name.to_str()
                && let Ok(p) = n.parse::<u32>()
            {
                v.push(p);
            }
        }
    }
    v.sort_unstable();
    v
}

/// `claude` 进程的识别：comm 是 `claude`，或者 cmdline 里任意一段的 basename 是 `claude`。
///
/// 注意实测：Claude Code 的进程 comm 可能是 `claude`，也可能是 `node`（
/// 取决于安装方式）—— 所以 cmdline 也要看，不能只看 comm。
fn looks_like_claude(p: &ProcInfo) -> bool {
    if p.comm == "claude" {
        return true;
    }
    p.cmdline.iter().any(|a| {
        let base = a.rsplit('/').next().unwrap_or(a);
        base == "claude" || base == "claude-code"
    })
}

/// 从 cmdline 里提取 `--resume <id>` 或 `--resume=<id>`。
fn resume_session_id(cmdline: &[String]) -> Option<String> {
    let mut it = cmdline.iter();
    while let Some(a) = it.next() {
        if (a == "--resume" || a == "-r")
            && let Some(v) = it.next()
        {
            return Some(v.clone());
        }
        if let Some(v) = a.strip_prefix("--resume=") {
            return Some(v.to_string());
        }
    }
    None
}

/// 会话开始时间窗（用于 Heuristic）。transcript 首行时间往前放宽一点，
/// 因为进程一定是在会话开始**之前或同时**启动的。
const START_WINDOW_BEFORE_NS: u64 = 6 * 3600 * 1_000_000_000; // 前 6 小时
const START_WINDOW_AFTER_NS: u64 = 60 * 1_000_000_000; // 后 60 秒

/// 核心：把一个 agent 会话绑定到进程树。
///
/// - `root`：用户用 `-p` 指定的根进程。给了它就以它为准做 Exact 判定。
/// - `session_id`：transcript 的 sessionId。
/// - `cwd`：transcript 记录的 cwd。
/// - `session_start_wall_ns`：transcript 首条事件的时间（墙钟）。
pub fn resolve(
    root: Option<u32>,
    session_id: Option<&str>,
    cwd: Option<&str>,
    session_start_wall_ns: Option<u64>,
) -> BindingResult {
    // ---------- 1. Exact：cmdline 里含 `claude --resume <sessionId>` ----------
    if let Some(sid) = session_id {
        // 先看用户指定的 root，再看全系统 —— 顺序决定了 explanation 的措辞。
        let mut checked: Vec<u32> = Vec::new();
        if let Some(r) = root {
            checked.push(r);
        }
        for p in list_procs() {
            if Some(p) != root {
                checked.push(p);
            }
        }
        for pid in checked {
            let Some(info) = read_proc(pid) else { continue };
            if !looks_like_claude(&info) {
                continue;
            }
            if let Some(rid) = resume_session_id(&info.cmdline)
                && rid == sid
            {
                return BindingResult {
                    level: Binding::Exact,
                    pid: Some(pid),
                    candidates: vec![pid],
                    explanation: format!(
                        "cmdline of pid {} contains `claude --resume {}`, equal to the transcript sessionId",
                        pid, sid
                    ),
                };
            }
        }
    }

    // ---------- 2. Heuristic：cwd + 启动时间窗 + comm ----------
    let mut cands: Vec<(u32, String)> = Vec::new();
    let probes: Vec<u32> = match root {
        Some(r) => {
            // 指定了 -p 时，只在它自己和它的后代里找 —— 别去猜别的进程。
            //
            // `scan_descendants` 的返回值**已经包含 root 本身**（它要给 PidTree 当
            // seeds，root 必须在里面）。曾经这里又 push 了一次 r，于是同一个 pid 在
            // 候选列表里出现两遍，`cands.len() == 2` 触发"歧义不猜" → 明明只有一个
            // 匹配进程，却报 `pid_binding: none`。
            //
            // 这是最坏的一类 bug：它让工具在该确定的时候说"我不确定"。去重是必须的，
            // 因为候选数是**唯一**决定 Exact/Heuristic/None 的输入。
            let mut v = crate::collector::bpftrace::scan_descendants(r);
            if !v.contains(&r) {
                v.push(r);
            }
            v
        }
        None => list_procs(),
    };
    for pid in probes {
        let Some(info) = read_proc(pid) else { continue };
        if !looks_like_claude(&info) {
            continue;
        }
        let mut reasons: Vec<&str> = Vec::new();
        if let (Some(a), Some(b)) = (cwd, info.cwd.as_deref())
            && a == b
        {
            reasons.push("same cwd");
        }
        if let (Some(t0), Some(st)) = (session_start_wall_ns, info.start_wall_ns) {
            // 进程必须在会话开始附近或之前启动。
            if st <= t0 + START_WINDOW_AFTER_NS && t0.saturating_sub(st) <= START_WINDOW_BEFORE_NS {
                reasons.push("start time inside the session window");
            }
        }
        // 至少要有一条独立证据；只看 comm 就绑等于没绑。
        if reasons.is_empty() {
            continue;
        }
        // ppid 一起写进解释里：用户核对时最需要的就是"这个进程是谁的孩子"。
        // 把 pid/ppid/实际 cmdline 一起写进解释：用户要核对的就是这几个东西，
        // 让解释能自证，而不是只说"我觉得是它"。
        let cmd = crate::event::truncate_chars(&crate::event::one_line(&info.cmdline_str()), 120, 120).0;
        let who = match info.ppid {
            Some(pp) => format!("pid {} (ppid {}) `{}`", info.pid, pp, cmd),
            None => format!("pid {} `{}`", info.pid, cmd),
        };
        cands.push((pid, format!("{}: {}", who, reasons.join(" + "))));
    }

    match cands.len() {
        0 => BindingResult::none(match (session_id, cwd) {
            (None, _) => "the transcript has neither sessionId nor cwd, so no process can be bound".to_string(),
            (Some(_), None) => {
                "sessionId equals no `claude --resume` process and the transcript has no cwd for a heuristic match"
                    .to_string()
            }
            (Some(_), Some(_)) => {
                "sessionId matches no `claude --resume` process; no claude process has a matching cwd and a start time inside the session window either"
                    .to_string()
            }
        }),
        1 => BindingResult {
            level: Binding::Heuristic,
            pid: Some(cands[0].0),
            candidates: vec![cands[0].0],
            explanation: format!(
                "NOT cmdline-confirmed (verify yourself): heuristic match on pid {} — {}",
                cands[0].0, cands[0].1
            ),
        },
        // §3.5：多个候选时**不猜**。
        _ => {
            let mut pids: Vec<u32> = cands.iter().map(|(p, _)| *p).collect();
            pids.sort_unstable();
            let detail: Vec<String> = cands.iter().map(|(_, r)| r.clone()).collect();
            BindingResult {
                level: Binding::None,
                pid: None,
                candidates: pids,
                explanation: format!(
                    "ambiguous, not guessed (use -p): {} candidates — {}",
                    cands.len(),
                    detail.join("; ")
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_id_forms() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            resume_session_id(&v(&["claude", "--resume", "ba284a2a-6a00-4bc1"])),
            Some("ba284a2a-6a00-4bc1".into())
        );
        assert_eq!(
            resume_session_id(&v(&["claude", "--resume=ba284a2a"])),
            Some("ba284a2a".into())
        );
        assert_eq!(resume_session_id(&v(&["claude"])), None);
        assert_eq!(resume_session_id(&v(&["claude", "-r", "x"])), Some("x".into()));
        // 末尾悬空的 --resume 不得 panic
        assert_eq!(resume_session_id(&v(&["claude", "--resume"])), None);
    }

    #[test]
    fn claude_detection_by_comm_and_cmdline() {
        let mk = |comm: &str, cl: &[&str]| ProcInfo {
            pid: 1,
            comm: comm.into(),
            cmdline: cl.iter().map(|s| s.to_string()).collect(),
            cwd: None,
            start_wall_ns: None,
            ppid: None,
        };
        assert!(looks_like_claude(&mk("claude", &["claude"])));
        assert!(looks_like_claude(&mk(
            "node",
            &["node", "/usr/bin/claude", "--resume", "x"]
        )));
        assert!(!looks_like_claude(&mk("bash", &["bash", "-c", "echo claude"])));
    }

    /// `/proc/<pid>/stat` 的 comm 里可能含空格和右括号 —— 必须从最后一个 `)` 切。
    #[test]
    fn stat_parsing_survives_parens_in_comm() {
        // 构造一个 comm 含 ")" 与空格的 stat 行
        let line = "1234 (weird ) name) S 1 1234 1234 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 987654 0 0";
        let close = line.rfind(')').unwrap();
        let rest: Vec<&str> = line[close + 1..].split_whitespace().collect();
        assert_eq!(rest[0], "S");
        assert_eq!(rest[1].parse::<u32>().unwrap(), 1); // ppid
        assert_eq!(rest[19].parse::<u64>().unwrap(), 987654); // starttime
    }

    /// 读自己的 /proc 必须成功 —— 这是所有绑定的基础能力。
    #[test]
    fn can_read_own_proc() {
        let me = std::process::id();
        let info = read_proc(me).expect("读不到自己的 /proc");
        assert_eq!(info.pid, me);
        assert!(!info.comm.is_empty());
        assert!(info.start_wall_ns.unwrap_or(0) > 0, "拿不到启动时间");
    }

    /// 读一个不存在的 pid 返回 None，不 panic。
    #[test]
    fn missing_pid_is_none_not_panic() {
        assert!(read_proc(999_999_999).is_none());
    }

    /// `-p` 指定了一个进程时，它自己不能被算成两个候选。
    ///
    /// 回归测试：`scan_descendants(root)` 已含 root，早先又 push 了一次，
    /// 导致唯一匹配的进程被判成"2 个候选，歧义不猜"，binding 从 Heuristic 掉成 None。
    #[test]
    fn scan_descendants_does_not_duplicate_root() {
        let me = std::process::id();
        let v = crate::collector::bpftrace::scan_descendants(me);
        let n = v.iter().filter(|p| **p == me).count();
        assert_eq!(n, 1, "root 在后代列表里出现了 {} 次", n);
    }

    /// 走一遍真实的 -p 路径：候选里同一个 pid 只能算一次。
    /// 这里不依赖系统里真有 claude 进程 —— 只验证候选列表本身无重复。
    #[test]
    fn candidates_are_deduplicated() {
        let me = std::process::id();
        let mut probes = crate::collector::bpftrace::scan_descendants(me);
        if !probes.contains(&me) {
            probes.push(me);
        }
        let mut sorted = probes.clone();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "候选 pid 有重复：{:?}", probes);
    }

    /// 没有任何线索时必须老实说 None，而不是随便绑一个 claude 进程。
    #[test]
    fn no_clues_means_none() {
        let r = resolve(None, None, None, None);
        assert_eq!(r.level, Binding::None);
        assert!(r.pid.is_none());
        assert!(!r.explanation.is_empty(), "必须解释为什么绑不上");
    }
}
