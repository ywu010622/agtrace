//! 派生视图（DESIGN.md §8 ④⑤）。
//!
//! 这些视图**不产生新的事实**，只把已经存在的事件重新组织成"值得看一眼"的信号：
//! - ④ 时序异常：tool call → result 的大 gap、静默重试、悬空调用、以及 §10.3 楔形
//!   （tool_result 说成功，但内核侧压根没发生对应的系统调用）。
//! - ⑤ watchlist：命中敏感目标时把整行标红（alert-only）。
//!
//! **诚实性要求**：派生事件一律渲染成 `!!` 层，与真实证据在视觉上区分开。
//! 它们是**怀疑**，不是**证据** —— 用户必须能一眼看出这个区别。

use crate::event::{Binding, Corr, Event, Kind, Layer, Payload, TsSource};
use std::collections::{HashMap, HashSet, VecDeque};

/// watchlist 规则的匹配维度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchKind {
    /// 匹配 exec 的文件名或 argv[0]。
    Exec,
    /// 匹配 file.open 的路径。
    File,
    /// 匹配 net.connect 的对端地址。
    NetAddr,
    /// 匹配 net.connect 的端口。
    NetPort,
    /// 匹配 Bash 工具的命令串。
    Bash,
    /// 匹配任意工具调用的 input preview。
    ToolArg,
}

impl WatchKind {
    pub fn parse(s: &str) -> Option<WatchKind> {
        Some(match s {
            "exec" => WatchKind::Exec,
            "file" => WatchKind::File,
            "net_addr" | "net-addr" | "net" => WatchKind::NetAddr,
            "net_port" | "net-port" | "port" => WatchKind::NetPort,
            "bash" => WatchKind::Bash,
            "tool_arg" | "tool-arg" | "tool" => WatchKind::ToolArg,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WatchRule {
    pub name: String,
    pub kind: WatchKind,
    pub pattern: String,
}

impl WatchRule {
    fn new(name: &str, kind: WatchKind, pattern: &str) -> Self {
        WatchRule {
            name: name.into(),
            kind,
            pattern: pattern.into(),
        }
    }
}

/// ④⑤ 的阈值与规则。
#[derive(Debug, Clone)]
pub struct ViewsConfig {
    /// 这次运行是否**真的**有内核事件源。纯 agent 侧（`-S` 读 transcript）时为 false，
    /// 此时任何"内核里没看到 X"的推断都是无根据的，相关视图必须整体关闭。
    pub kernel_available: bool,
    pub enable_gap: bool,
    pub enable_retry: bool,
    pub enable_watch: bool,
    /// 收尾时是否报告悬空调用（`derived.tool.dangling`）。
    ///
    /// `--no-views` 必须把它关掉：`disabled()` 之前只把 `dangling_min_ms` 设成
    /// `u64::MAX`，而 `finish()` 根本没读那个字段 —— 于是 `--no-views` 仍会冒出
    /// 派生行（2026-10-17 审计）。
    pub enable_dangling: bool,
    /// tool call → result 超过这个间隔就报告（默认 5s）。
    pub gap_ms: u64,
    /// 同一 (tool, input) 在这个窗口内再次出现才算"重试"（默认 60s）。
    /// 窗口存在的意义：会话开头和结尾各 Read 一次同一个文件是正常的，
    /// 不设窗口就会把正常的重复访问误报成重试。
    pub retry_window_ms: u64,
    /// 流结束时，call 已经等了这么久还没 result 才算悬空（默认 3s）。
    /// 不设这个下限的话，流末尾那个"正在进行中"的调用会被误报。
    pub dangling_min_ms: u64,
    pub watch: Vec<WatchRule>,
}

impl Default for ViewsConfig {
    fn default() -> Self {
        ViewsConfig {
            // Default 刻意取 false：默认值要选"不会下没有根据的结论"的那一边。
            // 真正运行时由 main 按有没有 -p/-C 显式覆盖。
            kernel_available: false,
            enable_gap: true,
            enable_retry: true,
            enable_watch: true,
            enable_dangling: true,
            gap_ms: 5_000,
            retry_window_ms: 60_000,
            dangling_min_ms: 3_000,
            watch: default_watchlist(),
        }
    }
}

/// 硬编码默认 watchlist（§8 ⑤）。原则：**只放"看到就该停下来看一眼"的东西**，
/// 不放"agent 天天都在干"的东西 —— 一个永远在报警的告警等于没有告警。
fn default_watchlist() -> Vec<WatchRule> {
    use WatchKind::*;
    vec![
        // --- 凭据 / 私钥 ---
        WatchRule::new("ssh private key", File, "*/.ssh/id_*"),
        WatchRule::new("ssh private key (no suffix)", File, "*/id_rsa"),
        WatchRule::new("ssh private key (no suffix)", File, "*/id_ed25519"),
        WatchRule::new("aws credentials", File, "*/.aws/credentials"),
        WatchRule::new("gcloud credentials", File, "*/gcloud/credentials.db"),
        WatchRule::new("kube config", File, "*/.kube/config"),
        WatchRule::new("netrc", File, "*/.netrc"),
        WatchRule::new("dotenv", File, "*/.env"),
        WatchRule::new("system password database", File, "/etc/shadow"),
        WatchRule::new("sudoers", File, "/etc/sudoers*"),
        WatchRule::new("docker credentials", File, "*/.docker/config.json"),
        WatchRule::new("npm token", File, "*/.npmrc"),
        WatchRule::new("git credentials", File, "*/.git-credentials"),
        // --- 进程环境（常被用来偷密钥） ---
        WatchRule::new("process environment read", File, "/proc/*/environ"),
        // --- 网络外联 ---
        WatchRule::new("cloud metadata endpoint", NetAddr, "169.254.169.254"),
        WatchRule::new("reverse shell tool", Exec, "nc"),
        WatchRule::new("reverse shell tool", Exec, "ncat"),
        WatchRule::new("relay tool socat", Exec, "socat"),
        WatchRule::new("remote login ssh", Exec, "ssh"),
        WatchRule::new("tunneling tool", Exec, "sshpass"),
        WatchRule::new("tunneling tool", Exec, "chisel"),
        WatchRule::new("tunneling tool", Exec, "frpc"),
        WatchRule::new("common reverse-shell port", NetPort, "4444"),
        WatchRule::new("common reverse-shell port", NetPort, "1337"),
        WatchRule::new("common reverse-shell port", NetPort, "9001"),
        // --- 破坏性操作 ---
        WatchRule::new("recursive force delete", Bash, "*rm -rf*"),
        WatchRule::new("recursive force delete", Bash, "*rm -fr*"),
        WatchRule::new("raw disk overwrite", Bash, "*dd if=*of=/dev/*"),
        WatchRule::new("chmod 777", Bash, "*chmod 777*"),
        WatchRule::new("download-and-execute", Bash, "*curl * | *sh*"),
        WatchRule::new("download-and-execute", Bash, "*curl * | *bash*"),
        WatchRule::new("download-and-execute", Bash, "*wget * | *sh*"),
        WatchRule::new("history wipe / anti-forensics", Bash, "*history -c*"),
        WatchRule::new("history wipe / anti-forensics", Bash, "*shred *"),
        // --- 提权 ---
        WatchRule::new("sudo privilege escalation", Bash, "*sudo *"),
        WatchRule::new("system password change", Bash, "*chpasswd*"),
        WatchRule::new("authorized_keys write", Bash, "*authorized_keys*"),
    ]
}

/// 极简 glob：只支持 `*`（匹配任意长度，含 `/`）。
///
/// 刻意不做 `?` / `[]` / `**` —— 规则表达式越复杂，用户越难预测它匹配什么，
/// 而"我能预测它在匹配什么"是安全工具的基本要求。
pub(crate) fn glob_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 一个还没等到 result 的 tool call。
struct Pending {
    ts_ns: u64,
    wall_ns: u64,
    ts_src: TsSource,
    source: String,
    corr: Corr,
    tool: String,
    /// Bash 命令（如果需要判断"本该有内核效应"）。
    bash_cmd: Option<String>,
    /// 这个调用是否已经报过 gap。
    gap_reported: bool,
}

/// 一个待复核的楔形候选。收尾时才拿全量的 connect 记录来判定。
struct WedgeCandidate {
    call_ts: u64,
    result_ts: u64,
    cmd: String,
    binding: Option<crate::event::Binding>,
    /// 触发它的事件，用来给派生行提供 ts/pid/comm 等上下文。
    src: Event,
}

pub struct Views {
    cfg: ViewsConfig,
    /// tool_use_id（缺失时退化成"单飞"槽位）→ 进行中的调用。
    pending: Vec<Pending>,
    /// (tool, input_fingerprint) → 出现过的 ts（窗口内）。
    seen_inputs: HashMap<String, VecDeque<u64>>,
    /// 最近的内核 net.connect 时间戳（用于 §10.3 楔形判定）。
    recent_connects: VecDeque<u64>,
    /// 本次运行中**所有**成功 connect 的时间戳。
    ///
    /// 与 `recent_connects`（只留最近 5 分钟，给增量判定用）不同，这份是全量：
    /// 楔形结论只能在收尾时下，因为"内核里有没有 connect"是一个**关于整段运行**的
    /// 断言。在 tool.result 到达的那一刻判定是错的 —— 那时采集器可能刚起来，
    /// 内核事件还一条都没到，于是每个联网命令都会被误判成楔形。实测踩到过：
    /// 受控场景里 agent 事件在 0~1s 到达、内核事件在 67s 才到，判定时
    /// `kernel_events_seen == 0`，楔形被静默跳过。
    all_connects: Vec<u64>,
    /// 收尾时要复核的楔形候选：(call_ts, result_ts, 命令, 绑定等级, 触发事件序号)
    wedge_candidates: Vec<WedgeCandidate>,
    /// 已经报过的 watchlist 命中，避免同一目标刷屏。
    watch_reported: HashSet<String>,
    /// 实际观察到的内核事件数。楔形判定要求它 > 0 ——
    /// 采集器起来了但一条事件都没有（脚本加载失败、目标进程已死）时，
    /// "没看到 connect"同样是无信息的，不能当成发现。
    kernel_events_seen: u64,
    /// **第一条**内核事件的时间戳，即内核观测窗口的左边界。
    ///
    /// 楔形说的是"内核里没有 connect"。这句话只有在**我们当时确实在看**的
    /// 时间范围内才成立。`-S` 读一份已有 transcript 时会把历史全部回放 ——
    /// 那些几十分钟前的 `curl` 落在观测窗口之外，内核当然看不到它们，
    /// 但这不构成任何发现。实测踩到：`-p 140957 -S <live 4.8MB transcript>` 下
    /// 内核只产出 1 条事件，却报出 **4 个楔形** —— 全是历史回放造成的假阳性。
    ///
    /// 判据取"第一条内核事件"而不是"bpftrace 启动时刻"：前者可从事件流直接
    /// 得到，且偏保守（空闲期会被算作没在看）。保守方向的误差是**少报**，
    /// 而少报只是漏掉一个发现，多报却会让用户学会忽略这个标记。
    kernel_first_ts: Option<u64>,
    /// 因为落在内核观测窗口之前而被放弃的楔形候选数（`-v` 可见）。
    /// 静默丢弃是不行的 —— 用户需要知道"这里本来会报楔形，但因为当时没在看而没报"。
    wedge_skipped_precollection: u64,
    /// 本轮 observe 产生的派生事件。
    derived: Vec<Event>,
    /// 观察到的**最后一个**事件的 ts（单调钟）—— 收尾时用它算"这条 pending
    /// 调用已经等了多久"，`dangling_min_ms` 的判据（2026-10-17 审计：
    /// 之前这个字段的配置读进来了却没人用）。
    last_event_ts: u64,
    pub gap_count: u64,
    pub retry_count: u64,
    pub watch_count: u64,
    pub dangling_count: u64,
    pub wedge_count: u64,
}

impl Views {
    pub fn new(cfg: ViewsConfig) -> Self {
        Views {
            cfg,
            pending: Vec::new(),
            seen_inputs: HashMap::new(),
            recent_connects: VecDeque::new(),
            all_connects: Vec::new(),
            wedge_candidates: Vec::new(),
            watch_reported: HashSet::new(),
            kernel_events_seen: 0,
            kernel_first_ts: None,
            wedge_skipped_precollection: 0,
            derived: Vec::new(),
            last_event_ts: 0,
            gap_count: 0,
            retry_count: 0,
            watch_count: 0,
            dangling_count: 0,
            wedge_count: 0,
        }
    }

    /// 全部关闭。用于 `--no-views`：用户只想要原始时间线时，派生行是噪声。
    /// 单元测试也用它，保证 merger 的排序测试不被派生事件干扰。
    ///
    /// 2026-10-17：`finish()` 现在真的检查 `enable_dangling`（旧实现只看
    /// `dangling_min_ms` 且根本没读它，`--no-views` 会漏出 dangling 行）。
    pub fn disabled() -> Self {
        Views::new(ViewsConfig {
            kernel_available: false,
            enable_gap: false,
            enable_retry: false,
            enable_watch: false,
            enable_dangling: false,
            gap_ms: u64::MAX,
            retry_window_ms: 0,
            dangling_min_ms: u64::MAX,
            watch: Vec::new(),
        })
    }

    /// 从 TOML 载入用户规则，**追加**在默认规则之后（默认规则不可被悄悄关掉）。
    pub fn load_toml(path: &str, cfg: &mut ViewsConfig) -> Result<usize, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read watchlist config {}: {}", path, e))?;
        let v: toml::Value = text
            .parse()
            .map_err(|e| format!("watchlist config parse failed {}: {}", path, e))?;

        let mut n = 0;
        if let Some(views) = v.get("views").and_then(|x| x.as_table()) {
            if let Some(x) = views.get("gap_ms").and_then(|x| x.as_integer()) {
                cfg.gap_ms = x.max(0) as u64;
            }
            if let Some(x) = views.get("retry_window_ms").and_then(|x| x.as_integer()) {
                cfg.retry_window_ms = x.max(0) as u64;
            }
            if let Some(x) = views.get("dangling_min_ms").and_then(|x| x.as_integer()) {
                cfg.dangling_min_ms = x.max(0) as u64;
            }
        }
        if let Some(arr) = v.get("watch").and_then(|x| x.as_array()) {
            for (i, item) in arr.iter().enumerate() {
                let name = item
                    .get("name")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| format!("watch[{}] is missing `name`", i))?;
                let kind_s = item
                    .get("kind")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| format!("watch[{}] is missing `kind`", i))?;
                let pattern = item
                    .get("pattern")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| format!("watch[{}] is missing `pattern`", i))?;
                let kind = WatchKind::parse(kind_s).ok_or_else(|| {
                    format!(
                        "watch[{}] has unknown kind `{}` (available: exec|file|net_addr|net_port|bash|tool_arg)",
                        i, kind_s
                    )
                })?;
                cfg.watch.push(WatchRule {
                    name: name.into(),
                    kind,
                    pattern: pattern.into(),
                });
                n += 1;
            }
        }
        Ok(n)
    }

    pub fn drain_derived(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.derived)
    }

    /// 观察一个即将输出的事件。**可能修改它**（设置 `watch` / `retry` 标记）。
    /// 楔形视图当前是否真的能下结论。给 `-v` 诊断用：关掉了就要说清楚为什么。
    pub fn wedge_capable(&self) -> bool {
        self.cfg.kernel_available && self.kernel_events_seen > 0
    }

    /// 这次运行**本该**有内核源吗（即给了 `-p`/`-C`）。
    pub fn kernel_source_expected(&self) -> bool {
        self.cfg.kernel_available
    }

    pub fn kernel_events_seen(&self) -> u64 {
        self.kernel_events_seen
    }

    /// 落在内核观测窗口之前、因而被放弃的楔形候选数（`-v` 诊断用）。
    pub fn wedge_skipped_precollection(&self) -> u64 {
        self.wedge_skipped_precollection
    }

    pub fn observe(&mut self, ev: &mut Event) {
        self.last_event_ts = self.last_event_ts.max(ev.ts_ns);
        if ev.from_kernel_collector() {
            self.kernel_events_seen += 1;
            // 内核观测窗口的左边界 = 第一条内核事件。注意事件是**乱序**进入
            // observe 的（merger 的重排窗口），所以取最小值而不是"第一次见到的"。
            self.kernel_first_ts = Some(match self.kernel_first_ts {
                Some(t) => t.min(ev.ts_ns),
                None => ev.ts_ns,
            });
        }
        // 内核 net.connect 先记账 —— 楔形判定要用，且必须在 agent 事件之前更新，
        // 否则同一批里"先 connect 后 result"的合法顺序会被判成楔形。
        if ev.kind == Kind::InfraNetConnect {
            if let Payload::NetConnect { ok, .. } = &ev.payload {
                if *ok {
                    self.recent_connects.push_back(ev.ts_ns);
                    self.all_connects.push(ev.ts_ns);
                    self.trim_connects(ev.ts_ns);
                }
            }
        }

        if self.cfg.enable_watch {
            self.check_watch(ev);
        }

        match ev.kind {
            Kind::AgentToolCall => self.on_tool_call(ev),
            Kind::AgentToolResult => self.on_tool_result(ev),
            _ => {}
        }
    }

    fn trim_connects(&mut self, now: u64) {
        // 只保留最近 5 分钟的 connect —— 再久远的跟当前 tool call 无关。
        const KEEP_NS: u64 = 300 * 1_000_000_000;
        while let Some(&t) = self.recent_connects.front() {
            if now.saturating_sub(t) > KEEP_NS {
                self.recent_connects.pop_front();
            } else {
                break;
            }
        }
    }

    fn on_tool_call(&mut self, ev: &mut Event) {
        let (tool, input_preview, bash_cmd) = match &ev.payload {
            Payload::ToolCall {
                tool,
                input_preview,
                bash_cmd,
                ..
            } => (tool.clone(), input_preview.clone(), bash_cmd.clone()),
            _ => return,
        };

        // ---- ④ retry ----
        if self.cfg.enable_retry && self.cfg.retry_window_ms > 0 {
            // 指纹用 bash_cmd 优先（同一命令的不同 preview 截断不该算不同输入）。
            let fp_src = bash_cmd.as_deref().unwrap_or(&input_preview);
            let fp = format!("{}\u{1}{}", tool, fp_src);
            let win_ns = self.cfg.retry_window_ms * 1_000_000;
            let q = self.seen_inputs.entry(fp).or_default();
            while let Some(&front) = q.front() {
                if ev.ts_ns.saturating_sub(front) > win_ns {
                    q.pop_front();
                } else {
                    break;
                }
            }
            let prev = q.len() as u64;
            q.push_back(ev.ts_ns);
            if prev >= 1 {
                ev.retry = true;
                self.retry_count += 1;
                // 一行装得下是硬要求（§3 可读性）：`x{prev+1}` 已经表达了次数，
                // 不再追加 `(count=N)` —— 那会让这一行超过 120 列而被截断。
                let d = format!(
                    "{} x{} in {}s (first {:.1}s ago)",
                    tool,
                    prev + 1,
                    self.cfg.retry_window_ms / 1000,
                    (ev.ts_ns - q.front().copied().unwrap_or(ev.ts_ns)) as f64 / 1e9
                );
                let e = derived_from(ev, Kind::DerivedToolRetry, "possible silent retry", &d, 0);
                self.derived.push(e);
            }
        }

        // ---- 记录 pending，供 gap / dangling / 楔形使用 ----
        self.pending.push(Pending {
            ts_ns: ev.ts_ns,
            wall_ns: ev.ts_wall_ns,
            ts_src: ev.ts_src,
            source: ev.source.clone(),
            corr: ev.corr.clone(),
            tool,
            bash_cmd,
            gap_reported: false,
        });
    }

    fn on_tool_result(&mut self, ev: &mut Event) {
        // 匹配 pending：优先 tool_use_id，没有就取**最早**的未完成调用（FIFO），
        // 而不是"最后一个" —— 并发调用时 FIFO 更接近真实配对顺序。
        let id = ev.corr.tool_use_id.clone();
        let idx = match id.as_deref() {
            Some(id) => self
                .pending
                .iter()
                .position(|p| p.corr.tool_use_id.as_deref() == Some(id)),
            None => {
                // 有 id 的 result 不该抢无 id 的槽位，反之亦然：按 tool 名匹配最早的。
                // 只配对**同工具**（或 result 没带工具名）的调用：工具名对不上时
                // 退到"最早的那条"会把一条 Bash 结果配给一个 Read 调用，既假造了
                // gap、又掩盖了真正的 dangling（2026-10-17 审计）。
                let tool = match &ev.payload {
                    Payload::ToolResult { tool, .. } => tool.as_deref(),
                    _ => None,
                };
                match tool {
                    Some(want) => self.pending.iter().position(|p| p.tool == want),
                    None => {
                        if self.pending.is_empty() {
                            None
                        } else {
                            Some(0)
                        }
                    }
                }
            }
        };
        let Some(i) = idx else { return };
        let p = self.pending.remove(i);

        let gap_ns = ev.ts_ns.saturating_sub(p.ts_ns);
        let gap_ms = gap_ns / 1_000_000;

        // ---- ④ gap ----
        if self.cfg.enable_gap && gap_ms >= self.cfg.gap_ms && !p.gap_reported {
            self.gap_count += 1;
            let d = format!(
                "{} call->result {:.1}s (threshold {}s)",
                p.tool,
                gap_ns as f64 / 1e9,
                self.cfg.gap_ms / 1000
            );
            self.derived
                .push(derived_from(ev, Kind::DerivedToolGap, "abnormal call gap", &d, gap_ms));
        }

        // ---- §10.3 楔形：说成功，但内核侧没有对应的外联 ----
        if self.cfg.enable_gap {
            if let Some(cmd) = &p.bash_cmd {
                let status_ok = match &ev.payload {
                    Payload::ToolResult { status, .. } => {
                        let s = status.to_ascii_lowercase();
                        !(s.contains("error") || s.contains("fail") || s.contains("denied"))
                    }
                    _ => false,
                };
                // **没有内核源时绝不做楔形判定。**
                //
                // 楔形的断言是"命令报告成功，但内核里没有对应的 connect"。如果这次
                // 运行压根没有内核采集器（纯 `-S` 读 transcript），那"没有 connect"
                // 是必然的、无信息的 —— 对它报警等于把"我没在看"说成"它没发生"。
                // §4.3 允许说"不知道"，不允许把不知道包装成发现。
                // 第三个前提：agent 会话与内核进程树必须**真有关联**。
                //
                // 楔形的结论是"内核里没有对应的 connect"。如果 pid_binding 是 None，
                // 我们看的进程树和这个会话之间没有任何证据链 —— 在那棵树上没看到
                // connect，与"这个命令没联网"是两件不相干的事。§3.5 说绑不上就要
                // 说绑不上；那么在绑不上的基础上做跨层推断，更是不能做的事。
                let linked = matches!(
                    ev.corr.pid_binding,
                    Some(crate::event::Binding::Exact) | Some(crate::event::Binding::Heuristic)
                );
                if status_ok && linked && expects_network(cmd) {
                    // 只**登记候选**，不在这里下结论 —— 见 `finish()`。
                    self.wedge_candidates.push(WedgeCandidate {
                        call_ts: p.ts_ns,
                        result_ts: ev.ts_ns,
                        cmd: cmd.to_string(),
                        binding: ev.corr.pid_binding,
                        src: ev.clone(),
                    });
                }
            }
        }

        // 让渲染层知道这个 result 配到了哪个 call（gap 大时打 `~` 便于肉眼对齐）。
        if gap_ms >= self.cfg.gap_ms {
            ev.retry = ev.retry || false;
        }
    }

    fn check_watch(&mut self, ev: &mut Event) {
        // 逐条规则判定；用 (rule.name, 目标) 去重，避免刷屏。
        let mut hits: Vec<(usize, String)> = Vec::new();
        match (&ev.kind, &ev.payload) {
            (Kind::RuntimeProcExec, Payload::ProcExec { filename, argv, .. }) => {
                for (i, r) in self.cfg.watch.iter().enumerate() {
                    if r.kind != WatchKind::Exec {
                        continue;
                    }
                    let cands = std::iter::once(filename.as_str()).chain(argv.first().map(|s| s.as_str()));
                    for c in cands {
                        let base = c.rsplit('/').next().unwrap_or(c);
                        if glob_match(&r.pattern, c) || glob_match(&r.pattern, base) {
                            hits.push((i, c.to_string()));
                            break;
                        }
                    }
                }
            }
            (Kind::InfraFileOpen, Payload::FileOpen { path, ok, .. }) => {
                if *ok {
                    for (i, r) in self.cfg.watch.iter().enumerate() {
                        if r.kind == WatchKind::File && glob_match(&r.pattern, path) {
                            hits.push((i, path.clone()));
                        }
                    }
                }
            }
            (Kind::InfraNetConnect, Payload::NetConnect { addr, port, .. }) => {
                for (i, r) in self.cfg.watch.iter().enumerate() {
                    match r.kind {
                        WatchKind::NetAddr => {
                            if glob_match(&r.pattern, addr) || addr.contains(&r.pattern) {
                                hits.push((i, addr.clone()));
                            }
                        }
                        WatchKind::NetPort => {
                            if let Some(p) = port {
                                if r.pattern.trim() == p.to_string() {
                                    hits.push((i, format!("port {}", p)));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            (
                Kind::AgentToolCall,
                Payload::ToolCall {
                    tool,
                    bash_cmd,
                    input_preview,
                    ..
                },
            ) => {
                let cmd = bash_cmd.as_deref().unwrap_or(input_preview.as_str());
                let is_bash = tool == "Bash";
                for (i, r) in self.cfg.watch.iter().enumerate() {
                    match r.kind {
                        WatchKind::Bash if is_bash => {
                            // segment-aware：按子命令逐条匹配，`*` 不能横跨 `;`/`&&`/`||`
                            // 把不相干的子命令拼成"证据"（2026-10-11 误报教训）。
                            if crate::exact::split_commands(cmd)
                                .iter()
                                .any(|seg| glob_match(&r.pattern, seg))
                            {
                                hits.push((i, crate::event::truncate_chars(cmd, 120, 120).0));
                            }
                        }
                        WatchKind::ToolArg => {
                            if glob_match(&r.pattern, cmd) || glob_match(&r.pattern, input_preview) {
                                hits.push((i, crate::event::truncate_chars(cmd, 120, 120).0));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        for (i, target) in hits {
            let r = &self.cfg.watch[i];
            ev.watch = true;
            let key = format!("{}\u{1}{}", r.name, target);
            if self.watch_reported.insert(key) {
                self.watch_count += 1;
                let d = format!("rule \"{}\" ({}) hit: {}", r.name, pattern_kind_str(r.kind), target);
                let e = derived_from(ev, Kind::DerivedWatchlist, "watchlist", &d, 0);
                self.derived.push(e);
            }
        }
    }

    /// 流结束：报告悬空的 tool call。
    pub fn finish(&mut self) -> Vec<Event> {
        let mut out = std::mem::take(&mut self.derived);
        let pending = std::mem::take(&mut self.pending);
        // 流的结尾 = 观察到的最后一个事件。用它的 ts 算 call 已经等了多久：
        // 不再用"只要还在 pending 就是悬空"（那会把流的最后一条调用误报，而且
        // 让 `dangling_min_ms` 成为死配置）。
        let stream_end = self.last_event_ts;
        let min_ns = self.cfg.dangling_min_ms.saturating_mul(1_000_000);
        for p in pending {
            if !self.cfg.enable_dangling {
                continue;
            }
            let waited_ns = stream_end.saturating_sub(p.ts_ns);
            if waited_ns < min_ns {
                // 流末尾刚开始的调用属于扫描窗口问题，不是 agent 卡住。
                continue;
            }
            self.dangling_count += 1;
            let mut e = Event {
                seq: 0,
                ts_ns: p.ts_ns,
                ts_wall_ns: p.wall_ns,
                ts_src: p.ts_src,
                layer: Layer::Derived,
                kind: Kind::DerivedToolDangling,
                source: p.source.clone(),
                pid: None,
                tid: None,
                ppid: None,
                comm: None,
                cgroup_id: None,
                corr: p.corr.clone(),
                payload: Payload::Derived {
                    label: "dangling call".into(),
                    detail: format!(
                        "{} was called but no tool_result arrived before the stream ended \
                         (agent crashed, was interrupted, or the transcript was not flushed yet)",
                        p.tool
                    ),
                    count: 0,
                },
                trunc: Vec::new(),
                notes: Vec::new(),
                late: false,
                watch: false,
                binding: Binding::None,
                retry: false,
            };
            e.layer = Layer::Derived;
            out.push(e);
        }

        // ---- §10.3 楔形：现在才判定 ----
        //
        // 放在收尾是因为"内核里有没有 connect"是关于**整段运行**的断言。
        // 在 tool.result 到达那一刻判定会漏：采集器可能刚起来、内核事件还没到，
        // 于是每个联网命令都被当成"内核无效应"。受控实验里 agent 事件在 0~1s 到达、
        // 内核事件到 67s 才来，早判定就是必然漏报。
        //
        // 四个前提缺一不可：
        //   1. 本次运行真的有内核源，且确实收到过内核事件（否则"没看到"= "没在看"）；
        //   2. **候选窗口落在内核观测窗口之内**（见下）；
        //   3. agent 会话与进程树有证据链（Exact/Heuristic）—— 否则跨层推断无根据；
        //   4. Bash 报成功且命令本应联网（在 on_tool_result 里已筛过）。
        let capable = self.wedge_capable();
        let first = self.kernel_first_ts;
        for c in std::mem::take(&mut self.wedge_candidates) {
            if !capable {
                continue;
            }
            // 前提 2：这次调用是不是发生在**我们开始看内核之前**。
            //
            // `-S` 会把 transcript 的历史整个回放。那些几十分钟前的 curl 的内核效应
            // 发生在采集器启动之前，窗口里当然没有 connect —— 但这是"我们没在看"，
            // 不是"内核里没有"。实测：`-p 140957 -S <live 4.8MB transcript>` 下
            // 内核只产出 1 条事件（其余 1462 条是 agent 历史回放），却报出 4 个楔形，
            // 四个全是历史回放造成的假阳性。
            //
            // 取 call_ts 而非窗口与观测窗口的**交叠**：只要调用的起点在观测窗口之前，
            // 我们就无法排除"connect 发生在开始看之前那一瞬"，所以整条候选作废。
            if let Some(f) = first {
                if c.call_ts < f {
                    self.wedge_skipped_precollection += 1;
                    continue;
                }
            }
            // 允许 result 落盘比内核事件晚一点（transcript 是事后写的）。
            let lo = c.call_ts;
            let hi = c.result_ts.saturating_add(1_000_000_000);
            if self.all_connects.iter().any(|&t| t >= lo && t <= hi) {
                continue;
            }
            self.wedge_count += 1;
            let d = format!(
                // 结论放在最前面：这一行几乎必然超过 120 列而被截断，被砍掉的
                // 只能是尾部的命令原文，不能是"内核里没有 connect"这个断言本身。
                "no kernel net.connect inside [call, result+1s] while Bash reported success; \
                 command: {} (pid_binding={}, {})",
                crate::event::truncate_chars(&c.cmd, 160, 160).0,
                c.binding.map(|b| b.as_str()).unwrap_or("None"),
                if c.binding == Some(crate::event::Binding::Exact) {
                    "association confirmed by cmdline"
                } else {
                    "association is heuristic — verify the process tree really is that session"
                }
            );
            // 楔形有自己的 kind（`derived.tool.wedge`）：它是**因果**矛盾，
            // 不是 gap 那种**时间**异常。混在 gap 里会让按 kind 过滤的消费者
            // 分不开"这条慢"和"这条对不上账"。
            out.push(derived_from(
                &c.src,
                Kind::DerivedToolWedge,
                "wedge:no kernel effect",
                &d,
                0,
            ));
        }
        out
    }
}

fn pattern_kind_str(k: WatchKind) -> &'static str {
    match k {
        WatchKind::Exec => "exec",
        WatchKind::File => "file",
        WatchKind::NetAddr => "net_addr",
        WatchKind::NetPort => "net_port",
        WatchKind::Bash => "bash",
        WatchKind::ToolArg => "tool_arg",
    }
}

/// 这个命令**本该**产生一个 net.connect 吗？
///
/// 保守起见只认最明确的外联工具；宁可漏报也不要把 `ls` 判成"该联网"。
fn expects_network(cmd: &str) -> bool {
    // 判定标准：这条命令**必然**发起一次网络连接，没有别的可能。
    //
    // 判松了的代价比判漏了更大：一个误报会让用户学会无视 `⚠ 楔形` 标记，
    // 那这个视图就等于不存在。实测踩到的坑：`git` 曾经在"总是联网"表里，
    // 于是 `git log` / `git status` / `git diff` 这些纯本地命令全部被标成
    // "报告成功但没有内核 connect" —— 它们本来就不该有 connect。
    //
    // 所以拆成两类：
    //   A. 本身就是网络工具 → 必然联网；
    //   B. 工具有联网子命令，但大多数子命令不联网 → 必须看子命令。
    // 只检查每段的**首个命令 token**（跳过 `sudo`/`timeout` 之类的包装与它们的参数），
    // 避免 `echo "curl http://x"` 这种引号里的字符串被误判。
    const ALWAYS_NET: &[&str] = &[
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "dig",
        "host",
        "nslookup",
        "ping",
        "traceroute",
        "telnet",
        "gh",
        "apt",
        "apt-get",
        "aptitude",
        "dnf",
        "yum",
        "pacman",
        "zypper",
        "kubectl",
        "helm",
        "docker",
        "podman",
    ];
    // 这些工具只有下列子命令会联网。
    const NET_SUBCMD: &[(&str, &[&str])] = &[
        (
            "git",
            &["fetch", "pull", "push", "clone", "ls-remote", "submodule", "remote"],
        ),
        ("cargo", &["install", "publish", "search", "update", "add", "login"]),
        (
            "npm",
            &["install", "i", "ci", "publish", "view", "outdated", "audit", "update"],
        ),
        ("pip", &["install", "download", "search", "wheel"]),
        ("pip3", &["install", "download", "search", "wheel"]),
        ("uv", &["pip", "sync", "add", "lock", "run"]),
    ];
    // 包装命令：它们自己联网与否取决于后面跟的命令，所以要穿过去。
    // 注意它们**自带参数**（`timeout 5 cmd`、`nice -n 10 cmd`），必须一并跳过。
    const WRAPPERS: &[&str] = &[
        "sudo", "doas", "env", "time", "nohup", "setsid", "command", "exec", "xargs", "timeout", "nice", "ionice",
        "stdbuf", "watch",
    ];

    for seg in cmd.split(['|', ';', '&', '\n']) {
        let toks: Vec<&str> = seg.split_whitespace().collect();
        let mut i = 0usize;
        let (base, second);
        loop {
            if i >= toks.len() {
                base = "";
                second = "";
                break;
            }
            let t = toks[i].rsplit('/').next().unwrap_or(toks[i]);
            // `VAR=x` 前缀赋值：不是命令本身。
            if t.contains('=') && !t.starts_with('-') {
                i += 1;
                continue;
            }
            if WRAPPERS.contains(&t) {
                i += 1;
                // 跳过包装命令自己的参数：选项、纯数字（timeout 的秒数）、VAR=x。
                while i < toks.len() {
                    let a = toks[i];
                    let is_opt = a.starts_with('-');
                    let is_num = !a.is_empty() && a.chars().all(|c| c.is_ascii_digit());
                    let is_assign = a.contains('=') && !a.starts_with('-');
                    if is_opt || is_num || is_assign {
                        i += 1;
                    } else {
                        break;
                    }
                }
                continue;
            }
            base = t;
            second = toks.get(i + 1).copied().unwrap_or("");
            break;
        }
        if base.is_empty() {
            continue;
        }
        if ALWAYS_NET.contains(&base) {
            return true;
        }
        if let Some((_, subs)) = NET_SUBCMD.iter().find(|(t, _)| *t == base) {
            if subs.contains(&second) {
                return true;
            }
        }
    }
    false
}

fn derived_from(src: &Event, kind: Kind, label: &str, detail: &str, count: u64) -> Event {
    Event {
        seq: 0,
        // 用触发事件的 ts：派生行紧贴在触发它的那行之后，便于肉眼对照。
        ts_ns: src.ts_ns,
        ts_wall_ns: src.ts_wall_ns,
        ts_src: src.ts_src,
        layer: Layer::Derived,
        kind,
        source: "views".into(),
        pid: src.pid,
        tid: None,
        ppid: None,
        comm: src.comm.clone(),
        cgroup_id: None,
        corr: src.corr.clone(),
        payload: Payload::Derived {
            label: label.to_string(),
            detail: detail.to_string(),
            count,
        },
        trunc: Vec::new(),
        notes: Vec::new(),
        late: false,
        watch: false,
        binding: Binding::None,
        retry: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*/.ssh/id_*", "/home/v/.ssh/id_rsa"));
        assert!(glob_match("/etc/sudoers*", "/etc/sudoers"));
        assert!(glob_match("/etc/sudoers*", "/etc/sudoers.d/x"));
        assert!(glob_match("*rm -rf*", "cd /tmp && rm -rf /"));
        assert!(!glob_match("*/.ssh/id_*", "/home/v/.ssh/known_hosts"));
        assert!(!glob_match("nc", "nice"));
        assert!(glob_match("/proc/*/environ", "/proc/1234/environ"));
        // 中文与多字节不能 panic
        assert!(glob_match("*密钥*", "读取密钥文件"));
    }

    #[test]
    fn expects_network_only_for_real_net_tools() {
        assert!(expects_network("curl -s http://x"));
        assert!(expects_network("cd /tmp && wget http://x"));
        assert!(expects_network("/usr/bin/git fetch"));
        assert!(!expects_network("ls -la"));
        assert!(!expects_network("echo hello"));
        assert!(!expects_network("cat file.txt"));
    }

    fn call(ts: u64, id: &str, tool: &str, bash: Option<&str>) -> Event {
        let mut e = Event {
            seq: 0,
            ts_ns: ts,
            ts_wall_ns: ts,
            ts_src: TsSource::Kernel,
            layer: Layer::Agent,
            kind: Kind::AgentToolCall,
            source: "claude-code".into(),
            pid: None,
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr {
                tool_use_id: Some(id.into()),
                ..Default::default()
            },
            payload: Payload::ToolCall {
                tool: tool.into(),
                input_preview: bash.unwrap_or("x").into(),
                input_bytes: 1,
                via_mcp: false,
                bash_cmd: bash.map(String::from),
            },
            trunc: vec![],
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        };
        e.corr.tool_use_id = Some(id.into());
        e
    }

    fn result(ts: u64, id: &str, tool: &str, status: &str) -> Event {
        Event {
            seq: 0,
            ts_ns: ts,
            ts_wall_ns: ts,
            ts_src: TsSource::Kernel,
            layer: Layer::Agent,
            kind: Kind::AgentToolResult,
            source: "claude-code".into(),
            pid: None,
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr {
                tool_use_id: Some(id.into()),
                ..Default::default()
            },
            payload: Payload::ToolResult {
                tool: Some(tool.into()),
                status: status.into(),
                result_preview: "ok".into(),
            },
            trunc: vec![],
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        }
    }

    const S: u64 = 1_000_000_000;

    #[test]
    fn gap_is_reported() {
        let mut v = Views::new(ViewsConfig {
            gap_ms: 1000,
            ..Default::default()
        });
        let mut c = call(0, "t1", "Bash", None);
        v.observe(&mut c);
        let mut r = result(5 * S, "t1", "Bash", "success");
        v.observe(&mut r);
        let d = v.drain_derived();
        assert!(d.iter().any(|e| e.kind == Kind::DerivedToolGap), "{:?}", d);
        assert_eq!(v.gap_count, 1);
    }

    #[test]
    fn small_gap_is_not_reported() {
        let mut v = Views::new(ViewsConfig {
            gap_ms: 1000,
            ..Default::default()
        });
        let mut c = call(0, "t1", "Bash", None);
        v.observe(&mut c);
        let mut r = result(S / 10, "t1", "Bash", "success");
        v.observe(&mut r);
        assert!(v.drain_derived().is_empty());
    }

    #[test]
    fn identical_input_marks_retry() {
        let mut v = Views::new(ViewsConfig {
            retry_window_ms: 60_000,
            ..Default::default()
        });
        for i in 0..3 {
            let mut c = call(i * S, &format!("t{}", i), "Bash", Some("pytest -q"));
            v.observe(&mut c);
            if i >= 1 {
                assert!(c.retry, "第 {} 次相同输入未被标记为重试", i + 1);
            }
        }
        assert_eq!(v.retry_count, 2);
    }

    #[test]
    fn same_input_outside_window_is_not_retry() {
        let mut v = Views::new(ViewsConfig {
            retry_window_ms: 10_000,
            ..Default::default()
        });
        let mut a = call(0, "t1", "Read", Some("x"));
        v.observe(&mut a);
        let mut b = call(600 * S, "t2", "Read", Some("x"));
        v.observe(&mut b);
        assert!(!b.retry, "超出窗口的重复不该算重试");
    }

    /// 流尾那条"正在进行中"的调用**不该**被报成悬空：`dangling_min_ms`
    /// （默认 3s）现在真的生效了（2026-10-17 审计前是 `let _ = ...`）。
    #[test]
    fn dangling_at_stream_end_is_filtered_by_the_threshold() {
        let mut v = Views::new(ViewsConfig::default());
        let mut c = call(0, "t1", "Bash", Some("sleep 9"));
        v.observe(&mut c);
        // 流结束只比调用晚 100ms —— 扫描窗口问题，不是 agent 卡住。
        let mut later = call(100_000_000, "t2", "Read", Some("y"));
        v.observe(&mut later);
        let f = v.finish();
        assert!(
            f.iter().all(|e| e.kind != Kind::DerivedToolDangling),
            "流末尾刚开始的调用被误报成悬空: {:?}",
            f
        );
        assert_eq!(v.dangling_count, 0);
    }

    #[test]
    fn dangling_reported_at_finish() {
        let mut v = Views::new(ViewsConfig::default());
        let mut c = call(0, "t1", "Bash", Some("sleep 9"));
        v.observe(&mut c);
        // 流又跑了 10s 才结束：这条调用确实一直没等到 result。
        let mut later = call(10 * S, "t2", "Read", Some("y"));
        v.observe(&mut later);
        let f = v.finish();
        let rows: Vec<&Event> = f.iter().filter(|e| e.kind == Kind::DerivedToolDangling).collect();
        assert_eq!(rows.len(), 1, "只有等了 10s 的那条才算悬空: {:?}", f);
        assert_eq!(v.dangling_count, 1);
    }

    /// `--no-views`（`Views::disabled()`）在收尾时**一行派生都不能产出**：
    /// 旧实现只把 `dangling_min_ms` 设成 `u64::MAX`，而 `finish()` 没读它。
    #[test]
    fn disabled_views_produce_nothing_at_finish() {
        let mut v = Views::disabled();
        let mut c = call(0, "t1", "Bash", Some("sleep 9"));
        v.observe(&mut c);
        let mut later = call(10 * S, "t2", "Read", Some("y"));
        v.observe(&mut later);
        assert!(v.finish().is_empty(), "disabled views leaked a derived row");
        assert_eq!(v.dangling_count, 0);
    }

    /// 工具名对不上任何 pending 的结果**不能**退到"最早的那条"：那会把一条
    /// Bash 结果配给一个 Read 调用（假造 gap、掩盖真正的 dangling）。
    #[test]
    fn a_result_of_a_different_tool_is_not_paired_with_the_oldest_pending() {
        let mut v = Views::new(ViewsConfig::default());
        let mut c = call(0, "t1", "Read", None);
        c.corr.tool_use_id = None;
        v.observe(&mut c);

        let mut r = result(5 * S, "t2", "Bash", "success");
        r.corr.tool_use_id = None;
        v.observe(&mut r);
        assert!(
            v.drain_derived().is_empty(),
            "wrong-tool pairing fabricated a gap/retry row"
        );

        let tail = v.finish();
        assert_eq!(v.dangling_count, 1, "Read 调用仍应悬空");
        assert!(tail.iter().any(|e| e.kind == Kind::DerivedToolDangling));

        // 同工具、都没有 id 时 FIFO 配对必须照旧工作。
        let mut v = Views::new(ViewsConfig::default());
        let mut c = call(0, "t1", "Read", None);
        c.corr.tool_use_id = None;
        v.observe(&mut c);
        let mut r = result(1 * S, "t2", "Read", "success");
        r.corr.tool_use_id = None;
        v.observe(&mut r);
        assert_eq!(v.finish().len(), 0, "同工具的无 id 结果没配上");
        assert_eq!(v.dangling_count, 0);
    }

    /// §10.3 楔形：Bash 说成功，但窗口内没有任何内核 connect。
    #[test]
    fn wedge_when_success_without_kernel_connect() {
        let mut v = views_with_kernel();
        let mut c = exact("t1", "curl -s https://example.com", 0);
        v.observe(&mut c);
        let mut r = exact_result(2 * S, "t1", "success");
        v.observe(&mut r);
        // 楔形是**关于整段运行**的断言，只能在收尾时下 —— 见 finish() 里的说明。
        let d = v.finish();
        assert!(
            d.iter().any(|e| e.kind == Kind::DerivedToolWedge
                && matches!(&e.payload, Payload::Derived { label, .. } if label.contains("wedge"))),
            "未报出楔形：{:?}",
            d
        );
        // 楔形不得再借用 gap 的 kind：两者的语义（因果 vs 时间）必须能按 kind 分开。
        assert!(
            !d.iter().any(|e| e.kind == Kind::DerivedToolGap),
            "楔形不能以 derived.tool.gap 报出：{:?}",
            d
        );
        assert_eq!(v.wedge_count, 1);
    }

    /// 造一个 View，并让它处于"内核源确实在采"的状态。
    /// 楔形断言的是"内核里没有对应的 connect"，所以必须先证明我们**在看**内核。
    fn views_with_kernel() -> Views {
        let mut v = Views::new(ViewsConfig {
            kernel_available: true,
            ..Default::default()
        });
        let mut k = call(0, "k0", "Bash", None);
        k.layer = Layer::Infra;
        k.kind = Kind::RuntimeProcExec;
        v.observe(&mut k);
        v.drain_derived();
        v
    }

    /// 在上面基础上，再给 agent 事件盖上"已确证绑定"——楔形正例需要这个前提。
    fn exact(id: &str, cmd: &str, ts: u64) -> Event {
        let mut e = call(ts, id, "Bash", Some(cmd));
        e.corr.pid_binding = Some(crate::event::Binding::Exact);
        e
    }

    fn exact_result(ts: u64, id: &str, status: &str) -> Event {
        let mut e = result(ts, id, "Bash", status);
        e.corr.pid_binding = Some(crate::event::Binding::Exact);
        e
    }

    /// 绑定为 None 时不得报楔形：看的树和会话没有证据链，
    /// "那棵树上没有 connect"说明不了这条命令的行为。
    #[test]
    fn no_wedge_when_binding_is_none() {
        let mut v = views_with_kernel();
        let mut c = call(0, "t1", "Bash", Some("curl -s https://example.com"));
        c.corr.pid_binding = Some(crate::event::Binding::None);
        v.observe(&mut c);
        let mut r = result(2 * S, "t1", "Bash", "success");
        r.corr.pid_binding = Some(crate::event::Binding::None);
        v.observe(&mut r);
        let _ = v.finish();
        assert_eq!(v.wedge_count, 0, "pid_binding=None 时不得下楔形结论");
    }

    /// **没有内核源时绝不报楔形。**
    ///
    /// 实测踩到：纯 `-S` 读 transcript 时，`git log` 这类纯本地命令被标成
    /// "报告成功但内核无 connect"。那次的"没看到 connect"只是因为**我们没在看内核** ——
    /// 把观测能力的缺失说成被观测对象的异常，是这类工具最不能犯的错。
    #[test]
    fn no_wedge_without_kernel_source() {
        // kernel_available 保持 false（纯 -S 运行）
        let mut v = Views::new(ViewsConfig::default());
        let mut c = call(0, "t1", "Bash", Some("curl -s https://example.com"));
        v.observe(&mut c);
        let mut r = result(2 * S, "t1", "Bash", "success");
        v.observe(&mut r);
        let _ = v.finish();
        assert_eq!(v.wedge_count, 0, "没有内核源时不得下楔形结论");
        assert!(!v.wedge_capable());
    }

    /// 采集器起来了但一条内核事件都没有时，同样不报楔形 —— 脚本加载失败、
    /// 目标进程已死都会造成这种局面，"没看到"依然是无信息的。
    #[test]
    fn no_wedge_when_zero_kernel_events() {
        let mut v = Views::new(ViewsConfig {
            kernel_available: true,
            ..Default::default()
        });
        let mut c = call(0, "t1", "Bash", Some("curl -s https://example.com"));
        v.observe(&mut c);
        let mut r = result(2 * S, "t1", "Bash", "success");
        v.observe(&mut r);
        let _ = v.finish();
        assert_eq!(v.wedge_count, 0, "内核事件数为 0 时不得下楔形结论");
    }

    /// **晚到的内核 connect 必须能推翻楔形。**
    ///
    /// 这是把判定挪到收尾的直接理由：agent 事件可能在内核事件之前到达
    /// （transcript 先落盘、采集器后起来）。受控实验里 agent 事件在 0~1s 到、
    /// 内核事件 67s 才到，增量判定那一刻 `kernel_events_seen == 0`，
    /// 于是"该报的没报"和"不该报的乱报"同时发生。
    #[test]
    fn late_kernel_connect_defeats_wedge() {
        let mut v = views_with_kernel();
        let mut c = exact("t1", "curl -s https://example.com", 0);
        v.observe(&mut c);
        let mut r = exact_result(S, "t1", "success");
        v.observe(&mut r);
        // result 之后内核事件才到 —— connect 落在 [call, result+1s] 窗口内
        let mut conn = result(S / 2, "c1", "Bash", "ok");
        conn.kind = Kind::InfraNetConnect;
        conn.layer = Layer::Infra;
        conn.payload = Payload::NetConnect {
            family: 2,
            family_name: "AF_INET".into(),
            addr: "93.184.216.34".into(),
            port: Some(443),
            ok: true,
            pending: false,
        };
        conn.corr.tool_use_id = None;
        v.observe(&mut conn);
        let d = v.finish();
        assert_eq!(v.wedge_count, 0, "晚到的 connect 应当推翻楔形：{:?}", d);
    }

    /// 纯本地命令不得被当成"本该联网"。判松了的代价是用户学会无视这个标记。
    #[test]
    fn local_git_subcommands_are_not_network() {
        for cmd in [
            "git log --oneline -5",
            "cd /repo && git status && git diff",
            "git commit -m x",
            "git branch -a",
            "cargo build --release",
            "cargo test",
            "npm run build",
            "ls -la /home",
            "echo \"curl http://x\"", // 引号里的不算
        ] {
            assert!(!expects_network(cmd), "误判为联网: {:?}", cmd);
        }
    }

    /// 真会联网的必须认出来，包括带 sudo / 环境变量前缀的写法。
    #[test]
    fn real_network_commands_are_detected() {
        for cmd in [
            "curl -s https://example.com",
            "wget http://x/y",
            "git fetch origin",
            "git push",
            "sudo curl -H 'A: b' http://x",
            "FOO=1 curl http://x",
            "cd /tmp && wget http://x",
            "timeout 5 ssh host uptime",
            "pip install requests",
            "npm install",
        ] {
            assert!(expects_network(cmd), "漏判为不联网: {:?}", cmd);
        }
    }

    /// 有内核 connect 时**不能**报楔形（否则就是狼来了）。
    #[test]
    fn no_wedge_when_kernel_connect_present() {
        let mut v = views_with_kernel();
        let mut c = exact("t1", "curl -s https://example.com", 0);
        v.observe(&mut c);
        let mut conn = result(1 * S, "c1", "Bash", "ok");
        conn.kind = Kind::InfraNetConnect;
        conn.layer = Layer::Infra;
        conn.payload = Payload::NetConnect {
            family: 2,
            family_name: "AF_INET".into(),
            addr: "93.184.216.34".into(),
            port: Some(443),
            ok: true,
            pending: false,
        };
        conn.corr.tool_use_id = None;
        v.observe(&mut conn);
        let mut r = exact_result(2 * S, "t1", "success");
        v.observe(&mut r);
        let d = v.finish();
        assert!(
            !d.iter()
                .any(|e| matches!(&e.payload, Payload::Derived{label,..} if label.contains("wedge")))
        );
        assert_eq!(v.wedge_count, 0);
    }

    /// 历史回放的 tool call 不得被判成楔形。
    ///
    /// 这是**假阳性**里最恶劣的一种：`-S` 读一份已有 transcript 时会把几十分钟前的
    /// 工具调用整个回放，它们的内核效应发生在采集器启动之前。不设这条边界，
    /// 每个历史 curl 都会变成一个"内核无效应"的指控 —— 实测报出过 4 个。
    #[test]
    fn wedge_does_not_fire_for_calls_before_kernel_collection() {
        // 不能用 views_with_kernel()：它在 0s 塞了一条内核事件，把观测窗口左边界
        // 钉死在 0s，本用例要验证的"窗口之前"就不存在了。这里自己建，且**不**预置
        // 任何内核事件 —— 窗口左边界完全由下面那条 100s 的内核事件决定。
        let mut v = Views::new(ViewsConfig {
            kernel_available: true,
            ..Default::default()
        });
        // 历史调用：0s 发出、1s 成功，那时还没开始看内核
        let mut c = exact("t1", "curl -s https://example.com", 0);
        v.observe(&mut c);
        let mut r = exact_result(1 * S, "t1", "success");
        v.observe(&mut r);
        // 内核采集 100s 才起来（这条事件同时定义了观测窗口左边界）
        let mut k = result(100 * S, "k1", "Bash", "ok");
        k.kind = Kind::InfraFileOpen;
        k.layer = Layer::Infra;
        k.payload = Payload::FileOpen {
            path: "/tmp/x".into(),
            flags: 0,
            dirfd: -100,
            path_is_relative: false,
            ok: true,
            errno: 0,
        };
        k.corr.tool_use_id = None;
        v.observe(&mut k);

        let d = v.finish();
        assert_eq!(v.wedge_count, 0, "观测窗口之前的历史调用被误报为楔形: {:?}", d);
        assert_eq!(
            v.wedge_skipped_precollection(),
            1,
            "放弃的候选数应被计数（-v 要看得见）"
        );
    }

    /// 边界内的调用仍然正常报楔形 —— 上面那条不能把功能整个关掉。
    #[test]
    fn wedge_still_fires_inside_kernel_window() {
        let mut v = views_with_kernel();
        // 内核先起来（定义窗口左边界）
        let mut k = result(10 * S, "k1", "Bash", "ok");
        k.kind = Kind::InfraFileOpen;
        k.layer = Layer::Infra;
        k.payload = Payload::FileOpen {
            path: "/tmp/x".into(),
            flags: 0,
            dirfd: -100,
            path_is_relative: false,
            ok: true,
            errno: 0,
        };
        k.corr.tool_use_id = None;
        v.observe(&mut k);
        // 之后才发生的调用，且窗口内确实没有 connect
        let mut c = exact("t1", "curl -s https://example.com", 20 * S);
        v.observe(&mut c);
        let mut r = exact_result(21 * S, "t1", "success");
        v.observe(&mut r);

        let d = v.finish();
        assert_eq!(v.wedge_count, 1, "窗口内的楔形漏报了: {:?}", d);
        assert_eq!(v.wedge_skipped_precollection(), 0);
    }

    #[test]
    fn watchlist_hits_file_rule() {
        let mut v = Views::new(ViewsConfig::default());
        let mut e = result(0, "x", "Read", "ok");
        e.kind = Kind::InfraFileOpen;
        e.layer = Layer::Infra;
        e.payload = Payload::FileOpen {
            path: "/home/viktor/.ssh/id_rsa".into(),
            flags: 0,
            dirfd: -100,
            path_is_relative: false,
            ok: true,
            errno: 0,
        };
        v.observe(&mut e);
        assert!(e.watch, "ssh 私钥读取未被标记");
        assert!(v.watch_count >= 1);
    }

    #[test]
    fn watchlist_hits_bash_rule() {
        let mut v = Views::new(ViewsConfig::default());
        let mut c = call(0, "t1", "Bash", Some("sudo rm -rf /var/tmp/x"));
        v.observe(&mut c);
        assert!(c.watch);
        // 同一目标第二次不重复报
        let n = v.watch_count;
        let mut c2 = call(S, "t2", "Bash", Some("sudo rm -rf /var/tmp/x"));
        v.observe(&mut c2);
        assert!(c2.watch);
        assert_eq!(v.watch_count, n, "同一目标重复报警了");
    }

    #[test]
    fn benign_tool_call_not_watched() {
        let mut v = Views::new(ViewsConfig::default());
        let mut c = call(0, "t1", "Bash", Some("cargo test --release"));
        v.observe(&mut c);
        assert!(!c.watch, "良性命令被误报");
    }
}
