//! 渲染层（DESIGN.md §4.2 / §4.3）。
//!
//! 输出保真承诺（§4.3）在这里落地：
//! - 时间线**不是**严格时间序 —— 用 `(late)` 如实标出；
//! - 每行自包含；
//! - 任何截断都必须能在行内或 `-v` 下被发现，**没有静默的丢失**。

pub mod json;
pub mod text;

use crate::event::{Binding, Event, Kind, Layer, Payload, errno_name};

#[derive(Debug, Clone)]
pub struct RenderOpts {
    pub color: bool,
    pub full: bool,
    pub verbose: bool,
}

impl Default for RenderOpts {
    fn default() -> Self {
        RenderOpts {
            color: false,
            full: false,
            verbose: false,
        }
    }
}

/// 是否 stdout 是 tty —— 非 tty（重定向/管道）时自动关色，避免日志里全是转义码。
pub fn stdout_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const DIM: &str = "\x1b[2m";

/// 计算所有事件共用的起始时间（第一条事件的墙钟），用于相对时间戳。
pub fn time_origin(events: &[Event]) -> Option<u64> {
    events.iter().filter(|e| e.ts_wall_ns > 0).map(|e| e.ts_wall_ns).min()
}

/// 该事件行应当带上的保真标记（§4.2）。
///
/// - `?` 尾缀 = 这条 **agent 行**没有被精确归因（`binding != Exact`，§3.5）
///   —— **绝不在绑不上的时候假装绑上了**
/// - `=` 尾缀 = 这条 **内核行**被 argv 精确绑到了某次 `tool.call`（§3.5 三级）
/// - `(late)` = agent 事件到达时已错过重排窗口（§2.4）
/// - `~` = 有字段被截断
/// - `!!` = watchlist 命中（§8 ⑤）
/// - `>>` = 疑似静默重试（§8 ④）
///
/// 标记一律用 ASCII：`↺`/`⚠` 是宽字形，在部分终端里宽度按 2 列算，
/// 会把后面的列整体推歪（§3 要的是**稳定的定宽列**）。
pub fn markers(ev: &Event) -> String {
    let mut s = String::new();
    if ev.late {
        s.push_str(" (late)");
    }
    if let Some(b) = ev.corr.pid_binding {
        // `?` 只加在 agent 层：内核事件的 pid 是从内核里读出来的，不存在"绑定"问题。
        if b.suffix() == "?" && ev.layer == Layer::Agent {
            s.push_str(" ?");
        }
    }
    // v0.3：内核行打 `=`。v0.2 之前内核行**没有**任何绑定信息可打（它们的 pid 是
    // 事实，但"属于哪次 tool.call"是空白），于是"exact binding"在默认视图里看不见。
    // 现在 argv 匹配给出了这个事实，它必须在默认视图里可见 —— 否则用户还是只能
    // 靠 `?` 的缺席去猜，而"没有标记"和"标记为无"在读起来是一样的。
    //
    // 折叠行（execvp/fork-burst）也算内核事实：它们是原始内核行的无损摘要。
    // 派生视图行（§8 的 `!!`）不算 —— 那些是 agtrace 的怀疑，不是内核说的。
    let kernelish = matches!(ev.layer, Layer::Runtime | Layer::Infra | Layer::Policy) || ev.is_collapse();
    if kernelish && ev.binding == Binding::Exact {
        s.push_str(" =");
    }
    if !ev.trunc.is_empty() {
        s.push_str(" ~");
    }
    if ev.retry {
        s.push_str(" >>");
    }
    if ev.watch {
        s.push_str(" !!");
    }
    s
}

/// 展开截断说明（`-v` / `--full` 下作为续行打印）。
pub fn trunc_detail(ev: &Event) -> Option<String> {
    if ev.trunc.is_empty() {
        return None;
    }
    let parts: Vec<String> = ev
        .trunc
        .iter()
        .map(|t| match (t.orig_bytes, &t.note) {
            (Some(o), Some(n)) => {
                format!("{}: {}->{} bytes ({})", t.field, o, t.kept_bytes, n)
            }
            (Some(o), None) => format!("{}: {}->{} bytes", t.field, o, t.kept_bytes),
            (None, Some(n)) => format!("{}: kept {} bytes ({})", t.field, t.kept_bytes, n),
            (None, None) => format!("{}: kept {} bytes", t.field, t.kept_bytes),
        })
        .collect();
    Some(format!("truncated: {}", parts.join("; ")))
}

/// 一行的事件正文（`layer` 之后的 `kind` + `payload` 部分）。
///
/// 长度只受 §1 的截断控制；这里不再二次截断 —— 静默的二次截断正是 §4.3 禁止的。
///
/// `budget` 是**这一行正文还剩多少显示列**（渲染器已经扣掉时间戳/列前缀/标记列）。
/// 除了 v0.3 的 bind 行，其它 payload 都忽略它、交给渲染器统一按 `~` 截断；
/// bind 行必须用它做**定向省略**，理由见 [`bind_line`]。
pub fn payload_line(ev: &Event, budget: usize) -> String {
    match &ev.payload {
        Payload::Prompt { text_preview, chars } => {
            format!("prompt \"{}\" ({} chars)", text_preview, chars)
        }
        Payload::PromptQueued { text_preview } => format!("queued \"{}\"", text_preview),
        Payload::ModelRequest {
            model,
            input_tokens,
            detail_preview,
        } => {
            // 不要把 kind 的名字再抄一遍当 payload —— 那个位置应当放**信息**。
            let mut p = vec![model.clone().unwrap_or_else(|| "(model unknown)".to_string())];
            if let Some(t) = input_tokens {
                p.push(format!("in={}", t));
            }
            if let Some(d) = detail_preview {
                p.push(format!("\"{}\"", d));
            }
            p.join("  ")
        }
        Payload::Thinking { preview, duration_ms } => match duration_ms {
            Some(d) => format!("\"{}\"  {}ms", preview, d),
            None => format!("\"{}\"", preview),
        },
        Payload::ModelText { preview } => format!("\"{}\"", preview),
        Payload::ModelUsage {
            model,
            input_tokens,
            output_tokens,
            cache_read,
            cost_usd,
        } => {
            let mut p = Vec::new();
            if let Some(m) = model {
                p.push(m.clone());
            }
            if let Some(i) = input_tokens {
                p.push(format!("in={}", i));
            }
            if let Some(o) = output_tokens {
                p.push(format!("out={}", o));
            }
            if let Some(c) = cache_read {
                p.push(format!("cache={}", c));
            }
            if let Some(c) = cost_usd {
                p.push(format!("cost=${:.4}", c));
            }
            if p.is_empty() {
                "usage".to_string()
            } else {
                p.join("  ")
            }
        }
        Payload::ToolCall {
            tool,
            input_preview,
            via_mcp,
            bash_cmd,
            ..
        } => {
            let name = if *via_mcp {
                // §8 ②：MCP 工具单独标注，别让它伪装成内置工具。
                format!("{} [mcp]", tool)
            } else {
                tool.clone()
            };
            match bash_cmd {
                // Bash 命令用引号包起来，因为它内部可能有空格/引号。
                Some(c) => format!("{}  cmd=\"{}\"", name, c),
                None => format!("{}  {}", name, input_preview),
            }
        }
        Payload::ToolResult {
            tool,
            status,
            result_preview,
        } => {
            let t = tool.as_deref().unwrap_or("?");
            format!("{}  {}  \"{}\"", t, status, result_preview)
        }
        Payload::SandboxDisabled { disabled } => {
            // §8.1：模型主动关沙箱是最强的越界前兆。
            format!("!! dangerouslyDisableSandbox={}", disabled)
        }
        Payload::ProcFork {
            child_pid,
            child_comm,
            parent_argv,
        } => {
            // §v0.2：内核只给得出 comm（`python`），而"哪个 python"才是用户要问的。
            // 父进程 argv 由 /proc 侧补齐；拿不到就**什么都不加**，不留空壳。
            match parent_argv {
                Some(a) => format!("fork -> {} ({})  <= \"{}\"", child_pid, child_comm, a),
                None => format!("fork -> {} ({})", child_pid, child_comm),
            }
        }
        Payload::ProcExec {
            filename,
            argv,
            argc_total,
        } => {
            let a = render_argv(argv);
            match argc_total {
                Some(n) if *n > argv.len() => format!("{}  argv={} ({} total)", filename, a, n),
                _ => format!("{}  argv={}", filename, a),
            }
        }
        Payload::ProcExecFail {
            filename,
            errno,
            errno_name,
            argv,
        } => {
            let a = if argv.is_empty() {
                String::new()
            } else {
                format!("  argv={}", render_argv(argv))
            };
            // 数字只在这里补一次：`errno_name` 是纯名字（未知时 `?`）——
            // 两边都补就会打出 `ENOENT(-2) (-2)`。
            let name = if errno_name == "?" {
                format!("ERRNO({})", errno)
            } else {
                format!("{}({}{})", errno_name, if *errno < 0 { "" } else { "+" }, errno)
            };
            format!("{}  {}{}", filename, name, a)
        }
        Payload::ProcExit { exit_code } => format!("exit({})", exit_code),
        Payload::FileOpen {
            path,
            flags,
            dirfd,
            path_is_relative,
            ok,
            errno,
        } => {
            let f = decode_openat_flags(*flags);
            let rel = if *path_is_relative {
                // §5.2 #2：相对路径无法还原成绝对路径 —— 不猜。
                format!(" (rel dirfd={}, absolute path unknown)", dirfd)
            } else {
                String::new()
            };
            // §5.1：只记录写意图、不记录写入内容。写意图必须在时间线上**看得见** ——
            // 否则"这个文件被改了"这个判断就得靠用户自己去读 flags 位。
            let w = if is_write_intent(*flags) {
                "  [write intent]"
            } else {
                ""
            };
            if *ok {
                format!("openat {}  {}{}{}", path, f, w, rel)
            } else {
                // v0.4：errno 是内核报的原始 `ret`，与 `exec_fail` 同一套命名。
                // `errno == 0` 只可能来自 v0.4 之前的 fixture —— 那时**不编造**名字
                // （写成 EACCES 会让人以为这是权限拒绝，而它可能只是 ENOENT）。
                if *errno == 0 {
                    format!("openat {}  {}=failed (errno not captured){}", path, f, rel)
                } else {
                    format!(
                        "openat {}  {}=failed {}({}){}",
                        path,
                        f,
                        errno_name(*errno),
                        errno,
                        rel
                    )
                }
            }
        }
        Payload::NetConnect {
            family_name,
            addr,
            port,
            ok,
            pending,
            ..
        } => {
            // AF_UNIX 没有地址，`addr` 本身就是"非IP族"的字面量。原来会渲染成
            // "connect 非IP族 (非 IP 族)" —— 同一件事说两遍。
            let target = match port {
                Some(p) => format!("{}:{}", addr, p),
                None => addr.clone(),
            };
            if *pending {
                // 非阻塞 connect 的正常返回。**不能**写成"失败"。
                format!("connect {}  {}  (in progress EINPROGRESS)", target, family_name)
            } else if *ok {
                format!("connect {}  {}", target, family_name)
            } else {
                format!("connect {}  {} failed", target, family_name)
            }
        }
        Payload::NetSendto { fd, len, peer } => match peer {
            Some(p) => format!("sendto fd={} len={} -> {}", fd, len, p),
            None => format!("sendto fd={} len={}", fd, len),
        },
        Payload::PolicyDeny {
            syscall,
            target,
            errno,
            decided_by,
            ..
        } => {
            let n = errno_name(*errno);
            format!("{} {}  {}({})  [decision:{}]", syscall, target, n, errno, decided_by)
        }
        Payload::LostEvents { count } => {
            format!("N={}  (kernel buffer overflow; this segment is incomplete)", count)
        }
        Payload::Derived { label, detail, count } => {
            if *count > 0 {
                format!("[{}] {}  (count={})", label, detail, count)
            } else {
                format!("[{}] {}", label, detail)
            }
        }
        // v0.2 折叠行：摘要本身就是正文。**不加 `[label]` 前缀** ——
        // kind 列已经写着 `execvp`/`fork-burst`，再加一层方括号只是把同一件事说两遍，
        // 而那 8 列在 120 列的预算里是拿"哪些探测被折叠了"换来的。
        Payload::Collapse { detail, calls, .. } => {
            if *calls > 1 {
                // 等价的并发调用合并成一行。次数必须**看得见**：读者要能分辨
                // "一次 execvp 探了 13 个目录"和"7 个进程各探了 13 个目录"。
                format!("{}, x{} calls", detail, calls)
            } else {
                detail.clone()
            }
        }
        // v0.3 §3.5 三级：这一行是"意图 == 实际执行"的**证据**。
        //
        // 形态刻意与 V03_PROMPT §3 给的例子一致：
        //   `tool.call Bash "curl -s -m 3 ..." <-> exec /bin/bash  (argv exact)`
        // 括号里是**真实用上的规则名**，不是"exact"这个褒义词 —— 模糊匹配会写成
        // `argv overlap 85%`，永远不会被念成 exact。
        Payload::Bind {
            tool,
            cmd_preview,
            exec_filename,
            rule,
            delta_ms,
            subtree_pids,
            ..
        } => bind_line(tool, cmd_preview, exec_filename, rule, *delta_ms, *subtree_pids, budget),
        // v0.4 §13：失败归因行。
        //
        // 形态与 V04_PROMPT 的例子一致：
        //   `tool.call Bash "ls /nonexistent..." -> exit 2 (deepest: openat /x ENOENT)`
        // 与 bind 行同样的取舍：`->` 之后的部分是**这一行存在的理由**，
        // 绝不能因为命令行太长而被截掉，所以命令从中间省略、尾部优先。
        Payload::Fail {
            tool,
            cmd_preview,
            class,
            head,
            deepest,
            kernel_events,
        } => fail_line(tool, cmd_preview, class, head, deepest.as_deref(), *kernel_events, budget),
    }
}

/// 渲染失败归因行（§13）。
///
/// `class` 不占列：它是 `head`/`deepest` 措辞的机器可读版本（`exit 2; unbound: ...`
/// 已经把类别说完了），再花一遍 120 列的预算等于把命令又挤掉一截。
/// 参数保留是为了让调用点与 json 字段一一对应，读者不必猜哪个字段没被渲染。
fn fail_line(
    tool: &str,
    cmd: &str,
    _class: &str,
    head: &str,
    deepest: Option<&str>,
    _kernel_events: u64,
    budget: usize,
) -> String {
    let prefix = format!("tool.call {} \"", tool);
    let deepest_seg = match deepest {
        Some(d) => format!(" (deepest: {})", d),
        None => String::new(),
    };
    let head_seg = format!("\" -> {}", head);
    let full = fit_fail(&prefix, cmd, &head_seg, &deepest_seg, budget);
    if full.contains(&head_seg) {
        return full;
    }
    // 整句放不下，退到紧凑版再来一次。**只在必要时退** —— 能说全就必须说全。
    let b = brief(head);
    if b == head {
        return full;
    }
    let brief_seg = format!("\" -> {}", b);
    let out = fit_fail(&prefix, cmd, &brief_seg, &deepest_seg, budget);
    if out.contains(&brief_seg) { out } else { full }
}

/// `head` 的紧凑版：砍掉尾部的括号限定语。
///
/// 约定（由 `fail.rs` 保证）：`head` 尾部的括号说的是**我们这一轮的观测条件**
/// —— `(no kernel event)`、`(this run had no kernel capture)`。这属于**运行级**
/// 事实：整轮没采内核的话，banner 和 footer 已经各说了一次，不必在每一行上
/// 再花 20 列重复，把命令和内核证据挤出 120 列之外。括号之外的部分（`BEFORE
/// exec: sandbox init failed`）才是**这条调用**的事实，一条都不能少。
///
/// 注意这与"结论必须完整"不冲突：完整句仍然在 footer 里逐字打印（那里的行首
/// 短得多），也在 json 的 `payload.head` 里。这里砍掉的只是**屏幕上的重复**。
fn brief(head: &str) -> &str {
    match head.find(" (") {
        Some(i) => &head[..i],
        None => head,
    }
}

/// 把 `prefix + "<cmd>" + head + deepest` 塞进 `budget` 列（§13.4）。
///
/// 分配顺序是**结论 > 证据 > 命令**，与 [`bind_line`] 同源但更强硬。理由：这个
/// 行式出现的每一个场合里，命令**都已经在紧挨着的地方**了 —— 时间线上它就是
/// 300ms 之前那条 `tool.call` 行，footer 里它就在同一行的引号当中。反过来，
/// `BEFORE exec:` 和 `openat ... ENOENT` **只在这里出现一次**；把它们挤掉，
/// 这一行就退化成"有个 Bash 失败了"，正是 §13 要消灭的东西。
///
/// 命令有地板（[`CMD_FLOOR`]）：一行连"是哪条命令"都认不出来时，读者没法把它
/// 和旁边那条 `tool.call` 对上号。地板之上的部分按 `CMD_PREFERRED` 给足。
fn fit_fail(prefix: &str, cmd: &str, head_seg: &str, deepest_seg: &str, budget: usize) -> String {
    /// 命令的理想列数：够看出是条什么命令（`ls /nonexistent-dir-abc`）。
    const CMD_PREFERRED: usize = 18;
    /// 命令的地板：再挤也要留下这么多，否则这一行定位不到任何东西。
    const CMD_FLOOR: usize = 8;

    let p = display_width(prefix);
    let h = display_width(head_seg);
    let d = display_width(deepest_seg);
    if p + h + d + CMD_PREFERRED <= budget {
        let c = budget - p - h - d;
        return format!("{}{}{}{}", prefix, elide_right(cmd, c), head_seg, deepest_seg);
    }
    if p + h + d + CMD_FLOOR <= budget {
        let c = budget - p - h - d;
        return format!("{}{}{}{}", prefix, elide_right(cmd, c), head_seg, deepest_seg);
    }
    // 命令已经到地板，还是塞不下：deepest 在行尾，先牺牲它 —— 但只在能留下
    // 一段**有用**的它时才牺牲（14 列以下连 `(deepest: ` 都放不下）。
    let room = budget.saturating_sub(p + CMD_FLOOR);
    if d > 0 && room > h + 14 {
        let dseg = elide_right(deepest_seg, room - h);
        if p + h + display_width(&dseg) + CMD_FLOOR <= budget {
            return format!("{}{}{}{}", prefix, elide_right(cmd, CMD_FLOOR), head_seg, dseg);
        }
    }
    // 最后只剩结论。
    format!(
        "{}{}{}",
        prefix,
        elide_right(cmd, CMD_FLOOR),
        elide_right(head_seg, room)
    )
}

/// 渲染 bind 证据行（§3.5）。
///
/// **预算必须花在刀刃上**：这一行里唯一"读者必须无条件相信"的部分是括号里的规则名
/// （它决定了要不要把这条链当事实）。如果按普通 payload 那样从头截断，一条长命令
/// 会把 `(argv exact)` 挤出行尾 —— 于是"精确"这两个字正好在需要它的那一行消失。
/// 所以这里**先给尾部留位置**，再把剩下的列数给命令行；命令被省略时用 `...`
/// 明示（完整值在 `--output json` 里，一行不丢）。
fn bind_line(
    tool: &str,
    cmd: &str,
    exec_filename: &str,
    rule: &str,
    delta_ms: u64,
    subtree_pids: u64,
    budget: usize,
) -> String {
    // 可执行文件从**左边**省：`/usr/local/lib/python3.11/bin/python3` →
    // `.../bin/python3`。尾巴（文件名本身）才是识别度所在。
    let file = elide_left(exec_filename, 28);
    let head = format!("tool.call {} \"", tool);
    // 尾部先预留：`" <-> exec <file> (<rule>)`
    let tail = format!("\" <-> exec {} ({})", file, rule);
    let mut out = String::with_capacity(budget);
    out.push_str(&head);
    let avail = budget.saturating_sub(display_width(&head) + display_width(&tail));
    // 命令行的最小可用列数；再挤就只剩 `"..."`，那还不如老实省略。
    if avail < 6 {
        out.push_str("...");
    } else {
        out.push_str(&elide_right(cmd, avail));
    }
    out.push_str(&tail);
    // 括号之后的口径：这一条链把多少个进程标成了 exact（1 = 只有它自己）。
    // 放在行尾，是因为它是**可被截掉的补充信息**；规则名绝不放这儿。
    if subtree_pids > 1 && display_width(&out) + 12 <= budget {
        out.push_str(&format!("  +{} pids", subtree_pids - 1));
    }
    let _ = delta_ms; // 时间差在 notes / json 里，默认行不花列数
    out
}

/// 从右侧省略到 `cols` 列以内，末尾补 `...`（省略是**可见**的）。
fn elide_right(s: &str, cols: usize) -> String {
    if display_width(s) <= cols {
        return s.to_string();
    }
    if cols <= 3 {
        let (cut, _) = truncate_display(s, cols);
        return cut;
    }
    let (cut, _) = truncate_display(s, cols - 3);
    format!("{}...", cut)
}

/// 从左侧省略到 `cols` 列以内，开头补 `...`。用于路径（保 basename）。
fn elide_left(s: &str, cols: usize) -> String {
    if display_width(s) <= cols {
        return s.to_string();
    }
    if cols <= 3 {
        let (cut, _) = truncate_display(s, cols);
        return cut;
    }
    // 先尽量保住 basename；basename 本身就超宽时按普通右侧省略处理。
    let base = s.rsplit('/').next().unwrap_or(s);
    let bw = display_width(base);
    if bw + 3 <= cols {
        return format!(".../{}", base);
    }
    // basename 太长：右边留 `...`，左边也留 `...`，中间是文件名的前半段。
    let keep = cols.saturating_sub(6);
    let (cut, _) = truncate_display(base, keep);
    format!("...{}...", cut)
}

fn render_argv(argv: &[String]) -> String {
    if argv.is_empty() {
        return "[]".to_string();
    }
    let inner: Vec<String> = argv
        .iter()
        .map(|a| {
            // 先做一行化再转义引号：内核里的 argv 可以含换行（`bash -c $'a\nb'`），
            // 原样输出会把一行事件撕成两行，定宽列和"一行一事件"一起失效（§3/§4.2）。
            let a = crate::event::one_line(a);
            format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\""))
        })
        .collect();
    format!("[{}]", inner.join(" "))
}

/// openat 的 flags 解码（§5.1：只关心"写意图"）。
///
/// 值取自 Linux `O_*` 常量（x86-64）。未知位**不丢弃**，以十六进制尾部附上 ——
/// 静默丢掉看不懂的位就等于假装自己懂了。
pub fn decode_openat_flags(flags: u64) -> String {
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_CREAT: u64 = 0o100;
    const O_EXCL: u64 = 0o200;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;
    const O_DIRECTORY: u64 = 0o200000;
    const O_NOFOLLOW: u64 = 0o400000;
    const O_CLOEXEC: u64 = 0o2000000;

    let mut v = Vec::new();
    let acc = flags & 0o3;
    match acc {
        O_WRONLY => v.push("O_WRONLY"),
        O_RDWR => v.push("O_RDWR"),
        _ => v.push("O_RDONLY"),
    }
    for (bit, name) in [
        (O_CREAT, "O_CREAT"),
        (O_EXCL, "O_EXCL"),
        (O_TRUNC, "O_TRUNC"),
        (O_APPEND, "O_APPEND"),
        (O_DIRECTORY, "O_DIRECTORY"),
        (O_NOFOLLOW, "O_NOFOLLOW"),
        (O_CLOEXEC, "O_CLOEXEC"),
    ] {
        if flags & bit != 0 {
            v.push(name);
        }
    }
    let known = O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    let unknown = flags & !known & !0o3;
    if unknown != 0 {
        v.push("O_?");
    }
    v.join("|")
}

/// 这个 openat 是否带"写意图"（§5.1：不记录写入内容，只记录写意图）。
pub fn is_write_intent(flags: u64) -> bool {
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;
    (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0
}

// ---------------------------------------------------------------
// 显示宽度（§3 可读性）
//
// 终端按**列**对齐，不按字节、也不按字符数：CJK 一个字占 2 列。用
// `s.len()`（字节）或 `s.chars().count()` 算预算，遇到中西混排的 payload
// 就会算错，最后表现为"某几行莫名其妙折行"。
//
// 不引 unicode-width：本项目的依赖只有 libc/serde/serde_json/toml。
// 这里只需要区分"宽/全角"与"零宽"两类，下面的简化表覆盖了 CJK、
// 全角形式与常见 emoji，行为可预测（宁可把窄的当宽的，也不要反过来 ——
// 把宽的当窄的会导致行真的超宽）。
// ---------------------------------------------------------------

/// 一个字符占几列。
pub fn char_width(c: char) -> usize {
    let u = c as u32;
    // 零宽：组合记号、变体选择符、零宽空格/连接符。
    if (0x0300..=0x036F).contains(&u) || (0x200B..=0x200F).contains(&u) || (0xFE00..=0xFE0F).contains(&u) || u == 0x200D
    {
        return 0;
    }
    let wide = matches!(u,
        0x1100..=0x115F      // Hangul Jamo 初声
        | 0x2E80..=0x303E    // CJK 部首 / 康熙部首 / CJK 符号（含 U+3000 全角空格）
        | 0x3041..=0x33FF    // 平假名 / 片假名 / 注音 / CJK 兼容
        | 0x3400..=0x4DBF    // CJK 扩展 A
        | 0x4E00..=0x9FFF    // CJK 基本区
        | 0xA000..=0xA4CF    // 彝文
        | 0xA960..=0xA97F    // Hangul Jamo 扩展 A
        | 0xAC00..=0xD7A3    // Hangul 音节
        | 0xF900..=0xFAFF    // CJK 兼容表意文字
        | 0xFE10..=0xFE19    // 竖排标点
        | 0xFE30..=0xFE6F    // CJK 兼容形式
        | 0xFF00..=0xFF60    // 全角 ASCII
        | 0xFFE0..=0xFFE6    // 全角符号
        | 0x1F300..=0x1F64F  // emoji
        | 0x1F680..=0x1F6FF
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x3FFFD  // CJK 扩展 B 及以上
    );
    if wide { 2 } else { 1 }
}

/// 字符串的显示列数（不是字节数，也不是字符数）。
pub fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// 按**显示列**截断。绝不切开一个 UTF-8 序列，也绝不把一个宽字符切成半个。
/// 返回 (截断后的串, 是否发生了截断)。
pub fn truncate_display(s: &str, max_cols: usize) -> (String, bool) {
    if display_width(s) <= max_cols {
        return (s.to_string(), false);
    }
    let mut out = String::new();
    let mut w = 0usize;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw > max_cols {
            return (out, true);
        }
        out.push(c);
        w += cw;
    }
    (out, true)
}

/// §3：默认一行最多 120 列。超过就按显示列截断并补 `~`，**绝不折行** ——
/// 折行会破坏 strace 式定宽列，让纵向扫读失效。
pub const MAX_COLS: usize = 120;

/// 把**一行**按 MAX_COLS 截断（超宽时补 `~`）。用于横幅、注记与统计行 ——
/// 上限只对时间线成立、对错误信息不成立的话，用户还是会被折行烦到。
pub fn cap_cols(s: &str) -> String {
    if display_width(s) <= MAX_COLS {
        return s.to_string();
    }
    let (cut, _) = truncate_display(s, MAX_COLS - 1);
    format!("{}~", cut)
}

/// 逐行套用 cap_cols（横幅与统计行都是多行字符串）。
pub fn cap_lines(s: &str) -> String {
    s.split('\n').map(cap_cols).collect::<Vec<_>>().join("\n")
}

/// 注记行（banner notes）专用的截断。
///
/// 与事件行的 `~` 不同：注记经常是**保真度声明**（比如 pid_binding 为什么绑不上），
/// 用 `~` 在词中间切断会读成"话说了一半就没了"，恰好毁掉它存在的意义。
/// 所以这里退到词边界，并在行尾明确指向 `-v` 里的完整版本 —— 截断可以，
/// 静默地截断并让人以为那就是全部，不行。
pub fn cap_note(s: &str) -> String {
    if display_width(s) <= MAX_COLS {
        return s.to_string();
    }
    const TAIL: &str = " ... (full text under -v)";
    let budget = MAX_COLS.saturating_sub(display_width(TAIL));
    let (mut cut, _) = truncate_display(s, budget);
    if let Some(i) = cut.rfind(' ') {
        cut.truncate(i);
    }
    format!("{}{}", cut, TAIL)
}

pub fn layer_str(ev: &Event) -> String {
    // v0.2：折叠行写 `derived`，而不是 §8 视图行的 `!!`。
    //
    // 两者都不是内核原始行，但性质相反：`!!` 是**怀疑**（"内核里没看到 connect，
    // 但命令说成功了"），折叠行是**摘要**（那 13 条 exec_fail 真的发生过，一条没丢，
    // `-v` 和 `--output json` 里都在）。用同一个记号会让读者按怀疑去读摘要 ——
    // 而 `!!` 一旦失去"这里有可疑之处"的含义，§8 的告警也就跟着贬值。
    //
    // v0.3 的 bind 行同理：它是"intent 与 reality 是同一条命令"这个**判断本身**，
    // 同样不是怀疑。
    //
    // v0.4 的失败归因行是唯一的例外：它写 `XX` 而不是 `derived`。归因行与其它摘要行
    // 的性质一样（都是 agtrace 推出来的事实），但它的**用途**不同 —— 这一列是给人
    // 竖向扫"哪几行失败了"用的，`derived` 这个词在满屏摘要里扫不出来，`XX` 可以。
    // 与 `!!`（怀疑）/`??`（绑不上）一样是两个 ASCII 字符，宽度稳定、各终端一致。
    let s = if ev.kind == Kind::DerivedFail {
        "XX"
    } else if ev.renders_as_derived() {
        "derived"
    } else {
        ev.layer.as_str()
    };
    format!("{:<8}", s)
}

pub fn colorize(opts: &RenderOpts, color: &str, s: &str) -> String {
    if opts.color {
        format!("{}{}{}", color, s, RESET)
    } else {
        s.to_string()
    }
}
