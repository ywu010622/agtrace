//! agtrace —— 让 Agent 的行为像系统调用一样可调试。
//!
//! 主循环（DESIGN.md §3.1）：**不引入 tokio**。内核采集器与 agent adapter 都是
//! 非阻塞 poll，2ms 轮询一次，Merger 用 min-heap 窗口兜住乱序。

mod adapter;
mod binding;
mod cli;
mod collapse;
mod collector;
mod event;
mod exact;
mod fail;
mod merger;
mod poll;
mod redact;
mod render;
mod views;

use cli::{Cli, OutputMode, Parsed};
use collapse::{CollapseCfg, Collapser};
use collector::Collector;
use collector::bpftrace::{BpftraceCollector, SourceFilter, Target, scan_descendants};
use event::Binding;
use fail::{FailAttributor, FailCfg};
use merger::Merger;
use poll::PollOutcome;
use render::RenderOpts;
use render::text::{Header, Summary, TextRenderer};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use views::{Views, ViewsConfig};

const BPF_TEMPLATE: &str = include_str!("../scripts/agtrace.bt");
/// 轮询间隔。内核事件靠 min-heap 窗口兜底，2ms 的调度延迟可以接受（§3.1）。
const POLL_INTERVAL: Duration = Duration::from_millis(2);

static QUIT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    // 只用 async-signal-safe 的操作。真正的清理在主循环退出后做。
    QUIT.store(true, Ordering::SeqCst);
}

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let cli = match cli::parse(args) {
        Ok(Parsed::Help(h)) => {
            print!("{}", h);
            return 0;
        }
        Ok(Parsed::Version) => {
            println!("agtrace {}", cli::VERSION);
            return 0;
        }
        Ok(Parsed::Run(c)) => *c,
        Err(e) => {
            eprintln!("agtrace: argument error: {}", e);
            return 2;
        }
    };

    install_signal_handlers();

    match run_inner(&cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("agtrace: {}", e);
            1
        }
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}

fn run_inner(cli: &Cli) -> Result<(), String> {
    let opts = RenderOpts {
        color: !cli.no_color && render::stdout_is_tty(),
        full: cli.full,
        verbose: cli.verbose,
    };

    // ---------------- 派生视图配置 ----------------
    let mut vcfg = ViewsConfig {
        // 有 `-p`/`-C` 才有内核源。纯 `-S` 读 transcript 时，"内核里没有看到 X"
        // 只是因为**我们没在看内核** —— 那种推断必须整条关掉（见 views.rs 楔形部分）。
        kernel_available: cli.pid.is_some() || cli.cgroup.is_some(),
        gap_ms: cli.gap_ms,
        retry_window_ms: cli.retry_window_ms,
        enable_gap: !cli.no_views,
        enable_retry: !cli.no_views,
        enable_watch: !cli.no_views,
        ..Default::default()
    };
    if let Some(path) = &cli.watchlist {
        let n = Views::load_toml(path, &mut vcfg)?;
        eprintln!(
            "agtrace: loaded {} watchlist rule(s) from {} (appended after the built-in rules)",
            n, path
        );
    }
    // `--no-views` 不是"把三个开关设 false"这么简单：gap/retry/watch 之外还有
    // dangling（收尾必发）和楔形判定，漏掉一个就会在 --no-views 下冒出派生行。
    // 统一走 disabled()，语义只有一个来源。
    let views = if cli.no_views {
        Views::disabled()
    } else {
        Views::new(vcfg)
    };

    // ---------------- 时钟 / Merger ----------------
    let mut merger = Merger::new(cli.merge_window_ms, cli.resync_secs, views);

    // ---------------- 内核采集器 ----------------
    let sources = cli.source.clone().unwrap_or_else(SourceFilter::all);
    let mut collector: Option<BpftraceCollector> = None;
    let mut target_desc = String::new();
    // v0.2：这些进程在 attach 之前就已经 exec 完了，内核不会再把那次 exec 报给我们。
    // 但它们的 fork 行同样要回答"这是哪个 python？"，所以先把 /proc 里的命令行抄下来。
    let mut seed_pids: Vec<u32> = Vec::new();

    if let Some(pid) = cli.pid {
        // 先确认进程真的存在 —— 否则 bpftrace 会安静地 attach 到空集合上，
        // 用户看到的是一条空时间线，会误以为"这个进程什么也没干"。
        if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
            return Err(format!(
                "pid {} does not exist or is not visible (/proc/{}/ is unreadable); check the process id",
                pid, pid
            ));
        }
        let seeds = scan_descendants(pid);
        seed_pids = seeds.clone();
        target_desc = format!("pid {} (tree, {} initial members)", pid, seeds.len());
        let target = Target::PidTree { root: pid, seeds };
        let c = BpftraceCollector::spawn(
            BPF_TEMPLATE,
            &target,
            cli.argv_max,
            cli.file_all,
            &sources,
            cli.redact,
            None,
        )
        .map_err(|e| e.to_string())?;
        collector = Some(c);
    } else if let Some(path) = &cli.cgroup {
        let id = collector::bpftrace::cgroup_path_to_id(path)?;
        target_desc = format!("cgroup {} (id {})", path, id);
        let target = Target::Cgroup { path: path.clone(), id };
        let c = BpftraceCollector::spawn(
            BPF_TEMPLATE,
            &target,
            cli.argv_max,
            cli.file_all,
            &sources,
            cli.redact,
            None,
        )
        .map_err(|e| e.to_string())?;
        collector = Some(c);
    }
    if let Some(c) = collector.as_mut() {
        c.keep_script = cli.keep_script;
    }

    // ---------------- v0.2 折叠器 ----------------
    //
    // 位置：merger **之后**、渲染**之前**。放这里的理由：
    // - merger 保持纯粹（它只负责"把乱序的事件排成近似时间序"），可单测；
    // - 10ms 的 fork 突发窗口完全落在 200ms 的重排窗口内，不需要额外的等待；
    // - 折叠需要的 `watch`/`retry` 标记是 views 在 merger 里盖的章，到这一步已经齐了 ——
    //   顺序反过来会拿不到标记，于是把 watchlist 命中的行也折叠掉（安全视图失效）。
    let collapse_cfg = CollapseCfg {
        // `--no-collapse` 恢复原始行；`--output json` 永远无损 ——
        // 折叠是**呈现**选择，json 是给下游算的，里面只能有原始事件（铁律）。
        enabled: !cli.no_collapse && cli.output == OutputMode::Text,
        verbose: cli.verbose,
        // 身份标注是给一行**加**信息（"这是哪个 python"），不是把多行合成一行，
        // 所以 json 里也留着：它不违反无损原则，而下游同样需要这个答案。
        identity: !cli.no_collapse,
        // 折叠器看到的事件固定落后墙钟一个 merger 重排窗口，分组窗口必须按这个
        // 差额校准，否则"10ms 内的 fork"永远判成早就过期（实测：一条都折不了）。
        stream_lag_ns: cli.merge_window_ms.saturating_mul(1_000_000),
    };
    let mut collapser = Collapser::new(collapse_cfg);
    collapser.seed_procs(&seed_pids);

    // ---------------- v0.4 失败归因（§13）----------------
    //
    // 位置：binder **之后**（内核行要带上 `corr.tool_use_id` 才谈得上"挂住的子树"）、
    // collapser **之后**（归因要解释屏幕上那个折叠过的世界）、renderer **之前**。
    let fail_cfg = FailCfg {
        only: cli.failures_only,
        // "内核**没在采集**"和"内核采集了但这条调用没有事件"是两件完全不同的事，
        // 后者才有资格说"内核里没有 X"。判据是**这一轮有没有开内核维度**，
        // 不是"收到了几条内核事件" —— 后者会把 `--source agent` 下的
        // "我们没看 exec" 说成"exec 没发生"。
        kernel_available: collector.is_some() && sources.any_kernel(),
        // 挂起一条失败后等多久，才允许说"内核里没有它的足迹"：取重排窗口 ——
        // 合并器保证的是"ts 比水位线早一个窗口以上的内核事件都已放出"（§13.5）。
        settle_ns: cli.merge_window_ms.saturating_mul(1_000_000),
    };
    let mut failer = FailAttributor::new(fail_cfg);

    // 内核采集没有自然 EOF —— 不说清楚的话用户会以为它卡住了。
    // 折成两行是为了守住"默认输出不超过 120 列"这条：这条注记和事件行一样会落到
    // 用户的终端里，一个照 120 列摆的窗口不该被它顶出折行。
    if collector.is_some() && !cli.follow {
        eprintln!(
            "agtrace: note — kernel capture (bpftrace) has no natural end.\n\
             agtrace: without -f, bound the run with --duration or --max-events."
        );
    }

    // ---------------- agent adapter ----------------
    let mut adapters: Vec<Box<dyn adapter::EventAdapter>> = Vec::new();
    let mut session_desc: Option<String> = None;
    let mut bind_session_id: Option<String> = None;
    let mut bind_cwd: Option<String> = None;
    let mut transcript_path: Option<String> = None;

    if let Some(src) = &cli.session {
        match cli.adapter.as_str() {
            "claude-code" => {
                let cfg = adapter::claude_code::AdapterCfg {
                    tool_arg_max: cli.tool_arg_max,
                    bash_cmd_max: cli.bash_cmd_max,
                    redact: cli.redact,
                };
                let mut a =
                    adapter::claude_code::ClaudeCodeAdapter::new(src, cfg, cli.follow).map_err(|e| e.to_string())?;
                // 启动时校验（§5.4 #4）：格式变了就直接报错，别产出空事件流。
                a.validate().map_err(|e| e.to_string())?;
                session_desc = Some(match &a.session_id {
                    Some(s) => s.chars().take(8).collect::<String>(),
                    None => src.clone(),
                });
                bind_session_id = a.session_id.clone();
                bind_cwd = a.cwd.clone();
                transcript_path = Some(a.path().display().to_string());
                adapters.push(Box::new(a));
            }
            "openshell" => {
                let a = adapter::openshell::OpenShellAdapter::new(src, cli.time_base, cli.tool_arg_max)
                    .map_err(|e| e.to_string())?;
                // fixture 没有真正的会话标识，硬凑一个只会在表头里产生噪声。
                target_desc = format!("openshell fixture {}", file_basename(src));
                adapters.push(Box::new(a));
            }
            other => {
                return Err(format!(
                    "unknown --adapter `{}` (available: claude-code | openshell)",
                    other
                ));
            }
        }
    }

    // ---------------- pid 绑定（§3.5）----------------
    let bind = binding::resolve(cli.pid, bind_session_id.as_deref(), bind_cwd.as_deref(), None);

    // ---------------- v0.3 argv 级绑定（§3.5 三级）----------------
    //
    // 位置：merger **之后**、折叠**之前**。三条理由：
    // - merger 之后：匹配的时间窗判定依赖 `ts_ns` 单调有序，乱序流会误判；
    // - 折叠之前：折叠行继承源行的 `binding`，先绑后折，`execvp` 摘要行才能带上 `=`；
    //   反过来先折就把被绑定的进程行藏进摘要里，绑定信息随之消失；
    // - 渲染之前：绑定是**判断**不是呈现 —— 它要说"这条内核事实属于哪次 tool.call"，
    //   所以 `--output json` 里必须原样存在（V03_PROMPT §5）。与折叠不同，
    //   它**不因 json 模式而关闭**，只有 `--no-bind` 关得掉。
    let mut binder = exact::ExactBinder::new(!cli.no_bind);

    // ---------------- 渲染器 ----------------
    // 只列**实际启用**的源：没有内核采集器时列 exec/file/net 是骗人的。
    let source_names: Vec<String> = {
        let mut v = Vec::new();
        if !adapters.is_empty() && sources.agent {
            v.push("agent".to_string());
        }
        if collector.is_some() {
            if sources.exec {
                v.push("exec".into());
            }
            if sources.file {
                v.push("file".into());
            }
            if sources.net {
                v.push("net".into());
            }
        }
        v
    };

    let mut notes: Vec<String> = Vec::new();
    if let Some(p) = &transcript_path {
        notes.push(format!("transcript: {}", p));
    }
    if cli.adapter == "openshell" {
        notes.push(format!(
            "openshell fixture: --time-base={} (relative seconds); no OS process tree, \
             so pid_binding is none",
            cli.time_base.as_str()
        ));
    }
    // 只有**真的需要绑定**的 adapter（Claude Code transcript）才谈绑定这件事。
    // openshell fixture 与 OS 进程树无关，对它输出一条"绑不上"的警告是噪声。
    let needs_binding = adapters.iter().any(|a| a.capabilities().needs_pid_binding);
    if needs_binding && bind.level != Binding::Exact {
        notes.push(format!("pid_binding={}: {}", bind.level.as_str(), bind.explanation));
    } else if needs_binding {
        // Exact 也要说清楚绑到了谁 —— 用户需要能自己去核对。
        if let Some(p) = bind.pid {
            notes.push(format!("pid_binding=exact -> pid {} ({})", p, bind.explanation));
        }
    }
    if cli.redact == redact::RedactMode::Argv {
        notes.push(
            "--redact argv: command-line credentials masked; agent-layer text \
             (prompt/thinking/tool results) is NOT masked"
                .into(),
        );
    }
    if cli.failures_only {
        // 剪枝模式下的 `--- N events` 和 `--- span` 描述的是**过滤后**剩下的行。
        // 不说这一句，读的人会把 "12 events" 当成整条会话的规模，
        // 把 fail 那一段的相对时间当成会话的第一个动作。
        notes.push(
            "--failures-only: only failing tool.call chains are shown; the event counts below \
             describe the rows that survived the filter, while the span and the failure times \
             stay session-relative"
                .into(),
        );
    }

    let header = Header {
        target: if target_desc.is_empty() {
            session_desc.clone().unwrap_or_else(|| "-".into())
        } else {
            target_desc.clone()
        },
        session: session_desc.clone(),
        binding: if needs_binding { Some(bind.level) } else { None },
        sources: source_names.clone(),
        following: cli.follow,
        notes,
    };

    let mut text_renderer = TextRenderer::new(opts.clone());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    write_out(&mut out, cli, &text_renderer.header(&header))?;

    // ---------------- 主循环 ----------------
    let start = Instant::now();
    let mut summary = Summary {
        binding: if needs_binding { Some(bind.level) } else { None },
        session: session_desc.clone(),
        ..Default::default()
    };
    let mut agent_eof: Vec<bool> = vec![false; adapters.len()];
    let mut total_out: u64 = 0;
    let mut truncated_by_limit = false;
    let mut collector_failed: Option<String> = None;

    loop {
        if QUIT.load(Ordering::SeqCst) {
            break;
        }
        if let Some(d) = cli.duration_secs {
            if start.elapsed() >= Duration::from_secs(d) {
                break;
            }
        }
        if let Some(m) = cli.max_events {
            if total_out >= m {
                truncated_by_limit = true;
                break;
            }
        }

        // --- 内核 ---
        let mut kdone = collector.is_none();
        if let Some(c) = collector.as_mut() {
            let mut evs = Vec::new();
            match c.poll(&mut evs) {
                Ok(PollOutcome::Eof) => kdone = true,
                Ok(_) => kdone = c.exited(),
                Err(e) => {
                    let msg = e.to_string();
                    // 采集器挂了必须**在时间线里**留下痕迹：只打到 stderr 的话，
                    // 事后看时间线的人会以为这段时间"什么都没发生"（§4.3）。
                    merger.push_collector_end(&msg);
                    collector_failed = Some(msg);
                    kdone = true;
                }
            }
            for ev in evs {
                // §4.1 --source 的 Rust 侧兜底过滤（脚本侧已按同一组开关裁剪，
                // 这里是双保险，防止脚本模板出偏差时漏出不该有的 kind）。
                if sources.allows(ev.kind) {
                    merger.push_kernel(ev);
                }
            }
        }

        // --- agent ---
        for (i, a) in adapters.iter_mut().enumerate() {
            if agent_eof[i] {
                continue;
            }
            let mut evs = Vec::new();
            match a.poll(&mut evs) {
                Ok(PollOutcome::Eof) => agent_eof[i] = true,
                Ok(_) => {}
                Err(e) => {
                    eprintln!("agtrace: adapter {} failed, stopping this source: {}", a.id(), e);
                    agent_eof[i] = true;
                }
            }
            // 只有声明 needs_pid_binding 的 adapter 才盖章 —— 给一个与进程树无关的
            // fixture 盖上 binding 标记，等于凭空制造一个不存在的关联。
            let stamp = a.capabilities().needs_pid_binding;
            for mut ev in evs {
                if stamp {
                    // 在这里盖章而不是在 adapter 里：绑定是 merger/main 层的知识。
                    ev.corr.pid_binding = Some(bind.level);
                    ev.corr.pid_root = cli.pid;
                    // v0.3：每条 agent 行的归因等级先按会话级填上。
                    // tool.call 级的证据由 exact.rs 在有匹配时**升级**为 exact
                    // （那要有 exec 才知道），所以这里是"兜底"不是"结论"。
                    ev.binding = bind.level;
                }
                merger.push_agent(ev);
            }
        }

        merger.clock.maybe_resync();
        merger.flush_due();

        let ready = merger.take_ready();
        if !ready.is_empty() {
            // `--max-events` 数的是**采集到的**事件，不是打印出来的行数：
            // 折叠改变的是呈现，不该顺手把上限也改掉（否则同样的参数在
            // 折叠开关两边的采集量会不一样，成了"显示影响了采集"）。
            total_out += ready.len() as u64;
            // v0.3：先绑（可能插入 bind 证据行），再折。两步都只改呈现与标记，
            // 不改 `total_out` —— 上限数的始终是**采集到的**事件。
            let bound = binder.process(ready);
            let shown = collapser.process(bound, merger::mono_now_ns());
            // v0.4：归因行紧跟在它解释的那条 `tool.result` 之后（同 ts，所以
            // 时间序不回退）；`--failures-only` 下这里同时完成"只放行失败链"的剪枝。
            let shown = failer.process(shown);
            if !shown.is_empty() {
                // 统计的是**用户看得见的那条时间线**：`--- N events` 与逐层计数
                // 必须与屏幕上的行对得上，否则它就是一句无法核对的话。
                for e in &shown {
                    summary.observe(e);
                }
                // 剪枝模式下的时间原点必须在**第一次输出之前**钉死，否则
                // `4.995s` 那条失败会被渲染成 `0.000s`（见 `lock_origin`）。
                lock_origin_if_filtered(cli, &failer, &mut text_renderer);
                match cli.output {
                    OutputMode::Text => text_renderer.write_batch(&mut out, &shown),
                    OutputMode::Json => render::json::write_batch(&mut out, &shown),
                }
                .map_err(|e| e.to_string())?;
                out.flush().map_err(|e| e.to_string())?;
            }
        }

        // 采集器自报的诊断（时钟假设不成立、丢包统计等），只报一次。
        if !merger.warnings.is_empty() {
            for w in merger.warnings.drain(..) {
                eprintln!("agtrace: {}", render::cap_cols(&w));
            }
        }

        // --- 退出判定 ---
        //
        // `can_follow` 必须**每轮重算**，不能在启动时定一次。原因：bpfrace 可能
        // 因为脚本加载失败、权限不足、内核不认 probe 而在几秒内就退出。启动时
        // 定死的 can_follow 仍是 true，`-f` 就会永远空转 —— 时间线停在第一行，
        // 用户看到的是"卡住了"，而不是"采集器已经死了"。这个 bug 在验收 #1 里
        // 真实发生过：进程树跑完、bpftrace 已退出，agtrace 还在 loop 里等。
        let can_follow = (collector.is_some() && !kdone)
            || adapters
                .iter()
                .zip(agent_eof.iter())
                .any(|(a, eof)| !eof && a.capabilities().live);
        let adone = agent_eof.iter().all(|x| *x);
        if kdone && adone && (!cli.follow || !can_follow) {
            break;
        }

        std::thread::sleep(POLL_INTERVAL);
    }

    // ---------------- 收尾 ----------------
    merger.flush_all();
    // 收尾顺序要紧：先 `process` 把能放的行放掉，再 `finish` 给未决分组定格
    //（"没有等到成功 exec"这个结论只有在流真的结束了才能下）。两段拼接天然有序。
    let end_now = merger::mono_now_ns();
    // 收尾也要过绑定器：最后一批里可能正躺着那条被匹配的 exec。
    // 顺序：先 `process` —— 它把上一批暂缓的后缀放行在这一批的**前面**，并在本批
    // 末尾重新暂缓一段后缀；再 `finish` 交出那一段。它是全流最新的行，所以接在
    // **后面**。
    let mut tail_evs = binder.process(merger.take_ready());
    tail_evs.extend(binder.finish());
    let mut tail = collapser.process(tail_evs, end_now);
    tail.extend(collapser.finish(end_now));
    // 收尾批一样要过归因器：最后一条 `tool.result` 常常正躺在这里
    //（会话在最后一次失败之后立刻结束，是最常见的收尾形状）。
    let tail = failer.process(tail);
    let tail = {
        let mut t = tail;
        t.extend(failer.finish());
        t
    };
    if !tail.is_empty() {
        for e in &tail {
            summary.observe(e);
        }
        lock_origin_if_filtered(cli, &failer, &mut text_renderer);
        match cli.output {
            OutputMode::Text => {
                let _ = text_renderer.write_batch(&mut out, &tail);
            }
            OutputMode::Json => {
                let _ = render::json::write_batch(&mut out, &tail);
            }
        }
    }

    if let Some(c) = collector.as_mut() {
        let lost = c.lost_events();
        let unfinished = c.unfinished_line_bytes();
        if unfinished > 0 {
            // 输出在行中间被截断 —— 这行**没有被解析**，必须让用户知道。
            eprintln!(
                "agtrace: collector output ends with {} bytes of an unfinished line (truncated, not parsed)",
                unfinished
            );
        }
        c.shutdown();
        if lost > 0 {
            eprintln!(
                "agtrace: collector reported {} perf-buffer lost event(s) (marked in the timeline as !! lost_events rows)",
                lost
            );
        }
    }
    for a in adapters.iter_mut() {
        a.shutdown();
    }

    // ---------------- 统计与诊断 ----------------
    let cs = collapser.stats();
    let bs = binder.stats();
    // 屏幕上的折叠行数 = 定案的组数 − 被合并掉的等价行数（每个合并少打一行）。
    // 用 `stats` 而不是数屏幕，是为了让这个数字**来自折叠器本身**，
    // 而不是来自"我们事后觉得打了几行"。
    summary.collapse_rows =
        (cs.execvp_resolved + cs.execvp_not_found + cs.fork_bursts).saturating_sub(cs.execvp_merged);
    summary.collapse_raw = cs.raw_events_replaced;
    // v0.4：失败账交给收尾段。搬走而不是 clone —— 这是最后一次读它。
    summary.failures = std::mem::take(&mut failer.failures);
    summary.kernel_available = fail_cfg.kernel_available;
    // 结论是**等到证据才下**的（§13.5），所以入账顺序是"何时定论"而不是"何时失败"：
    // 一条早早失败但等到流尾才定论的调用，会排在它后面才失败的调用之后。
    // 收尾段按时间读，这里就按时间排。
    summary.failures.sort_by_key(|f| (f.ts_wall_ns, f.ts_ns));
    // 时间基准统一到**会话**的两端。默认模式下这与逐行统计出来的
    // first/last 完全相同（归因器看到的就是同一批行）；`--failures-only` 下
    // 它把 span 和失败时间从"只剩下失败的那 79ms"拉回真正的会话跨度 ——
    // 否则 footer 会打出 `0.079s`（相对第一条**活下来的**行）而时间线打出
    // `4.615000`（相对会话起点），同一个事实两个时间。
    if let Some(w) = failer.origin_wall() {
        summary.first_wall = Some(w);
    }
    if let Some(w) = failer.end_wall() {
        summary.last_wall = Some(w);
    }
    let attributed = summary.failures.iter().filter(|f| f.deepest.is_some()).count();

    let extra = serde_json::json!({
        "late": merger.late_count,
        "collapse": {
            "enabled": collapse_cfg.enabled,
            "execvp_resolved": cs.execvp_resolved,
            "execvp_not_found": cs.execvp_not_found,
            "execvp_merged_calls": cs.execvp_merged,
            "fork_bursts": cs.fork_bursts,
            "raw_events_replaced": cs.raw_events_replaced,
            "identity_hits": cs.identity_hits,
        },
        "views": {
            "gap": merger.views.gap_count,
            "retry": merger.views.retry_count,
            "dangling": merger.views.dangling_count,
            "watchlist": merger.views.watch_count,
            "wedge": merger.views.wedge_count,
        },
        "pid_binding": bind.level.as_str(),
        "pid_binding_explanation": bind.explanation,
        "pid_binding_candidates": bind.candidates,
        // v0.3 §3.5 三级：argv 级绑定的账。`calls_matched` 而不是"标了多少 pid"，
        // 是因为前者才是用户真正在问的"哪几次工具调用被钉在了内核事实上"。
        "bind": {
            "enabled": binder.enabled(),
            "calls_seen": bs.calls_seen,
            "calls_matched": bs.calls_matched,
            "execs_seen": bs.execs_seen,
            "pids_exact": bs.pids_exact,
            "by_argv_exact": bs.by_direct,
            "by_argv_substring": bs.by_substring,
            "by_argv_segment": bs.by_segment,
            "by_argv_overlap": bs.by_tokens,
            "derived_rows": bs.derived_rows,
            "window_s": exact::EXEC_AFTER_CALL_NS / 1_000_000_000,
            "overlap_threshold_pct": exact::TOKEN_OVERLAP_PCT,
        },
        // v0.4 §13：失败归因的账。`list` 与 footer 的失败段**同源**（同一份
        // `Failure` 记录），所以屏幕上数出来的行数与 json 里的条数永远一致。
        //
        // `attributed` 是"有多少条真的给出了内核侧最深点"。它不是成败指标，
        // 而是**归因覆盖率**：`-S` 单跑（没采内核）时它一定是 0，看到 0 应该去
        // 看 `kernel_available`，而不是怀疑归因算法。
        "failures": {
            "only": cli.failures_only,
            "kernel_available": fail_cfg.kernel_available,
            "count": summary.failures.len(),
            "attributed": attributed,
            "by_class": {
                "before_exec": summary.failures.iter().filter(|f| f.class == fail::CLASS_BEFORE_EXEC).count(),
                "kernel": summary.failures.iter().filter(|f| f.class == fail::CLASS_KERNEL).count(),
                "bound_no_evidence": summary.failures.iter().filter(|f| f.class == fail::CLASS_BOUND_NO_EVIDENCE).count(),
                "unbound": summary.failures.iter().filter(|f| f.class == fail::CLASS_UNBOUND).count(),
                "no_kernel_source": summary.failures.iter().filter(|f| f.class == fail::CLASS_NO_KERNEL_SOURCE).count(),
            },
            "list": summary.failures.iter().map(|f| serde_json::json!({
                "ts_wall_ns": f.ts_wall_ns,
                "ts_ns": f.ts_ns,
                "tool": f.tool,
                "cmd": f.cmd,
                "class": f.class,
                "head": f.head,
                "deepest": f.deepest,
                "kernel_events": f.kernel_events,
                "detected_by": f.detected_by,
                "tool_use_id": f.tool_use_id,
            })).collect::<Vec<_>>(),
        },
        "clock_offset_ns": merger.clock.offset().to_string(),
    });

    let tail_text = match cli.output {
        OutputMode::Text => text_renderer.summary(&summary),
        OutputMode::Json => format!("{}\n", render::json::summary(&summary, &extra)),
    };
    let _ = out.write_all(tail_text.as_bytes());

    if cli.verbose {
        print_diagnostics(cli, &summary, &merger, collector.as_ref(), &adapters, &bind, cs, bs);
    }

    if truncated_by_limit {
        eprintln!(
            "agtrace: reached --max-events {}, **stopped on purpose** — the timeline is truncated, this is not the end of capture",
            cli.max_events.unwrap_or(0)
        );
    }
    if let Some(e) = collector_failed {
        eprintln!("agtrace: kernel collector exited abnormally: {}", e);
    }

    let _ = out.flush();
    Ok(())
}

/// 剪枝模式下把时间原点钉在**会话起点**上（§13.4）。
///
/// 只对 text 生效：json 的每一行都带绝对 `ts_wall_ns`，不存在"相对谁"的问题。
/// 非剪枝模式也不用管 —— 那里渲染器看到的第一批就是会话开头，它的自动定原点
/// 本来就会落在同一个值上。
fn lock_origin_if_filtered(cli: &Cli, failer: &FailAttributor, r: &mut TextRenderer) {
    if !cli.failures_only || cli.output != OutputMode::Text {
        return;
    }
    if let Some(w) = failer.origin_wall() {
        r.lock_origin(w);
    }
}

fn write_out<W: Write>(w: &mut W, cli: &Cli, s: &str) -> Result<(), String> {
    let line = match cli.output {
        OutputMode::Text => format!("{}\n", s),
        OutputMode::Json => format!("{}\n", render::json::header(s, None, None, &[], cli.follow, &[],)),
    };
    w.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

/// FNV-1a 64 —— 只用来给人核对"跑的是不是同一份脚本"，不是密码学用途。
fn fnv1a(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in b {
        h ^= *x as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

fn print_diagnostics(
    cli: &Cli,
    summary: &Summary,
    merger: &Merger,
    collector: Option<&BpftraceCollector>,
    adapters: &[Box<dyn adapter::EventAdapter>],
    bind: &binding::BindingResult,
    cs: collapse::CollapseStats,
    bs: exact::BindStats,
) {
    // 这一节**不套** §3 的 120 列上限：它是给人 grep 的 key=value 转储，
    // 截断它等于把 `-v` 存在的理由截掉。上限管的是时间线（横幅 / 事件行 / 统计行），
    // 以及默认模式下的全部输出。
    // 这一节**不套** §3 的 120 列上限：它是给人 grep 的 key=value 转储，
    // 截断它等于把 `-v` 存在的理由截掉。上限管的是时间线（横幅 / 事件行 / 统计行），
    // 以及默认模式下的全部输出。
    // 这一节**不套** §3 的 120 列上限：它是给人 grep 的 key=value 转储，
    // 截断它等于把 `-v` 存在的理由截掉。上限管的是时间线（横幅 / 事件行 / 统计行），
    // 以及默认模式下的全部输出。
    // 这一节**不套** §3 的 120 列上限：它是给人 grep 的 key=value 转储，
    // 截断它等于把 `-v` 存在的理由截掉。上限管的是时间线（横幅 / 事件行 / 统计行），
    // 以及默认模式下的全部输出。
    eprintln!("--- diagnostics (-v) ---");
    eprintln!(
        "  events: {} (agent {} / runtime {} / infra {} / policy {} / derived {})",
        summary.total, summary.agent, summary.runtime, summary.infra, summary.policy, summary.derived
    );
    eprintln!(
        "  (late) {}; truncated {}; merge window {} ms; clock offset {} ns",
        merger.late_count,
        summary.truncated,
        merger.window_ms(),
        merger.clock.offset()
    );
    // 折叠的账目：每一类各折了几次、合计替掉了多少条原始行。
    // 单看屏幕只能看到"派生行有几条"，看不出它背后是 3 条还是 300 条 ——
    // 而这个数量级正是判断"这里到底吵不吵"的依据。
    eprintln!(
        "  collapse: execvp resolved {} / not-found {}; fork-burst {}; merged-equivalent {}; \
         raw lines replaced {}; fork rows with parent cmdline {}",
        cs.execvp_resolved,
        cs.execvp_not_found,
        cs.fork_bursts,
        cs.execvp_merged,
        cs.raw_events_replaced,
        cs.identity_hits
    );
    // v0.3 的账目：会话级绑定只回答"这堆进程是不是这个 agent 的"，
    // 这里回答"哪几次工具调用被钉在了内核事实上"。两句话都要能核对 ——
    // 分子分母都给出，用户自己判断漏了多少。
    eprintln!(
        "  bind (§3.5 3rd level, argv join key): enabled={}; calls with a shell command {}; \
         matched {} (argv exact {} / argv substring {} / argv segment {} / argv overlap {}); \
         execs seen {}; pids marked exact {}; \
         derived bind rows {}; window {}s; overlap threshold {}%",
        if cli.no_bind { "false (--no-bind)" } else { "true" },
        bs.calls_seen,
        bs.calls_matched,
        bs.by_direct,
        bs.by_substring,
        bs.by_segment,
        bs.by_tokens,
        bs.execs_seen,
        bs.pids_exact,
        bs.derived_rows,
        exact::EXEC_AFTER_CALL_NS / 1_000_000_000,
        exact::TOKEN_OVERLAP_PCT
    );
    if !merger.views.wedge_capable() {
        // 两种关闭原因要分清：没有内核源（没在看）vs 有源但一条事件都没有
        // （脚本没加载上 / 目标进程已死）。前者是设计选择，后者是采集故障。
        let why = if !merger.views.kernel_source_expected() {
            "no kernel source this run (no -p/-C given)"
        } else if merger.views.kernel_events_seen() == 0 {
            "kernel source present but zero kernel events arrived (check bpftrace stderr)"
        } else {
            "too few kernel events"
        };
        eprintln!(
            "  wedge view: **disabled** — {}; without comparable kernel events, any \
             \"no connect seen\" conclusion is unfounded ({} kernel events seen)",
            why,
            merger.views.kernel_events_seen()
        );
    }
    eprintln!(
        "  views 4/5: gap {} / retry {} / dangling {} / watchlist {} / wedge {}",
        merger.views.gap_count,
        merger.views.retry_count,
        merger.views.dangling_count,
        merger.views.watch_count,
        merger.views.wedge_count
    );
    // 被放弃的楔形候选必须显式说出来。静默丢弃会让 `-S` 回放历史时
    // "一个楔形都没有"看起来像"全都正常"，而真相是"那些调用发生时我们还没在看"。
    let skipped = merger.views.wedge_skipped_precollection();
    if skipped > 0 {
        eprintln!(
            "      ({} network-tool candidate(s) dropped because they happened **before** the \
             kernel observation window opened: common when replaying a historical transcript — \
             that is \"we were not watching\", not \"it is not in the kernel\")",
            skipped
        );
    }
    if let Some(c) = collector {
        let s = c.parse_stats();
        eprintln!("  collector: {}", Collector::id(c));
        eprintln!(
            "  bpftrace: lines {} / unknown tag {} / malformed {} / non-protocol {} / argv orphans {} / lost {}",
            s.lines_total,
            s.lines_unknown_tag,
            s.lines_malformed,
            s.lines_non_protocol,
            s.argv_orphans,
            c.lost_events()
        );
        // 脚本指纹：bpftrace 是把脚本拷到临时文件后加载的，"我渲染的脚本"和
        // "实际跑的脚本"是两件事。给出字节数 + 行数 + FNV-1a 摘要，用户拿它就能
        // 确认 -p 的过滤器真的被替换进去了（配合 --keep-script 可逐字节比对）。
        let script = &c.rendered_script;
        eprintln!(
            "  script: {} bytes / {} lines / fnv1a={:016x}; argv masked in {} event(s)",
            script.len(),
            script.lines().count(),
            fnv1a(script.as_bytes()),
            c.redacted_events()
        );
        if !c.stderr_tail.is_empty() {
            eprintln!("  bpftrace stderr (last {} lines):", c.stderr_tail.len());
            for l in c.stderr_tail.iter().take(20) {
                eprintln!("    {}", l);
            }
        }
    }
    for a in adapters {
        let caps = a.capabilities();
        let kinds: Vec<&str> = caps.kinds.iter().map(|k| k.as_str()).collect();
        eprintln!(
            "  [{}] declared kinds: {}; live={} needs_pid_binding={}",
            a.id(),
            if kinds.is_empty() {
                "-".to_string()
            } else {
                kinds.join(",")
            },
            caps.live,
            caps.needs_pid_binding
        );
        for d in a.diagnostics() {
            eprintln!("  [{}] {}", a.id(), d);
        }
    }
    // 头部那行 pid_binding 注记受 120 列约束，可能只留下结论；完整解释在这里
    // 给出（-v 是给人读的，不做宽度截断）。
    eprintln!("  pid_binding: {} — {}", bind.level.as_str(), bind.explanation);
    // -v 下唯一一处打码提示（启动横幅已按 v0.1 移除）：默认 argv 是模式匹配，
    // 只覆盖命令行，agent 层内容原样输出。
    eprintln!(
        "  redact mode: {} (credential-shaped command-line args masked; agent content passes through)",
        cli.redact.as_str()
    );
}

fn file_basename(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}
