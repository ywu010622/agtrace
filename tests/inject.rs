//! v0.6 §14.4：故障注入流水线（warm-start fault injection）。
//!
//! # 这个测试在做什么
//!
//! 每个种子（`tests/inject/seeds/<name>/`）是一份**形状真实**的 transcript
//! （`--adapter jsonl` 的格式），在它的第 K 步注入**一个**故障，后面接上"本该
//! 继续走下去"的那几步；再配一份内核行捕获。两者一起喂给**真正的二进制**：
//!
//! ```text
//! agtrace --adapter jsonl -S events.jsonl --kernel-lines kernel.txt --failures-only
//! ```
//!
//! 为什么不去直接调归因器：**验收的是屏幕上那句话**。归因器单测（`src/fail.rs`）
//! 验的是内部结构；"用户看到 `XX` 行指向第几步、解释对不对、血缘链有没有连上
//! 下游"要跑通 CLI 解析 → 回放 → 合并器 → binder → 折叠 → 归因 → 渲染整条路
//! 才谈得上 —— 而那一段路恰恰是 bug 最爱躲的地方。
//!
//! # 四类种子
//!
//! | 类 | 注入物 | 屏幕上的样子 |
//! |----|--------|--------------|
//! | `honest-*` | `tool.result` 如实报错（404 / 非零退出） | 四层归因；血缘指回上游、指向下游 |
//! | `dishonest-*` | 结果说成功，内核里没有那笔写 / 那次连接 | `claim: … \| kernel: … !!` |
//! | `loop-*` | 同一条命令重复 3 次（A.4 的 looping 模式） | 失败落在具体哪一次上；血缘指向第 1 次 |
//! | `sniff-*` | 内核**确实**看见了那笔写 —— 写下去的是错误页 | `userspace heuristic`，且必须自曝不是内核证据 |
//!
//! 最后一类是这套东西的**诚实边界**：内核说"写了"，文件也确实在磁盘上，只有把它
//! 打开看一眼才知道里面不是 PDF。它证明不了"agent 撒谎"（内核那半句是真的），
//! 所以措辞里必须写明这是用户态启发式。
//!
//! # 种子里的时间戳为什么是"相对毫秒"
//!
//! 内核行协议里的 `nsecs` 是 **CLOCK_MONOTONIC**，而 CLOCK_MONOTONIC 在同一个
//! boot 里是**全机共享**的：任何进程读到的都是同一条轴。所以种子不能写死时间戳
//! ——写死了，合并器会（正确地）警告"这不是同一个钟"，agent 行和内核行也会落到
//! 相隔几个月的位置上。种子写相对毫秒，加载时统一平移到**跑之前 3 秒**：
//!
//! * 落在**过去**：落在未来的 agent 行会被合并器按"尚未发生"排队，时间线就不是
//!   种子安排的那个顺序了；
//! * 3 秒远小于 `check_mono` 的 5 秒阈值，所以不会误报时钟警告。
//!
//! 于是种子文件可以逐字地 diff/评审（"第 K 步注入了什么"一眼看得出），而时间轴
//! 每次运行都是新鲜的。

use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------
// 时间与工作目录
// ---------------------------------------------------------------

/// 整份种子落在 `now - BASE` 之后的几秒里。
const BASE_NS: u64 = 3_000_000_000;

fn mono_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn wall_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// 一次运行的时间轴。种子里的 `ms` 都是相对它起点的偏移。
struct Clock {
    wall_base: u64,
    mono_base: u64,
}

impl Clock {
    fn new() -> Self {
        Clock {
            wall_base: wall_now_ns().saturating_sub(BASE_NS),
            mono_base: mono_now_ns().saturating_sub(BASE_NS),
        }
    }

    /// `tool.call` / `tool.result` 认的 `ts`：epoch 秒（adapter 两条都收，用数字
    /// 就不必在这里写一遍日历转换）。
    fn ts(&self, ms: u64) -> f64 {
        (self.wall_base + ms * 1_000_000) as f64 / 1e9
    }

    /// 内核行的 `nsecs`：CLOCK_MONOTONIC 的纳秒。
    fn nsecs(&self, ms: u64) -> u64 {
        self.mono_base + ms * 1_000_000
    }
}

/// 一个种子用的临时目录。名字带种子名，测试并行跑也不会互相踩。
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("agtrace_inject_{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("work")).expect("cannot create the scratch directory");
        Scratch { dir }
    }

    /// 种子的根目录 —— 也就是 `$DIR`。出现在种子里的绝对路径都挂在它下面（约定
    /// 是 `$DIR/work/<名字>`），这样两个种子并行跑也不会互相看见对方"写过"的文件
    /// （内容嗅探真的会去读）。
    fn root(&self) -> String {
        self.dir.display().to_string()
    }

    /// 种子声称的产物落地处：`$DIR/work`。
    fn work(&self) -> PathBuf {
        self.dir.join("work")
    }

    fn write(&self, name: &str, body: &str) -> String {
        let p = self.dir.join(name);
        std::fs::write(&p, body).expect("cannot write the seed file");
        p.display().to_string()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------
// 种子
// ---------------------------------------------------------------

const SEED_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/inject/seeds");

struct Seed {
    name: String,
    events_raw: String,
    kernel_raw: String,
    /// `files/` 下要真的落到 `$DIR/work/` 的文件。只有内容嗅探会去读文件，所以
    /// 那一类种子必须真的有个文件在磁盘上 —— 假装有文件就测不到那条路。
    files: Vec<(String, String)>,
}

impl Seed {
    fn load(name: &str) -> Self {
        let dir = Path::new(SEED_ROOT).join(name);
        let read = |p: PathBuf| {
            std::fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("cannot read {}: {}", p.display(), e))
        };
        let events_raw = read(dir.join("events.jsonl"));
        let kernel_raw = read(dir.join("kernel.txt"));
        let mut files = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir.join("files")) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_file() {
                    files.push((p.file_name().unwrap().to_string_lossy().to_string(), read(p)));
                }
            }
        }
        files.sort();
        Seed {
            name: name.to_string(),
            events_raw,
            kernel_raw,
            files,
        }
    }

    /// 把相对毫秒平移到这次运行的钟上，并把 `$DIR` 换成这次的根目录。
    fn materialize(&self, sc: &Scratch, c: &Clock) -> (String, String) {
        let work = sc.root();
        let events = self
            .events_raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let l = l.replace("$DIR", &work);
                let mut v: serde_json::Value = serde_json::from_str(&l)
                    .unwrap_or_else(|e| panic!("[{}] bad seed line: {}", self.name, e));
                let ms = v["ts"].as_u64().unwrap_or_else(|| {
                    panic!(
                        "[{}] every seed event needs an integer `ts` in ms: {}",
                        self.name, l
                    )
                });
                v["ts"] = serde_json::json!(c.ts(ms));
                v.to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let kernel = self
            .kernel_raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let l = l.replace("$DIR", &work);
                // 协议的第 1 个字段恒是 nsecs；不是数字的行原样留着（种子里可以
                // 故意放一行垃圾，验解析器的降级计数）。
                let mut f: Vec<&str> = l.split('|').collect();
                if f.len() > 1 {
                    if let Ok(ms) = f[1].parse::<u64>() {
                        let abs = c.nsecs(ms).to_string();
                        f[1] = &abs;
                        return f.join("|");
                    }
                }
                l
            })
            .collect::<Vec<_>>()
            .join("\n");
        (events, kernel)
    }

    /// 落地（含 `files/`），跑一次 `--failures-only`。
    fn run(&self) -> (Run, Scratch) {
        self.run_with_env(&[])
    }

    /// 同 `run`，但给子进程多传环境变量（测试钩子用，不污染全局）。
    fn run_with_env(&self, env: &[(&str, &str)]) -> (Run, Scratch) {
        let c = Clock::new();
        let sc = Scratch::new(&self.name);
        for (name, body) in &self.files {
            std::fs::write(sc.work().join(name), body)
                .unwrap_or_else(|e| panic!("[{}] cannot write {}: {}", self.name, name, e));
        }
        let (events, kernel) = self.materialize(&sc, &c);
        let transcript = sc.write("events.jsonl", &(events + "\n"));
        let kfile = sc.write("kernel.txt", &(kernel + "\n"));
        let run = run_agtrace_with_env(
            &[
                "--adapter",
                "jsonl",
                "-S",
                &transcript,
                "--kernel-lines",
                &kfile,
                "--failures-only",
            ],
            env,
        );
        (run, sc)
    }
}

// ---------------------------------------------------------------
// 跑真二进制
// ---------------------------------------------------------------

fn agtrace() -> &'static str {
    env!("CARGO_BIN_EXE_agtrace")
}

fn run_agtrace(args: &[&str]) -> Run {
    run_agtrace_with_env(args, &[])
}

fn run_agtrace_with_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(agtrace());
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("cannot run the agtrace binary");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

struct Run {
    stdout: String,
    stderr: String,
}

impl Run {
    /// 时间线里的 `XX`（失败归因）行。
    ///
    /// 按列取而不是按子串：`XX` 也可能出现在命令行文本里（种子自己写的命令），
    /// 而这一列是渲染器给归因行留的位置。
    fn fail_rows(&self) -> Vec<&str> {
        self.stdout
            .lines()
            .filter(|l| l.split_whitespace().nth(1) == Some("XX"))
            .collect()
    }

    fn must_contain(&self, needle: &str, case: &str) {
        assert!(
            self.stdout.contains(needle),
            "[{}] the output does not contain {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            case,
            needle,
            self.stdout,
            self.stderr
        );
    }

    fn must_not_contain(&self, needle: &str, case: &str) {
        assert!(
            !self.stdout.contains(needle),
            "[{}] the output unexpectedly contains {:?}\n--- stdout ---\n{}",
            case,
            needle,
            self.stdout
        );
    }

    fn assert_row_count(&self, n: usize, case: &str) {
        assert_eq!(
            self.fail_rows().len(),
            n,
            "[{}] rows: {:#?}\n--- stdout ---\n{}",
            case,
            self.fail_rows(),
            self.stdout
        );
    }
}

/// 断言"有一行 `XX` 指向第 step 步、工具是 `tool`"，并把它交回来。
///
/// 步号是**这份流里 `tool.call` 的出现次序**（从 1 数）：它只跟 transcript 有关，
/// 与内核无关。验收里"指向第 K 步"指的就是这个数。
fn assert_points_at<'a>(run: &'a Run, step: u64, tool: &str, case: &str) -> &'a str {
    let want = format!("step {}", step);
    run.fail_rows()
        .into_iter()
        .find(|l| l.contains(&want) && l.contains(tool))
        .unwrap_or_else(|| {
            panic!(
                "[{}] no `XX` row points at {} / {}\nrows: {:#?}\n--- stdout ---\n{}",
                case,
                want,
                tool,
                run.fail_rows(),
                run.stdout
            )
        })
}

/// `XX` 行超过 120 列时会被截断 —— 这是**约定**（一行不能撑破时间线），而整句
/// 会在 footer 的 `--- failures` 里逐字重排一遍。所以断言分两层：**指哪一步、
/// 哪个工具**看行本身，**解释**看整份输出（footer 就是那句话的全文）。
fn assert_explains(run: &Run, needle: &str, case: &str) {
    run.must_contain(needle, case);
}

/// 断言**同一行**里同时出现这几个片段（顺序无关）。
///
/// 为什么不写整行：路径可能被 `clip` 从左截（`.../work/q3.pdf` —— 尾部的文件名
/// 才是识别度所在），而临时目录的名字和长度是机器相关的。把整行写死，测试就会
/// 依赖 tmp 目录的长度；按片段断言既稳，又仍然强制"这几件事出现在同一行"。
fn assert_line(run: &Run, case: &str, parts: &[&str]) {
    if run
        .stdout
        .lines()
        .any(|l| parts.iter().all(|p| l.contains(p)))
    {
        return;
    }
    panic!(
        "[{}] no single line contains all of {:?}\n--- stdout ---\n{}",
        case, parts, run.stdout
    );
}

// ===============================================================
// 一、老实故障（结果自己报错）
// ===============================================================

/// 下载 404，**后来**有一步用了那个产物。
///
/// 断言的后半是 v0.6 的新东西：血缘的**正向**链（"这个产物后来被谁用了"）。
/// 它只能在流尾补齐 —— 失败行放出去的那一刻，"后来"还没发生（§14.1）。
#[test]
fn honest_failure_links_the_downstream_consumer() {
    let case = "honest-download-404";
    let (run, sc) = Seed::load(case).run();

    assert_points_at(&run, 1, "Bash", case);
    assert_explains(
        &run,
        "exit 22 (deepest: connect 93.184.216.34:443 failed",
        case,
    );
    run.assert_row_count(1, case);
    // 下游消费者（第 2 步的 Read）被血缘链连上；它自己**没有**失败行。
    let _ = &sc;
    assert_line(
        &run,
        case,
        &["└─ output", "q3.pdf", "referenced later by step 2 Read"],
    );
    run.must_not_contain("tool.call Read step 2 \"", case);
    // 结果是错误、不是自述成功，所以不该冒出 `claim:` 两列。
    run.must_not_contain("claim:", case);
}

/// **V06_PROMPT 里那张图**的形状：失败发生在下游，血缘指回上游那个报错的产出者。
///
/// ```text
/// XX  step 2: display_pdf -> exit 1
///     └─ input /tmp/report.pdf produced by step 1 Bash (ERRORED: exit 22)
/// ```
#[test]
fn honest_failure_names_the_failed_producer_of_its_input() {
    let case = "honest-404-breaks-render";
    let (run, sc) = Seed::load(case).run();

    // 两次失败都在，各自指向自己的步号。
    assert_points_at(&run, 1, "Bash", case);
    assert_explains(&run, "exit 22", case);
    assert_points_at(&run, 2, "Bash", case);
    assert_explains(&run, "exit 1", case);
    run.assert_row_count(2, case);
    // 第 2 步的血缘指回第 1 步 —— 而且带上"那一步是错的"这个限定。产出者的定论
    // 用它**自己的**退出码（正文里的 `HTTP 404` 是同一件事的另一种说法）。
    let _ = &sc;
    assert_line(
        &run,
        case,
        &[
            "└─ input",
            "r.pdf",
            "produced by step 1 Bash (ERRORED: exit 22)",
        ],
    );
}

// ===============================================================
// 二、不老实故障（说成功，内核不认）—— v0.6 的楔子
// ===============================================================

/// 结果说"已保存到 X"，内核里**没有**任何写意图的 open。
#[test]
fn dishonest_write_claim_is_contradicted_by_the_kernel() {
    let case = "dishonest-write-claim";
    let (run, sc) = Seed::load(case).run();

    let row = assert_points_at(&run, 1, "Bash", case);
    // `!!` 必须留在行尾：它是这一行存在的理由，被 120 列截掉就等于什么都没说。
    assert!(row.ends_with("!!"), "the row lost its `!!`:\n{}", row);
    let _ = &sc;
    assert_line(
        &run,
        case,
        &["claim:", "saved", "report.pdf", "| kernel: no write open observed !!"],
    );
    run.assert_row_count(1, case);
    assert_line(
        &run,
        case,
        &["└─ output", "report.pdf", "referenced later by step 2 Read"],
    );
}

/// 一句结果里两笔 claim（"下载了 URL，存到了路径"），内核**两笔都不认**。
///
/// 第一笔占 `XX` 行，第二笔自己占一行 `derived.claim` —— 一行里塞不下两句对账，
/// 塞得下也不该塞：它们是两个可以分别被查证的断言。
#[test]
fn dishonest_fetch_claim_reports_no_outbound_connect() {
    let case = "dishonest-fetch-claim";
    let (run, sc) = Seed::load(case).run();

    let row = assert_points_at(&run, 1, "Bash", case);
    assert!(row.ends_with("!!"), "the row lost its `!!`:\n{}", row);
    assert_explains(
        &run,
        "claim: downloaded https://10.1.2.3/x.json | kernel: no outbound connect observed !!",
        case,
    );
    // 这是 IP 字面量，可以直接对上，所以这里说得出"没看见过这次 connect"；
    // 换成域名就说不出这句话（见 `lineage::match_net`）。
    let _ = &sc;
    assert_line(
        &run,
        case,
        &["claim:", "downloaded", "x.json", "| kernel: no write open observed !!"],
    );
    run.assert_row_count(1, case);
}

/// Write 工具的一句结果（"Wrote X"），内核里**没有**那笔写。
///
/// 这是 critical #1（`fail.rs::window_ok` 时钟域错配）的端到端回归：Write
/// 工具不 spawn 进程，这个调用**没有任何**内核事件 —— `window_ok` 走的是
/// 墙钟比较那条路，而不是 `kernel_events > 0` 的短路。修复前那条比较恒为假，
/// 这句 claim 会被记成 `unverified`（悄悄放过），而不是这里断言的 `!!`。
#[test]
fn dishonest_write_tool_claim_is_contradicted_by_the_kernel() {
    let case = "dishonest-write-tool-claim";
    // 回放没有 live pid 可绑定，`session_linked` 恒为 false —— 不开这个钩子，
    // 零内核事件的 Write 调用永远到不了 `evaluate`，这个测试就恒为"无行"。
    let (run, _sc) =
        Seed::load(case).run_with_env(&[("AGTRACE_TEST_FORCE_PID_LINKED", "1")]);

    let row = assert_points_at(&run, 1, "Write", case);
    assert!(row.ends_with("!!"), "the row lost its `!!`:\n{}", row);
    assert_line(
        &run,
        case,
        &["claim:", "wrote", "report.pdf", "| kernel: no write open observed !!"],
    );
    run.assert_row_count(1, case);
    assert_line(
        &run,
        case,
        &["└─ output", "report.pdf", "referenced later by step 2 Read"],
    );
}

/// 没有内核源时，不许说 `!!`。
///
/// 这是上一条的反面（诚实边界）：`can_speak()` 的门槛没过，claim 只能记
/// `unverified`。测试锁的是"不乱说话" —— 修 clock bug 的时候如果把门拆了，
/// 这条会先叫。
#[test]
fn write_tool_claim_without_kernel_is_unverified_not_mismatched() {
    let case = "unverified-write-tool-no-kernel";
    let (run, _sc) = Seed::load(case).run();

    run.assert_row_count(0, case);
    run.must_not_contain("!!", case);
}

// ===============================================================
// 三、循环故障（同一条命令重复 3 次，A.4 的 looping 模式）
// ===============================================================



/// 循环的第 3 次真的失败了：失败落在第 3 步，血缘说明"这个产物第 1 步就下过"。
#[test]
fn looping_fault_lands_on_the_last_repeat() {
    let case = "loop-last-times-out";
    let (run, _sc) = Seed::load(case).run();

    assert_points_at(&run, 3, "Bash", case);
    assert_explains(&run, "exit 28", case);
    run.assert_row_count(1, case);
    // 血缘：第 3 步的产物在第 1 步就已经出现过 —— 循环的账写在这里。
    assert_explains(&run, "produced by step 1 Bash", case);
}

/// 循环里**只有第一次**真的写成功了：后两次的"成功"是空话。
///
/// 这是"每条调用只看它自己挂住的内核事件"这条设计的直接体现 —— 三条调用的命令、
/// 产物、结果文本一模一样，区别只在**内核把那次写挂在了谁的头上**。
#[test]
fn looping_fault_exposes_stale_successes() {
    let case = "loop-stale-successes";
    let (run, _sc) = Seed::load(case).run();

    run.assert_row_count(2, case);
    for step in [2, 3] {
        let row = assert_points_at(&run, step, "Bash", case);
        assert!(row.ends_with("!!"), "step {}: lost `!!`:\n{}", step, row);
    }
    // 第 1 次是**真的**成功了 —— 它一条 `XX` 都不该有（否则就是冤枉）。
    assert!(
        !run.fail_rows().iter().any(|r| r.contains("step 1")),
        "the first (honest) repeat must not be flagged: {:#?}",
        run.fail_rows()
    );
    assert_explains(&run, "produced by step 1 Bash (ok)", case);
}

// ===============================================================
// 四、嗅探（内核看见了那笔写，只是写下去的东西不对）
// ===============================================================

/// `.pdf` 里装着 HTML。
///
/// **这类种子是诚实边界本身**：内核那半句是真的（那个路径确实被写过），所以楔子
/// 一句话都不说 —— "agent 撒谎"的资格在这里不存在。能说的只有"我们打开看了一眼，
/// 头几个字节是 `<!DOCTYPE html>`"，而且必须写明这不是内核证据。
#[test]
fn a_pdf_that_smells_like_html_is_flagged_as_a_userspace_heuristic() {
    let case = "sniff-pdf-is-html";
    let (run, sc) = Seed::load(case).run();

    // 失败在**下游**（渲染出空白）：这一行不指控任何人撒谎。
    assert_points_at(&run, 2, "Bash", case);
    // 嗅探说的是文件内容，措辞里必须自曝身份。
    assert_explains(&run, "userspace heuristic", case);
    assert_explains(&run, "smells like HTML", case);
    // 上游那一步在内核里是**成功**的（写 open 在），绝不能背上对不上账。
    run.must_not_contain("no write open observed", case);
    let _ = &sc;
    assert_line(
        &run,
        case,
        &["└─ input", "q3.pdf", "produced by step 1 Bash (ok)"],
    );
    // 身份标签和结论必须落在**同一行**（长路径会把行尾吃掉，见 `lineage::sniff`）。
    assert_line(&run, case, &["userspace heuristic", "smells like HTML"]);
}

// ===============================================================
// 诚实边界：没有资格说话的时候，一个字都不说
// ===============================================================

/// 同一条不老实的结果，在**没有内核源**的那一轮里必须一言不发。
///
/// `claim: X | kernel: 没看见` 这半句在没有内核采集时是无信息的（我们根本没在看），
/// 说出口就等于把"我没在看"包装成"我发现了"。`-S` 单跑（不带 `--kernel-lines`）
/// 正是那一轮。
#[test]
fn without_a_kernel_source_no_claim_is_ever_asserted() {
    let seed = Seed::load("dishonest-write-claim");
    let sc = Scratch::new("no-kernel-source");
    let (events, _) = seed.materialize(&sc, &Clock::new());
    let transcript = sc.write("events.jsonl", &(events + "\n"));

    let run = run_agtrace(&["--adapter", "jsonl", "-S", &transcript, "--failures-only"]);
    assert!(
        !run.stdout.contains("claim:") && run.fail_rows().is_empty(),
        "a run with no kernel source must not assert anything about the kernel:\n{}",
        run.stdout
    );
}

/// 回放的账必须自报家门：`--output json` 里要有 `replay` 一节。
///
/// 没有它，读 json 的人就分不清"这份内核证据是采来的"还是"是从文件里读回来的"。
#[test]
fn the_json_account_says_that_the_kernel_side_was_replayed() {
    let seed = Seed::load("dishonest-write-claim");
    let sc = Scratch::new("json-account");
    let (events, kernel) = seed.materialize(&sc, &Clock::new());
    let transcript = sc.write("events.jsonl", &(events + "\n"));
    let kfile = sc.write("kernel.txt", &(kernel + "\n"));

    let out = run_agtrace(&[
        "--adapter",
        "jsonl",
        "-S",
        &transcript,
        "--kernel-lines",
        &kfile,
        "--output",
        "json",
    ]);
    let summary = out
        .stdout
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .expect("the last json line must be the summary");
    let x = &summary["extra"];
    assert_eq!(x["replay"]["lines_total"], 6, "{}", x["replay"]);
    assert_eq!(x["claims"]["checked"], 1, "{}", x["claims"]);
    assert_eq!(x["claims"]["mismatched"], 1, "{}", x["claims"]);
    assert_eq!(x["claims"]["unverified"], 0, "{}", x["claims"]);
    assert_eq!(x["lineage"]["steps"], 2, "{}", x["lineage"]);
    assert_eq!(x["failures"]["count"], 1, "{}", x["failures"]);
    assert_eq!(x["failures"]["list"][0]["step"], 1);
    assert_eq!(x["failures"]["list"][0]["class"], "claim-mismatch");
    assert!(x["replay"].is_object(), "replay must self-identify: {}", x["replay"]);
}

/// 一条根本不存在的内核文件必须**报错退出**，不能安静地给出一条空时间线。
#[test]
fn a_missing_kernel_file_is_an_error_not_an_empty_timeline() {
    let sc = Scratch::new("missing-kernel-file");
    let transcript = sc.write(
        "events.jsonl",
        "{\"type\":\"tool.call\",\"id\":\"c1\",\"tool\":\"Bash\",\"command\":\"ls /tmp\",\"ts\":1.0}\n",
    );
    let missing = sc.dir.join("nope.txt").display().to_string();
    let out = Command::new(agtrace())
        .args([
            "--adapter",
            "jsonl",
            "-S",
            &transcript,
            "--kernel-lines",
            &missing,
        ])
        .output()
        .expect("cannot run the agtrace binary");
    assert!(!out.status.success(), "a missing capture must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("nope.txt"), "stderr was: {}", stderr);
}
