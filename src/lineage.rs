//! v0.6 §14：产物血缘（artifact lineage）+ claim vs kernel。
//!
//! **纯用户态**：这里只读 `Event` 里已经有的东西 —— `tool.call` 的输入预览、
//! `tool.result` 的文本、以及挂在这条调用上的内核事件。它不采集、不解析协议、
//! 不碰 `src/ebpf/` 与 `agtrace-ebpf/`（V06_PROMPT 的硬约束）。
//!
//! 三件事，边界要说清：
//!
//! 1. [`Lineage`] —— **产物**（transcript 里出现过的绝对路径 / URL）与"第一次提到
//!    它的那次 `tool.call` 就是产出者"这个映射。失败视图里那条
//!    `└─ input /tmp/report.pdf produced by step 3 fetch_pdf (ERRORED: 404)` 来自这里。
//!    这是**用户态推断**：依据只是"前后两次提到同一个字符串"。它没有内核证据，
//!    所以每条血缘行都在 `notes` 里写明这一点，措辞里也带着 `produced by step N`
//!    这种"我在引用第几步"的句式，而不是"这个文件是第 3 步写的"这种事实断言。
//!
//! 2. **claim 抽取**（[`claims`]）—— `tool.result` 的**文本**说它写了哪个文件、
//!    下了哪个 URL。判据是一个小型动词表 + 紧邻窗口，属于启发式；它只负责
//!    "transcript 这一侧说了什么"，不做任何判断。
//!
//! 3. **对账**（[`evaluate`]）—— 把 claim 与"这条调用挂住的内核事件"并排成两列。
//!    不一致时打 `!!`。**否定陈述的门槛与 §13 的楔形视图完全一致**：只有
//!    "这一轮有内核源" **且** "这条调用确实被连上了（有 join key 的内核事件，
//!    或会话级 pid 绑定是 exact/heuristic）"时，才允许说"内核里没看见"。
//!    门槛不满足时**一行都不产出**。这里要诚实：不产出本身**分不清**
//!    "核对了、没问题"和"没资格核对"—— 说清这件事的责任落在调用方
//!    （`fail.rs`）：它把两者分别计数，`-v` 里按 `checked / matched / unverified`
//!    三个数报出来。本模块只保证"没资格时绝不说内核里没有"这一条不破。
//!
//! ## 为什么不用正则
//!
//! 本项目的依赖只有 libc/serde/serde_json/toml（DESIGN §3.1 铁律）。绝对路径与
//! URL 的手写扫描器比正则更可读，也更容易把"边界条件"写清楚（哪种字符能出现在
//! 路径里、尾部标点要不要吃掉）。见 [`extract`] 的注释。

use crate::event::{Payload, one_line};
use std::collections::HashMap;
use std::io::Read;

/// 一段文本里最多认几个产物。上下文里通常只有一两个，设上限是为了让
/// 一条命令里塞了十几个路径时（`grep -r a /x /y /z`）不让血缘行刷屏。
pub const MAX_ARTIFACTS: usize = 4;
/// 单次抽取扫描的最大字节数（输入的 preview 本身就是几百字节，这是兜底）。
const MAX_SCAN: usize = 8192;
/// 一次失败最多打几条血缘行（前后两个方向合起来）。
pub const MAX_CHAIN: usize = 2;
/// 一次失败最多核对几个 claim。
pub const MAX_CLAIMS: usize = 2;
/// 一次失败最多嗅探几个文件内容。
pub const MAX_SNIFF: usize = 2;
/// 一条调用最多留几个写意图路径（见 [`KernelFacts::write_paths`]）。
pub const MAX_WRITE_PATHS: usize = 64;

// ---------------------------------------------------------------
// 产物抽取
// ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Artifact {
    /// 绝对路径。相对路径**不**进这张表：没有 cwd 就无法判断两次提到的是不是
    /// 同一个东西（§5.2 #2 的同一条理由）。
    Path(String),
    /// `http(s)://` URL。`host` 单独存：claim 的对账要比的是主机。
    Url { host: String, url: String },
}

impl Artifact {
    /// 产物映射的键。路径直接用自己的字符串，URL 用完整 URL
    /// （同一主机的两个不同 URL 是两个产物）。
    pub fn key(&self) -> String {
        match self {
            Artifact::Path(p) => p.clone(),
            Artifact::Url { url, .. } => url.clone(),
        }
    }

    pub fn display(&self) -> &str {
        match self {
            Artifact::Path(p) => p,
            Artifact::Url { url, .. } => url,
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Artifact::Path(p) => Some(p),
            Artifact::Url { .. } => None,
        }
    }
}

/// 路径里允许出现的字符。**刻意不含** `:`、`,`、`=`、`;` —— 它们在 shell 与 JSON
/// 语境里几乎总是分隔符而不是路径的一部分（`--flag=/tmp/x`、`: /tmp/a:/tmp/b`）。
/// 宁可把路径截短（少认一个产物），也不要认出一个不存在的路径：一个假产物会在
/// 血缘里连出一条假链。
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | '@' | '%' | '~')
}

/// URL 里允许出现的字符（`?a=b&c=d` 这类查询串必须留在里面）。
fn is_url_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '/' | '.' | '_' | '-' | '~' | ':' | '?' | '#' | '[' | ']' | '@' | '!' | '$' | '&'
                | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | '%'
        )
}

/// 这些不是"产物"。它们是每条命令都会碰的系统噪声（`2>/dev/null`、
/// locale 探测），进了血缘表只会把真正的产物挤出去。
const PATH_DENY: &[&str] = &[
    "/dev/null",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/stdin",
    "/dev/tty",
    "/dev/urandom",
    "/proc/self",
    "/usr/share/locale",
    "/usr/share/locale-langpack",
    "/etc/ld.so.cache",
];

fn denied(path: &str) -> bool {
    PATH_DENY.iter().any(|d| path == *d || path.starts_with(&format!("{}/", d)))
}

/// 从一段文本里抽产物。顺序 = 出现顺序（稳定），去重，最多 [`MAX_ARTIFACTS`] 个。
///
/// 优先级：**像文件名的**（basename 里有 `.` 或本身就是 URL）先，
/// 其余的（`/usr/lib/python3`、`/home/me/proj`）后。理由：命令里塞满目录是很常见的
/// （`cd`、`grep -r`），而"第 3 步产出的那个东西"几乎总是有扩展名的文件或一个 URL。
/// 上限截断时，先丢的是目录。
pub fn extract(text: &str) -> Vec<Artifact> {
    let mut strong: Vec<Artifact> = Vec::new();
    let mut weak: Vec<Artifact> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    // 扫描窗口必须在**字符边界**上收口：按字节切一个多字节字符会 panic，
    // 而我们扫的是**别人的**命令输出。
    let mut end = text.len().min(MAX_SCAN);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut i = 0usize;

    while i < end {
        // ---- URL 优先：`http://x/y.pdf` 里的 `/y.pdf` 不该被当成绝对路径 ----
        let rest = &text[i..];
        if rest.starts_with("https://") || rest.starts_with("http://") {
            let mut j = i;
            for c in text[i..end].chars() {
                if is_url_char(c) {
                    j += c.len_utf8();
                } else {
                    break;
                }
            }
            let mut url = &text[i..j];
            // 尾部标点几乎总是句子的一部分（`see https://x/y.`、`(https://x/y)`）。
            url = url.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '"', '\'']);
            if let Some(host) = url_host(url) {
                let a = Artifact::Url {
                    host,
                    url: url.to_string(),
                };
                if !seen.contains(&a.key()) {
                    seen.push(a.key());
                    strong.push(a);
                }
            }
            i = j.max(i + 1);
            continue;
        }

        // ---- 绝对路径：`/` 必须出现在**边界**上（行首、空白、引号、`=`、`(` …），
        // 否则 `-o/tmp/x`、`a//b` 里的斜杠也会被当成路径开头。 ----
        if bytes[i] == b'/' {
            let boundary_ok = i == 0
                || !matches!(
                    text[..i].chars().next_back(),
                    Some(c) if is_path_char(c)
                );
            let next_ok = text[i + 1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '~');
            if boundary_ok && next_ok {
                let mut j = i;
                for c in text[i..end].chars() {
                    if is_path_char(c) {
                        j += c.len_utf8();
                    } else {
                        break;
                    }
                }
                let raw = &text[i..j];
                let path = raw.trim_end_matches(['.', ',', ';', ':', '!', '?', '/']);
                if path.len() > 1 && !denied(path) {
                    // `-` 开头的段（`/tmp/-x`）留着；只要 basename 不是空的就行。
                    let base = path.rsplit('/').next().unwrap_or("");
                    if !base.is_empty() {
                        let a = Artifact::Path(path.to_string());
                        if !seen.contains(&a.key()) {
                            seen.push(a.key());
                            if looks_like_a_file(path) {
                                strong.push(a);
                            } else {
                                weak.push(a);
                            }
                        }
                    }
                }
                i = j.max(i + 1);
                continue;
            }
        }

        // ---- 相对路径：**必须带目录分量**（`work/live.pdf`、`./x.json`）。
        // 只有 basename 的（`cat report.pdf`）仍然不算 —— 没有 cwd，两次提到同名
        // 的完全可能是两个文件，宁可少认。
        //
        // 但"带目录分量的相对路径"要认，这条线是 v0.6 实测后划的：真实
        // `claude -p` 会话里 Bash 工具的命令**几乎全是相对路径**（工具自己的 cwd
        // 就是项目根），只认绝对路径等于血缘在真机上永远连不起来 —— acceptance #4
        // 第一次跑出来的就是"一条链都没有"。同一个 cwd 下重复出现的同一个相对
        // 字符串，和绝对路径一样是可对齐的。
        let word_start = i == 0
            || !text[..i]
                .chars()
                .next_back()
                .is_some_and(is_path_char);
        if word_start && is_path_char(text[i..].chars().next().unwrap_or('\0')) {
            let mut j = i;
            for c in text[i..end].chars() {
                if is_path_char(c) {
                    j += c.len_utf8();
                } else {
                    break;
                }
            }
            let raw = &text[i..j];
            let rel = raw.trim_end_matches(['.', ',', ';', ':', '!', '?', '/']);
            if rel.contains('/')
                && !rel.starts_with('/')
                && !rel.starts_with("//")
                && looks_like_a_file(rel)
                && !denied(rel)
            {
                let a = Artifact::Path(rel.to_string());
                if !seen.contains(&a.key()) {
                    seen.push(a.key());
                    strong.push(a);
                }
            }
            i = j.max(i + 1);
            continue;
        }

        i += text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
    }

    let mut out = strong;
    out.extend(weak);
    out.truncate(MAX_ARTIFACTS);
    out
}

/// basename 里有 `.`（且不在开头）就算"像文件"。`/tmp/report.pdf` 是，
/// `/home/me/proj` 不是，`/etc/.hidden` 也不是。
fn looks_like_a_file(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    match base.find('.') {
        Some(0) => false,
        Some(_) => true,
        None => false,
    }
}

/// `https://user:pw@host:8443/path?q=1` → `host`。取不到时 `None`
/// （例如 `http://` 后面什么都没有），此时这个 URL 不是产物。
fn url_host(url: &str) -> Option<String> {
    let after = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // IPv6 字面量 `[::1]:8080`
    if let Some(rest) = hostport.strip_prefix('[') {
        let h = rest.split(']').next().unwrap_or("");
        return if h.is_empty() { None } else { Some(h.to_string()) };
    }
    let host = hostport.split(':').next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// 是不是 IP 字面量。**这个区分很关键**：内核报的是解析之后的地址，
/// 所以只有字面量主机名才能拿来做"连的不是它"这种否定陈述；域名必须做 DNS
/// 才能对上，我们不做，于是对域名只说"有没有发生 connect"。
fn is_ip_literal(host: &str) -> bool {
    if host.contains(':') {
        // IPv6
        return host.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    }
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
}

// ---------------------------------------------------------------
// 血缘
// ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// 结果还没到（或没有结果 —— dangling）。
    Pending,
    Ok,
    /// 失败了，括号里那句话是**结果文本里能找到的**最短证据
    /// （`exit 7` / `HTTP 404` / 结果第一行）。
    Error(String),
}

impl Status {
    fn label(&self) -> String {
        match self {
            Status::Pending => "(no result yet)".to_string(),
            Status::Ok => "(ok)".to_string(),
            Status::Error(note) => format!("(ERRORED: {})", note),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub n: u64,
    /// 归因器给这条调用分配的键（`tool_use_id`，或没有 id 时的 `#<序号>`）。
    /// 只用于内部反查（[`Lineage::key_of_step`]）—— 屏幕上引用的永远是**步号**。
    pub key: String,
    pub tool: String,
    pub artifacts: Vec<Artifact>,
    pub status: Status,
    /// claim 文本（这条**结果**说的），留给对账用。
    pub claims: Vec<Claim>,
    /// 结果原文（截断后的 preview），对账时用来抽 claim。
    pub result: String,
}

/// 步号计数器 + 产物 → 产出者映射。
///
/// 步号就是"这是本次会话的第几次 `tool.call`"，从 1 数起，**全部**调用都数
/// （包括成功的）。`XX` 行上的步号与血缘行里的步号必须是同一套编号，
/// 否则用户没法在屏幕上把两句话对上。
#[derive(Debug, Default)]
pub struct Lineage {
    steps: Vec<Step>,
    by_key: HashMap<String, usize>,
    /// 产物键 → 第一次提到它的那一步（下标）。
    producers: HashMap<String, usize>,
    /// 每个产物被哪些步提到过（含产出者自己），按步号递增。
    mentions: HashMap<String, Vec<usize>>,
}

impl Lineage {
    pub fn new() -> Self {
        Lineage::default()
    }

    /// 一条 `tool.call`。返回它的步号（1 起）。
    ///
    /// `key` 必须与 `fail.rs` 的 `call_key` 用同一套（有 id 用 id，没有用
    /// `#<序号>`）—— 两条模块各自维护一套键就会在"没有 tool_use_id 的 adapter"
    /// 上悄悄错位。
    pub fn on_call(&mut self, key: &str, tool: &str, args: &str, ts_wall_ns: u64) -> u64 {
        let artifacts = extract(args);
        let idx = self.steps.len();
        let n = idx as u64 + 1;
        for a in &artifacts {
            let k = a.key();
            self.producers.entry(k.clone()).or_insert(idx);
            let m = self.mentions.entry(k).or_default();
            if m.last() != Some(&idx) {
                m.push(idx);
            }
        }
        self.by_key.insert(key.to_string(), idx);
        self.steps.push(Step {
            n,
            key: key.to_string(),
            tool: tool.to_string(),
            artifacts,
            status: Status::Pending,
            claims: Vec::new(),
            result: String::new(),
        });
        let _ = ts_wall_ns;
        n
    }

    /// 一条 `tool.result`。
    ///
    /// 结果文本里**带产出动词**的产物也算这次调用产出的（`curl` 的输出说明
    /// `Saved to /tmp/x.pdf`），但只在"此前没人认领"时才登记 —— 先提到的那个
    /// 调用才是产出者。动词门槛是必须的：`ls /tmp` 的输出里全是路径，
    /// 不加门槛的话每次 `ls` 都会变成一堆文件的"产出者"。
    pub fn on_result(&mut self, key: &str, status_ok: bool, error_note: Option<String>, text: &str) {
        let Some(&idx) = self.by_key.get(key) else {
            return;
        };
        let claims = claims(text);
        let produced: Vec<Artifact> = claims.iter().filter_map(|c| c.artifact.clone()).collect();
        for a in &produced {
            let k = a.key();
            // 只在"此前没人提到过"时才认领：`mentions` 是这条断言的判据
            // （它在 on_call 里对同一批产物一起填，所以包含关系是 producers ⊆ mentions）。
            if !self.mentions.contains_key(&k) {
                self.producers.insert(k.clone(), idx);
            }
            let m = self.mentions.entry(k).or_default();
            if m.last() != Some(&idx) {
                m.push(idx);
            }
        }
        let st = if status_ok {
            Status::Ok
        } else {
            Status::Error(error_note.unwrap_or_else(|| "failed".into()))
        };
        let s = &mut self.steps[idx];
        s.status = st;
        s.claims = claims;
        s.result = one_line(text);
    }

    fn step(&self, key: &str) -> Option<&Step> {
        self.by_key.get(key).map(|i| &self.steps[*i])
    }

    /// 步号 → 键（[`Self::on_call`] 的逆）。步号在一次会话里唯一，所以它良定义。
    ///
    /// 留给"事后补算"的调用方：失败账是回顾性的，而键是顺着流记下来的
    ///（`Failure` 里只留了步号 —— 那是给人看的那个数）。
    pub fn key_of_step(&self, n: u64) -> Option<&str> {
        self.steps.iter().find(|s| s.n == n).map(|s| s.key.as_str())
    }

    /// 一个产物的产出者（步号 + 工具名 + 状态）。
    fn producer_of(&self, key: &str) -> Option<&Step> {
        self.producers.get(key).map(|i| &self.steps[*i])
    }

    /// 失败视图里的血缘链。两个方向都算，顺序 = "为什么失败" 在前、
    /// "还影响了谁" 在后：
    ///
    /// - **反向**：这次调用的输入里，有哪个产物是**更早**某一步产出的？
    ///   `└─ input /tmp/x.pdf produced by step 3 fetch_pdf (ERRORED: 404)`
    /// - **正向**：这次调用引用的产物，**后面**还有谁在用？
    ///   `└─ output /tmp/x.pdf referenced later by step 14 display_pdf`
    ///
    /// 一条都没有时返回空 —— 此时**不产出任何行**（没有血缘不是信息）。
    pub fn chain(&self, key: &str) -> Vec<String> {
        let Some(step) = self.step(key) else {
            return Vec::new();
        };
        let mut back: Vec<String> = Vec::new();
        let mut fwd: Vec<String> = Vec::new();

        for a in &step.artifacts {
            let k = a.key();
            if let Some(p) = self.producer_of(&k) {
                if p.n < step.n {
                    back.push(format!(
                        "\u{2514}\u{2500} input {} produced by step {} {} {}",
                        clip(&display_one(a), 52),
                        p.n,
                        p.tool,
                        p.status.label()
                    ));
                }
            }
            // 正向：后面还有谁提到这个产物（最多两个步号）。
            if let Some(ms) = self.mentions.get(&k) {
                let later: Vec<&Step> = ms
                    .iter()
                    .map(|i| &self.steps[*i])
                    .filter(|s| s.n > step.n)
                    .take(2)
                    .collect();
                for s in later {
                    fwd.push(format!(
                        "\u{2514}\u{2500} output {} referenced later by step {} {}",
                        clip(&display_one(a), 52),
                        s.n,
                        s.tool
                    ));
                }
            }
        }
        back.dedup();
        fwd.dedup();
        let mut out = back;
        out.extend(fwd);
        out.truncate(MAX_CHAIN);
        out
    }

    /// 这条调用涉及的**文件**产物（嗅探用：URL 没有本地内容可言）。
    pub fn paths_of(&self, key: &str) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        let Some(step) = self.step(key) else {
            return v;
        };
        for a in &step.artifacts {
            if let Some(p) = a.path() {
                // 目录不是文件内容，嗅探不了（也本来就不该嗅）。
                if looks_like_a_file(p) && !v.contains(&p.to_string()) {
                    v.push(p.to_string());
                }
            }
        }
        // 产出者的路径也算：失败发生在消费者身上时，要嗅的是**它拿到的那个文件**。
        for a in &step.artifacts {
            if let Some(prod) = self.producer_of(&a.key()) {
                for pa in &prod.artifacts {
                    if let Some(p) = pa.path() {
                        if looks_like_a_file(p) && !v.contains(&p.to_string()) {
                            v.push(p.to_string());
                        }
                    }
                }
            }
        }
        v.truncate(MAX_SNIFF);
        v
    }

    /// 这条调用的 claim（结果文本说的）。对账的输入。
    ///
    /// Exec 类 claim 在这里就被筛掉一道：只有 shell 类工具说"我执行了 X"才是
    /// 关于**它自己**的断言（见 [`is_shell_tool`]）。`Read` 的结果里出现
    /// "executed /tmp/x.sh" 是读到了这句话，不是它执行了。
    pub fn claims_of(&self, key: &str) -> Vec<Claim> {
        let Some(st) = self.step(key) else {
            return Vec::new();
        };
        let shell = is_shell_tool(&st.tool);
        st.claims
            .iter()
            .filter(|c| shell || c.kind != ClaimKind::Exec)
            .cloned()
            .collect()
    }

    /// 血缘的账（进 `-v` 与 `--output json` 的 summary）。
    ///
    /// `reused` 是**产物复用**的次数：有多少个产物被不止一步提到过。它才是"血缘"
    /// 这件事的规模 —— `steps` 只说这次会话有多少次工具调用（那是 §13 的账）。
    pub fn stats(&self) -> LineageStats {
        LineageStats {
            steps: self.steps.len() as u64,
            artifacts: self.producers.len() as u64,
            mentions: self.mentions.values().map(|v| v.len() as u64).sum(),
            reused: self.mentions.values().filter(|v| v.len() > 1).count() as u64,
        }
    }
}

/// [`Lineage::stats`] 的返回值。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LineageStats {
    pub steps: u64,
    pub artifacts: u64,
    pub mentions: u64,
    pub reused: u64,
}

fn display_one(a: &Artifact) -> String {
    a.display().to_string()
}

/// 长路径从**左边**截（`.../reports/2026/report.pdf`）：尾部的文件名才是识别度所在。
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let tail: String = s
        .chars()
        .rev()
        .take(max.saturating_sub(3))
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    format!("...{}", tail)
}

// ---------------------------------------------------------------
// claim 抽取
// ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimKind {
    /// 说它写了 / 存了 / 生成了一个文件。
    Write,
    /// 说它取回了一个 URL。
    Fetch,
    /// 说它执行了一条命令（Bash 结果非空且判成功）。
    Exec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub kind: ClaimKind,
    /// 摘要里用的动词（`wrote` / `downloaded` / `saved` …）—— 保留原文用词，
    /// 因为"下载"和"保存"对读者的含义不一样，而这两句都是 transcript 说的。
    pub verb: String,
    /// Write/Fetch 指向的产物；Exec 没有。
    pub artifact: Option<Artifact>,
}

impl Claim {
    /// `claim:` 那一列的正文（不含 `claim: ` 前缀）。
    pub fn render(&self) -> String {
        match (&self.kind, &self.artifact) {
            (ClaimKind::Exec, _) => format!("{} a command", self.verb),
            // 路径截得比血缘链（52）更狠：这一列要和 `| kernel: …` 挤在同一行
            // （见 `ClaimVsKernel::render`），而**结论**才是这一行存在的理由 ——
            // 路径长到把结论顶出行尾，就是拿读者最需要的那半句换最不必要的那半句。
            (_, Some(a)) => format!("{} {}", self.verb, clip(a.display(), 32)),
            (_, None) => self.verb.clone(),
        }
    }
}

/// 说"我做了这件事"的动词表。**刻意短**：每一个都要在结果文本里以**词边界**
/// 出现，且必须紧邻一个产物（前后 48/32 列内）。
const WRITE_VERBS: &[&str] = &[
    "wrote", "written", "saved", "saved to", "downloaded", "downloaded to", "created",
    "generated", "exported", "stored", "writing", "saving",
];
const FETCH_VERBS: &[&str] = &["fetched", "downloaded", "retrieved", "pulled", "got", "fetched from"];
/// 说"我执行了这个文件"的动词表（§14.2 的第三种对账）。
///
/// 比前两张表更窄，而且**额外**要求工具名是 shell 类（见 [`is_shell_tool`]）：
/// `ran` / `executed` 是常见英文词，一个 `Read` 的结果里出现
/// "the script ran /tmp/x.sh" 是**读到了这句话**，不是这个 agent 执行了它。
const EXEC_VERBS: &[&str] = &["ran", "executed", "invoked", "launched", "spawned"];
/// Exec claim 的动词后窗口：比 Write/Fetch 更紧（24 列）。`ran` 太短，
/// 隔着半个段落去认领一个路径必然是巧合。
const EXEC_AFTER: usize = 24;

/// 这条调用是不是"能执行东西"的工具。只有它说的话里 `executed X` 才是
/// "我执行了 X" —— 别的工具（Read/Grep/WebFetch）的文本里出现 `executed`
/// 只是它**看到**了那个词。
pub fn is_shell_tool(tool: &str) -> bool {
    let t = tool.to_ascii_lowercase();
    matches!(
        t.as_str(),
        "bash" | "sh" | "shell" | "zsh" | "fish" | "exec" | "command" | "run" | "terminal"
    )
}

/// `tool.result` 文本 → 它声称做了什么。
///
/// 启发式，且**只在文本里真的出现了产物和产出动词**时才认一个 claim。
/// 词边界是必须的：`unsaved` 里的 `saved`、`recreated` 里的 `created` 都不是 claim。
pub fn claims(text: &str) -> Vec<Claim> {
    let flat = one_line(text);
    let mut out: Vec<Claim> = Vec::new();
    for a in extract(&flat) {
        // 产物在文本里的位置（取第一次出现）。
        let Some(pos) = flat.find(a.display()) else {
            continue;
        };
        let before = &flat[..pos];
        let end = (pos + a.display().len()).min(flat.len());
        let after = &flat[end..];
        // 动词表按产物类型分派。路径先看 exec 表（"ran /tmp/x.sh" 比
        // "wrote /tmp/x.sh" 更具体），URL 只有取回一说。
        let (kind, verbs) = match a {
            Artifact::Url { .. } => (ClaimKind::Fetch, FETCH_VERBS),
            Artifact::Path(_) => (ClaimKind::Write, WRITE_VERBS),
        };
        let hit = match a {
            Artifact::Path(_) => find_verb(before, after, EXEC_VERBS, EXEC_AFTER)
                .map(|v| (ClaimKind::Exec, v))
                .or_else(|| find_verb(before, after, verbs, 32).map(|v| (kind.clone(), v))),
            _ => find_verb(before, after, verbs, 32).map(|v| (kind.clone(), v)),
        };
        if let Some((kind, v)) = hit {
            let _ = &kind;
            let c = Claim {
                kind,
                verb: v,
                artifact: Some(a.clone()),
            };
            if !out.contains(&c) {
                out.push(c);
            }
        }
        if out.len() >= MAX_CLAIMS {
            break;
        }
    }
    out
}

/// 在产物**前面 48 列 / 后面 32 列**里找动词。前窗口比后窗口大：英文里
/// "wrote X" 远多于 "X was written"。
fn find_verb(before: &str, after: &str, verbs: &[&str], after_cols: usize) -> Option<String> {
    let b: Vec<char> = before.chars().rev().take(48).collect();
    let b: String = b.into_iter().rev().collect();
    let a: String = after.chars().take(after_cols).collect();
    for v in verbs {
        if contains_word(&b.to_ascii_lowercase(), v) {
            return Some(v.to_string());
        }
    }
    for v in verbs {
        if contains_word(&a.to_ascii_lowercase(), v) {
            return Some(v.to_string());
        }
    }
    None
}

/// 词边界包含：`needle` 两侧不能是字母/数字/下划线。
fn contains_word(hay: &str, needle: &str) -> bool {
    let mut from = 0usize;
    while let Some(i) = hay[from..].find(needle) {
        let at = from + i;
        let end = at + needle.len();
        let left_ok = at == 0
            || !hay[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        let right_ok = end >= hay.len()
            || !hay[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if left_ok && right_ok {
            return true;
        }
        from = end;
    }
    false
}

/// 结果文本里最短的失败证据：`exit 7` / `HTTP 404` / 结果第一行。
///
/// 与 §13 的 `head` 同源但更短 —— 血缘行只有一行的预算，括号里塞不下整句。
pub fn error_note(text: &str) -> Option<String> {
    if let Some(n) = crate::fail::exit_code_from_text(text) {
        if n != 0 {
            return Some(format!("exit {}", n));
        }
    }
    if let Some(c) = http_status(text) {
        return Some(format!("HTTP {}", c));
    }
    let first = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(clip(first, 28))
}

/// `HTTP 404` / `returned error: 404` / `status 500` → 404。
///
/// 只在**紧跟着状态键**的数字里找，且限定 100..=599：任何三位数都当状态码
/// 会把 `curl: (22)` 里的 22 之外的随机数字变成"HTTP 断言"。
fn http_status(text: &str) -> Option<u32> {
    const KEYS: &[&str] = &["HTTP ", "http ", "status ", "Status ", "error: ", "code "];
    for k in KEYS {
        let mut from = 0usize;
        while let Some(i) = text[from..].find(k) {
            let at = from + i + k.len();
            let digits: String = text[at..].chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.len() == 3 {
                if let Ok(n) = digits.parse::<u32>() {
                    if (100..=599).contains(&n) {
                        return Some(n);
                    }
                }
            }
            from = at.max(from + 1);
        }
    }
    None
}

// ---------------------------------------------------------------
// 对账：claim vs kernel
// ---------------------------------------------------------------

/// 这条调用在内核侧的事实。**全部来自已经被 join key 绑到这条调用上的行**
/// （或由调用方明确的会话级绑定），不是"整个内核里搜了一遍"。
#[derive(Debug, Default, Clone)]
pub struct Facts<'a> {
    /// 这一轮有没有内核源（§13 的同一口径）。
    pub kernel_available: bool,
    /// 这条调用挂上了 ≥1 条内核事件（argv 绑定成功）。
    pub linked: bool,
    /// 会话级 pid 绑定是 exact 或 heuristic（楔形视图的第二个门槛）。
    pub session_linked: bool,
    /// 这条调用落在内核观测窗口**之内**（它的结果晚于第一条内核事件）。
    ///
    /// 只对 `session_linked` 那条路有意义：会话级绑定说的是"这条调用的进程树
    /// 我们看着"，但没看着的**那一小段**（采集器 attach 之前）里发生的事，
    /// 我们不能拿"没看见"当"没发生"。绑到了内核事件的调用天然在窗口内。
    pub in_window: bool,
    /// 这条调用子树里**写意图**的 open（路径，成功与否）。
    pub write_paths: &'a [String],
    /// 这条调用子树里的 connect/sendto 对端。
    pub net_targets: &'a [String],
    /// 这条调用子树里被认领的那次 exec。
    pub exec_seen: bool,
}

impl Facts<'_> {
    /// 有资格对**这条调用**做否定陈述吗。
    ///
    /// 两个门槛缺一不可，与 §13 的楔形视图一致：
    /// - 这一轮确实在看内核（否则"内核里没有"是一句没有主语的话）；
    /// - 这条调用确实被连上了（有 join key 的内核事件，或会话级绑定可用）。
    fn can_speak(&self) -> bool {
        self.kernel_available && (self.linked || (self.session_linked && self.in_window))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimVsKernel {
    pub claim: String,
    pub kernel: String,
    pub mismatch: bool,
}

impl ClaimVsKernel {
    /// 渲染成一行：`claim: X | kernel: Y !!`
    pub fn render(&self) -> String {
        format!(
            "claim: {} | kernel: {}{}",
            self.claim,
            self.kernel,
            if self.mismatch { " !!" } else { "" }
        )
    }
}

/// claim 与内核事实对账。
///
/// **门槛不满足时返回空**（不是"核对通过"）：我们没有资格核对的东西，
/// 一行都不产出。行首的 `kernel:` 列永远是内核侧的原话或它的缺失，
/// 不允许出现"大概"。
pub fn evaluate(claims: &[Claim], facts: &Facts) -> Vec<ClaimVsKernel> {
    if !facts.can_speak() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for c in claims.iter().take(MAX_CLAIMS) {
        match (c.kind.clone(), &c.artifact) {
            (ClaimKind::Write, Some(a)) => {
                let claimed = a.display().to_string();
                let (kernel, mismatch) = match_write(&claimed, facts.write_paths);
                out.push(ClaimVsKernel {
                    claim: c.render(),
                    kernel,
                    mismatch,
                });
            }
            (ClaimKind::Fetch, Some(a)) => {
                let host = match a {
                    Artifact::Url { host, .. } => host.clone(),
                    Artifact::Path(_) => continue,
                };
                let (kernel, mismatch) = match_net(&host, facts.net_targets);
                out.push(ClaimVsKernel {
                    claim: c.render(),
                    kernel,
                    mismatch,
                });
            }
            (ClaimKind::Exec, _) => {
                let (kernel, mismatch) = if facts.exec_seen {
                    ("exec observed".to_string(), false)
                } else {
                    ("no exec linked to this call".to_string(), true)
                };
                out.push(ClaimVsKernel {
                    claim: c.render(),
                    kernel,
                    mismatch,
                });
            }
            _ => {}
        }
    }
    out
}

/// 内核侧的写事实 vs 声明的路径。
///
/// 三种回答，从强到弱：
/// 1. 有写意图 open 落在**这个路径**上 → `write open observed`（不矛盾）；
/// 2. 有写意图 open，但都不在这个路径上 → `write open observed, but not to this path`（矛盾）；
/// 3. 一条写意图 open 都没有 → `no write open observed`（矛盾）。
///
/// 第 2 种的存在是为了**不冤枉**：`curl -o /tmp/a -o /tmp/b` 这种调用里，
/// 只报"没写"是不对的，内核明明看到了写。
fn match_write(claimed: &str, write_paths: &[String]) -> (String, bool) {
    if write_paths.is_empty() {
        return ("no write open observed".to_string(), true);
    }
    if let Some(p) = write_paths.iter().find(|p| path_matches(p, claimed)) {
        let s = if *p == claimed {
            "write open observed".to_string()
        } else {
            format!("write open observed at {}", clip(p, 40))
        };
        return (s, false);
    }
    let others: Vec<String> = write_paths.iter().take(2).map(|p| clip(p, 28)).collect();
    (
        format!("write open observed, but not to this path (saw {})", others.join(", ")),
        true,
    )
}

/// 内核侧的连出事实 vs 声明的主机。
///
/// **域名不做否定陈述**：内核报的是解析后的地址，把 `example.com` 和
/// `93.184.216.34` 对上需要 DNS 记录，我们没有 —— 所以对域名只回答
/// "有没有发生 outbound connect"。IP 字面量可以直接对。
fn match_net(host: &str, targets: &[String]) -> (String, bool) {
    if targets.is_empty() {
        return ("no outbound connect observed".to_string(), true);
    }
    if is_ip_literal(host) {
        if targets.iter().any(|t| t == host || t.starts_with(&format!("{}:", host))) {
            return (format!("connect to {} observed", host), false);
        }
        let saw: Vec<String> = targets.iter().take(2).map(|t| clip(t, 24)).collect();
        return (
            format!("connect observed, but not to {} (saw {})", host, saw.join(", ")),
            true,
        );
    }
    ("outbound connect observed (hostname resolution is not visible to us)".to_string(), false)
}

/// 内核路径与声明的路径是不是同一个东西。
///
/// - 完全相同 → 是；
/// - 内核路径以 `/claim` 结尾 → 是（内核报的是同一个文件但路径更长）；
/// - 声明路径以 `/内核路径` 结尾，且断在**分量边界**上 → 是；
/// - 内核侧是**相对**路径且 basename 相同（`work/x.pdf` vs `/a/work/x.pdf`
///   或 `x.pdf`）→ 是。
///
/// 最后两条都是**相对路径**在兜底：`openat` 报的是原始实参，相对路径是相对
/// **进程 cwd** 解析的，而 cwd 不在我们的行协议里（§5.2 #2）。
///
/// 为什么宁可认账：这个检查的全部价值在于"屏幕上的 `!!` 都值得看"。相对路径
/// 在真实会话里是**常态**（`curl -o work/q3.pdf`、`> out.txt`），而 transcript
/// 的自我陈述常常写绝对路径 —— 一次真实会话里就这么冤枉过一次：`curl -s -o
/// work/q3.pdf` 明明写了文件，内核只是报了相对路径，我们却说出"no write open
/// observed"，那是一句**关于内核的假话**。两种错误的代价不对称：认账认错了是
/// 漏报（少抓一次谎），不认账是**诬告**（把真写说成没写）。所以边界后缀算匹配。
///
/// 代价写在明处：cwd 不同的同名相对路径会**误认成同一个文件**。缓解来自上下文 ——
/// 走到这里的内核写意图必须绑定到**这一次调用**（同一 pid 子树、同一时间窗），
/// 而不是全局任意一次写。
fn path_matches(kernel_path: &str, claimed: &str) -> bool {
    // `./x` 和 `x` 是同一个相对路径，只差一个书写前缀。
    let kernel_path = kernel_path.strip_prefix("./").unwrap_or(kernel_path);
    if kernel_path == claimed {
        return true;
    }
    if kernel_path.len() > claimed.len()
        && kernel_path.ends_with(claimed)
        && kernel_path[..kernel_path.len() - claimed.len()].ends_with('/')
    {
        return true;
    }
    if claimed.len() > kernel_path.len()
        && claimed.ends_with(kernel_path)
        && claimed[..claimed.len() - kernel_path.len()].ends_with('/')
    {
        return true;
    }
    if !kernel_path.contains('/') && !claimed.is_empty() {
        let base = claimed.rsplit('/').next().unwrap_or("");
        return kernel_path == base;
    }
    false
}

// ---------------------------------------------------------------
// magic number 嗅探（用户态启发式）
// ---------------------------------------------------------------

/// 嗅探上限：只读前 1 MiB（json 的"能不能 parse"也只在这个窗口里判，
/// 说明里会写清楚）。
const SNIFF_READ_MAX: usize = 1024 * 1024;
/// 超过这个大小就不嗅了：读 1 MiB 只为说一句话，代价不成比例。
const SNIFF_FILE_MAX: u64 = 64 * 1024 * 1024;

/// 按扩展名核对文件的前几个字节。
///
/// **这不是内核证据**，措辞里必须写明：它是"我们打开这个文件看了一眼"，
/// 而不是"内核说这个文件是 HTML"。存在的理由：服务器返回 200 + 一个错误页、
/// 客户端把错误页存成 `.pdf`，是"下载成功"这个 claim 最常见的假象 ——
/// 而这个假象在 transcript 里看不出来（`curl` 的退出码是 0）。
pub fn sniff(path: &str) -> Option<String> {
    let ext = path.rsplit('.').next()?.to_ascii_lowercase();
    if !matches!(ext.as_str(), "pdf" | "json" | "png" | "zip" | "html" | "htm" | "csv") {
        return None;
    }
    let md = std::fs::metadata(path).ok()?;
    if !md.is_file() || md.len() == 0 || md.len() > SNIFF_FILE_MAX {
        return None;
    }
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    std::io::Read::take(f, SNIFF_READ_MAX as u64)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.is_empty() {
        return None;
    }
    // 只有把整个文件都读进来了，才敢说"它 parse 不了"。
    let complete = md.len() as usize <= buf.len();
    let head = String::from_utf8_lossy(&buf[..buf.len().min(64)]);
    let h = head.trim_start();
    let hl = h.to_ascii_lowercase();

    let looks_html = hl.starts_with("<!doctype html") || hl.starts_with("<html") || hl.starts_with("<?xml") && hl.contains("html");
    let looks_pdf = buf.starts_with(b"%PDF");
    let looks_png = buf.starts_with(&[0x89, b'P', b'N', b'G']);
    let looks_zip = buf.starts_with(b"PK\x03\x04");
    let looks_json = h.starts_with('{') || h.starts_with('[');

    let verdict = match ext.as_str() {
        "pdf" => {
            if looks_pdf {
                None
            } else if looks_html {
                Some("HTML")
            } else if looks_json {
                Some("JSON")
            } else if !buf.iter().take(16).any(|b| *b == 0) && looks_text(&buf) {
                Some("plain text")
            } else {
                None
            }
        }
        "html" | "htm" => {
            if looks_html {
                None
            } else if looks_pdf {
                Some("PDF")
            } else {
                None
            }
        }
        "png" => {
            if looks_png {
                None
            } else if looks_html {
                Some("HTML")
            } else if looks_zip {
                Some("ZIP")
            } else {
                None
            }
        }
        "zip" => {
            if looks_zip {
                None
            } else if looks_html {
                Some("HTML")
            } else {
                None
            }
        }
        "json" => {
            if !looks_json {
                None
            } else if !complete {
                // 只读了前 1 MiB 的文件不下"能不能 parse"的结论。
                None
            } else if serde_json::from_slice::<serde_json::Value>(&buf).is_err() {
                Some("truncated/invalid JSON")
            } else {
                None
            }
        }
        "csv" => {
            if looks_html {
                Some("HTML")
            } else {
                None
            }
        }
        _ => None,
    }?;

    let expect = match ext.as_str() {
        "pdf" => "%PDF",
        "png" => "PNG",
        "zip" => "ZIP",
        "json" => "{",
        "csv" => "a CSV row",
        _ => "HTML",
    };
    // **身份标签写在最前面**，这一条是有意的：footer 的注解行受 120 列约束，长路径
    // 会把行尾吃掉 —— 而"这不是内核证据"是这句话里唯一不能丢的部分（丢了它，读到的
    // 就是一次凭空的指控）。路径、结论、期望值都可以被截，身份不行。
    Some(format!(
        "(userspace heuristic, not kernel evidence) {} smells like {} (expected {})",
        clip(path, 30),
        verdict,
        expect
    ))
}

fn looks_text(buf: &[u8]) -> bool {
    buf.iter().take(32).all(|b| *b == b'\n' || *b == b'\r' || *b == b'\t' || (0x20..0x7f).contains(b))
}

// ---------------------------------------------------------------
// 从内核事件里取"这条调用挂住的事实"
// ---------------------------------------------------------------

/// 把一条**已经带 join key** 的内核事件折进事实里。
///
/// 与 §13 的 `Evidence` 分开累加、互不干扰：那边要的是"最深失败点"，
/// 这边要的是"有没有写、有没有连、有没有 exec"。
#[derive(Debug, Default, Clone)]
pub struct KernelFacts {
    /// 写意图 open 的路径（去重）。**有界**：一次 `find /` 也会写几十个路径，
    /// 而对账只关心"声明的那个在不在里面"，多留无益。
    pub write_paths: Vec<String>,
    pub net_targets: Vec<String>,
    pub exec_seen: bool,
}

impl KernelFacts {
    /// 一条内核事件。`kind` 只用来兜底判断——真正的依据是 payload。
    pub fn observe(&mut self, ev: &crate::event::Event) {
        match &ev.payload {
            Payload::ProcExec { .. } => self.exec_seen = true,
            Payload::FileOpen {
                path, flags, ok, ..
            } => {
                let write = crate::render::is_write_intent(*flags);
                // 失败**也**记：`openat /tmp/x.pdf EACCES` 说明这次调用确实碰了这个
                // 路径；把它丢掉会让"没写"变成一个假结论。成功与否由渲染层决定。
                if write && self.write_paths.len() < MAX_WRITE_PATHS {
                    let p = (*path).clone();
                    if !self.write_paths.contains(&p) {
                        self.write_paths.push(p);
                    }
                    let _ = ok;
                }
            }
            Payload::NetConnect { addr, port, .. } => {
                let t = match port {
                    Some(p) => format!("{}:{}", addr, p),
                    None => addr.clone(),
                };
                if !self.net_targets.contains(&t) {
                    self.net_targets.push(t);
                }
            }
            Payload::NetSendto { peer, .. } => {
                if let Some(p) = peer {
                    if !self.net_targets.contains(p) {
                        self.net_targets.push(p.clone());
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(a: &Artifact) -> &str {
        a.path().unwrap()
    }

    // -----------------------------------------------------------
    // 产物抽取
    // -----------------------------------------------------------

    #[test]
    fn extract_takes_absolute_paths_and_urls() {
        let got = extract("curl -sL https://example.com/a.pdf -o /tmp/a.pdf && ls /tmp");
        assert_eq!(got.len(), 3, "{:?}", got);
        // "像文件名"的排在前面（URL 和带扩展名的路径），目录垫底。
        assert_eq!(got[0].display(), "https://example.com/a.pdf");
        assert_eq!(
            got[0],
            Artifact::Url {
                host: "example.com".into(),
                url: "https://example.com/a.pdf".into()
            }
        );
        assert_eq!(paths(&got[1]), "/tmp/a.pdf");
        assert_eq!(paths(&got[2]), "/tmp");
    }

    #[test]
    fn relative_paths_are_not_artifacts() {
        // 只有 basename 的相对路径不算产物：没有 cwd，`cat report.pdf` 两次提到
        // 的完全可能是两个文件。
        assert!(extract("cat report.pdf").is_empty());
        assert!(extract("python3 script.py").is_empty());
    }

    #[test]
    fn a_relative_path_with_a_directory_component_is_an_artifact() {
        // 带目录分量就不一样了：它和绝对路径一样能对齐两次提到的东西，
        // 而真实会话里 Bash 工具的命令几乎全长这样（见 `extract` 里的注释）。
        let got = extract("curl -s -o work/q3.pdf https://example.com/q3.pdf");
        assert_eq!(got.len(), 2, "{:?}", got);
        assert_eq!(paths(&got[0]), "work/q3.pdf");
        assert_eq!(got[1].display(), "https://example.com/q3.pdf");
        // `./x` 和 `x` 只差书写前缀，两条都要能认出来。
        assert_eq!(paths(&extract("cat ./report.pdf")[0]), "./report.pdf");
        // 目录本身（没有扩展名）不占名额：`cd src/lib` 不是产物。
        assert!(extract("cd src/lib").is_empty());
    }

    #[test]
    fn system_noise_is_not_an_artifact() {
        // `/dev/null` 这类每条命令都会碰的东西不该进血缘表：它们会把真正的产物
        // 从 4 个名额里挤出去，还会连出假的链。
        let got = extract("ls /tmp > /dev/null 2>/dev/null");
        assert!(
            got.iter().all(|a| a.path() != Some("/dev/null")),
            "{:?}",
            got
        );
    }

    #[test]
    fn extract_prefers_files_over_directories() {
        // 目录在命令里很常见（`cd`、`grep -r`），而"第 3 步产出的那个东西"
        // 几乎总是有扩展名的文件。
        let got = extract("grep -r x /usr/lib/python3 /tmp/x.pdf /home/me/proj");
        assert_eq!(got.len(), 3, "{:?}", got);
        assert_eq!(paths(&got[0]), "/tmp/x.pdf");
    }

    #[test]
    fn extract_is_bounded() {
        let text = "/a/1.pdf /a/2.pdf /a/3.pdf /a/4.pdf /a/5.pdf /a/6.pdf";
        assert!(extract(text).len() <= MAX_ARTIFACTS);
    }

    // -----------------------------------------------------------
    // claim 抽取
    // -----------------------------------------------------------

    fn claim_render(text: &str) -> Vec<String> {
        claims(text).iter().map(|c| c.render()).collect()
    }

    #[test]
    fn a_write_claim_needs_a_verb_next_to_a_path() {
        assert_eq!(
            claim_render("Saved to /tmp/report.pdf (128431 bytes)"),
            vec!["saved /tmp/report.pdf"]
        );
        // 有路径、没有动词：这是在**读**它，不是在造它。
        assert!(claims("Read /tmp/report.pdf").is_empty());
        // 有动词、没有路径：没有可查证的对象。
        assert!(claims("Saved the answer to memory").is_empty());
    }

    #[test]
    fn word_boundaries_matter() {
        // `unsaved` 里的 `saved` 不是 claim：差一个字母就是另一句话。
        assert!(claims("unsaved changes in /tmp/x.txt").is_empty());
        assert!(claims("recreated /tmp/x.txt").is_empty());
    }

    #[test]
    fn a_fetch_claim_keeps_the_url() {
        let got = claims("Downloaded https://10.1.2.3/x.json (2048 bytes)");
        assert_eq!(got.len(), 1, "{:?}", got);
        assert_eq!(got[0].kind, ClaimKind::Fetch);
        assert_eq!(got[0].render(), "downloaded https://10.1.2.3/x.json");
    }

    #[test]
    fn exec_claims_need_a_shell_tool() {
        // 同一个句子，工具不同，结论不同：`Read` 是**读到**了这句话。
        let text = "ran /tmp/setup.sh";
        assert!(claims(text).iter().any(|c| c.kind == ClaimKind::Exec));
        assert!(is_shell_tool("Bash") && is_shell_tool("shell"));
        assert!(!is_shell_tool("Read") && !is_shell_tool("WebFetch"));
    }

    #[test]
    fn http_status_is_only_read_next_to_a_status_key() {
        assert_eq!(http_status("HTTP 404 Not Found"), Some(404));
        assert_eq!(http_status("error: 503"), Some(503));
        // `curl: (22)` 里的 22 不是状态码（也不是三位数）。
        assert_eq!(http_status("curl: (22) failed"), None);
    }

    #[test]
    fn error_note_prefers_the_exit_code() {
        assert_eq!(error_note("boom\nExit code 7").as_deref(), Some("exit 7"));
        assert_eq!(error_note("HTTP 404 Not Found").as_deref(), Some("HTTP 404"));
        // 都没有：第一行，且必须截断（结果可以是几千字）。
        let n = error_note("something went wrong here\nmore").unwrap();
        assert_eq!(n, "something went wrong here");
    }

    // -----------------------------------------------------------
    // 对账
    // -----------------------------------------------------------

    fn facts<'a>(write: &'a [String], net: &'a [String], exec: bool) -> Facts<'a> {
        Facts {
            kernel_available: true,
            linked: true,
            session_linked: false,
            in_window: false,
            write_paths: write,
            net_targets: net,
            exec_seen: exec,
        }
    }

    #[test]
    fn no_kernel_source_means_no_verdict() {
        // 这是整个 v0.6 楔子的诚实边界：没在看，就不许说"没看见"。
        let c = claims("Saved to /tmp/a.pdf");
        let mut f = facts(&[], &[], false);
        f.kernel_available = false;
        assert!(evaluate(&c, &f).is_empty());
        // 有内核源、但这条调用没被连上：同样一句话都不说。
        let mut f = facts(&[], &[], false);
        f.linked = false;
        assert!(evaluate(&c, &f).is_empty());
    }

    #[test]
    fn the_second_door_needs_the_call_to_be_in_window() {
        let c = claims("Saved to /tmp/a.pdf");
        let mut f = facts(&[], &[], false);
        f.linked = false;
        f.session_linked = true;
        f.in_window = false; // 采集器 attach 之前的那一段
        assert!(evaluate(&c, &f).is_empty());
        f.in_window = true;
        assert_eq!(evaluate(&c, &f).len(), 1);
    }

    #[test]
    fn a_write_claim_is_matched_by_a_write_open_for_that_path() {
        let c = claims("Saved to /tmp/a.pdf");
        let w = vec!["/tmp/a.pdf".to_string()];
        let got = evaluate(&c, &facts(&w, &[], false));
        assert_eq!(got.len(), 1);
        assert!(!got[0].mismatch, "{:?}", got);
        assert_eq!(got[0].render(), "claim: saved /tmp/a.pdf | kernel: write open observed");
    }

    #[test]
    fn a_write_claim_with_no_write_open_is_a_mismatch() {
        let c = claims("Saved to /tmp/a.pdf");
        // 读了那个路径（甚至读成功了），但那不是**写**。
        let got = evaluate(&c, &facts(&[], &[], false));
        assert_eq!(got.len(), 1);
        assert!(got[0].mismatch);
        assert!(got[0].render().ends_with(" !!"), "{:?}", got[0]);
        assert_eq!(got[0].kernel, "no write open observed");
    }

    #[test]
    fn a_write_open_to_another_path_says_which_one_it_saw() {
        let c = claims("Saved to /tmp/a.pdf");
        let w = vec!["/tmp/b.pdf".to_string()];
        let got = evaluate(&c, &facts(&w, &[], false));
        assert!(got[0].mismatch);
        assert!(got[0].kernel.contains("/tmp/b.pdf"), "{:?}", got[0]);
    }

    #[test]
    fn a_domain_is_never_matched_to_an_address() {
        // 内核报的是解析后的地址；把域名和 IP 对上需要 DNS 记录 —— 我们没有。
        // 所以对域名只能回答**这次调用有没有连出去**，不能回答"连的是不是它"。
        let c = claims("Downloaded https://example.com/x.pdf");

        // 整条子树一次 connect 都没有：这句话说得出口，也确实对不上账。
        let got = evaluate(&c, &facts(&[], &[], false));
        assert!(got[0].mismatch);
        assert_eq!(got[0].kernel, "no outbound connect observed");

        // 有 connect（地址是别的）：**不能**说它对不上账 —— 我们不知道
        // example.com 解析到哪儿，硬说就是拿"不认识"当"不对"。
        let net = vec!["10.1.2.3:443".to_string()];
        let got = evaluate(&c, &facts(&[], &net, false));
        assert!(!got[0].mismatch, "{:?}", got[0]);
        assert!(got[0].kernel.contains("hostname resolution is not visible"), "{:?}", got[0]);
    }

    #[test]
    fn an_ip_literal_can_be_checked_directly() {
        let c = claims("Downloaded https://10.1.2.3/x.json");
        let got = evaluate(&c, &facts(&[], &[], false));
        assert!(got[0].mismatch);
        assert_eq!(got[0].kernel, "no outbound connect observed");
        // 连过：不再有话说（"没看见"的反面不是"看见了别的"）。
        let net = vec!["10.1.2.3:443".to_string()];
        let got = evaluate(&c, &facts(&[], &net, false));
        assert!(!got[0].mismatch);
    }

    #[test]
    fn an_exec_claim_needs_an_exec_in_the_subtree() {
        let c = claims("ran /tmp/setup.sh");
        let got = evaluate(&c, &facts(&[], &[], false));
        assert!(got[0].mismatch);
        assert_eq!(got[0].kernel, "no exec linked to this call");
        let got = evaluate(&c, &facts(&[], &[], true));
        assert!(!got[0].mismatch);
    }

    #[test]
    fn claims_are_capped() {
        // 一句话里塞三个产物时，只核对前两个：一次失败最多值得两行对账。
        let c = claims("wrote /a/1.pdf and saved /a/2.pdf and created /a/3.pdf");
        assert_eq!(c.len(), MAX_CLAIMS, "{:?}", c);
        assert!(evaluate(&c, &facts(&[], &[], false)).len() <= MAX_CLAIMS);
    }

    #[test]
    fn path_matching_uses_component_boundaries() {
        assert!(path_matches("/tmp/a.pdf", "/tmp/a.pdf"));
        // 内核只留了文件名（dirfd 相对路径）时按 basename 对。
        assert!(path_matches("a.pdf", "/tmp/a.pdf"));
        // `/xtmp/a.pdf` 不是 `/tmp/a.pdf`：少一个分隔符就是另一个文件。
        assert!(!path_matches("/xtmp/a.pdf", "/tmp/a.pdf"));
        // 内核看到的是**另一个更长的路径**时不算命中 —— 调用方会把"看见的是哪条"
        // 原样报出来（`write open observed, but not to this path (saw …)`），
        // 而不是替它圆场。
        assert!(!path_matches("/work/tmp/a.pdf", "/tmp/a.pdf"));
    }

    #[test]
    fn a_relative_kernel_path_is_matched_against_the_claim_tail() {
        // 真实会话里最常见的一对：transcript 写绝对路径，`openat` 记的是相对实参。
        // 冤枉一次真写比漏报一次谎更贵（见 `path_matches` 的注释）。
        assert!(path_matches("work/q3.pdf", "/tmp/v06demo/work/q3.pdf"));
        assert!(path_matches("./work/q3.pdf", "/tmp/v06demo/work/q3.pdf"));
        // 但**必须**断在分量边界上：`ork/q3.pdf` 只是长得像。
        assert!(!path_matches("ork/q3.pdf", "/tmp/v06demo/work/q3.pdf"));
        assert!(!path_matches("q3.pdf.bak", "/tmp/v06demo/q3.pdf"));
        // 边界后缀匹配的是**尾巴**，不是"随便哪个目录里的同名文件"。
        assert!(!path_matches("other/q3.pdf", "/tmp/v06demo/work/q3.pdf"));
    }

    // -----------------------------------------------------------
    // 血缘
    // -----------------------------------------------------------

    fn lineage_with(steps: &[(&str, &str, &str, bool, Option<&str>)]) -> Lineage {
        // (key, tool, args, ok, error note)
        let mut l = Lineage::new();
        for (i, (key, tool, args, ok, note)) in steps.iter().enumerate() {
            let n = l.on_call(key, tool, args, (i as u64 + 1) * 1_000);
            assert_eq!(n, i as u64 + 1);
            l.on_result(key, *ok, note.map(str::to_string), "");
        }
        l
    }

    #[test]
    fn steps_are_numbered_from_one_over_every_call() {
        let l = lineage_with(&[
            ("c1", "Bash", "curl -o /tmp/a.pdf https://x/a.pdf", true, None),
            ("c2", "Read", "/tmp/a.pdf", true, None),
        ]);
        assert_eq!(l.stats().steps, 2);
        assert_eq!(l.key_of_step(2), Some("c2"));
    }

    #[test]
    fn a_consumer_links_back_to_the_earlier_producer() {
        let l = lineage_with(&[
            ("c1", "Bash", "curl -o /tmp/a.pdf https://x/a.pdf", false, Some("exit 22")),
            ("c2", "Bash", "display_pdf /tmp/a.pdf", false, Some("exit 1")),
        ]);
        let chain = l.chain("c2");
        assert_eq!(chain.len(), 1, "{:?}", chain);
        assert!(chain[0].contains("/tmp/a.pdf"), "{:?}", chain);
        assert!(chain[0].contains("produced by step 1 Bash"), "{:?}", chain);
        // 产出者那一步是错的 —— 这句话必须带上（它把两次失败连成一件事）。
        assert!(chain[0].contains("ERRORED: exit 22"), "{:?}", chain);
    }

    #[test]
    fn a_producer_links_forward_to_the_later_consumer() {
        let l = lineage_with(&[
            ("c1", "Bash", "curl -o /tmp/a.pdf https://x/a.pdf", false, Some("exit 22")),
            ("c2", "Read", "/tmp/a.pdf", true, None),
        ]);
        let chain = l.chain("c1");
        assert_eq!(chain.len(), 1, "{:?}", chain);
        assert!(chain[0].contains("referenced later by step 2 Read"), "{:?}", chain);
    }

    #[test]
    fn the_first_mention_is_the_producer() {
        // 循环重试：第 2、3 次提到同一个产物，产出者仍然是第 1 次。
        let cmd = "curl -o /tmp/a.pdf https://x/a.pdf";
        let l = lineage_with(&[
            ("c1", "Bash", cmd, true, None),
            ("c2", "Bash", cmd, true, None),
            ("c3", "Bash", cmd, false, Some("exit 28")),
        ]);
        let chain = l.chain("c3");
        assert!(chain.iter().any(|c| c.contains("produced by step 1 Bash (ok)")), "{:?}", chain);
        // 命令里有一个路径**和一个 URL**，两个都被 3 步提到过。
        assert_eq!(l.stats().reused, 2, "both the path and the URL repeat");
    }

    #[test]
    fn a_claim_comes_from_the_result_text_not_from_the_call_args() {
        // claim 的语义是"**这条结果**说它做了 X"，不是"这条调用的参数里有 X"。
        // 所以一个 Read 读到的文件内容里写着 `saved /tmp/other.pdf`，也会抽出一条
        // claim —— 它不在这条调用的参数里（`/tmp/a.pdf` 才是）。
        //
        // 这是**故意**的取舍：代价是读到一句"我存了 X"的日志时会多出一行两列对账。
        // 那一行本身是真的（结果确实这么说了），而且行上有工具名（`Read`）——
        // 读者能自己判读。反过来把 claim 限制在参数里，绝大多数真实的
        // "脚本自己决定输出路径"就永远查不着。
        let mut l = Lineage::new();
        l.on_call("c1", "Bash", "curl -o /tmp/a.pdf https://x/a.pdf", 1);
        l.on_result("c1", true, None, "Saved to /tmp/a.pdf");
        l.on_call("c2", "Read", "/tmp/a.pdf", 2);
        l.on_result("c2", true, None, "the file says: saved /tmp/other.pdf");
        assert_eq!(l.claims_of("c1").len(), 1);
        let c2 = l.claims_of("c2");
        assert_eq!(c2.len(), 1, "{:?}", c2);
        assert_eq!(c2[0].artifact.as_ref().unwrap().display(), "/tmp/other.pdf");
    }

    #[test]
    fn a_chain_is_bounded_and_deduped() {
        let l = lineage_with(&[
            ("c1", "Bash", "curl -o /tmp/a.pdf https://x/a.pdf", true, None),
            ("c2", "Read", "/tmp/a.pdf", true, None),
            ("c3", "Bash", "cat /tmp/a.pdf", false, Some("exit 1")),
            ("c4", "Bash", "wc /tmp/a.pdf", false, Some("exit 1")),
        ]);
        let chain = l.chain("c1");
        assert!(chain.len() <= MAX_CHAIN, "{:?}", chain);
    }

    #[test]
    fn stats_count_artifacts_and_reuse() {
        let l = lineage_with(&[
            ("c1", "Bash", "curl -o /tmp/a.pdf https://x/a.pdf", true, None),
            ("c2", "Read", "/tmp/a.pdf", true, None),
        ]);
        let s = l.stats();
        assert_eq!(s.steps, 2);
        assert_eq!(s.artifacts, 2, "the path and the URL");
        assert_eq!(s.reused, 1, "only the path is mentioned twice");
    }

    // -----------------------------------------------------------
    // 嗅探（用户态启发式）
    // -----------------------------------------------------------

    fn tmp_file(name: &str, body: &[u8]) -> String {
        let p = std::env::temp_dir().join(format!("agtrace_lineage_{}_{}", std::process::id(), name));
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }

    #[test]
    fn a_pdf_full_of_html_is_flagged_and_labeled_as_a_heuristic() {
        let p = tmp_file("smell.pdf", b"<!DOCTYPE html>\n<html><body>404</body></html>");
        let v = sniff(&p).expect("html in a .pdf must be flagged");
        // 身份标签必须**在**这句话里 —— 这不是内核证据。
        assert!(v.contains("userspace heuristic"), "{}", v);
        assert!(v.contains("not kernel evidence"), "{}", v);
        assert!(v.contains("smells like HTML"), "{}", v);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_real_pdf_is_not_flagged() {
        let p = tmp_file("real.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n");
        assert!(sniff(&p).is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn json_that_does_not_parse_is_flagged_but_a_truncated_read_is_not() {
        let bad = tmp_file("bad.json", b"{\"a\": ");
        let v = sniff(&bad).expect("invalid json must be flagged");
        assert!(v.contains("smells like truncated/invalid JSON"), "{}", v);
        let _ = std::fs::remove_file(&bad);
        let good = tmp_file("good.json", b"{\"a\": 1}");
        assert!(sniff(&good).is_none());
        let _ = std::fs::remove_file(&good);
    }

    #[test]
    fn an_unknown_extension_is_never_sniffed() {
        let p = tmp_file("x.log", b"<!DOCTYPE html>");
        assert!(sniff(&p).is_none());
        let _ = std::fs::remove_file(&p);
        // 不存在的文件：安静地什么都不说（不是"看起来正常"）。
        assert!(sniff("/nonexistent/xyz.pdf").is_none());
    }

    #[test]
    fn clip_keeps_the_basename() {
        // 尾部的文件名才是识别度所在 —— 从左边截。
        assert_eq!(clip("/very/long/path/to/report.pdf", 16), "...to/report.pdf");
        assert_eq!(clip("/short.pdf", 40), "/short.pdf");
    }
}
