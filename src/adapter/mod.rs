//! Adapter 接口（DESIGN.md §3.1）。
//!
//! **为什么是 `poll` 而不是 `async Stream`**：v0 不引入 tokio（铁律）。
//! 主循环用一个简单的多路复用轮询，adapter 不得阻塞超过 ~10ms。

pub mod claude_code;
pub mod dsh;
pub mod jsonl;
pub mod openshell;

use crate::event::{Binding, Corr, Event, Kind, Layer, Payload, TruncNote};
use crate::poll::PollOutcome;

/// 一个 agent 事件源。
pub trait EventAdapter: Send {
    /// 稳定标识，用于 `--adapter` 选择和事件里的 source 字段。
    fn id(&self) -> &'static str;

    /// 能力声明：支持哪些 kind、是否支持实时 tail、是否需要外部传入路径。
    fn capabilities(&self) -> Capabilities;

    /// 非阻塞拉取。返回本次新增的事件（可能为空）。
    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, AdapterError>;

    /// 优雅关闭（flush、关闭文件句柄）。
    fn shutdown(&mut self);

    /// 解析过程中遇到的、`-v` 下应当可见的说明（未知 type 计数等）。
    fn diagnostics(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub struct Capabilities {
    /// 本 adapter 会产出哪些 kind。
    pub kinds: Vec<Kind>,
    /// 能否实时 tail（openshell stub 为 false，只读 fixture）。
    pub live: bool,
    /// 是否需要 merger 帮它绑定 pid（Claude Code adapter 需要，§3.5）。
    pub needs_pid_binding: bool,
}

#[derive(Debug)]
pub enum AdapterError {
    /// 启动时校验关键字段失败 —— 明确报错，而不是产出空事件（§5.4 #4）。
    Schema(String),
    Io(String),
    NotFound(String),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::Schema(s) => write!(f, "adapter schema error: {}", s),
            AdapterError::Io(s) => write!(f, "adapter io error: {}", s),
            AdapterError::NotFound(s) => write!(f, "adapter source not found: {}", s),
        }
    }
}

/// ISO8601（UTC，毫秒）→ Unix epoch 纳秒。
///
/// 手写解析而不是引入 chrono：transcript 的时间格式是固定的
/// `2026-10-03T15:16:53.634Z`（§1.4 已验证），格式简单且可以严格校验。
/// **解析失败返回 None**，调用方丢弃该事件并计数 —— 绝不 panic，绝不瞎猜时间。
pub fn parse_iso8601_ns(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |a: usize, n: usize| -> Option<i64> {
        let sl = s.get(a..a + n)?;
        if !sl.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        sl.parse::<i64>().ok()
    };
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (h, mi, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }

    // 小数秒
    let mut frac_ns: u64 = 0;
    let mut i = 19;
    if b.get(19) == Some(&b'.') {
        i = 20;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &s[start..i];
        // 只取前 9 位（纳秒精度），不足右侧补 0。
        let take = digits.len().min(9);
        let mut v: u64 = digits[..take].parse().ok()?;
        for _ in take..9 {
            v *= 10;
        }
        frac_ns = v;
    }

    // 时区：Z / +HH:MM / -HH:MM
    let mut offset_sec: i64 = 0;
    match b.get(i) {
        Some(&b'Z') | None => {}
        Some(&c) if c == b'+' || c == b'-' => {
            let sign = if c == b'+' { 1 } else { -1 };
            let oh = num(i + 1, 2)?;
            let om = if b.get(i + 3) == Some(&b':') {
                num(i + 4, 2)?
            } else {
                num(i + 3, 2)?
            };
            offset_sec = sign * (oh * 3600 + om * 60);
        }
        _ => return None,
    }

    // days_from_civil（Howard Hinnant）
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + h * 3600 + mi * 60 + sec - offset_sec;
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1_000_000_000 + frac_ns)
}

/// Unix epoch 纳秒 → ISO8601 UTC 毫秒（与 transcript 原生格式一致，避免精度幻觉，§3.2）。
pub fn iso8601_ms(wall_ns: u64) -> String {
    let secs = (wall_ns / 1_000_000_000) as i64;
    let ms = (wall_ns % 1_000_000_000) / 1_000_000;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days（Howard Hinnant）
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, m, d, h, mi, s, ms)
}

/// 把已有字段拼装成一个 Event 的助手，减少各 adapter 的样板代码。
#[allow(clippy::too_many_arguments)]
pub fn agent_event(
    wall_ns: u64,
    kind: Kind,
    layer: Layer,
    source: &str,
    corr: Corr,
    payload: Payload,
    trunc: Vec<TruncNote>,
    notes: Vec<String>,
) -> Event {
    Event {
        seq: 0,
        // ts_ns 由 merger 用 CLOCK_MONOTONIC offset 换算后填入（§1.4）。
        ts_ns: 0,
        ts_wall_ns: wall_ns,
        ts_src: crate::event::TsSource::Converted,
        layer,
        kind,
        source: source.to_string(),
        pid: None,
        tid: None,
        ppid: None,
        comm: None,
        cgroup_id: None,
        corr,
        payload,
        trunc,
        notes,
        late: false,
        watch: false,
        binding: Binding::None,
        retry: false,
    }
}

/// 增量 tail 一个不断被追加写的文件（§3.3）。
///
/// 三个必须处理的现实：
///  1. 文件可能**还不存在**（会话刚启动）→ 不是错误，返回 Idle。
///  2. 文件可能被**轮转/重建**（inode 变化）或**原地截断重写** → 重置 offset。
///  3. 写入**不保证以完整行结束** `[未验证]` → 半行留在缓冲区等下次（§5.4 #3）。
///
/// 恢复动作（restart from 0）从不假装无代价：`restarts` / `last_restart` /
/// `possible_duplicates` 记录发生了什么，调用方可以把它们放进诊断。截断+重写
/// 如果恰好发生在两次 poll 之间、新内容又长过旧 offset，`len < offset` 看不见它
/// —— 所以每轮 poll 都会用 `consumed_tail` 核对 offset 之前的一小段字节是否仍是
/// 我们读过的内容（见 `poll` 里的 `still_matches_tail`）。
pub struct FileTail {
    pub path: std::path::PathBuf,
    file: Option<std::fs::File>,
    /// (device, inode)。只比较 inode 号挡不住 inode 复用 / 跨设备替换。
    dev: u64,
    inode: u64,
    offset: u64,
    buf: crate::collector::LineBuffer,
    pub ever_opened: bool,
    /// 从 offset 0 读到的文件头若干字节：用来判断 restart 后重读的前缀是否和
    /// 已经输出过的内容相同（相同 → 可能有重复事件）。
    file_start: Option<Vec<u8>>,
    /// offset 之前最近读过的若干字节：下一轮 poll 用它验证这些字节没被重写。
    consumed_tail: Vec<u8>,
    /// 从 0 重新读的次数（截断 / 轮转 / 检测到重写）。
    pub restarts: u64,
    /// 最近一次 restart 的原因，供诊断（`-v` / adapter diagnostics）使用。
    pub last_restart: Option<String>,
    /// restart 后重读的前缀与已输出内容相同 → 可能有重复事件被再次产出。
    pub possible_duplicates: u64,
}

/// 核对/记录文件内容的字节数（前缀指纹 + 已消费尾巴）。
const FINGERPRINT_LEN: usize = 64;

impl FileTail {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        FileTail {
            path: path.into(),
            file: None,
            dev: 0,
            inode: 0,
            offset: 0,
            buf: crate::collector::LineBuffer::new(),
            ever_opened: false,
            file_start: None,
            consumed_tail: Vec::new(),
            restarts: 0,
            last_restart: None,
            possible_duplicates: 0,
        }
    }

    /// 读一轮。返回新增的完整行。第二个返回值表示"源当前处于 EOF 且不存在"。
    pub fn poll(&mut self) -> Result<(Vec<String>, bool), std::io::Error> {
        use std::io::{Read, Seek, SeekFrom};

        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // 文件还没出现（或已被删除）。已经读过又消失 → 视为结束。
                if self.ever_opened {
                    self.file = None;
                    return Ok((Vec::new(), true));
                }
                return Ok((Vec::new(), false));
            }
            Err(e) => return Err(e),
        };

        let (meta_dev, meta_ino) = identity_of(&meta);
        let meta_len = meta.len();

        let need_reopen = self.file.is_none()
            || self.dev != meta_dev
            || self.inode != meta_ino
            || meta_len < self.offset;

        // 截断+重写可能整个发生在两次 poll 之间：长度已经长回旧 offset 以上，
        // `len < offset` 看不见。在信任 offset 之前，核对 offset 之前的一小段
        // 字节是否仍是我们消费过的内容（一次 read_at，64 字节）。
        let mut rewritten = false;
        if !need_reopen
            && self.offset > 0
            && !self.consumed_tail.is_empty()
            && let Some(f) = self.file.as_ref()
        {
            rewritten = !still_matches_tail(f, self.offset, &self.consumed_tail)?;
        }

        let mut restarted_from_offset: u64 = 0;
        let mut restart_old_start: Option<Vec<u8>> = None;

        if need_reopen || rewritten {
            let mut f = std::fs::File::open(&self.path)?;
            // 相信**打开的那个句柄**，而不是与它竞争的路径 metadata：metadata 与
            // open 之间文件被替换时，旧代码会存下旧 inode，下一轮就重读整个新文件。
            let actual = f.metadata()?;
            let (dev, ino) = identity_of(&actual);
            let len = actual.len();

            let same_identity = self.ever_opened && self.dev == dev && self.inode == ino;
            let truncated = same_identity && len < self.offset;
            let rotated = self.ever_opened && !same_identity;
            let mut reset = truncated || rotated || rewritten;
            // need_reopen 也可能只是因为 file 句柄丢了（文件消失又回来）；若身份
            // 没变、长度也没缩，就还是同一个文件，接着读。但 metadata 可能和 open
            // 竞争，所以再对着句柄核对一次尾巴。
            if !reset && same_identity && self.offset > 0 && !self.consumed_tail.is_empty() {
                reset = !still_matches_tail(&f, self.offset, &self.consumed_tail)?;
            }

            if reset {
                restarted_from_offset = self.offset;
                restart_old_start = self.file_start.take();
                // restart 意味着"我们读过的字节不再是以为的那些字节"：缓冲区里的
                // 半行属于旧内容/旧 offset，必须丢掉，绝不能让它和新内容拼成一条
                // 看起来完整的行。
                self.buf = crate::collector::LineBuffer::new();
                self.consumed_tail.clear();
                self.offset = 0;
                self.restarts += 1;
                let why = if truncated {
                    format!(
                        "file truncated (length {} < old offset {}); restarting from 0",
                        len, restarted_from_offset
                    )
                } else if rotated {
                    "file replaced (device/inode changed); restarting from 0".to_string()
                } else {
                    format!(
                        "content before offset {} changed (truncate+rewrite between polls); restarting from 0",
                        restarted_from_offset
                    )
                };
                self.last_restart = Some(why);
            }

            f.seek(SeekFrom::Start(self.offset))?;
            self.file = Some(f);
            self.dev = dev;
            self.inode = ino;
            self.ever_opened = true;
        }

        let started_at_zero = self.offset == 0;
        let mut out = Vec::new();
        if let Some(f) = self.file.as_mut() {
            let mut chunk = [0u8; 65536];
            loop {
                match f.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = &chunk[..n];
                        if started_at_zero && self.file_start.is_none() {
                            let take = n.min(FINGERPRINT_LEN);
                            self.file_start = Some(data[..take].to_vec());
                        }
                        self.offset += n as u64;
                        self.consumed_tail.extend_from_slice(data);
                        if self.consumed_tail.len() > FINGERPRINT_LEN {
                            let cut = self.consumed_tail.len() - FINGERPRINT_LEN;
                            self.consumed_tail.drain(..cut);
                        }
                        out.extend(self.buf.push(data));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        // restart 之后重读到与旧文件头相同的前缀 → 我们已经输出过的行可能被再次
        // 输出。这是启发式（只比前 64 字节），但**计数**而不是假装干净。
        if restarted_from_offset > 0
            && let (Some(old), Some(new)) = (restart_old_start.as_deref(), self.file_start.as_deref())
            && old == new
        {
            self.possible_duplicates += 1;
        }

        Ok((out, false))
    }

    /// 尚未组成完整行的字节数（流被截断在行中间时用于收尾诊断，§4.3）。
    pub fn pending_bytes(&self) -> usize {
        self.buf.pending_bytes()
    }
}

/// 核对 `offset` 之前的 `tail` 个字节是否仍是我们读过的内容。
///
/// `Ok(false)` = 文件被截断后重写（且已长回旧 offset 以上），此时继续从旧
/// offset 读会把新内容从中间切开。`read_at` 不移动文件游标。
#[cfg(unix)]
fn still_matches_tail(
    f: &std::fs::File,
    offset: u64,
    tail: &[u8],
) -> std::io::Result<bool> {
    use std::os::unix::fs::FileExt;
    let n = tail.len() as u64;
    if tail.is_empty() || offset < n {
        return Ok(true);
    }
    let mut got = vec![0u8; tail.len()];
    let read = f.read_at(&mut got, offset - n)?;
    if read != got.len() {
        // 短读说明文件比 offset 还短（正常情况下上面已经按截断处理了）。
        return Ok(false);
    }
    Ok(got == tail)
}

#[cfg(not(unix))]
fn still_matches_tail(
    _f: &std::fs::File,
    _offset: u64,
    _tail: &[u8],
) -> std::io::Result<bool> {
    Ok(true)
}

#[cfg(unix)]
fn identity_of(m: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino())
}

#[cfg(not(unix))]
fn identity_of(_m: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_roundtrip() {
        let ns = parse_iso8601_ns("2026-10-03T15:16:53.634Z").unwrap();
        assert_eq!(iso8601_ms(ns), "2026-10-03T15:16:53.634Z");
        let ns2 = parse_iso8601_ns("1970-01-01T00:00:00.000Z").unwrap();
        assert_eq!(ns2, 0);
        assert_eq!(iso8601_ms(ns2), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn iso_rejects_garbage_without_panic() {
        for bad in [
            "",
            "not a date",
            "2026-13-40T99:99:99Z",
            "2026-10-03",
            "2026/10/03T00:00:00Z",
            "2026-10-03T15:16:53",
            "\u{4e2d}\u{6587}",
        ] {
            // 不 panic 即可；有的会被接受（无时区后缀），有的不会。
            let _ = parse_iso8601_ns(bad);
        }
        assert!(parse_iso8601_ns("").is_none());
        assert!(parse_iso8601_ns("2026-13-40T99:99:99Z").is_none());
    }

    #[test]
    fn iso_offset_form() {
        let a = parse_iso8601_ns("2026-10-03T15:16:53.634Z").unwrap();
        let b = parse_iso8601_ns("2026-10-03T16:16:53.634+01:00").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn iso_leap_year() {
        assert!(parse_iso8601_ns("2024-02-29T00:00:00Z").is_some());
        let ns = parse_iso8601_ns("2000-03-01T00:00:00Z").unwrap();
        assert_eq!(iso8601_ms(ns), "2000-03-01T00:00:00.000Z");
    }

    // ---- FileTail ----

    fn tail_test_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("agtrace_filetail_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("cannot create temp dir");
        dir.join("events.jsonl")
    }

    fn tail_lines(t: &mut FileTail) -> Vec<String> {
        let (lines, _gone) = t.poll().expect("tail poll failed");
        lines
    }

    /// 文件在 adapter 启动之后才出现：不是错误，出现后从 0 读，不能当成 EOF。
    #[test]
    fn a_file_created_after_start_is_picked_up_from_zero() {
        let p = tail_test_path("created_later");
        let mut t = FileTail::new(&p);
        let (lines, gone) = t.poll().unwrap();
        assert!(lines.is_empty());
        assert!(!gone, "a file that was never seen must not be reported as a vanished source");
        std::fs::write(&p, "hello\nworld\n").unwrap();
        assert_eq!(tail_lines(&mut t), vec!["hello".to_string(), "world".into()]);
        assert!(t.ever_opened);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// 截断之后**又长过旧 offset**：`len < offset` 看不见这种重写，旧代码会从旧
    /// offset 接着读（丢掉新文件开头、还可能从行中间开始）。尾部指纹必须识破它。
    #[test]
    fn truncate_then_regrow_past_the_old_offset_is_detected() {
        let p = tail_test_path("truncate_regrow");
        std::fs::write(&p, "alpha\nbeta\n").unwrap();
        let mut t = FileTail::new(&p);
        assert_eq!(tail_lines(&mut t), vec!["alpha".to_string(), "beta".into()]);
        // 原地重写成**更长**的内容，整个发生在两次 poll 之间。
        std::fs::write(&p, "gamma\ndelta\nepsilon\n").unwrap();
        let lines = tail_lines(&mut t);
        assert_eq!(
            lines,
            vec!["gamma".to_string(), "delta".into(), "epsilon".into()],
            "truncate+regrow was missed; the tail resumed at a stale offset"
        );
        assert_eq!(t.restarts, 1);
        assert!(
            t.last_restart.as_deref().unwrap_or("").contains("between polls"),
            "restart reason must say what was detected: {:?}",
            t.last_restart
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// 检测到重写后，如果重读前缀和已输出内容相同，旧行可能被再次输出：
    /// 计数（`possible_duplicates`），而不是假装干净。
    #[test]
    fn a_detected_rewrite_with_an_identical_prefix_counts_possible_duplicates() {
        let p = tail_test_path("dup_prefix");
        let prefix = "x".repeat(70);
        std::fs::write(&p, format!("{}\nold\n", prefix)).unwrap();
        let mut t = FileTail::new(&p);
        assert_eq!(tail_lines(&mut t), vec![prefix.clone(), "old".to_string()]);
        std::fs::write(&p, format!("{}\nnew\n", prefix)).unwrap();
        let lines = tail_lines(&mut t);
        assert_eq!(
            lines,
            vec![prefix.clone(), "new".to_string()],
            "rewrite not recognised; poll resumed at a stale offset"
        );
        assert_eq!(t.restarts, 1);
        assert_eq!(
            t.possible_duplicates, 1,
            "re-reading a prefix equal to already-emitted content must be counted"
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// 任何 restart 都必须丢掉缓冲里的半行，否则旧内容的后半行会和新内容的
    /// 开头拼成一条"完整"的假行。
    #[test]
    fn a_restart_drops_the_buffered_partial_line() {
        let p = tail_test_path("partial_reset");
        std::fs::write(&p, "partial").unwrap(); // no trailing newline
        let mut t = FileTail::new(&p);
        assert!(tail_lines(&mut t).is_empty());
        assert_eq!(t.pending_bytes(), 7);
        // 截断成更短的内容 → 检测到 restart；旧半行绝不能成为新行的前缀。
        std::fs::write(&p, "new\n").unwrap();
        assert_eq!(
            tail_lines(&mut t),
            vec!["new".to_string()],
            "stale partial line was completed with bytes from the new file"
        );
        assert_eq!(t.pending_bytes(), 0);
        assert_eq!(t.restarts, 1);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// 轮转（rename 换 inode）要重新从 0 读，而不是继续用旧 offset。
    #[test]
    fn a_replaced_file_is_reopened_from_zero() {
        let p = tail_test_path("rotate");
        std::fs::write(&p, "one\ntwo\n").unwrap();
        let mut t = FileTail::new(&p);
        assert_eq!(tail_lines(&mut t), vec!["one".to_string(), "two".into()]);
        let q = p.with_extension("next");
        std::fs::write(&q, "other\n").unwrap();
        std::fs::rename(&q, &p).unwrap();
        assert_eq!(tail_lines(&mut t), vec!["other".to_string()]);
        assert_eq!(t.restarts, 1);
        assert_eq!(t.possible_duplicates, 0);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
