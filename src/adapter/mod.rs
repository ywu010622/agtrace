//! Adapter 接口（DESIGN.md §3.1）。
//!
//! **为什么是 `poll` 而不是 `async Stream`**：v0 不引入 tokio（铁律）。
//! 主循环用一个简单的多路复用轮询，adapter 不得阻塞超过 ~10ms。

pub mod claude_code;
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
///  2. 文件可能被**轮转/重建**（inode 变化）→ 重置 offset。
///  3. 写入**不保证以完整行结束** `[未验证]` → 半行留在缓冲区等下次（§5.4 #3）。
pub struct FileTail {
    pub path: std::path::PathBuf,
    file: Option<std::fs::File>,
    inode: u64,
    offset: u64,
    buf: crate::collector::LineBuffer,
    pub ever_opened: bool,
}

impl FileTail {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        FileTail {
            path: path.into(),
            file: None,
            inode: 0,
            offset: 0,
            buf: crate::collector::LineBuffer::new(),
            ever_opened: false,
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

        let ino = inode_of(&meta);
        let len = meta.len();

        let need_reopen = self.file.is_none() || self.inode != ino || len < self.offset;
        if need_reopen {
            let mut f = std::fs::File::open(&self.path)?;
            // 被截断（len < offset）时从头再来，绝不假设内容连续。
            self.offset = if self.inode == ino && len < self.offset {
                0
            } else if self.inode != ino {
                0
            } else {
                self.offset
            };
            f.seek(SeekFrom::Start(self.offset))?;
            self.file = Some(f);
            self.inode = ino;
            self.ever_opened = true;
            // inode 变化 = 新文件，缓冲里的半行属于旧文件，必须丢弃。
            if self.offset == 0 {
                self.buf = crate::collector::LineBuffer::new();
            }
        }

        let mut out = Vec::new();
        if let Some(f) = self.file.as_mut() {
            let mut chunk = [0u8; 65536];
            loop {
                match f.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        self.offset += n as u64;
                        out.extend(self.buf.push(&chunk[..n]));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok((out, false))
    }
}

#[cfg(unix)]
fn inode_of(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}

#[cfg(not(unix))]
fn inode_of(_m: &std::fs::Metadata) -> u64 {
    0
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
}
