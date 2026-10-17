//! DeepSeek Harness (DSH) session adapter (`--adapter dsh`).
//!
//! Input: a DSH session log, `session.vN.jsonl.zstd` (default) or
//! `session.vN.jsonl` when the deployment sets `compression: 'none'`. The file
//! is written by DSH's JSONL persistence backend as a **concatenation of
//! independent checksummed Zstandard frames**: one frame with the header line,
//! then one frame per durable append batch. The format is documented by the
//! backend itself (`@deepseek-ai/dsh-session-persistence-jsonl`): frames are
//! appended and `fsync`ed, committed bytes are never rewritten, and a crash may
//! leave a torn final frame that the writer repairs on the next open.
//!
//! The tailer therefore ports the backend's own structural frame scanner
//! instead of guessing frame boundaries from the magic number: a frame is
//! consumed only when its header and blocks are complete, and bytes of the torn
//! final frame stay buffered until the rest arrives. A file that shrinks
//! (the documented torn-tail repair) only drops undecoded tail bytes; frames
//! that were already reported are never reported twice.
//!
//! ## Event mapping (DSH record type -> agtrace kind)
//!
//! | DSH record            | agtrace event                                  |
//! |-----------------------|------------------------------------------------|
//! | `session`             | none (session id / cwd / createdAt only)        |
//! | `user/message`        | `agent.prompt`                                  |
//! | `assistant/message`   | `agent.model.request` (derived once per step), `agent.model.thinking`, `agent.model.text` |
//! | `tool/call`           | `agent.tool.call` (with `bash_cmd` for shell tools) |
//! | `tool/result`         | `agent.tool.result`                             |
//!
//! Everything else (`step/*`, `turn/*`, `job/*`, `request/*`, `team/*`,
//! `subagent/*`, `agent/inbox/*`, `session/*`, approvals, sandbox/permission
//! state, titles) is an internal harness record, not agent behavior; it is
//! counted in `diagnostics()` (visible under `-v`) and never silently mapped to
//! a wrong kind. Truly unknown types are counted separately so a future DSH
//! format change is visible instead of being swallowed (§4.3 forward
//! compatibility).
//!
//! ## What is derived, not observed
//!
//! - `agent.model.request` has no record of its own: it is derived from the
//!   first `assistant/message` of a `(turn, step)` pair. Its timestamp is when
//!   the response was recorded, not when the request was sent — the event
//!   carries that caveat in `notes` (same rule as the Claude Code adapter).
//! - `tool/result.isError` is DSH's own verdict. The shell tools additionally
//!   append `[exit code: N]` to the output on a non-zero exit; when `isError`
//!   is false but that marker is non-zero the result is classified `Failure`
//!   and the disagreement is spelled out in `notes` — the process exit status
//!   is the ground truth agtrace exists to compare the transcript against.
//! - No token usage is emitted: DSH's session log does not record it.

use super::{AdapterError, Capabilities, EventAdapter, FileTail, agent_event};
use crate::event::{Corr, Event, Kind, Layer, Payload, TruncNote, one_line, truncate_chars};
use crate::poll::PollOutcome;
use crate::redact::{RedactMode, redact_text};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AdapterCfg {
    /// tool 参数 / 结果预览的截断上限（`--tool-arg-max`，默认 512）。
    pub tool_arg_max: usize,
    /// 命令行工具的命令串单独用更大的上限（`--bash-cmd-max`，默认 1024）。
    pub bash_cmd_max: usize,
    pub redact: RedactMode,
}

impl Default for AdapterCfg {
    fn default() -> Self {
        AdapterCfg {
            tool_arg_max: crate::cli::DEFAULT_TOOL_ARG_MAX,
            bash_cmd_max: crate::cli::DEFAULT_BASH_CMD_MAX,
            redact: RedactMode::Argv,
        }
    }
}

/// 命令行类工具的 DSH 名字。DSH 在 Windows 上把 shell 工具叫 `pwsh`，在
/// Linux 上叫 `bash`；未来的名字（`powershell` / `cmd` / `shell`）一并认下。
/// 这张表只决定"要不要从 `arguments` 里抽 `command`"，不影响任何结论。
fn is_shell_tool(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "pwsh"
            | "powershell"
            | "powershell.exe"
            | "pwsh.exe"
            | "cmd"
            | "cmd.exe"
            | "bash"
            | "bash.exe"
            | "sh"
            | "zsh"
            | "fish"
            | "shell"
            | "exec"
    )
}

/// DSH 记录里被识别为"harness 内部状态、不是 agent 行为"的类型。
/// 计数后丢弃（`-v` 可见），而不是当成未知类型——它们**已经被审计过**。
///
/// `job/registered` / `job/settled` 不在此列：`job/settled.detail` 是 shell
/// 退出码的**权威来源**（见 `record_job_settled`），结果是次要信号。
fn is_ignored_type(ty: &str) -> bool {
    matches!(
        ty,
        "step/start"
            | "step/end"
            | "turn/start"
            | "turn/end"
            | "job/registered"
            | "request/header"
            | "request/context"
            | "session/title"
            | "session/title-llm-request"
            | "session/end-seed"
            | "session-log-deepseek/delivery-accepted"
            | "agent/inbox/spliced"
            | "system/message"
            | "team/member"
            | "team/task"
            | "subagent/catalog"
            | "subagent/descriptor"
            | "approval/policy"
            | "approval/asked"
            | "approval/decided"
            | "permission/preset"
            | "sandbox/mode"
            | "todo/write"
            | "workspace/changes"
            | "deliverables/presented"
            | "web/deepseek-search-llm-request"
            | "command/run"
            | "command/done"
            | "model/selection"
    )
}

// ===========================================================================
// Zstandard frame scanning / tailing
// ===========================================================================

/// Zstandard 帧魔数（小端读出的 `0xFD2FB528`）。与 DSH 后端 `zstd.ts` 的
/// `ZSTD_MAGIC` 是同一个值。
const ZSTD_MAGIC: u32 = 4_247_762_216;

/// 一个完整帧在缓冲区里的范围 `[start, end)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameSpan {
    start: usize,
    end: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct ScanResult {
    frames: Vec<FrameSpan>,
    /// 末尾不完整帧的起点；`None` 表示缓冲区正好以完整帧结束。
    torn_start: Option<usize>,
}

/// 结构扫描 Zstandard 帧，不解压、不猜边界。
///
/// 这是 DSH 后端 `scanZstdFrames` 的逐字节移植（同一组合法性判定）：
/// 帧头 → 块头 → 块负载 → 校验和。完整帧返回范围；缓冲区在帧中间结束则
/// 返回 `torn_start` 让调用方把这段字节留到下一次读；非法的完整结构
/// （坏魔数、保留位、保留块类型）返回错误——这与 DSH 自己读取时的判定一致。
fn scan_zstd_frames(buffer: &[u8]) -> Result<ScanResult, String> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < buffer.len() {
        let start = offset;
        if buffer.len() - offset < 4 {
            return Ok(ScanResult {
                frames,
                torn_start: Some(start),
            });
        }
        if u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]])
            != ZSTD_MAGIC
        {
            return Err(format!(
                "corrupt Zstandard session log: invalid frame magic at byte {}",
                offset
            ));
        }
        offset += 4;
        if offset == buffer.len() {
            return Ok(ScanResult {
                frames,
                torn_start: Some(start),
            });
        }
        let descriptor = buffer[offset];
        offset += 1;
        if descriptor & 24 != 0 {
            return Err(format!(
                "corrupt Zstandard session log: reserved frame-header bit at byte {}",
                offset - 1
            ));
        }
        let content_size_flag = descriptor >> 6;
        let single_segment = descriptor & 32 != 0;
        let checksum = descriptor & 4 != 0;
        let dictionary_flag = descriptor & 3;
        let dictionary_bytes = if dictionary_flag == 3 {
            4
        } else {
            dictionary_flag as usize
        };
        let content_size_bytes: usize = if content_size_flag == 0 {
            usize::from(single_segment)
        } else {
            1usize << content_size_flag
        };
        let remaining_header_bytes =
            usize::from(!single_segment) + dictionary_bytes + content_size_bytes;
        if buffer.len() - offset < remaining_header_bytes {
            return Ok(ScanResult {
                frames,
                torn_start: Some(start),
            });
        }
        offset += remaining_header_bytes;
        loop {
            if buffer.len() - offset < 3 {
                return Ok(ScanResult {
                    frames,
                    torn_start: Some(start),
                });
            }
            let block_header = buffer[offset] as u32
                | (buffer[offset + 1] as u32) << 8
                | (buffer[offset + 2] as u32) << 16;
            offset += 3;
            let last_block = block_header & 1 != 0;
            let block_type = (block_header >> 1) & 3;
            let block_size = (block_header >> 3) as usize;
            if block_type == 3 {
                return Err(format!(
                    "corrupt Zstandard session log: reserved block type at byte {}",
                    offset - 3
                ));
            }
            // RLE 块只存 1 字节负载；其余块负载 = block_size。
            let payload_bytes = if block_type == 1 { 1 } else { block_size };
            if buffer.len() - offset < payload_bytes {
                return Ok(ScanResult {
                    frames,
                    torn_start: Some(start),
                });
            }
            offset += payload_bytes;
            if last_block {
                break;
            }
        }
        if checksum {
            if buffer.len() - offset < 4 {
                return Ok(ScanResult {
                    frames,
                    torn_start: Some(start),
                });
            }
            offset += 4;
        }
        frames.push(FrameSpan {
            start,
            end: offset,
        });
    }
    Ok(ScanResult {
        frames,
        torn_start: None,
    })
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

/// 追加写 Zstandard 会话日志的增量 reader。
///
/// 与 `FileTail` 的三条现实（文件未出现 / 文件被重建 / 结尾是半行）一致，
/// 多出的一条是"结尾是半个 zstd 帧"：未消费的字节留在 `pending` 里等下一次。
struct ZstdFrameLog {
    path: PathBuf,
    file: Option<std::fs::File>,
    inode: u64,
    /// 已经读进 `pending` 的文件字节偏移。
    offset: u64,
    /// 尚未组成完整帧的字节（总是从某个帧的起点开始）。
    pending: Vec<u8>,
    lines: crate::collector::LineBuffer,
    ever_opened: bool,
    // ---- 账（-v 可见）----
    pub bytes_read: u64,
    pub frames_decoded: u64,
    /// 可恢复的尾部截断（崩溃修复把未完成帧截掉后重新追加）次数。
    pub torn_repairs: u64,
    /// 文件被重建/轮转的次数。
    pub reopens: u64,
}

impl ZstdFrameLog {
    fn new(path: PathBuf) -> Self {
        ZstdFrameLog {
            path,
            file: None,
            inode: 0,
            offset: 0,
            pending: Vec::new(),
            lines: crate::collector::LineBuffer::new(),
            ever_opened: false,
            bytes_read: 0,
            frames_decoded: 0,
            torn_repairs: 0,
            reopens: 0,
        }
    }

    fn reset_from_start(&mut self) {
        self.offset = 0;
        self.pending.clear();
        self.lines = crate::collector::LineBuffer::new();
        self.file = None;
    }

    /// 读一轮。返回本次解出的完整行；第二个返回值表示"源曾经可读、现在消失了"。
    fn poll(&mut self) -> Result<(Vec<String>, bool), AdapterError> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if self.ever_opened {
                    self.file = None;
                    return Ok((Vec::new(), true));
                }
                return Ok((Vec::new(), false));
            }
            Err(e) => return Err(AdapterError::Io(e.to_string())),
        };
        let ino = inode_of(&meta);
        let len = meta.len();

        let need_open = self.file.is_none() || self.inode != ino;
        if need_open {
            // 新文件或文件被替换：从新文件的起点读。会话日志不做轮转，
            // 这是防御性分支（文件被外部删除后又重建）。
            if self.ever_opened && self.inode != ino {
                self.reopens += 1;
            }
            self.reset_from_start();
            self.inode = ino;
            let mut f = std::fs::File::open(&self.path)
                .map_err(|e| AdapterError::Io(format!("cannot open {}: {}", self.path.display(), e)))?;
            f.seek(SeekFrom::Start(0))
                .map_err(|e| AdapterError::Io(e.to_string()))?;
            self.file = Some(f);
            self.ever_opened = true;
        } else if len < self.offset {
            // 已提交前缀不可重写（DSH 后端的契约）；变小只能是崩溃修复截掉了
            // 未完成的尾帧，那些字节我们本来也没解码。保留已报告的事件，
            // 丢弃未解码的尾部，从新的文件末尾继续。**必须重新 seek**：文件
            // 句柄还停在旧偏移上，不 seek 会把新追加的帧从中间读起。
            self.torn_repairs += 1;
            self.offset = len;
            self.pending.clear();
            self.lines = crate::collector::LineBuffer::new();
            if let Some(f) = self.file.as_mut() {
                f.seek(SeekFrom::Start(len))
                    .map_err(|e| AdapterError::Io(e.to_string()))?;
            }
            return Ok((Vec::new(), false));
        }

        self.read_more()
    }

    fn read_more(&mut self) -> Result<(Vec<String>, bool), AdapterError> {
        let mut chunk = [0u8; 65536];
        if let Some(f) = self.file.as_mut() {
            loop {
                match f.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        self.pending.extend_from_slice(&chunk[..n]);
                        self.offset += n as u64;
                        self.bytes_read += n as u64;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(AdapterError::Io(e.to_string())),
                }
            }
        }
        self.decode_frames()
    }

    fn decode_frames(&mut self) -> Result<(Vec<String>, bool), AdapterError> {
        let scan = scan_zstd_frames(&self.pending)
            .map_err(|e| AdapterError::Schema(format!("{} ({})", e, self.path.display())))?;
        let mut lines = Vec::new();
        for span in &scan.frames {
            let decoded = zstd::stream::decode_all(&self.pending[span.start..span.end]).map_err(|e| {
                AdapterError::Schema(format!(
                    "corrupt Zstandard session log: frame at byte {} failed validation ({}): {}",
                    span.start,
                    self.path.display(),
                    e
                ))
            })?;
            self.frames_decoded += 1;
            lines.extend(self.lines.push(&decoded));
        }
        match scan.torn_start {
            Some(start) => {
                self.pending.drain(..start);
            }
            None => self.pending.clear(),
        }
        Ok((lines, false))
    }

    fn pending_bytes(&self) -> usize {
        self.pending.len()
    }
}

/// 一个 DSH 会话日志：压缩或明文。
enum SessionLog {
    Zstd(ZstdFrameLog),
    Plain(FileTail),
}

impl SessionLog {
    fn open(path: &Path) -> Result<Self, AdapterError> {
        let is_zstd = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".zstd") || n.ends_with(".zst"));
        if is_zstd {
            Ok(SessionLog::Zstd(ZstdFrameLog::new(path.to_path_buf())))
        } else {
            Ok(SessionLog::Plain(FileTail::new(path.to_path_buf())))
        }
    }

    fn poll(&mut self) -> Result<(Vec<String>, bool), AdapterError> {
        match self {
            SessionLog::Zstd(z) => z.poll(),
            SessionLog::Plain(p) => p.poll().map_err(|e| AdapterError::Io(e.to_string())),
        }
    }

    fn pending_tail_bytes(&self) -> usize {
        match self {
            SessionLog::Zstd(z) => z.pending_bytes(),
            SessionLog::Plain(p) => p.pending_bytes(),
        }
    }
}

// ===========================================================================
// Session discovery (workspace directory / session id / latest)
// ===========================================================================

/// DSH 的 `projectKey()`：cwd → `<root>/--<normalized-cwd>--/` 目录名。
///
/// 逐 UTF-16 码元移植（JS 的字符串是 UTF-16）：`/`、`\`、`:` 折叠为单个 `-`，
/// 其余非 `[A-Za-z0-9._-]` 码元转义为 `~XXXX`，去掉前导 `-`、截到 251 字符，
/// 两端包 `--`。与 DSH 自己的目录命名逐字节一致，否则自动定位会找不到会话。
pub fn project_key(cwd: &str) -> String {
    let mut readable = String::with_capacity(cwd.len() + 8);
    let mut separator_run = false;
    for unit in cwd.encode_utf16() {
        let ch = char::from_u32(unit as u32);
        match ch {
            Some('/') | Some('\\') | Some(':') => {
                if !separator_run {
                    readable.push('-');
                }
                separator_run = true;
            }
            Some(c) if c != '~' && (c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') => {
                readable.push(c);
                separator_run = false;
            }
            _ => {
                readable.push_str(&format!("~{:04X}", unit));
                separator_run = false;
            }
        }
    }
    let trimmed = readable.trim_start_matches('-');
    let body: String = if trimmed.is_empty() {
        "root".to_string()
    } else {
        trimmed.chars().take(251).collect()
    };
    format!("--{}--", body)
}

/// DSH 的 `encodeSegment()`：session id → 单个安全路径段。
fn encode_segment(raw: &str) -> String {
    if raw == "." {
        return "~002E".to_string();
    }
    if raw == ".." {
        return "~002E~002E".to_string();
    }
    let mut out = String::with_capacity(raw.len());
    for unit in raw.encode_utf16() {
        let ch = char::from_u32(unit as u32);
        match ch {
            Some(c) if c != '~' && (c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') => {
                out.push(c)
            }
            _ => out.push_str(&format!("~{:04X}", unit)),
        }
    }
    out
}

/// 解析 `session.vN.jsonl[.zstd]` / `session.jsonl[.zstd]` 里的代次 N
/// （v0 是 `session.jsonl`）。不是规范的代次文件名 → `None`。
fn parse_generation(filename: &str) -> Option<u32> {
    let body = filename.strip_suffix(".zstd").unwrap_or(filename);
    let body = body.strip_suffix(".jsonl")?;
    if body == "session" {
        return Some(0);
    }
    let rest = body.strip_prefix("session.v")?;
    if rest.is_empty() || (rest.len() > 1 && rest.starts_with('0')) {
        return None;
    }
    rest.parse::<u32>().ok()
}

/// 一个会话目录里最新（最高代次）的规范日志文件。
fn highest_generation(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(u32, PathBuf)> = None;
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(version) = parse_generation(name) else { continue };
        if best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, entry.path()));
        }
    }
    best.map(|(_, p)| p)
}

fn file_mtime(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// 目录下所有会话里最新的一个日志（按日志文件 mtime）。
fn newest_session_log(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let Some(log) = highest_generation(&p) else { continue };
        let ts = file_mtime(&log);
        if best.as_ref().is_none_or(|(t, _)| ts > *t) {
            best = Some((ts, log));
        }
    }
    best.map(|(_, p)| p)
}

/// DSH 的会话根目录：`$DSH_SESSIONS_ROOT` > `$DSH_HOME/sessions` >
/// `$HOME/.dsh/sessions` > `%USERPROFILE%\.dsh\sessions` >
/// WSL 视角的 `/mnt/<drive>/Users/*/.dsh/sessions`。
///
/// 最后一条是实际使用场景：DSH 是 Windows 应用，agtrace 跑在 WSL 里 ——
/// 如果不看 Windows 用户目录，`-S auto` 在 WSL 里永远找不到会话根。
pub fn sessions_root() -> Option<PathBuf> {
    if let Ok(root) = std::env::var("DSH_SESSIONS_ROOT") {
        if let Some(p) = first_existing_path(&root) {
            return Some(p);
        }
        return Some(PathBuf::from(root));
    }
    if let Ok(home) = std::env::var("DSH_HOME") {
        // Windows 形态的 `DSH_HOME`（`C:\Users\x\.dsh`）在 WSL 里要换成
        // `/mnt/c/Users/x/.dsh` —— 环境变量是 Windows 应用传给 shell 的原样字符串。
        let joined = PathBuf::from(home).join("sessions");
        if let Some(p) = first_existing_path(&joined.to_string_lossy()) {
            return Some(p);
        }
        return Some(joined);
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join(".dsh").join("sessions"));
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        candidates.push(PathBuf::from(home).join(".dsh").join("sessions"));
    }
    if let Some(p) = wsl_windows_sessions_root() {
        candidates.push(p);
    }
    candidates.into_iter().find(|p| p.is_dir())
}

/// 把 Windows 路径写法与 WSL 写法都试一遍，返回第一个存在的目录。
fn first_existing_path(path: &str) -> Option<PathBuf> {
    cwd_variants(path)
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_dir())
}

/// WSL: 从 `/mnt/<drive>/Users/*/.dsh/sessions` 找 Windows 侧 DSH 的会话根。
/// 选修改时间最新的一个（多用户机器上最可能是当前用户）。
fn wsl_windows_sessions_root() -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    for drive in ["c", "d", "e", "f"] {
        let users = PathBuf::from(format!("/mnt/{}/Users", drive));
        let Ok(entries) = std::fs::read_dir(&users) else { continue };
        for entry in entries.flatten() {
            let sessions = entry.path().join(".dsh").join("sessions");
            if !sessions.is_dir() {
                continue;
            }
            let ts = file_mtime(&sessions);
            if best.as_ref().is_none_or(|(t, _)| ts > *t) {
                best = Some((ts, sessions));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// 当 agtrace 跑在 WSL 里、而 DSH 跑在 Windows 上时，cwd 是 `/mnt/c/...`，
/// 而 DSH 记录的 cwd 是 `C:\...`。给出两种等价写法，自动定位才能对得上。
fn cwd_variants(cwd: &str) -> Vec<String> {
    let mut v = vec![cwd.to_string()];
    let bytes = cwd.as_bytes();
    if bytes.len() >= 7 && cwd.starts_with("/mnt/") {
        let mut it = cwd[5..].chars();
        if let Some(drive) = it.next() {
            let rest = &cwd[5 + drive.len_utf8()..];
            if rest.starts_with('/') {
                let converted = format!(
                    "{}:\\{}",
                    drive.to_ascii_uppercase(),
                    rest.trim_start_matches('/').replace('/', "\\")
                );
                v.push(converted);
            }
        }
    }
    // Windows 风格路径在 WSL 下也试一下 /mnt/<drive> 形式（用户可能直接粘贴）。
    if bytes.len() >= 2 && bytes[1] == b':' {
        let drive = (cwd.as_bytes()[0] as char).to_ascii_lowercase();
        let rest = cwd[2..].replace('\\', "/");
        let converted = format!("/mnt/{}{}", drive, rest);
        v.push(converted);
    }
    v
}

fn current_dir_variants() -> Vec<String> {
    match std::env::current_dir() {
        Ok(p) => cwd_variants(&p.to_string_lossy()),
        Err(_) => Vec::new(),
    }
}

fn newest_for_cwd(root: &Path) -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    for cwd in current_dir_variants() {
        if let Some(log) = newest_for_cwd_at(root, &cwd) {
            let ts = file_mtime(&log);
            if best.as_ref().is_none_or(|(t, _)| ts > *t) {
                best = Some((ts, log));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// 某个具体 cwd 对应的 workspace 目录里最新的日志（测试与 `newest_for_cwd`
/// 共用的唯一实现）。cwd 会先展开成 Windows/WSL 两种等价写法。
fn newest_for_cwd_at(root: &Path, cwd: &str) -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    for variant in cwd_variants(cwd) {
        let dir = root.join(project_key(&variant));
        let Some(log) = newest_session_log(&dir) else { continue };
        let ts = file_mtime(&log);
        if best.as_ref().is_none_or(|(t, _)| ts > *t) {
            best = Some((ts, log));
        }
    }
    best.map(|(_, p)| p)
}

fn find_session_by_id(root: &Path, id: &str) -> Option<PathBuf> {
    let wanted = encode_segment(id);
    let mut best: Option<(u64, PathBuf)> = None;
    let projects = std::fs::read_dir(root).ok()?;
    for project in projects.flatten() {
        if !project.path().is_dir() {
            continue;
        }
        let sessions = match std::fs::read_dir(project.path()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for session in sessions.flatten() {
            let dir = session.path();
            if !dir.is_dir() {
                continue;
            }
            let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let exact = name == wanted;
            // 允许用 id 前缀（`-S 22cf76ab`）—— 一个 workspace 里前缀撞车几乎不可能，
            // 真撞上了取 mtime 最新的，并在 diagnostics 里能看到实际文件路径。
            let prefix = !exact && name.starts_with(&wanted);
            if !exact && !prefix {
                continue;
            }
            let Some(log) = highest_generation(&dir) else { continue };
            let ts = file_mtime(&log);
            if best.as_ref().is_none_or(|(t, _)| ts > *t) {
                best = Some((ts, log));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// `-S` 在 `--adapter dsh` 下的解析：日志文件 / 会话目录 / workspace 目录 /
/// 会话 id（可前缀）/ `auto`|`latest`。
pub fn resolve_session(source: &str) -> Result<PathBuf, AdapterError> {
    let direct = Path::new(source);
    if direct.is_file() {
        return Ok(direct.to_path_buf());
    }
    if direct.is_dir() {
        if let Some(log) = highest_generation(direct) {
            return Ok(log);
        }
        if let Some(log) = newest_session_log(direct) {
            return Ok(log);
        }
        return Err(AdapterError::NotFound(format!(
            "directory {} contains no DSH session log (session.vN.jsonl[.zstd])",
            direct.display()
        )));
    }

    let root = sessions_root().ok_or_else(|| {
        AdapterError::NotFound(format!(
            "cannot resolve `{}`: no DSH session root found. Set DSH_SESSIONS_ROOT (or DSH_HOME), \
             or pass the session log/directory path explicitly",
            source
        ))
    })?;
    if !root.is_dir() {
        return Err(AdapterError::NotFound(format!(
            "DSH session root {} does not exist",
            root.display()
        )));
    }

    let auto = matches!(source, "auto" | "latest" | "@latest" | "@auto");
    if auto {
        // 在 DSH 的工具 shell 里运行时，harness 会导出 DSH_SESSION_ID /
        // DSH_HOME —— 于是 `agtrace --adapter dsh -S auto` 能精确找到**当前**
        // 会话，而不是"当前 workspace 里最新的一个"（两者在多会话并行时会不同）。
        if let Ok(id) = std::env::var("DSH_SESSION_ID") {
            if !id.trim().is_empty() {
                if let Some(log) = find_session_by_id(&root, id.trim()) {
                    return Ok(log);
                }
            }
        }
        if let Some(log) = newest_for_cwd(&root) {
            return Ok(log);
        }
        // 没有当前 workspace 的会话 → 退到整棵树里最新的一个。这是"最新"的
        // 字面含义，路径会写进表头注记，用户能核对。
        if let Some(log) = newest_session_log(&root) {
            return Ok(log);
        }
        return Err(AdapterError::NotFound(format!(
            "no DSH session log under {} (searched every project directory)",
            root.display()
        )));
    }

    // 会话目录名可能是 `session-<uuid>`，也可能就是裸 id；先按 id 找。
    if let Some(log) = find_session_by_id(&root, source) {
        return Ok(log);
    }
    // 再试"用户把 workspace 路径写成了字符串"的情况。
    for cwd in cwd_variants(source) {
        let dir = root.join(project_key(&cwd));
        if let Some(log) = newest_session_log(&dir) {
            return Ok(log);
        }
    }
    Err(AdapterError::NotFound(format!(
        "no DSH session `{}` found under {} (looked for a session id, its directory, \
         or the workspace directory naming)",
        source,
        root.display()
    )))
}

// ===========================================================================
// Adapter
// ===========================================================================

/// 一个 shell 作业的终局（来自 `job/settled`）。
///
/// DSH 把退出码放在这里，**不在** `tool/result` 的结构化字段里：
/// `isError` 只表示"工具调用本身失败"，像 `git` 退出 1 这种命令失败仍然是
/// `isError:false`。`job/settled.detail` = `"exit code: N"`，`status` =
/// `completed`/`killed`，`cause` = `producer`/`kill`。所以退出码的权威来源是
/// 这条记录；结果文本末尾的 `[exit code: N]` 只是方便的镜像（可能被截断）。
#[derive(Debug, Clone, Default)]
struct JobOutcome {
    status: String,
    cause: Option<String>,
    detail: Option<String>,
    exit_code: Option<i64>,
}

pub struct DshAdapter {
    log: SessionLog,
    path: PathBuf,
    follow: bool,
    cfg: AdapterCfg,
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    /// callId → tool 名（`tool/result` 记录本身不带 name）。
    call_tools: HashMap<String, String>,
    /// callId → job 终局（`job/settled`，退出码的权威来源）。
    jobs: HashMap<String, JobOutcome>,
    /// 已经产出过 `agent.model.request` 的 `(turn, step)`。
    request_seen: HashSet<(u64, u64)>,
    // ---- 诊断 ----
    pub unknown_types: BTreeMap<String, u64>,
    pub ignored_types: BTreeMap<String, u64>,
    pub bad_json: u64,
    pub bad_ts: u64,
    pub emitted: u64,
    eof_done: bool,
    /// `validate()` 已经读掉的事件，等第一次 `poll()` 取走。
    prefetched: Vec<Event>,
}

impl DshAdapter {
    pub fn new(source: &str, cfg: AdapterCfg, follow: bool) -> Result<Self, AdapterError> {
        let path = resolve_session(source)?;
        Ok(DshAdapter {
            log: SessionLog::open(&path)?,
            path,
            follow,
            cfg,
            session_id: None,
            cwd: None,
            call_tools: HashMap::new(),
            jobs: HashMap::new(),
            request_seen: HashSet::new(),
            unknown_types: BTreeMap::new(),
            ignored_types: BTreeMap::new(),
            bad_json: 0,
            bad_ts: 0,
            emitted: 0,
            eof_done: false,
            prefetched: Vec::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 启动校验（§5.4 #4）：第一个可读记录必须是 DSH 的 `session` 头。
    /// 格式变了就明确报错，而不是产出一条空时间线。
    pub fn validate(&mut self) -> Result<(), AdapterError> {
        let (lines, _gone) = self.log.poll()?;
        if lines.is_empty() {
            // 文件可能还没物化（DSH 惰性建会话）；`-f` 下等待即可，离线模式
            // 在第一次 poll 时再报——空文件不是"格式变了"的证据，不在这里下结论。
            return Ok(());
        }
        let mut out = Vec::new();
        let mut header_ok = self.session_id.is_some();
        for line in &lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(v) => {
                    if v.get("type").and_then(Value::as_str) == Some("session") {
                        header_ok = true;
                    }
                    self.handle_value(&v, &mut out);
                }
                Err(_) => {
                    self.bad_json += 1;
                }
            }
        }
        if !header_ok {
            return Err(AdapterError::Schema(format!(
                "the first records of {} are not a DSH session header (`{{\"type\":\"session\",\"version\":…}}`) — \
                the session format may have changed (§5.4 #4)",
                self.path.display()
            )));
        }
        self.prefetched.extend(out);
        Ok(())
    }

    fn handle_lines(&mut self, lines: &[String], out: &mut Vec<Event>) {
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(v) => self.handle_value(&v, out),
                Err(_) => self.bad_json += 1,
            }
        }
    }

    fn wall_ns(&mut self, v: &Value) -> Option<u64> {
        if let Some(ms) = v.get("time").and_then(Value::as_u64) {
            return Some(ms.saturating_mul(1_000_000));
        }
        match v.get("type").and_then(Value::as_str) {
            Some("session") => v
                .get("createdAt")
                .and_then(Value::as_u64)
                .map(|ms| ms.saturating_mul(1_000_000)),
            _ => {
                self.bad_ts += 1;
                None
            }
        }
    }

    fn corr(&self, data: &Value, tool_use_id: Option<String>) -> Corr {
        let turn = data.get("turn").and_then(Value::as_u64);
        Corr {
            session_id: self.session_id.clone(),
            run_id: None,
            agent_id: None,
            turn_id: turn.map(|t| format!("turn-{}", t)),
            tool_use_id,
            uuid: None,
            parent_uuid: None,
            pid_root: None,
            pid_binding: None,
            sidechain: data.get("delegationDepth").and_then(Value::as_u64).is_some_and(|d| d > 0),
        }
    }

    fn handle_value(&mut self, v: &Value, out: &mut Vec<Event>) {
        let ty = v.get("type").and_then(Value::as_str).unwrap_or("").to_string();
        if ty == "session" {
            self.on_header(v);
            return;
        }
        if is_ignored_type(&ty) {
            *self.ignored_types.entry(ty).or_insert(0) += 1;
            return;
        }
        let Some(wall_ns) = self.wall_ns(v) else {
            return;
        };
        let data = v.get("data").cloned().unwrap_or(Value::Null);
        match ty.as_str() {
            "user/message" => self.map_user_message(&data, wall_ns, out),
            "assistant/message" => self.map_assistant_message(&data, wall_ns, out),
            "tool/call" => self.map_tool_call(&data, wall_ns, out),
            "tool/result" => self.map_tool_result(&data, wall_ns, out),
            "job/settled" => self.record_job_settled(&data),
            other => {
                *self.unknown_types.entry(other.to_string()).or_insert(0) += 1;
            }
        }
    }

    /// `job/settled`：shell 作业的终局。`data.toolCall.callId` 把作业联回工具调用，
    /// `detail` 里的 `exit code: N` / `status: killed` 是结果状态判定的权威证据。
    fn record_job_settled(&mut self, data: &Value) {
        let Some(call_id) = data
            .get("toolCall")
            .and_then(|t| t.get("callId"))
            .and_then(Value::as_str)
        else {
            return;
        };
        let detail = data.get("detail").and_then(Value::as_str).map(str::to_string);
        let status = data
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let cause = data.get("cause").and_then(Value::as_str).map(str::to_string);
        let exit_code = detail.as_deref().and_then(exit_code_marker);
        self.jobs.insert(
            call_id.to_string(),
            JobOutcome {
                status,
                cause,
                detail,
                exit_code,
            },
        );
    }

    fn on_header(&mut self, v: &Value) {
        // 头记录直接放在顶层（没有 `data` 包装）。
        if self.session_id.is_none() {
            self.session_id = v.get("id").and_then(Value::as_str).map(str::to_string);
        }
        if self.cwd.is_none() {
            self.cwd = v.get("cwd").and_then(Value::as_str).map(str::to_string);
        }
    }

    fn preview(&self, s: &str, max: usize, field: &str) -> (String, Vec<TruncNote>) {
        let s = if self.cfg.redact.redacts_content() {
            redact_text(s)
        } else {
            s.to_string()
        };
        let (cut, truncated, orig) = truncate_chars(&s, max, max);
        let mut notes = Vec::new();
        if truncated {
            notes.push(TruncNote::new(field, Some(orig), cut.len()));
        }
        (one_line(&cut), notes)
    }

    fn map_user_message(&mut self, data: &Value, wall_ns: u64, out: &mut Vec<Event>) {
        // 只把**真实用户输入**当 prompt。system-prompt / runtime-context 的注入
        // 走别的记录；`source.kind` 不是 "user" 的 user/message 是 harness 内部的
        // 转写（例如重放），不冒充用户说过的话。
        let kind = data
            .get("source")
            .and_then(|s| s.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if kind != "user" {
            return;
        }
        let Some(blocks) = data.get("content").and_then(Value::as_array) else {
            return;
        };
        for b in blocks {
            let bty = b.get("type").and_then(Value::as_str).unwrap_or("");
            if bty != "text" {
                continue;
            }
            let raw = b.get("text").and_then(Value::as_str).unwrap_or("");
            let (preview, note) = self.preview(raw, self.cfg.tool_arg_max, "text_preview");
            let corr = self.corr(data, None);
            out.push(agent_event(
                wall_ns,
                Kind::AgentPrompt,
                Layer::Agent,
                "dsh",
                corr,
                Payload::Prompt {
                    text_preview: preview,
                    chars: raw.chars().count(),
                },
                note,
                Vec::new(),
            ));
            self.emitted += 1;
        }
    }

    fn map_assistant_message(&mut self, data: &Value, wall_ns: u64, out: &mut Vec<Event>) {
        let Some(msg) = data.get("message") else { return };
        let source = msg.get("source");
        let model = source
            .and_then(|s| s.get("model"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let turn = data.get("turn").and_then(Value::as_u64);
        let step = data.get("step").and_then(Value::as_u64);

        // 推导 `agent.model.request`：DSH 没有独立的"请求开始"记录。时间戳是
        // 响应被记录的时刻，不是请求发出的时刻——这条 caveat 必须随行输出。
        if let (Some(t), Some(s)) = (turn, step) {
            if self.request_seen.insert((t, s)) {
                let corr = self.corr(data, None);
                out.push(agent_event(
                    wall_ns,
                    Kind::AgentModelRequest,
                    Layer::Agent,
                    "dsh",
                    corr,
                    Payload::ModelRequest {
                        model: model.clone(),
                        input_tokens: None,
                        detail_preview: None,
                    },
                    Vec::new(),
                    vec![
                        "agent.model.request is **derived**: ts is when the assistant message was \
                         recorded, not when the request was sent (DESIGN.md §3.3/§5.2#6)"
                            .to_string(),
                    ],
                ));
                self.emitted += 1;
            }
        }

        let Some(blocks) = msg.get("content").and_then(Value::as_array) else {
            return;
        };
        for b in blocks {
            let bty = b.get("type").and_then(Value::as_str).unwrap_or("");
            match bty {
                "reasoning" => {
                    let raw = b.get("text").and_then(Value::as_str).unwrap_or("");
                    let (preview, note) = self.preview(raw, self.cfg.tool_arg_max, "preview");
                    let duration_ms = b
                        .get("durationMs")
                        .or_else(|| b.get("duration_ms"))
                        .and_then(Value::as_u64);
                    out.push(agent_event(
                        wall_ns,
                        Kind::AgentModelThinking,
                        Layer::Agent,
                        "dsh",
                        self.corr(data, None),
                        Payload::Thinking {
                            preview,
                            duration_ms,
                        },
                        note,
                        Vec::new(),
                    ));
                    self.emitted += 1;
                }
                "text" => {
                    let raw = b.get("text").and_then(Value::as_str).unwrap_or("");
                    let (preview, note) = self.preview(raw, self.cfg.tool_arg_max, "preview");
                    out.push(agent_event(
                        wall_ns,
                        Kind::AgentModelText,
                        Layer::Agent,
                        "dsh",
                        self.corr(data, None),
                        Payload::ModelText { preview },
                        note,
                        Vec::new(),
                    ));
                    self.emitted += 1;
                }
                "tool-call" => {
                    // 同一次调用还有一条独立的 `tool/call` 记录（它带 turn/step 和
                    // 完整的 arguments）。这里只把名字记下来，供 `tool/result` 用，
                    // **不产出事件** —— 否则每一次工具调用都会在时间线上出现两遍。
                    if let (Some(id), Some(name)) = (
                        b.get("id").and_then(Value::as_str),
                        b.get("name").and_then(Value::as_str),
                    ) {
                        self.call_tools
                            .entry(id.to_string())
                            .or_insert_with(|| name.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    fn map_tool_call(&mut self, data: &Value, wall_ns: u64, out: &mut Vec<Event>) {
        let name = data
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
            .to_string();
        let call_id = data.get("callId").and_then(Value::as_str).map(str::to_string);
        // `arguments` 是 JSON **字符串**（不是对象）——原始串就是最忠实的预览。
        let args_raw = match data.get("arguments") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        };
        let input_bytes = args_raw.len();
        let (input_preview, mut note) =
            self.preview(&args_raw, self.cfg.tool_arg_max, "input_preview");

        let mut bash_cmd = None;
        if is_shell_tool(&name) {
            let parsed: Option<Value> = serde_json::from_str(&args_raw).ok();
            if let Some(obj) = parsed.as_ref() {
                let raw = obj
                    .get("command")
                    .and_then(Value::as_str)
                    .or_else(|| obj.get("cmd").and_then(Value::as_str));
                if let Some(cmd) = raw {
                    let (c2, mut n2) = self.preview(cmd, self.cfg.bash_cmd_max, "bash_cmd");
                    bash_cmd = Some(c2);
                    note.append(&mut n2);
                }
            }
        }
        if let Some(id) = &call_id {
            self.call_tools.insert(id.clone(), name.clone());
        }
        let corr = self.corr(data, call_id);
        out.push(agent_event(
            wall_ns,
            Kind::AgentToolCall,
            Layer::Agent,
            "dsh",
            corr,
            Payload::ToolCall {
                tool: name.clone(),
                input_preview,
                input_bytes,
                via_mcp: name.starts_with("mcp__"),
                bash_cmd,
            },
            note,
            Vec::new(),
        ));
        self.emitted += 1;
    }

    fn map_tool_result(&mut self, data: &Value, wall_ns: u64, out: &mut Vec<Event>) {
        let Some(msg) = data.get("message") else { return };
        let call_id = msg
            .get("toolCallId")
            .or_else(|| data.get("toolCallId"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let is_error = msg.get("isError").and_then(Value::as_bool).unwrap_or(false);
        let text = content_text(msg.get("content"));
        // 退出码的权威来源是 job/settled（见 `JobOutcome`）；结果文本里的
        // `[exit code: N]` 只是镜像，取它当 fallback。
        let job = call_id.as_ref().and_then(|id| self.jobs.get(id)).cloned();
        let text_exit = exit_code_marker(&text);
        let mut notes: Vec<String> = Vec::new();
        let status = if is_error {
            // 工具级错误：`data.error = {name, code}` 是结构化证据，比文本可靠。
            if let Some(err) = data.get("error") {
                let name = err.get("name").and_then(Value::as_str).unwrap_or("?");
                let code = err.get("code").and_then(Value::as_str).unwrap_or("?");
                notes.push(format!("dsh tool error: {}/{}", name, code));
            }
            "Failure".to_string()
        } else if let Some(j) = &job {
            if j.status == "killed" {
                notes.push(format!(
                    "dsh: job/settled status=killed (cause={}) — the command was cancelled, not a \\
                     tool-API error",
                    j.cause.as_deref().unwrap_or("?")
                ));
                "Failure".to_string()
            } else if let Some(n) = j.exit_code.filter(|n| *n != 0) {
                notes.push(format!(
                    "dsh: job/settled says `{}` while the tool result has isError=false — \
                     classified as Failure because the process exit status is the ground truth \
                     agtrace compares the claim against",
                    j.detail.as_deref().unwrap_or(&format!("exit code: {}", n))
                ));
                "Failure".to_string()
            } else {
                "Success".to_string()
            }
        } else if let Some(n) = text_exit.filter(|n| *n != 0) {
            notes.push(format!(
                "dsh: tool result isError=false, but the shell tool reported [exit code: {}] — \
                 classified as Failure because the process exit status is the ground truth \
                 agtrace compares the claim against",
                n
            ));
            "Failure".to_string()
        } else {
            "Success".to_string()
        };
        let tool = call_id
            .as_ref()
            .and_then(|id| self.call_tools.get(id).cloned());
        let (preview, trunc_notes) =
            self.preview(&text, self.cfg.tool_arg_max, "result_preview");
        let corr = self.corr(data, call_id);
        out.push(agent_event(
            wall_ns,
            Kind::AgentToolResult,
            Layer::Agent,
            "dsh",
            corr,
            Payload::ToolResult {
                tool,
                status,
                result_preview: preview,
            },
            trunc_notes,
            notes,
        ));
        self.emitted += 1;
    }
}

/// `tool/result.message.content` 可能是数组（每个 block 有 `text`）或字符串。
fn content_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => {
            let mut parts: Vec<&str> = Vec::new();
            for b in blocks {
                if let Some(t) = b.get("text").and_then(Value::as_str) {
                    parts.push(t);
                } else if b.get("type").and_then(Value::as_str) == Some("image") {
                    parts.push("[image]");
                }
            }
            parts.join("")
        }
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// 抽 DSH 的 `exit code: N` 形状（`job/settled.detail` 与结果文本末尾的
/// `[exit code: N]` 都认，大小写不敏感）。
fn exit_code_marker(text: &str) -> Option<i64> {
    let lower = text.to_ascii_lowercase();
    let needle = "exit code:";
    let mut from = 0usize;
    while let Some(i) = lower[from..].find(needle) {
        let idx = from + i;
        // 只认 `[exit code: N]` / `exit code: N` / 行首 `exit code: N` 这种明确
        // 形状，避免把命令输出里随便一句 "exit code: …" 当成工具自己的总结。
        let before_ok = idx == 0
            || lower[..idx].ends_with('[')
            || lower[..idx].ends_with(' ')
            || lower[..idx].ends_with('\n');
        if before_ok {
            let after = &text[idx + needle.len()..];
            let after = after.trim_start();
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() {
                return digits.parse::<i64>().ok();
            }
        }
        from = idx + needle.len();
    }
    None
}

impl EventAdapter for DshAdapter {
    fn id(&self) -> &'static str {
        "dsh"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            kinds: vec![
                Kind::AgentPrompt,
                Kind::AgentModelRequest,
                Kind::AgentModelThinking,
                Kind::AgentModelText,
                Kind::AgentToolCall,
                Kind::AgentToolResult,
            ],
            live: true,
            needs_pid_binding: true,
        }
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, AdapterError> {
        let mut buf = std::mem::take(&mut self.prefetched);
        if self.eof_done {
            out.append(&mut buf);
            return Ok(PollOutcome::Eof);
        }

        if !self.follow {
            // 离线：把文件抽干再结束。
            loop {
                let (lines, gone) = self.log.poll()?;
                if lines.is_empty() {
                    if gone {
                        self.eof_done = true;
                    }
                    break;
                }
                self.handle_lines(&lines, &mut buf);
            }
            self.eof_done = true;
            let n = buf.len();
            out.append(&mut buf);
            return Ok(if n > 0 {
                PollOutcome::Progress
            } else {
                PollOutcome::Eof
            });
        }

        let (lines, gone) = self.log.poll()?;
        self.handle_lines(&lines, &mut buf);
        let n = buf.len();
        out.append(&mut buf);
        if gone {
            self.eof_done = true;
            return Ok(PollOutcome::Eof);
        }
        Ok(if n > 0 {
            PollOutcome::Progress
        } else {
            PollOutcome::Idle
        })
    }

    fn shutdown(&mut self) {}

    fn diagnostics(&self) -> Vec<String> {
        let mut d = vec![format!(
            "dsh log: {} (session {})",
            self.path.display(),
            self.session_id.as_deref().unwrap_or("<no header>")
        )];
        if let Some(cwd) = &self.cwd {
            d.push(format!("dsh cwd: {}", cwd));
        }
        d.push(format!(
            "produced {} agent event(s); bad JSON lines {}; missing/invalid timestamp lines {}",
            self.emitted, self.bad_json, self.bad_ts
        ));
        match &self.log {
            SessionLog::Zstd(z) => d.push(format!(
                "zstd: {} bytes read, {} frames decoded, {} torn-tail repair(s), {} reopen(s)",
                z.bytes_read, z.frames_decoded, z.torn_repairs, z.reopens
            )),
            SessionLog::Plain(p) => {
                d.push("plain JSONL (compression: none)".to_string());
                if p.restarts > 0 {
                    d.push(format!(
                        "file tail: {} restart(s) (last: {}); {} possible duplicate event(s)",
                        p.restarts,
                        p.last_restart.as_deref().unwrap_or("-"),
                        p.possible_duplicates
                    ));
                }
            }
        }
        let tail = self.log.pending_tail_bytes();
        if tail > 0 {
            d.push(format!(
                "{} byte(s) of an incomplete final Zstandard frame are buffered, not decoded yet",
                tail
            ));
        }
        if !self.ignored_types.is_empty() {
            let s: Vec<String> = self
                .ignored_types
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            d.push(format!(
                "harness-internal record type(s) (known, no event produced): {}",
                s.join(" ")
            ));
        }
        if !self.unknown_types.is_empty() {
            let s: Vec<String> = self
                .unknown_types
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            d.push(format!(
                "unknown record type(s) (counted, no event produced — forward compatible): {}",
                s.join(" ")
            ));
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn frame(bytes: &[u8]) -> Vec<u8> {
        let mut enc = zstd::stream::Encoder::new(Vec::new(), 0).unwrap();
        enc.include_checksum(true).unwrap();
        enc.include_contentsize(true).unwrap();
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn session_file(dir: &Path, compressed: bool, records: &[&str]) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = if compressed {
            dir.join("session.v4.jsonl.zstd")
        } else {
            dir.join("session.v4.jsonl")
        };
        let mut bytes = Vec::new();
        for r in records {
            if compressed {
                bytes.extend(frame(format!("{}\n", r).as_bytes()));
            } else {
                bytes.extend(format!("{}\n", r).as_bytes());
            }
        }
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn project_key_matches_dsh_naming() {
        assert_eq!(
            project_key("C:\\Users\\61773\\Documents\\projects"),
            "--C-Users-61773-Documents-projects--"
        );
        assert_eq!(
            project_key("C:\\Users\\61773\\Documents\\deepseek-harness\\default-workspace"),
            "--C-Users-61773-Documents-deepseek-harness-default-workspace--"
        );
        // 分隔符连续出现折叠成一个 '-'；POSIX 绝对路径的前导 '-' 被去掉。
        assert_eq!(project_key("/root/proj"), "--root-proj--");
        // 非安全字符逐 UTF-16 码元转义（与 DSH 的 encode 规则一致）。
        assert_eq!(project_key("C:\\a b"), "--C-a~0020b--");
        assert_eq!(project_key("~"), "--~007E--");
    }

    #[test]
    fn encode_segment_is_injective() {
        assert_eq!(encode_segment("session-abc"), "session-abc");
        assert_eq!(encode_segment(".."), "~002E~002E");
        assert_eq!(encode_segment("a/b"), "a~002Fb");
    }

    #[test]
    fn generation_filenames() {
        assert_eq!(parse_generation("session.v4.jsonl.zstd"), Some(4));
        assert_eq!(parse_generation("session.v2.jsonl"), Some(2));
        assert_eq!(parse_generation("session.jsonl.zstd"), Some(0));
        assert_eq!(parse_generation("session.v04.jsonl.zstd"), None);
        assert_eq!(parse_generation("session.vN.jsonl.zstd"), None);
        assert_eq!(parse_generation("notes.txt"), None);
    }

    #[test]
    fn scanner_finds_frames_and_torn_tail() {
        let f1 = frame(b"{\"a\":1}\n");
        let f2 = frame(b"{\"b\":2}\n");
        let mut buf = f1.clone();
        buf.extend(&f2);
        let scan = scan_zstd_frames(&buf).unwrap();
        assert_eq!(scan.frames.len(), 2);
        assert_eq!(scan.frames[0], FrameSpan { start: 0, end: f1.len() });
        assert_eq!(scan.torn_start, None);

        // 把第二帧切掉 2 字节：第一帧仍然完整，尾部是 tORN。
        let mut torn = f1.clone();
        torn.extend(&f2[..f2.len() - 2]);
        let scan = scan_zstd_frames(&torn).unwrap();
        assert_eq!(scan.frames.len(), 1);
        assert_eq!(scan.torn_start, Some(f1.len()));
    }

    #[test]
    fn scanner_rejects_corrupt_magic() {
        let mut buf = frame(b"{}\n");
        buf[0] = 0;
        assert!(scan_zstd_frames(&buf).is_err());
    }

    fn header() -> String {
        r#"{"type":"session","version":4,"id":"session-abc","createdAt":1792267905617,"cwd":"C:\\Users\\x\\projects","isSeeded":false,"delegationDepth":0,"agentPreset":"standard"}"#.to_string()
    }

    fn call(id: &str, name: &str, args: &str) -> String {
        format!(
            r#"{{"type":"tool/call","seq":1,"time":1792268096616,"data":{{"turn":1,"step":1,"callId":"{}","name":"{}","arguments":{}}}}}"#,
            id,
            name,
            serde_json::to_string(args).unwrap()
        )
    }

    fn result(id: &str, text: &str, is_error: bool) -> String {
        format!(
            r#"{{"type":"tool/result","seq":2,"time":1792268097230,"data":{{"turn":1,"step":1,"message":{{"role":"tool","toolCallId":"{}","content":[{{"type":"text","text":{}}}],"isError":{}}}}}}}"#,
            id,
            serde_json::to_string(text).unwrap(),
            is_error
        )
    }

    #[test]
    fn maps_tool_call_and_result_from_plain_log() {
        let dir = std::env::temp_dir().join("agtrace_dsh_test_plain");
        let _ = std::fs::remove_dir_all(&dir);
        let h = header();
        let c = call("call_1", "pwsh", r#"{"command":"ls /nonexistent-dir","description":"x"}"#);
        let r = result("call_1", "ls: cannot access '/nonexistent-dir'\n[exit code: 2]", false);
        let path = session_file(&dir, false, &[&h, &c, &r]);
        let mut a = DshAdapter::new(path.to_str().unwrap(), AdapterCfg::default(), false).unwrap();
        a.validate().unwrap();
        let mut out = Vec::new();
        let outcome = a.poll(&mut out).unwrap();
        assert!(matches!(outcome, PollOutcome::Eof | PollOutcome::Progress));
        assert_eq!(out.len(), 2, "expected tool.call + tool.result: {:#?}", out);
        assert_eq!(out[0].kind, Kind::AgentToolCall);
        assert_eq!(out[1].kind, Kind::AgentToolResult);
        assert_eq!(out[0].corr.tool_use_id.as_deref(), Some("call_1"));
        match &out[0].payload {
            Payload::ToolCall { bash_cmd, tool, .. } => {
                assert_eq!(tool, "pwsh");
                assert_eq!(bash_cmd.as_deref(), Some("ls /nonexistent-dir"));
            }
            other => panic!("unexpected payload {:?}", other),
        }
        match &out[1].payload {
            Payload::ToolResult { status, tool, .. } => {
                assert_eq!(status, "Failure", "non-zero [exit code] even with isError=false must be Failure");
                assert_eq!(tool.as_deref(), Some("pwsh"));
            }
            other => panic!("unexpected payload {:?}", other),
        }
        assert!(out[1]
            .notes
            .iter()
            .any(|n| n.contains("isError=false") && n.contains("exit code: 2")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn maps_prompt_and_assistant_message() {
        let dir = std::env::temp_dir().join("agtrace_dsh_test_prompt");
        let _ = std::fs::remove_dir_all(&dir);
        let h = header();
        let u = r#"{"type":"user/message","seq":8,"time":1792268094774,"data":{"content":[{"type":"text","text":"do the thing"}],"source":{"kind":"user","rpcId":"r1"},"role":"user","id":"m1"}}"#;
        let am = r#"{"type":"assistant/message","seq":19,"time":1792268096616,"data":{"turn":1,"step":1,"message":{"role":"assistant","content":[{"type":"reasoning","text":"thinking hard"},{"type":"text","text":"on it"},{"type":"tool-call","id":"call_9","name":"write","arguments":"{}"}],"source":{"kind":"model","provider":"deepseek-account","model":"deepseek-flash"}}}}"#;
        let path = session_file(&dir, false, &[&h, u, am]);
        let mut a = DshAdapter::new(path.to_str().unwrap(), AdapterCfg::default(), false).unwrap();
        a.validate().unwrap();
        let mut out = Vec::new();
        a.poll(&mut out).unwrap();
        let kinds: Vec<Kind> = out.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                Kind::AgentPrompt,
                Kind::AgentModelRequest,
                Kind::AgentModelThinking,
                Kind::AgentModelText
            ],
            "tool-call blocks must not duplicate the separate tool/call record"
        );
        assert_eq!(a.session_id.as_deref(), Some("session-abc"));
        assert_eq!(a.cwd.as_deref(), Some("C:\\Users\\x\\projects"));
        match &out[1].payload {
            Payload::ModelRequest { model, .. } => assert_eq!(model.as_deref(), Some("deepseek-flash")),
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn job_settled_exit_code_is_the_authoritative_failure_signal() {
        let dir = std::env::temp_dir().join("agtrace_dsh_test_jobs");
        let _ = std::fs::remove_dir_all(&dir);
        let h = header();
        let c = call("call_j", "pwsh", r#"{"command":"git clone x"}"#);
        // 真实语料形状：tool/result 的 isError=false，退出码只在 job/settled 里。
        let settled = r#"{"type":"job/settled","seq":3,"time":1792268097229,"data":{"jobId":"j1","status":"completed","cause":"producer","detail":"exit code: 1","toolCall":{"callId":"call_j","rootCallId":"call_j"}}}"#;
        let r = result("call_j", "Cloning into 'x'...\r\n", false);
        let path = session_file(&dir, false, &[&h, &c, settled, &r]);
        let mut a = DshAdapter::new(path.to_str().unwrap(), AdapterCfg::default(), false).unwrap();
        a.validate().unwrap();
        let mut out = Vec::new();
        a.poll(&mut out).unwrap();
        let res = out.iter().find(|e| e.kind == Kind::AgentToolResult).unwrap();
        match &res.payload {
            Payload::ToolResult { status, tool, .. } => {
                assert_eq!(status, "Failure");
                assert_eq!(tool.as_deref(), Some("pwsh"));
            }
            other => panic!("unexpected {:?}", other),
        }
        assert!(res.notes.iter().any(|n| n.contains("job/settled") && n.contains("exit code: 1")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn killed_job_and_tool_error_are_failures_with_evidence() {
        let dir = std::env::temp_dir().join("agtrace_dsh_test_killed");
        let _ = std::fs::remove_dir_all(&dir);
        let h = header();
        let c1 = call("call_k", "pwsh", r#"{"command":"sleep 99"}"#);
        let settled = r#"{"type":"job/settled","seq":3,"time":1792268097229,"data":{"status":"killed","cause":"kill","detail":"killed","toolCall":{"callId":"call_k"}}}"#;
        let r1 = result("call_k", "", false);
        // 工具级错误：isError=true + data.error
        let c2 = call("call_e", "write", r#"{"file_path":"/tmp/a","content":"x"}"#);
        let r2 = r#"{"type":"tool/result","seq":9,"time":1792268099000,"data":{"turn":1,"step":2,"message":{"role":"tool","toolCallId":"call_e","content":[{"type":"text","text":"stale"}],"isError":true},"error":{"name":"FsError","code":"FS_STALE_VERSION"}}}"#;
        let path = session_file(&dir, false, &[&h, &c1, settled, &r1, &c2, r2]);
        let mut a = DshAdapter::new(path.to_str().unwrap(), AdapterCfg::default(), false).unwrap();
        a.validate().unwrap();
        let mut out = Vec::new();
        a.poll(&mut out).unwrap();
        let results: Vec<&Event> = out.iter().filter(|e| e.kind == Kind::AgentToolResult).collect();
        assert_eq!(results.len(), 2);
        match &results[0].payload {
            Payload::ToolResult { status, .. } => assert_eq!(status, "Failure"),
            other => panic!("unexpected {:?}", other),
        }
        assert!(results[0].notes.iter().any(|n| n.contains("killed")));
        match &results[1].payload {
            Payload::ToolResult { status, .. } => assert_eq!(status, "Failure"),
            other => panic!("unexpected {:?}", other),
        }
        assert!(results[1].notes.iter().any(|n| n.contains("FsError") && n.contains("FS_STALE_VERSION")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compressed_log_tails_live_and_survives_torn_frame() {
        let dir = std::env::temp_dir().join("agtrace_dsh_test_live");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.v4.jsonl.zstd");
        let h = header();
        std::fs::write(&path, frame(format!("{}\n", h).as_bytes())).unwrap();

        let mut a = DshAdapter::new(path.to_str().unwrap(), AdapterCfg::default(), true).unwrap();
        a.validate().unwrap();
        let mut out = Vec::new();
        assert!(matches!(a.poll(&mut out).unwrap(), PollOutcome::Idle));
        assert!(out.is_empty());

        // 追加一帧的**前半段**：还不应产出任何事件。
        let c = call("call_7", "read", r#"{"file_path":"/tmp/a"}"#);
        let f = frame(format!("{}\n", c).as_bytes());
        let split = f.len() / 2;
        {
            use std::io::Write as _;
            let mut fh = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            fh.write_all(&f[..split]).unwrap();
        }
        let mut out = Vec::new();
        assert!(matches!(a.poll(&mut out).unwrap(), PollOutcome::Idle));
        assert!(out.is_empty(), "half a frame must not be decoded");

        // 补上后半段：事件恰好出现一次。
        {
            use std::io::Write as _;
            let mut fh = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            fh.write_all(&f[split..]).unwrap();
        }
        let mut out = Vec::new();
        assert!(matches!(a.poll(&mut out).unwrap(), PollOutcome::Progress));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, Kind::AgentToolCall);

        // 再 poll 一次不会重复。
        let mut out = Vec::new();
        assert!(matches!(a.poll(&mut out).unwrap(), PollOutcome::Idle));
        assert!(out.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_tail_repair_does_not_duplicate_committed_events() {
        let dir = std::env::temp_dir().join("agtrace_dsh_test_repair");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.v4.jsonl.zstd");
        let h = header();
        let c = call("call_1", "pwsh", r#"{"command":"true"}"#);
        let f = frame(format!("{}\n", c).as_bytes());
        let mut bytes = frame(format!("{}\n", h).as_bytes());
        bytes.extend(&f);
        // 文件以半帧结束（模拟崩溃）。
        let torn_at = bytes.len() - f.len() / 2;
        std::fs::write(&path, &bytes[..torn_at]).unwrap();

        let mut a = DshAdapter::new(path.to_str().unwrap(), AdapterCfg::default(), true).unwrap();
        a.validate().unwrap();
        let mut out = Vec::new();
        a.poll(&mut out).unwrap();
        assert!(out.is_empty());

        // 崩溃修复：截掉未完成帧（文件变短）后再完整追加。
        std::fs::write(&path, frame(format!("{}\n", h).as_bytes())).unwrap();
        let mut out = Vec::new();
        let _ = a.poll(&mut out).unwrap();
        assert!(out.is_empty(), "repair must not replay the header as an event");
        {
            use std::io::Write as _;
            let mut fh = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            fh.write_all(&f).unwrap();
        }
        let mut out = Vec::new();
        a.poll(&mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].corr.tool_use_id.as_deref(), Some("call_1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_resolution_finds_latest_session_for_cwd() {
        let root = std::env::temp_dir().join("agtrace_dsh_test_root");
        let _ = std::fs::remove_dir_all(&root);
        let proj = root.join(project_key("C:\\Users\\x\\projects"));
        let s1 = proj.join("session-old");
        let s2 = proj.join("session-new");
        std::fs::create_dir_all(&s1).unwrap();
        std::fs::create_dir_all(&s2).unwrap();
        let h = header();
        std::fs::write(s1.join("session.v4.jsonl"), format!("{}\n", h)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(s2.join("session.v4.jsonl"), format!("{}\n", h)).unwrap();

        let found = newest_for_cwd_at(&root, "C:\\Users\\x\\projects").expect("cwd variant must match");
        assert_eq!(found, s2.join("session.v4.jsonl"));
        // WSL 视角的 cwd 也应该能映射到同一个 workspace 目录。
        let found = newest_for_cwd_at(&root, "/mnt/c/Users/x/projects").expect("wsl cwd variant");
        assert_eq!(found, s2.join("session.v4.jsonl"));
        // 显式 session id 也能找到。
        let by_id = find_session_by_id(&root, "session-new").expect("id lookup");
        assert_eq!(by_id, s2.join("session.v4.jsonl"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
