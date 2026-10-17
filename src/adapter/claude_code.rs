//! Claude Code transcript adapter（DESIGN.md §3.3）。
//!
//! 输入：`~/.claude/projects/<slug>/<sessionId>.jsonl`，slug 是 cwd 路径把 `/` 换成 `-`。
//! 读取方式：tail -f 语义（见 `FileTail`）。
//!
//! **本文件对 DESIGN.md 的两处实测修正**（都写进了 BUILD_LOG.md）：
//!  1. §3.3 的映射表假定 `turn_id`(promptId) 可以直接读。**实测：assistant 行没有
//!     `promptId` 字段**（本机 1735 条 assistant 行，`has("promptId")` 全为 false；
//!     user 行 867/869 有）。→ assistant 事件的 turn_id 必须**沿 parentUuid 链上溯**
//!     到最近一条带 promptId 的 user 行。这是近似，但对单线程会话是可靠的。
//!  2. §3.3 说"出现一条新的 assistant 行且 message.id 与上一条不同 → 一次模型调用"。
//!     **实测：同一个 message.id 会横跨 2~11 条 JSONL 行**（每个 content block 一行，
//!     usage 在每一行重复）。→ `agent.model.usage` 必须按 message.id 去重，否则
//!     一次模型调用会被打印 8 次。

use super::{AdapterError, Capabilities, EventAdapter, FileTail, agent_event, parse_iso8601_ns};
use crate::event::{Corr, Event, Kind, Layer, Payload, TruncNote, one_line, truncate_chars};
use crate::poll::PollOutcome;
use crate::redact::{RedactMode, redact_text};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AdapterCfg {
    /// tool_use input 截断上限（§4.1 --tool-arg-max，默认 512）。
    pub tool_arg_max: usize,
    /// Bash `input.command` 用更大的上限（§3.3 --bash-cmd-max，默认 1024）。
    pub bash_cmd_max: usize,
    pub redact: RedactMode,
}

impl Default for AdapterCfg {
    fn default() -> Self {
        AdapterCfg {
            tool_arg_max: 512,
            bash_cmd_max: 1024,
            redact: RedactMode::Argv,
        }
    }
}

pub struct ClaudeCodeAdapter {
    tail: FileTail,
    cfg: AdapterCfg,
    follow: bool,
    pub session_id: Option<String>,
    pub cwd: Option<String>,

    // ---- 去重 / 配对状态 ----
    /// 上一条 assistant 行的 `message.id`，用于推导 `agent.model.request`。
    last_message_id: Option<String>,
    /// 已经产出过 `agent.model.usage` 的 `message.id`（实测一行一个 block）。
    usage_seen: HashSet<String>,
    /// transcript 行 uuid → parentUuid（重建因果链，§1.3）。
    uuid_parent: HashMap<String, String>,
    /// user 行 uuid → promptId（turn_id 的唯一来源）。
    uuid_turn: HashMap<String, String>,
    /// 上溯解析结果的缓存：uuid → turn_id。
    turn_cache: HashMap<String, Option<String>>,
    /// tool_use_id → tool name（tool_result 行本身不带 name）。
    call_tools: HashMap<String, String>,

    // ---- 诊断（-v 可见）----
    pub unknown_types: BTreeMap<String, u64>,
    pub bad_json: u64,
    pub bad_ts: u64,
    pub emitted: u64,
    pub eof_done: bool,
    /// `validate()` 读掉的行所产出的事件，暂存在这里等第一次 poll() 取走。
    prefetched: Vec<Event>,
}

impl ClaudeCodeAdapter {
    /// `source` 可以是 session id，也可以是一个 .jsonl 路径或包含 .jsonl 的目录。
    pub fn new(source: &str, cfg: AdapterCfg, follow: bool) -> Result<Self, AdapterError> {
        let path = resolve_transcript(source)?;
        let session_id = path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string());
        Ok(ClaudeCodeAdapter {
            tail: FileTail::new(path),
            cfg,
            follow,
            session_id,
            cwd: None,
            last_message_id: None,
            usage_seen: HashSet::new(),
            uuid_parent: HashMap::new(),
            uuid_turn: HashMap::new(),
            turn_cache: HashMap::new(),
            call_tools: HashMap::new(),
            unknown_types: BTreeMap::new(),
            bad_json: 0,
            bad_ts: 0,
            emitted: 0,
            eof_done: false,
            prefetched: Vec::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.tail.path
    }

    /// 启动时校验关键字段是否存在（§5.4 #4）—— 缺失时明确报错而不是产出空事件。
    ///
    /// 这里做的是**惰性校验**：如果文件已存在且非空，至少要能读到一行合法 JSON，
    /// 否则说明格式已经变了，直接告诉用户，别装作一切正常。
    pub fn validate(&mut self) -> Result<(), AdapterError> {
        if !self.tail.path.exists() {
            if self.follow {
                // 实时模式下文件可能稍后才出现（会话刚起来）—— 不算错误。
                return Ok(());
            }
            return Err(AdapterError::NotFound(format!(
                "transcript does not exist: {}",
                self.tail.path.display()
            )));
        }
        let (lines, _) = self.tail.poll().map_err(|e| AdapterError::Io(e.to_string()))?;
        let mut out = Vec::new();
        for l in &lines {
            self.handle_line(l, &mut out);
        }
        if lines.is_empty() {
            return Ok(());
        }
        // 至少要认出一行我们认识的 type，否则格式多半变了。
        let recognized = out.len() as u64 + self.unknown_types.values().sum::<u64>();
        if recognized == 0 && self.bad_json == lines.len() as u64 {
            return Err(AdapterError::Schema(format!(
                "the first {} lines of {} are all invalid JSON — the transcript format may have changed (§5.4 #4)",
                self.tail.path.display(),
                lines.len()
            )));
        }
        // 已产出的事件先缓存起来，由 poll() 取走，避免 validate() 吞掉开头。
        self.prefetched.extend(out);
        Ok(())
    }

    fn handle_line(&mut self, line: &str, out: &mut Vec<Event>) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                // 未知/半行/坏 JSON —— 计数、跳过，**绝不 panic**（§3.3 前向兼容）。
                self.bad_json += 1;
                return;
            }
        };
        let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
        if self.cwd.is_none() {
            self.cwd = v.get("cwd").and_then(|c| c.as_str()).map(|s| s.to_string());
        }
        let uuid = sfield(&v, "uuid");
        let parent = sfield(&v, "parentUuid");
        if let (Some(u), Some(p)) = (&uuid, &parent) {
            self.uuid_parent.insert(u.clone(), p.clone());
        }
        let wall_ns = match v.get("timestamp").and_then(|t| t.as_str()) {
            Some(t) => match parse_iso8601_ns(t) {
                Some(n) => n,
                None => {
                    self.bad_ts += 1;
                    return;
                }
            },
            None => {
                self.bad_ts += 1;
                return;
            }
        };

        match ty.as_str() {
            "user" => self.map_user(&v, wall_ns, &uuid, out),
            "assistant" => self.map_assistant(&v, wall_ns, &uuid, out),
            "queue-operation" => self.map_queue(&v, wall_ns, out),
            // §3.3：attachment 是 system-reminder 环境快照（噪声），v0 丢弃。
            // atis-latch / last-prompt / cost-state / mode / ai-title / system /
            // permission-mode / file-history-* / agent-name 都是内部状态，非行为事件。
            "attachment"
            | "atis-latch"
            | "last-prompt"
            | "cost-state"
            | "mode"
            | "ai-title"
            | "system"
            | "permission-mode"
            | "file-history-delta"
            | "file-history-snapshot"
            | "agent-name"
            | "summary"
            | "compact-boundary" => {}
            other => {
                // 未知 type：**计数，不产出事件、不报错** —— 前向兼容（本机已见 8 个版本）。
                *self.unknown_types.entry(other.to_string()).or_insert(0) += 1;
            }
        }

        // §1.2：`toolUseResult.dangerouslyDisableSandbox == true` 是最强的越界前兆，
        // 单列一个 kind，任意行都检查。
        if v.get("toolUseResult")
            .and_then(|r| r.get("dangerouslyDisableSandbox"))
            .and_then(|b| b.as_bool())
            == Some(true)
        {
            let corr = self.corr(&v, &uuid, None);
            let notes: Vec<String> = Vec::new();
            out.push(agent_event(
                wall_ns,
                Kind::AgentSandboxDisabled,
                Layer::Agent,
                "claude-code",
                corr,
                Payload::SandboxDisabled { disabled: true },
                Vec::new(),
                notes,
            ));
            self.emitted += 1;
        }
    }

    fn corr(&self, v: &Value, uuid: &Option<String>, tool_use_id: Option<String>) -> Corr {
        Corr {
            session_id: self.session_id.clone().or_else(|| sfield(v, "sessionId")),
            run_id: None,
            agent_id: None,
            turn_id: self.resolve_turn(uuid.as_deref()),
            tool_use_id,
            uuid: uuid.clone(),
            parent_uuid: sfield(v, "parentUuid"),
            pid_root: None,
            pid_binding: None,
            sidechain: v.get("isSidechain").and_then(|b| b.as_bool()).unwrap_or(false),
        }
    }

    /// 沿 parentUuid 链上溯找最近的 promptId（见文件头修正 #1）。
    fn resolve_turn(&self, uuid: Option<&str>) -> Option<String> {
        let mut cur = uuid?;
        for _ in 0..500 {
            if let Some(c) = self.turn_cache.get(cur) {
                return c.clone();
            }
            if let Some(t) = self.uuid_turn.get(cur) {
                return Some(t.clone());
            }
            match self.uuid_parent.get(cur) {
                Some(p) => cur = p.as_str(),
                None => return None,
            }
        }
        None
    }

    /// 把解析结果写进 turn_cache（`resolve_turn` 是 `&self`，在 map_* 之后统一回填）。
    fn cache_turn(&mut self, uuid: &Option<String>) {
        let Some(u) = uuid else { return };
        let t = self.resolve_turn(Some(u));
        self.turn_cache.insert(u.clone(), t);
    }

    fn map_queue(&mut self, v: &Value, wall_ns: u64, out: &mut Vec<Event>) {
        if v.get("operation").and_then(|o| o.as_str()) != Some("enqueue") {
            return; // dequeue 是内部状态，不是行为事件
        }
        let content = v.get("content").and_then(|c| c.as_str()).unwrap_or("");
        let (preview, note) = self.preview(content, self.cfg.tool_arg_max, "text_preview");
        let corr = self.corr(v, &sfield(v, "uuid"), None);
        let notes: Vec<String> = Vec::new();
        out.push(agent_event(
            wall_ns,
            Kind::AgentPromptQueued,
            Layer::Agent,
            "claude-code",
            corr,
            Payload::PromptQueued { text_preview: preview },
            note,
            notes,
        ));
        self.emitted += 1;
    }

    fn map_user(&mut self, v: &Value, wall_ns: u64, uuid: &Option<String>, out: &mut Vec<Event>) {
        // promptId 只在 user 行上（见文件头修正 #1）。
        if let (Some(u), Some(pid)) = (uuid, sfield(v, "promptId")) {
            self.uuid_turn.insert(u.clone(), pid);
        }
        let corr = self.corr(v, uuid, None);
        let content = v.get("message").and_then(|m| m.get("content"));

        match content {
            // `message.content` 是 string → 真实用户输入（§3.3）。
            Some(Value::String(s)) => {
                let (preview, note) = self.preview(s, self.cfg.tool_arg_max, "text_preview");
                let notes: Vec<String> = Vec::new();
                out.push(agent_event(
                    wall_ns,
                    Kind::AgentPrompt,
                    Layer::Agent,
                    "claude-code",
                    corr,
                    Payload::Prompt {
                        text_preview: preview,
                        chars: s.chars().count(),
                    },
                    note,
                    notes,
                ));
                self.emitted += 1;
            }
            // 含 tool_result 块的数组 → 工具返回。
            Some(Value::Array(blocks)) => {
                for b in blocks {
                    if b.get("type").and_then(|t| t.as_str()) != Some("tool_result") {
                        continue;
                    }
                    let tool_use_id = sfield(b, "tool_use_id");
                    let is_error = b.get("is_error").and_then(|e| e.as_bool()).unwrap_or(false);
                    let tool = tool_use_id.as_ref().and_then(|id| self.call_tools.get(id)).cloned();
                    // 结果内容可能很长（Read 返回整个文件，§3.3）——只放 preview，
                    // 换行转义成字面 \n，保证一个事件永远只占一行。
                    let raw = b.get("content");
                    let text = tool_result_text(raw, v.get("toolUseResult"), tool.as_deref());
                    let (preview, mut note) = self.preview(&text, self.cfg.tool_arg_max, "result_preview");
                    // `toolUseResult` 类型不固定（实测 object/string/array 三种，§3.3）。
                    // 未知形状已经降级成 JSON 文本，这里再补一条说明。
                    if let Some(tur) = v.get("toolUseResult") {
                        if tur.is_object() && !is_known_result_shape(tur) {
                            note.push(
                                TruncNote::new("result_preview", None, preview.len())
                                    .with_note("unknown toolUseResult shape -> degraded to JSON text (§3.3)"),
                            );
                        }
                    }
                    let notes: Vec<String> = Vec::new();
                    out.push(agent_event(
                        wall_ns,
                        Kind::AgentToolResult,
                        Layer::Agent,
                        "claude-code",
                        self.corr(v, uuid, tool_use_id),
                        Payload::ToolResult {
                            tool,
                            status: if is_error { "Failure".into() } else { "Success".into() },
                            result_preview: preview,
                        },
                        note,
                        notes,
                    ));
                    self.emitted += 1;
                }
            }
            _ => {}
        }
        self.cache_turn(uuid);
    }

    fn map_assistant(&mut self, v: &Value, wall_ns: u64, uuid: &Option<String>, out: &mut Vec<Event>) {
        let msg = v.get("message");
        let msg_id = msg.and_then(|m| m.get("id")).and_then(|i| i.as_str()).map(String::from);
        let model = msg
            .and_then(|m| m.get("model"))
            .and_then(|m| m.as_str())
            .map(String::from);

        // §3.3：transcript 里**没有**独立的"请求开始"行，用 message.id 变化推导。
        // 诚实说明（§5.2 #6）：assistant 行的 timestamp 是**响应记录**的时刻，
        // 不是请求发出的时刻 —— 与内核事件存在系统性偏移（≈ 思考+生成耗时）。
        // **不可用于推断"模型想了 N 秒才去执行命令"**。
        let is_new_request = match (&msg_id, &self.last_message_id) {
            (Some(cur), Some(prev)) => cur != prev,
            (Some(_), None) => true,
            _ => false,
        };
        if is_new_request {
            let corr = self.corr(v, uuid, None);
            let input_tokens = msg
                .and_then(|m| m.get("usage"))
                .and_then(|u| u.get("input_tokens"))
                .and_then(|t| t.as_u64());
            out.push(agent_event(
                wall_ns,
                Kind::AgentModelRequest,
                Layer::Agent,
                "claude-code",
                corr,
                Payload::ModelRequest {
                    model: model.clone(),
                    input_tokens,
                    // transcript 里 model.request 是**推导**出来的（没有独立的一行），
                    // 没有额外的自由文本可填 —— 如实留 None。
                    detail_preview: None,
                },
                // 没有任何内容被截断（§4.3 的 `~` 只表示"截断"），
                // "ts 是推导的"是一条 caveat，走 notes。
                Vec::new(),
                vec!["agent.model.request is **derived**: ts is when the response was recorded, not when the request was sent (§3.3/§5.2#6)".to_string()],
            ));
            self.emitted += 1;
            self.last_message_id = msg_id.clone();
        }

        // usage：**按 message.id 去重**（见文件头修正 #2）。
        if let (Some(id), Some(usage)) = (&msg_id, msg.and_then(|m| m.get("usage"))) {
            if self.usage_seen.insert(id.clone()) {
                let g = |k: &str| usage.get(k).and_then(|x| x.as_u64());
                let corr = self.corr(v, uuid, None);
                let notes: Vec<String> = Vec::new();
                out.push(agent_event(
                    wall_ns,
                    Kind::AgentModelUsage,
                    Layer::Agent,
                    "claude-code",
                    corr,
                    Payload::ModelUsage {
                        model: model.clone(),
                        input_tokens: g("input_tokens"),
                        output_tokens: g("output_tokens"),
                        cache_read: g("cache_read_input_tokens"),
                        // 不编造成本：transcript 里只有 cost-state 的**会话累计**快照，
                        // 没有单次请求成本。§4.2 示例里的 cost= 在 v0 里不产出。
                        cost_usd: None,
                    },
                    Vec::new(),
                    notes,
                ));
                self.emitted += 1;
            }
        }

        let Some(Value::Array(blocks)) = msg.and_then(|m| m.get("content")) else {
            self.cache_turn(uuid);
            return;
        };
        for b in blocks {
            match b.get("type").and_then(|t| t.as_str()) {
                Some("thinking") => {
                    let raw = b.get("thinking").and_then(|t| t.as_str()).unwrap_or("");
                    let (preview, note) = self.preview(raw, self.cfg.tool_arg_max, "preview");
                    let dur = b
                        .get("thinkingDurationMs")
                        .and_then(|d| d.as_u64())
                        .or_else(|| v.get("thinkingDurationMs").and_then(|d| d.as_u64()));
                    let notes: Vec<String> = Vec::new();
                    out.push(agent_event(
                        wall_ns,
                        Kind::AgentModelThinking,
                        Layer::Agent,
                        "claude-code",
                        self.corr(v, uuid, None),
                        Payload::Thinking {
                            preview,
                            duration_ms: dur,
                        },
                        note,
                        notes,
                    ));
                    self.emitted += 1;
                }
                Some("text") => {
                    let raw = b.get("text").and_then(|t| t.as_str()).unwrap_or("");
                    let (preview, note) = self.preview(raw, self.cfg.tool_arg_max, "preview");
                    let notes: Vec<String> = Vec::new();
                    out.push(agent_event(
                        wall_ns,
                        Kind::AgentModelText,
                        Layer::Agent,
                        "claude-code",
                        self.corr(v, uuid, None),
                        Payload::ModelText { preview },
                        note,
                        notes,
                    ));
                    self.emitted += 1;
                }
                Some("tool_use") => {
                    let name = b
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("<unknown>")
                        .to_string();
                    let id = sfield(b, "id");
                    if let Some(idv) = &id {
                        self.call_tools.insert(idv.clone(), name.clone());
                    }
                    let input = b.get("input").cloned().unwrap_or(Value::Null);
                    // `input` 是 JSON 对象 → to_string 后截断（§3.3）。
                    let serialized = serde_json::to_string(&input).unwrap_or_default();
                    let input_bytes = serialized.len();
                    // F1（DESIGN §5.3）：`--redact argv`（**默认**）必须打码 argv 与
                    // Bash 命令。Bash 的 `input` 就是命令行；任何工具只要 input 里带
                    // `command`/`cmd` 键，整段 input preview 也按命令行处理 —— 否则同一
                    // 个 secret 在这一行是明文、在下一行内核 exec argv 里却是 `***`。
                    // prompt / thinking / tool result 是 content，仍只在 `argv+content`
                    // 下打码，那是文档承诺的边界。
                    let shell_tool = name == "Bash";
                    let raw_cmd = input
                        .get("command")
                        .and_then(|c| c.as_str())
                        .or_else(|| input.get("cmd").and_then(|c| c.as_str()));
                    let preview_src = if self.cfg.redact.redacts_argv() && (shell_tool || raw_cmd.is_some()) {
                        redact_text(&serialized)
                    } else {
                        serialized
                    };
                    let (mut input_preview, mut note) =
                        self.preview(&preview_src, self.cfg.tool_arg_max, "input_preview");
                    // Bash 是绝对主力（本机实测 481 次，§3.3）→ `input.command` 单独
                    // 用更大的 --bash-cmd-max 上限提取。
                    //
                    // `cmd` 是备用键名（V03_PROMPT §1 写的是 `command`/`cmd`）：
                    // 不同的 harness（以及被包装过的工具）会用 `cmd`。两个键都认，
                    // 顺序固定为 `command` 优先，是为了**同一个 input 只取一个值**、
                    // 不产生歧义 —— v0.3 会拿这个字符串去和内核 argv 精确匹配，
                    // "猜"一个错的命令行会直接变成一条错误的 exact 断言。
                    let mut bash_cmd = None;
                    if shell_tool
                        && let Some(cmd) = raw_cmd
                    {
                        // 命令行字段：默认模式就按 argv 打码（F1）。
                        let (c2, mut n2) =
                            self.preview_argvish(cmd, self.cfg.bash_cmd_max, "bash_cmd");
                        bash_cmd = Some(c2);
                        note.append(&mut n2);
                        // input_preview 保留完整 input（含其他字段如 timeout），
                        // 但如果它太长，Bash 行会变得难读 —— 不影响正确性，保留。
                        let _ = &mut input_preview;
                    }
                    let notes: Vec<String> = Vec::new();
                    out.push(agent_event(
                        wall_ns,
                        Kind::AgentToolCall,
                        Layer::Agent,
                        "claude-code",
                        self.corr(v, uuid, id),
                        Payload::ToolCall {
                            tool: name.clone(),
                            input_preview,
                            input_bytes,
                            // §8 ②：MCP 工具以 `mcp__server__tool` 形式出现，单独标注。
                            via_mcp: name.starts_with("mcp__"),
                            bash_cmd,
                        },
                        note,
                        notes,
                    ));
                    self.emitted += 1;
                }
                _ => {}
            }
        }
        self.cache_turn(uuid);
    }

    /// 生成一个 `_preview` 字段：按**字符边界**截断（§5.5 #8），换行转义（§3.2），
    /// 并在 `--redact argv+content` 下打码（§5.3）。
    fn preview(&self, s: &str, max: usize, field: &str) -> (String, Vec<TruncNote>) {
        let s = if self.cfg.redact.redacts_content() {
            redact_text(s)
        } else {
            s.to_string()
        };
        self.preview_plain(&s, max, field)
    }

    /// 命令行 / argv 形态的 preview：`--redact argv`（**默认**）就打码。
    ///
    /// DESIGN §5.3 承诺 "credential-shaped patterns in argv **and Bash commands**
    /// are masked" —— 命令行的凭据不能只在 `argv+content` 下才遮（F1）。
    fn preview_argvish(&self, s: &str, max: usize, field: &str) -> (String, Vec<TruncNote>) {
        let s = if self.cfg.redact.redacts_argv() {
            redact_text(s)
        } else {
            s.to_string()
        };
        self.preview_plain(&s, max, field)
    }

    /// 截断 + 单行化（不含打码；打码由 [`Self::preview`] /
    /// [`Self::preview_argvish`] 按模式决定）。
    fn preview_plain(&self, s: &str, max: usize, field: &str) -> (String, Vec<TruncNote>) {
        let (cut, truncated, orig) = truncate_chars(s, max, max);
        let mut notes = Vec::new();
        if truncated {
            notes.push(TruncNote::new(field, Some(orig), cut.len()));
        }
        (one_line(&cut), notes)
    }
}

impl EventAdapter for ClaudeCodeAdapter {
    fn id(&self) -> &'static str {
        "claude-code"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            kinds: vec![
                Kind::AgentPrompt,
                Kind::AgentPromptQueued,
                Kind::AgentModelRequest,
                Kind::AgentModelThinking,
                Kind::AgentModelText,
                Kind::AgentModelUsage,
                Kind::AgentToolCall,
                Kind::AgentToolResult,
                Kind::AgentSandboxDisabled,
            ],
            live: true,
            needs_pid_binding: true,
        }
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, AdapterError> {
        let mut buf = std::mem::take(&mut self.prefetched);
        let (lines, gone) = self.tail.poll().map_err(|e| AdapterError::Io(e.to_string()))?;
        for l in &lines {
            self.handle_line(l, &mut buf);
        }
        let n = buf.len();
        out.append(&mut buf);

        if n > 0 {
            return Ok(PollOutcome::Progress);
        }
        if gone && (self.eof_done || !self.follow) {
            return Ok(PollOutcome::Eof);
        }
        if self.eof_done && !self.follow {
            return Ok(PollOutcome::Eof);
        }
        // 非 follow 模式下，文件已读到 EOF 且没有新行 → 结束。
        if !self.follow && self.tail.ever_opened {
            self.eof_done = true;
            return Ok(PollOutcome::Eof);
        }
        Ok(PollOutcome::Idle)
    }

    fn shutdown(&mut self) {
        self.tail = FileTail::new(self.tail.path.clone());
    }

    fn diagnostics(&self) -> Vec<String> {
        let mut d = Vec::new();
        d.push(format!(
            "produced {} agent event(s); bad JSON lines {}; missing/invalid timestamp lines {}",
            self.emitted, self.bad_json, self.bad_ts
        ));
        if !self.unknown_types.is_empty() {
            let s: Vec<String> = self.unknown_types.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            d.push(format!(
                "unknown transcript type(s) (counted, no event produced): {}",
                s.join(" ")
            ));
        }
        // FileTail 的重开/重读不是无声的：轮转或截断会让"这条事件出现过几次"
        // 变成一个必须能回答的问题（§4.3）。
        if self.tail.restarts > 0 {
            d.push(format!(
                "file tail: {} restart(s) (last: {}); {} possible duplicate event(s)",
                self.tail.restarts,
                self.tail.last_restart.as_deref().unwrap_or("-"),
                self.tail.possible_duplicates
            ));
        }
        d
    }
}

/// `Read` 的 toolUseResult 是整个文件内容、`Bash` 是 stdout/stderr（§3.3）——
/// 所以结果文本必须归一化后截断。
///
/// **`toolUseResult` 类型不固定**：实测 object / string / array 三种。
/// `tool_result` 块里的 `content` 也可能是 string 或 block 数组。
fn tool_result_text(block_content: Option<&Value>, tur: Option<&Value>, tool: Option<&str>) -> String {
    // 优先用 toolUseResult 的归一化结果（信息量更大、更有结构）。
    if let Some(t) = tur {
        let normalized = normalize_result(tool.unwrap_or(""), t);
        if !normalized.is_empty() {
            return normalized;
        }
    }
    if let Some(c) = block_content {
        return value_to_text(c);
    }
    String::new()
}

/// 把任意 JSON 值转成文本（数组 → 拼接每个 block 的 text）。
fn value_to_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => {
            let mut parts = Vec::new();
            for item in a {
                if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                    parts.push(t.to_string());
                } else if item.is_string() {
                    parts.push(item.as_str().unwrap_or("").to_string());
                }
            }
            parts.join("\n")
        }
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// 已知的 toolUseResult dict 形状（§3.3 实测频次排序）。
fn is_known_result_shape(v: &Value) -> bool {
    let has = |k: &str| v.get(k).is_some();
    // Bash: {stdout, stderr, interrupted, isImage, noOutputExpected, dangerouslyDisableSandbox}
    if has("stdout") || has("stderr") {
        return true;
    }
    // Read: {file:{filePath,content}, type}
    if v.get("file").map(|f| f.is_object()).unwrap_or(false) {
        return true;
    }
    // Write: {content, filePath, originalFile, structuredPatch, userModified, type}
    if has("filePath") && (has("content") || has("originalFile")) {
        return true;
    }
    // Edit: {filePath, newString, oldString, originalFile, replaceAll, structuredPatch}
    if has("newString") || has("oldString") {
        return true;
    }
    // TaskUpdate: {statusChange, success, taskId, updatedFields}
    if has("statusChange") || has("updatedFields") {
        return true;
    }
    false
}

/// 每个工具一个 normalize_result（§3.3）。**未知形状必须能降级，不能 panic。**
fn normalize_result(tool: &str, tur: &Value) -> String {
    match tur {
        // 实测 string 43 次 / array 5 次 —— 直接降级成文本/JSON。
        Value::String(s) => return s.clone(),
        Value::Array(_) => return value_to_text(tur),
        Value::Object(_) => {}
        _ => return String::new(),
    }
    let s = |k: &str| tur.get(k).and_then(|x| x.as_str()).unwrap_or("");

    match tool {
        // Bash（本机 244+ 次）：stdout/stderr 是主体。
        "Bash" => {
            let mut out = String::new();
            let stdout = s("stdout");
            let stderr = s("stderr");
            if tur.get("interrupted").and_then(|b| b.as_bool()) == Some(true) {
                out.push_str("[interrupted] ");
            }
            if !stderr.is_empty() {
                out.push_str("stderr: ");
                out.push_str(stderr);
            }
            if !stdout.is_empty() {
                if !out.is_empty() {
                    out.push_str(" | ");
                }
                out.push_str("stdout: ");
                out.push_str(stdout);
            }
            if out.is_empty() {
                if tur.get("noOutputExpected").and_then(|b| b.as_bool()) == Some(true) {
                    out.push_str("(no output expected)");
                } else if tur.get("isImage").and_then(|b| b.as_bool()) == Some(true) {
                    out.push_str("(image)");
                }
            }
            out
        }
        // Read: file.content 是整个文件（数千字符）→ 只留 preview。
        "Read" => {
            let fp = tur
                .get("file")
                .and_then(|f| f.get("filePath"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            let content = tur
                .get("file")
                .and_then(|f| f.get("content"))
                .and_then(|c| c.as_str())
                .unwrap_or("");
            format!("{} :: {}", fp, content)
        }
        "Write" => {
            let fp = s("filePath");
            let c = s("content");
            format!("{} :: {} bytes", fp, c.len())
        }
        "Edit" => {
            let fp = s("filePath");
            let old = s("oldString");
            let new = s("newString");
            let all = tur.get("replaceAll").and_then(|b| b.as_bool()).unwrap_or(false);
            format!(
                "{} :: -{} +{}{}",
                fp,
                old.len(),
                new.len(),
                if all { " (replaceAll)" } else { "" }
            )
        }
        "TaskUpdate" => {
            let sc = s("statusChange");
            let ok = tur.get("success").and_then(|b| b.as_bool()).unwrap_or(false);
            let tid = s("taskId");
            format!("task={} statusChange={} success={}", tid, sc, ok)
        }
        _ => {
            // 未知形状 → serde_json 截断（由调用方的 preview() 负责截断）。
            serde_json::to_string(tur).unwrap_or_default()
        }
    }
}

fn sfield(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string())
}

/// 解析 `--session` / `--transcript` 的取值（§4.1）。
///
/// - 一个已存在的 `.jsonl` 文件 → 直接用
/// - 一个目录 → 取其中最近修改的 `.jsonl`
/// - 一个 session id → 在 `~/.claude/projects/*/<id>.jsonl` 里找
pub fn resolve_transcript(source: &str) -> Result<PathBuf, AdapterError> {
    let p = PathBuf::from(source);
    if p.is_file() {
        return Ok(p);
    }
    if p.is_dir() {
        return newest_jsonl(&p);
    }
    // 当作 session id
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let projects = PathBuf::from(home).join(".claude/projects");
    if let Ok(rd) = std::fs::read_dir(&projects) {
        for ent in rd.flatten() {
            let cand = ent.path().join(format!("{}.jsonl", source));
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    // 也可能是相对/绝对路径但还不存在（实时 tail 一个尚未创建的文件）
    if source.ends_with(".jsonl") {
        return Ok(p);
    }
    Err(AdapterError::NotFound(format!(
        "transcript not found: `{}` is neither a file/directory nor a session id under ~/.claude/projects/*/",
        source
    )))
}

fn newest_jsonl(dir: &Path) -> Result<PathBuf, AdapterError> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let rd = std::fs::read_dir(dir).map_err(|e| AdapterError::Io(e.to_string()))?;
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let Ok(md) = ent.metadata() else { continue };
        let Ok(ts) = md.modified() else { continue };
        if best.as_ref().map(|(t, _)| ts > *t).unwrap_or(true) {
            best = Some((ts, p));
        }
    }
    best.map(|(_, p)| p)
        .ok_or_else(|| AdapterError::NotFound(format!("no .jsonl file in directory {}", dir.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一个形如真实凭据的串。`redact_text` 只按**凭据形状**打码（header/kv/URL
    /// userinfo/JSON），不按长度或熵猜 —— 所以测试用这些形态而不是随机长串。
    const SECRET: &str = "sk-secret-123456";

    fn cfg(mode: RedactMode) -> AdapterCfg {
        AdapterCfg {
            tool_arg_max: 512,
            bash_cmd_max: 1024,
            redact: mode,
        }
    }

    /// `resolve_transcript()` 接受尚不存在的 `*.jsonl`（live tail 语义）；测试把
    /// 行直接喂给 `handle_line()`，不碰磁盘。
    fn adapter(mode: RedactMode) -> ClaudeCodeAdapter {
        let p = std::env::temp_dir().join(format!(
            "agtrace_cc_redact_{}_{:?}.jsonl",
            std::process::id(),
            mode
        ));
        ClaudeCodeAdapter::new(p.to_str().unwrap(), cfg(mode), true).expect("adapter")
    }

    fn secret_cmd() -> String {
        format!("curl -H 'Authorization: Bearer {}' https://x.dev", SECRET)
    }

    /// 一条 Bash tool_use + 一条 prompt + 一条 tool_result（真实 transcript 顺序）。
    fn run(mode: RedactMode) -> Vec<Event> {
        let mut a = adapter(mode);
        let mut out = Vec::new();
        let call = format!(
            r#"{{"type":"assistant","uuid":"u1","timestamp":"2026-10-11T20:00:00.000Z","message":{{"id":"m1","content":[{{"type":"tool_use","id":"t1","name":"Bash","input":{{"command":"{}"}}}}]}}}}"#,
            secret_cmd()
        );
        let prompt = format!(
            r#"{{"type":"user","uuid":"u2","timestamp":"2026-10-11T20:00:01.000Z","message":{{"content":"my command was: {}"}}}}"#,
            secret_cmd()
        );
        let result = format!(
            r#"{{"type":"user","uuid":"u3","timestamp":"2026-10-11T20:00:02.000Z","message":{{"content":[{{"type":"tool_result","tool_use_id":"t1","content":"output from {}"}}]}}}}"#,
            secret_cmd()
        );
        for line in [call, prompt, result] {
            a.handle_line(&line, &mut out);
        }
        out
    }

    fn tool_call(evs: &[Event]) -> &Payload {
        evs.iter()
            .find_map(|e| match &e.payload {
                p @ Payload::ToolCall { .. } => Some(p),
                _ => None,
            })
            .expect("no tool.call event")
    }

    fn prompt_text(evs: &[Event]) -> &str {
        evs.iter()
            .find_map(|e| match &e.payload {
                Payload::Prompt { text_preview, .. } => Some(text_preview.as_str()),
                _ => None,
            })
            .expect("no prompt event")
    }

    fn result_preview(evs: &[Event]) -> &str {
        evs.iter()
            .find_map(|e| match &e.payload {
                Payload::ToolResult { result_preview, .. } => Some(result_preview.as_str()),
                _ => None,
            })
            .expect("no tool.result event")
    }

    /// F1（HIGH）：默认 `--redact argv` 下，Bash 命令行和含命令的 input preview
    /// 必须打码；prompt / tool result 是 content，保持明文（文档承诺的边界）。
    #[test]
    fn default_argv_mode_masks_bash_command_and_input_preview() {
        let evs = run(RedactMode::Argv);
        match tool_call(&evs) {
            Payload::ToolCall {
                tool,
                bash_cmd,
                input_preview,
                ..
            } => {
                assert_eq!(tool, "Bash");
                let cmd = bash_cmd.as_deref().expect("Bash must have bash_cmd");
                assert!(!cmd.contains(SECRET), "F1: Bash 命令行默认未打码: {}", cmd);
                assert!(cmd.contains("***"), "打码必须留痕: {}", cmd);
                assert!(
                    !input_preview.contains(SECRET),
                    "F1: Bash input_preview 默认未打码: {}",
                    input_preview
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert!(prompt_text(&evs).contains(SECRET), "argv 模式不得打码 prompt");
        assert!(
            result_preview(&evs).contains(SECRET),
            "argv 模式不得打码 tool result"
        );
    }

    /// `--redact argv+content` 额外打码 agent 层内容；命令行仍然打码。
    #[test]
    fn argv_content_mode_also_masks_content() {
        let evs = run(RedactMode::ArgvContent);
        match tool_call(&evs) {
            Payload::ToolCall {
                bash_cmd,
                input_preview,
                ..
            } => {
                assert!(!bash_cmd.as_deref().unwrap().contains(SECRET));
                assert!(!input_preview.contains(SECRET));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert!(!prompt_text(&evs).contains(SECRET), "{}", prompt_text(&evs));
        assert!(
            !result_preview(&evs).contains(SECRET),
            "{}",
            result_preview(&evs)
        );
    }

    /// `--redact off` 必须真的不打码（用户显式关掉时不自作主张）。
    #[test]
    fn off_mode_masks_nothing() {
        let evs = run(RedactMode::Off);
        match tool_call(&evs) {
            Payload::ToolCall {
                bash_cmd,
                input_preview,
                ..
            } => {
                assert!(bash_cmd.as_deref().unwrap().contains(SECRET));
                assert!(input_preview.contains(SECRET));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert!(prompt_text(&evs).contains(SECRET));
        assert!(result_preview(&evs).contains(SECRET));
    }

    /// 非命令行工具的 input 属于 content：`argv` 模式**不**打码，`argv+content`
    /// 才打码 —— F1 要求的最小作用域（不能把 agent 内容当 argv 打）。
    #[test]
    fn non_command_tool_input_is_content_scoped() {
        let line = r#"{"type":"assistant","uuid":"u9","timestamp":"2026-10-11T20:00:00.000Z","message":{"id":"m2","content":[{"type":"tool_use","id":"t9","name":"Write","input":{"file_path":"/tmp/x","content":"password=hunter2"}}]}}"#;
        let mut a = adapter(RedactMode::Argv);
        let mut out = Vec::new();
        a.handle_line(line, &mut out);
        match tool_call(&out) {
            Payload::ToolCall {
                input_preview,
                bash_cmd,
                ..
            } => {
                assert!(bash_cmd.is_none(), "Write 不应有 bash_cmd");
                assert!(
                    input_preview.contains("hunter2"),
                    "argv 模式下 content input 不该被打码: {}",
                    input_preview
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }

        let mut a = adapter(RedactMode::ArgvContent);
        let mut out = Vec::new();
        a.handle_line(line, &mut out);
        match tool_call(&out) {
            Payload::ToolCall { input_preview, .. } => assert!(
                !input_preview.contains("hunter2"),
                "argv+content 下 content input 必须打码: {}",
                input_preview
            ),
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    /// 非 Bash 名称但 input 里带 `command`：整段 input preview 也按命令行处理
    /// （F1：“for the whole input when it contains the command”）。
    #[test]
    fn generic_tool_input_with_command_is_masked_in_argv_mode() {
        let line = format!(
            r#"{{"type":"assistant","uuid":"u10","timestamp":"2026-10-11T20:00:00.000Z","message":{{"id":"m3","content":[{{"type":"tool_use","id":"t10","name":"Shell","input":{{"command":"tool --token={}"}}}}]}}}}"#,
            SECRET
        );
        let mut a = adapter(RedactMode::Argv);
        let mut out = Vec::new();
        a.handle_line(&line, &mut out);
        match tool_call(&out) {
            Payload::ToolCall {
                input_preview,
                bash_cmd,
                ..
            } => {
                assert!(bash_cmd.is_none(), "只有 Bash 才产出 bash_cmd");
                assert!(
                    !input_preview.contains(SECRET),
                    "含 command 的 input 在 argv 模式下必须打码: {}",
                    input_preview
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }
}
