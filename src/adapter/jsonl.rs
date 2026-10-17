//! Generic JSONL adapter (`--adapter jsonl`).
//!
//! Input: one JSON object per line — a minimal, framework-agnostic agent event
//! schema designed to be trivial to emit from LangChain, LangGraph, CrewAI,
//! the OpenAI Agents SDK, or a hand-rolled loop. See
//! `examples/langchain_callback.py` for a ~60-line emitter.
//!
//! ## Schema
//!
//! ```json
//! {"type": "prompt",      "text": "do X", "ts": "2026-10-11T20:00:00.123Z"}
//! {"type": "tool.call",   "id": "call_1", "tool": "Bash", "command": "ls /tmp", "ts": "..."}
//! {"type": "tool.result", "id": "call_1", "status": "success", "output": "...", "ts": "..."}
//! {"type": "model.text",  "text": "I'll list /tmp", "ts": "..."}
//! {"type": "model.usage", "model": "gpt-4o", "input_tokens": 100, "output_tokens": 20, "ts": "..."}
//! ```
//!
//! - `type` (required): `prompt` | `tool.call` | `tool.result` |
//!   `model.request` | `model.text` | `model.usage` | `thinking`.
//!   Unknown types are counted in `diagnostics()` and skipped — never silently
//!   mis-mapped (§4.3).
//! - `ts` (optional): ISO8601 (`2026-10-11T20:00:00.123Z`) or epoch seconds
//!   (number). Missing or unparseable → wall-clock time at read; counted in
//!   diagnostics and noted on the event.
//! - `id` (optional): tool call id → `corr.tool_use_id`. This correlates a call
//!   with its result, and is what `--failures-only` and `--output json` use to
//!   select a chain (`jq 'select(.corr.tool_use_id==$id)'`).
//! - `session_id`, `run_id` (optional): passed through to `corr`.
//!
//! Type-specific fields: `prompt` / `model.text` / `thinking` take `text`;
//! `tool.call` takes `tool`, `command` (a Bash command is extracted as
//! `bash_cmd` so argv binding works), and `input` (object or string, previewed);
//! `tool.result` takes `status` and `output`; `model.request` takes `model` and
//! `input_tokens`; `model.usage` takes `model`, `input_tokens`, `output_tokens`,
//! `cache_read`; `thinking` takes `duration_ms`.
//!
//! The file is tailed (`live: true`): point agtrace at the file your callback
//! handler appends to and run with `-f`. Without `-f` the file is drained once
//! (offline replay).

use super::{AdapterError, Capabilities, EventAdapter, FileTail, agent_event, parse_iso8601_ns};
use crate::event::{Corr, Event, Kind, Layer, Payload, TruncNote, one_line, truncate_chars};
use crate::poll::PollOutcome;
use crate::redact::{RedactMode, redact_text};
use serde_json::Value;
use std::collections::HashMap;

pub struct JsonlAdapter {
    tail: FileTail,
    follow: bool,
    done: bool,
    pub tool_preview_max: usize,
    /// How `--redact` applies to this adapter (F2: it used to not apply at all).
    redact: RedactMode,
    /// tool.call id → tool name, so tool.result rows can name their tool.
    call_tools: HashMap<String, String>,
    pub emitted: u64,
    pub bad_json: u64,
    pub bad_ts: u64,
    pub missing_ts: u64,
    pub unknown_type: HashMap<String, u64>,
}

impl JsonlAdapter {
    pub fn new(path: &str, tool_preview_max: usize, follow: bool, redact: RedactMode) -> Result<Self, AdapterError> {
        let p = std::path::Path::new(path);
        if !p.is_file() && !follow {
            return Err(AdapterError::NotFound(format!(
                "jsonl event file does not exist: {} (use -f to wait for it to appear)",
                p.display()
            )));
        }
        Ok(JsonlAdapter {
            tail: FileTail::new(path),
            follow,
            done: false,
            tool_preview_max,
            redact,
            call_tools: HashMap::new(),
            emitted: 0,
            bad_json: 0,
            bad_ts: 0,
            missing_ts: 0,
            unknown_type: HashMap::new(),
        })
    }

    fn wall_now_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    fn str_field(v: &Value, key: &str) -> Option<String> {
        v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
    }

    /// `ts`: ISO8601 string or epoch seconds. Returns (ns, notes).
    fn parse_ts(&mut self, v: &Value) -> (u64, Vec<String>) {
        match v.get("ts") {
            None => {
                self.missing_ts += 1;
                (Self::wall_now_ns(), vec!["ts missing: wall-clock at read".to_string()])
            }
            Some(Value::String(s)) => match parse_iso8601_ns(s) {
                Some(ns) => (ns, Vec::new()),
                None => {
                    self.bad_ts += 1;
                    (
                        Self::wall_now_ns(),
                        vec![format!("ts unparseable {:?}: wall-clock at read", s)],
                    )
                }
            },
            Some(Value::Number(n)) => {
                // Integer seconds first: exact. Fractional → f64 (±sub-µs rounding).
                if let Some(secs) = n.as_u64() {
                    (secs * 1_000_000_000, Vec::new())
                } else {
                    match n.as_f64() {
                        Some(f) if f.is_finite() && f >= 0.0 => ((f * 1e9) as u64, Vec::new()),
                        _ => {
                            self.bad_ts += 1;
                            (
                                Self::wall_now_ns(),
                                vec!["ts not a valid epoch: wall-clock at read".to_string()],
                            )
                        }
                    }
                }
            }
            Some(_) => {
                self.bad_ts += 1;
                (
                    Self::wall_now_ns(),
                    vec!["ts wrong type: wall-clock at read".to_string()],
                )
            }
        }
    }

    fn corr_of(v: &Value) -> Corr {
        Corr {
            session_id: Self::str_field(v, "session_id"),
            run_id: Self::str_field(v, "run_id"),
            tool_use_id: Self::str_field(v, "id"),
            ..Default::default()
        }
    }

    /// Preview helper: one_line + truncate, returns (preview, trunc notes).
    ///
    /// `--redact argv+content` additionally masks credentials in free-form content;
    /// `--redact argv` only masks command fields (see the `tool.call` arm).
    fn preview(&self, s: &str, field: &str) -> (String, Vec<TruncNote>) {
        let s = if self.redact.redacts_content() {
            redact_text(s)
        } else {
            s.to_string()
        };
        self.preview_plain(&s, field)
    }

    fn preview_plain(&self, s: &str, field: &str) -> (String, Vec<TruncNote>) {
        let flat = one_line(s);
        let (p, cut, orig) = truncate_chars(&flat, self.tool_preview_max, self.tool_preview_max);
        let n = if cut {
            vec![TruncNote::new(field, Some(orig), p.len())]
        } else {
            Vec::new()
        };
        (p, n)
    }

    fn emit(&mut self, v: &Value, out: &mut Vec<Event>) {
        let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let (wall_ns, notes) = self.parse_ts(v);
        let corr = Self::corr_of(v);
        // match 产出 (kind, payload, trunc)；push 统一在后面做，避免闭包跨 arm 持有 &mut self。
        let produced: Option<(Kind, Payload, Vec<TruncNote>)> = match t.as_str() {
            "prompt" => {
                let text = Self::str_field(v, "text").unwrap_or_default();
                let (p, n) = self.preview(&text, "text");
                Some((
                    Kind::AgentPrompt,
                    Payload::Prompt {
                        text_preview: p,
                        chars: text.chars().count(),
                    },
                    n,
                ))
            }
            "tool.call" => {
                let tool = Self::str_field(v, "tool").unwrap_or_else(|| "<unknown>".into());
                let cmd = Self::str_field(v, "command");
                let input_present = v.get("input").is_some();
                let mut input_s = match v.get("input") {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => cmd.clone().unwrap_or_default(),
                };
                // F2: `command` is argv-shaped — it is masked under `--redact argv`
                // (the default) **and** `argv+content`. `input` itself is content
                // (masked only under `argv+content`), but when it is absent the
                // input preview is the command verbatim — that case is a command
                // field, so it is masked under `argv` too.
                let input_bytes = input_s.len();
                if self.redact.redacts_argv() && !input_present && cmd.is_some() {
                    input_s = redact_text(&input_s);
                }
                let (p, n) = self.preview(&input_s, "input");
                if let Some(id) = Self::str_field(v, "id") {
                    self.call_tools.insert(id, tool.clone());
                }
                let bash_cmd = if tool == "Bash" {
                    cmd.map(|c| if self.redact.redacts_argv() { redact_text(&c) } else { c })
                } else {
                    None
                };
                Some((
                    Kind::AgentToolCall,
                    Payload::ToolCall {
                        tool: tool.clone(),
                        input_preview: p,
                        input_bytes,
                        via_mcp: tool.starts_with("mcp__"),
                        bash_cmd,
                    },
                    n,
                ))
            }
            "tool.result" => {
                let status = Self::str_field(v, "status").unwrap_or_else(|| "Unknown".into());
                let output = Self::str_field(v, "output").unwrap_or_default();
                let (p, n) = self.preview(&output, "output");
                let tool = Self::str_field(v, "id").and_then(|id| self.call_tools.get(&id).cloned());
                Some((
                    Kind::AgentToolResult,
                    Payload::ToolResult {
                        tool,
                        status,
                        result_preview: p,
                    },
                    n,
                ))
            }
            "model.request" => {
                let (p, n) = self.preview(&Self::str_field(v, "detail").unwrap_or_default(), "detail");
                Some((
                    Kind::AgentModelRequest,
                    Payload::ModelRequest {
                        model: Self::str_field(v, "model"),
                        input_tokens: v.get("input_tokens").and_then(|x| x.as_u64()),
                        detail_preview: if p.is_empty() { None } else { Some(p) },
                    },
                    n,
                ))
            }
            "model.text" => {
                let text = Self::str_field(v, "text").unwrap_or_default();
                let (p, n) = self.preview(&text, "text");
                Some((Kind::AgentModelText, Payload::ModelText { preview: p }, n))
            }
            "model.usage" => Some((
                Kind::AgentModelUsage,
                Payload::ModelUsage {
                    model: Self::str_field(v, "model"),
                    input_tokens: v.get("input_tokens").and_then(|x| x.as_u64()),
                    output_tokens: v.get("output_tokens").and_then(|x| x.as_u64()),
                    cache_read: v.get("cache_read").and_then(|x| x.as_u64()),
                    cost_usd: v.get("cost_usd").and_then(|x| x.as_f64()),
                },
                Vec::new(),
            )),
            "thinking" => {
                let text = Self::str_field(v, "text").unwrap_or_default();
                let (p, n) = self.preview(&text, "text");
                Some((
                    Kind::AgentModelThinking,
                    Payload::Thinking {
                        preview: p,
                        duration_ms: v.get("duration_ms").and_then(|x| x.as_u64()),
                    },
                    n,
                ))
            }
            other => {
                *self.unknown_type.entry(other.to_string()).or_insert(0) += 1;
                None
            }
        };
        if let Some((kind, payload, trunc)) = produced {
            self.emitted += 1;
            out.push(agent_event(
                wall_ns,
                kind,
                Layer::Agent,
                "jsonl",
                corr,
                payload,
                trunc,
                notes,
            ));
        }
    }

    fn emit_line(&mut self, line: &str, out: &mut Vec<Event>) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => self.emit(&v, out),
            Err(_) => self.bad_json += 1,
        }
    }
}

impl EventAdapter for JsonlAdapter {
    fn id(&self) -> &'static str {
        "jsonl"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            kinds: vec![
                Kind::AgentPrompt,
                Kind::AgentToolCall,
                Kind::AgentToolResult,
                Kind::AgentModelRequest,
                Kind::AgentModelText,
                Kind::AgentModelUsage,
                Kind::AgentModelThinking,
            ],
            live: true,
            needs_pid_binding: true,
        }
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, AdapterError> {
        if self.done {
            return Ok(PollOutcome::Eof);
        }
        if !self.follow {
            // Offline replay: drain everything, then done.
            let mut n = 0usize;
            loop {
                let (lines, _) = self.tail.poll().map_err(|e| AdapterError::Io(e.to_string()))?;
                if lines.is_empty() {
                    break;
                }
                for l in &lines {
                    let before = out.len();
                    self.emit_line(l, out);
                    n += out.len() - before;
                }
            }
            self.done = true;
            return Ok(if n > 0 { PollOutcome::Progress } else { PollOutcome::Eof });
        }
        let (lines, _gone) = self.tail.poll().map_err(|e| AdapterError::Io(e.to_string()))?;
        let mut n = 0usize;
        for l in &lines {
            let before = out.len();
            self.emit_line(l, out);
            n += out.len() - before;
        }
        // In follow mode a vanished file is not EOF — the emitter may recreate it.
        Ok(if n > 0 {
            PollOutcome::Progress
        } else {
            PollOutcome::Idle
        })
    }

    fn shutdown(&mut self) {}

    fn diagnostics(&self) -> Vec<String> {
        let mut d = vec![format!(
            "jsonl emitted={} bad_json={} bad_ts={} missing_ts={}",
            self.emitted, self.bad_json, self.bad_ts, self.missing_ts
        )];
        let mut types: Vec<(&String, &u64)> = self.unknown_type.iter().collect();
        types.sort();
        for (t, c) in types {
            d.push(format!("unknown type `{}` x{}", t, c));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_lines(path: &std::path::Path, lines: &[&str]) {
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn tool_call_result_correlate_by_id() {
        let dir = std::env::temp_dir().join("agtrace_jsonl_test1");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("ev.jsonl");
        write_lines(
            &p,
            &[
                r#"{"type":"tool.call","id":"call_1","tool":"Bash","command":"ls /tmp","ts":"2026-10-11T20:00:00.000Z"}"#,
                r#"{"type":"tool.result","id":"call_1","status":"success","output":"a\nb","ts":"2026-10-11T20:00:01.000Z"}"#,
            ],
        );
        let mut a = JsonlAdapter::new(p.to_str().unwrap(), 512, false, RedactMode::Argv).unwrap();
        let mut out = Vec::new();
        let r = a.poll(&mut out).unwrap();
        assert!(matches!(r, PollOutcome::Progress));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, Kind::AgentToolCall);
        assert_eq!(out[1].kind, Kind::AgentToolResult);
        // id correlates
        assert_eq!(out[0].corr.tool_use_id.as_deref(), Some("call_1"));
        assert_eq!(out[1].corr.tool_use_id.as_deref(), Some("call_1"));
        // result inherits the tool name from the call
        match &out[1].payload {
            Payload::ToolResult { tool, status, .. } => {
                assert_eq!(tool.as_deref(), Some("Bash"));
                assert_eq!(status, "success");
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        // Bash command extracted for argv binding
        match &out[0].payload {
            Payload::ToolCall { bash_cmd, .. } => {
                assert_eq!(bash_cmd.as_deref(), Some("ls /tmp"))
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        // timestamps honored
        assert!(out[1].ts_wall_ns > out[0].ts_wall_ns);
        // offline: second poll is EOF
        let mut out2 = Vec::new();
        assert!(matches!(a.poll(&mut out2).unwrap(), PollOutcome::Eof));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epoch_ts_and_missing_ts() {
        let dir = std::env::temp_dir().join("agtrace_jsonl_test2");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("ev.jsonl");
        write_lines(
            &p,
            &[
                r#"{"type":"prompt","text":"hi","ts":1791741729.5}"#,
                r#"{"type":"model.text","text":"hello"}"#,
                r#"{"type":"bogus","x":1}"#,
                r#"not json"#,
            ],
        );
        let mut a = JsonlAdapter::new(p.to_str().unwrap(), 512, false, RedactMode::Argv).unwrap();
        let mut out = Vec::new();
        a.poll(&mut out).unwrap();
        assert_eq!(out.len(), 2);
        // f64 epoch: sub-microsecond rounding is expected
        assert!((out[0].ts_wall_ns as i64 - 1_791_741_729_500_000_000i64).abs() < 1_000);
        assert!(out[1].ts_wall_ns > 0); // missing ts → wall now
        // prompt line has ts; model.text AND bogus lines do not
        assert_eq!(a.missing_ts, 2);
        assert_eq!(a.bad_json, 1);
        assert_eq!(a.unknown_type.get("bogus"), Some(&1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_offline_is_notfound() {
        let r = JsonlAdapter::new("/tmp/agtrace_jsonl_nope_12345.jsonl", 512, false, RedactMode::Argv);
        assert!(matches!(r, Err(AdapterError::NotFound(_))));
    }

    #[test]
    fn missing_file_follow_is_allowed() {
        let r = JsonlAdapter::new("/tmp/agtrace_jsonl_nope_12345.jsonl", 512, true, RedactMode::Argv);
        assert!(r.is_ok());
    }

    // ===========================================================
    // F2：`--redact` 曾被完全丢弃 —— 自定义 agent 路径上 `argv` 和
    // `argv+content` 都没有任何作用。
    // ===========================================================

    const SECRET: &str = "sk-secret-123456";

    fn run_line(mode: RedactMode, line: &str) -> Vec<Event> {
        // Rust runs tests in parallel threads of one process: the temp dir must be
        // unique per call, not merely per process, or two tests clobber each other.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let uniq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "agtrace_jsonl_redact_{}_{}_{}",
            std::process::id(),
            uniq,
            mode.as_str()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("ev.jsonl");
        std::fs::write(&p, format!("{}\n", line)).unwrap();
        let mut a = JsonlAdapter::new(p.to_str().unwrap(), 512, false, mode).unwrap();
        let mut out = Vec::new();
        a.poll(&mut out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
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

    /// F2（HIGH）：`tool.call.command` 在 `argv` **和** `argv+content` 下都必须
    /// 打码；`input` 缺省时 input preview 直接由 command 兜底，同样要打码。
    #[test]
    fn tool_call_command_is_redacted_under_argv_and_content() {
        let line = format!(
            r#"{{"type":"tool.call","id":"c1","tool":"Bash","command":"curl -H 'Authorization: Bearer {}' https://x","ts":"2026-10-11T20:00:00.000Z"}}"#,
            SECRET
        );
        for mode in [RedactMode::Argv, RedactMode::ArgvContent] {
            let evs = run_line(mode, &line);
            match tool_call(&evs) {
                Payload::ToolCall {
                    bash_cmd,
                    input_preview,
                    ..
                } => {
                    let cmd = bash_cmd.as_deref().expect("bash_cmd");
                    assert!(!cmd.contains(SECRET), "[{:?}] command 未打码: {}", mode, cmd);
                    assert!(cmd.contains("***"), "[{:?}] 打码必须留痕: {}", mode, cmd);
                    assert!(
                        !input_preview.contains(SECRET),
                        "[{:?}] command 兜底的 input preview 未打码: {}",
                        mode,
                        input_preview
                    );
                }
                other => panic!("[{:?}] unexpected payload: {:?}", mode, other),
            }
        }
        // `off` → verbatim（用户显式关掉时不自作主张）
        let evs = run_line(RedactMode::Off, &line);
        match tool_call(&evs) {
            Payload::ToolCall { bash_cmd, .. } => {
                assert!(bash_cmd.as_deref().unwrap().contains(SECRET))
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    /// F2：`input`/`output`/`text` 是 content —— 只有 `argv+content` 打码。
    #[test]
    fn content_fields_only_redacted_under_argv_content() {
        let prompt = format!(
            r#"{{"type":"prompt","text":"run: curl -H 'Authorization: Bearer {}' https://x","ts":"2026-10-11T20:00:00.000Z"}}"#,
            SECRET
        );
        let evs = run_line(RedactMode::Argv, &prompt);
        assert!(prompt_text(&evs).contains(SECRET), "argv 模式不得打码 prompt");
        let evs = run_line(RedactMode::ArgvContent, &prompt);
        assert!(
            !prompt_text(&evs).contains(SECRET),
            "argv+content 必须打码 prompt: {}",
            prompt_text(&evs)
        );

        let result = format!(
            r#"{{"type":"tool.result","id":"c1","status":"success","output":"token={}","ts":"2026-10-11T20:00:00.000Z"}}"#,
            SECRET
        );
        let evs = run_line(RedactMode::Argv, &result);
        assert!(
            result_preview(&evs).contains(SECRET),
            "argv 模式不得打码 tool.result output"
        );
        let evs = run_line(RedactMode::ArgvContent, &result);
        assert!(
            !result_preview(&evs).contains(SECRET),
            "argv+content 必须打码 tool.result output"
        );
    }

    /// F2 scope：显式给出的 `input` 对象是 content（只在 `argv+content` 下打码）；
    /// 独立 `command` 字段是 argv 形态（两种模式都打码）。
    #[test]
    fn provided_input_is_content_while_command_is_argv() {
        let line = format!(
            r#"{{"type":"tool.call","id":"c1","tool":"Bash","command":"curl -H 'Authorization: Bearer {}' https://x","input":{{"command":"postgres://user:pw@localhost/db"}},"ts":"2026-10-11T20:00:00.000Z"}}"#,
            SECRET
        );
        let evs = run_line(RedactMode::Argv, &line);
        match tool_call(&evs) {
            Payload::ToolCall {
                bash_cmd,
                input_preview,
                ..
            } => {
                assert!(
                    !bash_cmd.as_deref().unwrap().contains(SECRET),
                    "command 必须在 argv 模式下打码"
                );
                assert!(
                    input_preview.contains("pw@localhost"),
                    "input 是 content，argv 模式下不该被打码: {}",
                    input_preview
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        let evs = run_line(RedactMode::ArgvContent, &line);
        match tool_call(&evs) {
            Payload::ToolCall {
                bash_cmd,
                input_preview,
                ..
            } => {
                assert!(!bash_cmd.as_deref().unwrap().contains(SECRET));
                assert!(
                    !input_preview.contains("pw@localhost"),
                    "argv+content 下 input 必须打码: {}",
                    input_preview
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }
}
