//! OpenShell adapter（stub，DESIGN.md §3.4）。
//!
//! 输入是 `~/jx/fixtures/openshell_*.jsonl`（离线，`live: false`）。
//! 实测字段：`time`(float 秒，**相对时间**)、`agent_id`、`run_id`、`activity`、
//! `tool`、`status`、`status_detail`、`tokens`。
//!
//! **最关键的一点**（§3.4）：fixture 的 `time` 是**相对秒**（如 `4003.0`、`8004.0`），
//! **不是跨 fixture 可比的绝对时间** —— 不同 fixture 的 time 起点不同。
//! **绝不能把 fixture 的时间当真实墙钟**，否则与内核事件的时间线会荒谬地错位。
//! 这是离线验证时最容易犯的错，所以 `--time-base` 是显式参数而不是隐含行为。

use super::{AdapterError, Capabilities, EventAdapter, FileTail, agent_event};
use crate::event::{Corr, Event, Kind, Layer, Payload, TruncNote, one_line, truncate_chars};
use crate::poll::PollOutcome;
use serde_json::Value;
use std::path::Path;

/// `--time-base` 的三种锚定方式（§4.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeBase {
    /// 默认：把 fixture 里最小的 `time` 锚定到**进程启动时的墙钟**。
    /// 适合"就地看一眼这个 fixture 里发生了什么"。
    Now,
    /// 把最小 `time` 锚定到 **fixture 文件的 mtime**（墙钟）。
    /// 适合"这份 fixture 是那一刻落盘的，就按那一刻对齐"。
    Wall,
    /// `time` 本身就是绝对的 Unix epoch 秒，不做任何锚定。
    Epoch,
}

impl TimeBase {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "now" => Ok(TimeBase::Now),
            "wall" => Ok(TimeBase::Wall),
            "epoch" => Ok(TimeBase::Epoch),
            other => Err(format!(
                "unknown --time-base value `{}` (available: now | wall | epoch)",
                other
            )),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            TimeBase::Now => "now",
            TimeBase::Wall => "wall",
            TimeBase::Epoch => "epoch",
        }
    }
}

pub struct OpenShellAdapter {
    tail: FileTail,
    base: TimeBase,
    origin_ns: u64,
    /// fixture 里见过的最小 `time`（第一遍扫描确定，用于 now/wall 锚定）。
    min_time: Option<f64>,
    /// 第一遍读取时把原始行走廊缓存下来，锚点确定后再统一换算 —— 避免
    /// "第一条事件决定了锚点，后面的行用错的锚点"这种错位。
    raw: Vec<(f64, Value)>,
    parsed: bool,
    done: bool,
    pub tool_preview_max: usize,
    pub run_id: Option<String>,
    pub agent_id: Option<String>,
    pub bad_json: u64,
    pub unknown_activity: std::collections::BTreeMap<String, u64>,
    pub emitted: u64,
}

impl OpenShellAdapter {
    pub fn new(path: &str, base: TimeBase, tool_preview_max: usize) -> Result<Self, AdapterError> {
        let p = Path::new(path);
        if !p.is_file() {
            return Err(AdapterError::NotFound(format!(
                "openshell fixture does not exist: {}",
                p.display()
            )));
        }
        Ok(OpenShellAdapter {
            tail: FileTail::new(p),
            base,
            origin_ns: 0,
            min_time: None,
            raw: Vec::new(),
            parsed: false,
            done: false,
            tool_preview_max,
            run_id: None,
            agent_id: None,
            bad_json: 0,
            unknown_activity: std::collections::BTreeMap::new(),
            emitted: 0,
        })
    }

    /// 读完全部 fixture：先确定时间锚点，再统一换算，最后一次性产出事件。
    ///
    /// 离线 fixture 不需要"实时感"，一次性读完比逐行流式更不容易错 ——
    /// 尤其是锚点必须在看到**所有**行的最小值之后才能定。
    fn parse_all(&mut self) -> Result<(), AdapterError> {
        loop {
            let (lines, gone) = self.tail.poll().map_err(|e| AdapterError::Io(e.to_string()))?;
            for l in &lines {
                let l = l.trim();
                if l.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(l) {
                    Ok(v) => {
                        let t = v.get("time").and_then(|t| t.as_f64()).unwrap_or(0.0);
                        self.min_time = Some(match self.min_time {
                            Some(m) => m.min(t),
                            None => t,
                        });
                        self.raw.push((t, v));
                    }
                    Err(_) => self.bad_json += 1,
                }
            }
            if gone || lines.is_empty() {
                break;
            }
        }

        // --- 锚点 ---
        let min_t = self.min_time.unwrap_or(0.0);
        self.origin_ns = match self.base {
            TimeBase::Epoch => 0,
            TimeBase::Now => now_wall_ns().saturating_sub((min_t * 1e9) as u64),
            TimeBase::Wall => file_mtime_ns(&self.tail.path)
                .unwrap_or_else(now_wall_ns)
                .saturating_sub((min_t * 1e9) as u64),
        };
        self.parsed = true;
        Ok(())
    }

    fn to_events(&mut self, out: &mut Vec<Event>) {
        let raw = std::mem::take(&mut self.raw);
        for (t, v) in raw {
            let wall_ns = self.origin_ns + (t.max(0.0) * 1e9) as u64;
            let activity = v.get("activity").and_then(|a| a.as_str()).unwrap_or("").to_string();
            let run_id = v.get("run_id").and_then(|x| x.as_str()).map(String::from);
            let agent_id = v.get("agent_id").and_then(|x| x.as_str()).map(String::from);
            if self.run_id.is_none() {
                self.run_id = run_id.clone();
            }
            if self.agent_id.is_none() {
                self.agent_id = agent_id.clone();
            }
            let detail = v.get("status_detail").and_then(|x| x.as_str()).unwrap_or("");
            let tool = v.get("tool").and_then(|x| x.as_str()).map(String::from);

            let corr = Corr {
                session_id: None,
                run_id: run_id.clone(),
                agent_id: agent_id.clone(),
                turn_id: None,
                tool_use_id: None,
                uuid: None,
                parent_uuid: None,
                pid_root: None,
                // fixture 的 agent 与 OS 进程树**毫无关系** —— 如实标 None（§3.5）。
                pid_binding: None,
                sidechain: false,
            };

            let (kind, payload, trunc): (Kind, Payload, Vec<TruncNote>) = match activity.as_str() {
                "llm.call" => {
                    let (p, n) = self.preview(detail, "status_detail");
                    (
                        Kind::AgentModelRequest,
                        // fixture 没有 model 名和 input token 数 —— 保持 None，不编造。
                        Payload::ModelRequest {
                            model: None,
                            input_tokens: None,
                            detail_preview: Some(p),
                        },
                        n,
                    )
                }
                "tool.invoke" => {
                    let (p, n) = self.preview(detail, "status_detail");
                    (
                        Kind::AgentToolCall,
                        Payload::ToolCall {
                            tool: tool.clone().unwrap_or_else(|| "<unknown>".into()),
                            input_preview: p,
                            input_bytes: detail.len(),
                            via_mcp: tool.as_deref().map(|t| t.starts_with("mcp__")).unwrap_or(false),
                            bash_cmd: None,
                        },
                        n,
                    )
                }
                "tool.result" => {
                    let status = v
                        .get("status")
                        .and_then(|x| x.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    let (p, n) = self.preview(detail, "status_detail");
                    (
                        Kind::AgentToolResult,
                        Payload::ToolResult {
                            tool: tool.clone(),
                            status,
                            result_preview: p,
                        },
                        n,
                    )
                }
                "token.usage" => {
                    let tokens = v.get("tokens").and_then(|x| x.as_u64());
                    (
                        Kind::AgentModelUsage,
                        Payload::ModelUsage {
                            model: None,
                            // fixture 只给一个总 token 数，没有 input/output 拆分 ——
                            // **不编造**，只填 output_tokens 并在 payload 里保持其余为 None。
                            input_tokens: None,
                            output_tokens: tokens,
                            cache_read: None,
                            cost_usd: None,
                        },
                        vec![
                            TruncNote::new("tokens", None, 0)
                                .with_note("fixture only has totals, no input/output split"),
                        ],
                    )
                }
                other => {
                    *self.unknown_activity.entry(other.to_string()).or_insert(0) += 1;
                    continue;
                }
            };

            out.push(agent_event(
                wall_ns,
                kind,
                Layer::Agent,
                "openshell",
                corr,
                payload,
                trunc,
                Vec::new(),
            ));
            self.emitted += 1;
        }
    }

    fn preview(&self, s: &str, field: &str) -> (String, Vec<TruncNote>) {
        let (cut, truncated, orig) = truncate_chars(s, self.tool_preview_max, self.tool_preview_max);
        let mut n = Vec::new();
        if truncated {
            n.push(TruncNote::new(field, Some(orig), cut.len()));
        }
        (one_line(&cut), n)
    }
}

impl EventAdapter for OpenShellAdapter {
    fn id(&self) -> &'static str {
        "openshell"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            kinds: vec![
                Kind::AgentModelRequest,
                Kind::AgentToolCall,
                Kind::AgentToolResult,
                Kind::AgentModelUsage,
            ],
            // 只读 fixture，不 tail（§3.4）。
            live: false,
            // fixture 里没有 pid 字段，也不需要绑定。
            needs_pid_binding: false,
        }
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, AdapterError> {
        if !self.parsed {
            self.parse_all()?;
            self.to_events(out);
            return Ok(PollOutcome::Progress);
        }
        if !self.done {
            self.done = true;
            return Ok(PollOutcome::Eof);
        }
        Ok(PollOutcome::Eof)
    }

    fn shutdown(&mut self) {}

    fn diagnostics(&self) -> Vec<String> {
        let mut d = vec![format!(
            "openshell fixture: produced {} event(s); bad JSON lines {}; time-base={}",
            self.emitted,
            self.bad_json,
            self.base.as_str()
        )];
        if !self.unknown_activity.is_empty() {
            let s: Vec<String> = self
                .unknown_activity
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            d.push(format!("unknown activity (skipped): {}", s.join(" ")));
        }
        d
    }
}

fn now_wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn file_mtime_ns(p: &Path) -> Option<u64> {
    let md = std::fs::metadata(p).ok()?;
    let m = md.modified().ok()?;
    m.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as u64)
}
