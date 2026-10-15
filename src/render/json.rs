//! JSON 输出：一行一个事件（JSONL），可直接 `| jq`。
//!
//! **关于 `--full` 的诚实说明**：`--full` 无法"还原"被截断的内容 ——
//! 数据在采集端就已经丢了（内核侧 64 字节硬上限、tool_arg_max 等）。
//! 所以 `--full` 在 json 模式下的唯一作用是**不额外压缩**，并且保证 `trunc`
//! 字段始终随行输出，让下游能判断"这条事件的哪个字段是不完整的"。

use crate::event::Event;
use std::io::Write;

/// 序列化一个事件为单行 JSON（不含换行）。
///
/// 序列化失败**不允许**导致整个进程退出：退化成一条带错误说明的记录，
/// 保证"丢了什么"这件事本身是可见的（§4.3）。
pub fn line(ev: &Event) -> String {
    match serde_json::to_string(ev) {
        Ok(s) => s,
        Err(e) => {
            let fallback = serde_json::json!({
                "seq": ev.seq,
                "ts_ns": ev.ts_ns,
                "ts_wall_ns": ev.ts_wall_ns,
                "layer": ev.layer.as_str(),
                "kind": ev.kind.as_str(),
                "source": ev.source,
                "serialize_error": e.to_string(),
                "note": "this event could not be serialized; fields may be incomplete — that itself is a fidelity warning",
            });
            fallback.to_string()
        }
    }
}

pub fn write_batch<W: Write>(w: &mut W, events: &[Event]) -> std::io::Result<()> {
    let mut buf = String::new();
    for ev in events {
        buf.push_str(&line(ev));
        buf.push('\n');
    }
    w.write_all(buf.as_bytes())
}

/// JSON 模式下的启动横幅（同样是一行 JSON，便于下游统一解析）。
pub fn header(
    target: &str,
    session: Option<&str>,
    binding: Option<&str>,
    sources: &[String],
    following: bool,
    notes: &[String],
) -> String {
    serde_json::json!({
        "agtrace": "header",
        "target": target,
        "session": session,
        "pid_binding": binding,
        "sources": sources,
        "following": following,
        "notes": notes,
        "schema_version": 0,
    })
    .to_string()
}

/// 收尾统计（一行 JSON）。
pub fn summary(s: &crate::render::text::Summary, extra: &serde_json::Value) -> String {
    serde_json::json!({
        "agtrace": "summary",
        "total": s.total,
        "by_layer": {
            "agent": s.agent,
            "runtime": s.runtime,
            "infra": s.infra,
            "policy": s.policy,
            "derived": s.derived,
        },
        "late": s.late,
        "truncated": s.truncated,
        "lost_events_reports": s.lost,
        "pid_binding": s.binding.map(|b| b.as_str()),
        "extra": extra,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Binding, Corr, Kind, Layer, Payload, TsSource};

    fn e() -> Event {
        Event {
            seq: 7,
            ts_ns: 123,
            ts_wall_ns: 456,
            ts_src: TsSource::Converted,
            layer: Layer::Agent,
            kind: Kind::AgentToolCall,
            source: "claude-code".into(),
            pid: None,
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr {
                tool_use_id: Some("toolu_1".into()),
                ..Default::default()
            },
            payload: Payload::ToolCall {
                tool: "Bash".into(),
                input_preview: "ls".into(),
                input_bytes: 2,
                via_mcp: false,
                bash_cmd: Some("ls".into()),
            },
            trunc: vec![],
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        }
    }

    #[test]
    fn json_is_single_line_and_typed() {
        let s = line(&e());
        assert!(!s.contains('\n'), "JSONL 必须是一行");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["kind"], "agent.tool.call");
        assert_eq!(v["layer"], "agent");
        assert_eq!(v["corr"]["tool_use_id"], "toolu_1");
        assert_eq!(v["payload"]["type"], "tool_call");
        assert_eq!(v["payload"]["bash_cmd"], "ls");
    }

    /// 楔形在线上必须是**自己的** kind：`--output json` 的消费者按 `kind`
    /// 过滤时得分得开"这条慢"（gap）和"这条对不上账"（wedge）。
    #[test]
    fn wedge_is_its_own_kind_on_the_wire() {
        let mut ev = e();
        ev.kind = Kind::DerivedToolWedge;
        let v: serde_json::Value = serde_json::from_str(&line(&ev)).unwrap();
        assert_eq!(v["kind"], "derived.tool.wedge");
        assert_eq!(Kind::DerivedToolWedge.as_str(), "derived.tool.wedge");
        assert_eq!(Kind::DerivedToolWedge.short(), "wedge");
        assert_ne!(Kind::DerivedToolGap.as_str(), Kind::DerivedToolWedge.as_str());
    }

    #[test]
    fn payload_type_tag_matches_serde_tag() {
        let v: serde_json::Value = serde_json::from_str(&line(&e())).unwrap();
        assert_eq!(v["payload"]["type"], "tool_call");
    }

    #[test]
    fn header_is_valid_json() {
        let h = header("pid 1 (tree)", Some("abc"), Some("exact"), &["exec".into()], true, &[]);
        let v: serde_json::Value = serde_json::from_str(&h).unwrap();
        assert_eq!(v["agtrace"], "header");
        assert_eq!(v["pid_binding"], "exact");
    }
}
