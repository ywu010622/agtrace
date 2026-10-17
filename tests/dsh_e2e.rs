//! End-to-end tests for the DeepSeek Harness adapter (`--adapter dsh`).
//!
//! These run the real binary against a synthetic DSH session log — the same
//! physical container DSH writes (concatenated checksummed Zstandard frames,
//! one frame per append batch), so the frame scanner / tailer / mapping are
//! exercised through the CLI exactly as a user would run them.
//!
//! The fixtures are generated here (not committed): DSH session logs contain
//! private conversation text, and a repository should not carry a copy of one.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agtrace")
}

fn frame(plain: &str) -> Vec<u8> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), 0).expect("zstd encoder");
    enc.include_checksum(true).expect("checksum");
    enc.write_all(plain.as_bytes()).expect("write");
    enc.finish().expect("finish")
}

fn header_line() -> &'static str {
    r#"{"type":"session","version":4,"id":"session-e2e-test","createdAt":1792267905617,"cwd":"C:\\Users\\e2e\\projects","isSeeded":false,"delegationDepth":0,"agentPreset":"standard"}"#
}

/// 写一个最小但真实的 DSH 会话：header 帧 + 一条 append 批帧。
/// 返回日志路径；`torn_tail` 为真时在末尾追加半个帧（模拟写入中/崩溃残留）。
fn make_session(dir: &Path, torn_tail: bool) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir");
    let path = dir.join("session.v4.jsonl.zstd");
    let user = r#"{"type":"user/message","seq":0,"time":1792268094774,"data":{"content":[{"type":"text","text":"run the tests"}],"source":{"kind":"user","rpcId":"r1"},"role":"user","id":"m1"}}"#;
    let assistant = r#"{"type":"assistant/message","seq":1,"time":1792268095000,"data":{"turn":1,"step":1,"message":{"role":"assistant","content":[{"type":"reasoning","text":"I should run the suite."},{"type":"text","text":"running tests"},{"type":"tool-call","id":"call_1","name":"pwsh","arguments":"{\"command\":\"pytest -q\"}"}],"source":{"kind":"model","provider":"deepseek-account","model":"deepseek-flash"}}}}"#;
    let call = r#"{"type":"tool/call","seq":2,"time":1792268095100,"data":{"turn":1,"step":1,"callId":"call_1","name":"pwsh","arguments":"{\"command\":\"pytest -q\",\"description\":\"run tests\"}"}}"#;
    // 失败命令：isError=false，退出码只在 job/settled.detail 里（真实语料形状）。
    let settled = r#"{"type":"job/settled","seq":3,"time":1792268096000,"data":{"jobId":"j1","status":"completed","cause":"producer","detail":"exit code: 2","toolCall":{"callId":"call_1","rootCallId":"call_1"}}}"#;
    let result = r#"{"type":"tool/result","seq":4,"time":1792268096001,"data":{"turn":1,"step":1,"message":{"role":"tool","source":{"kind":"tool","callId":"call_1"},"toolCallId":"call_1","content":[{"type":"text","text":"1 failed\n[exit code: 2]"}],"isError":false,"id":"r1"},"meta":{"cwd":"C:\\Users\\e2e\\projects"}}}"#;
    let mut bytes = frame(&format!("{}\n", header_line()));
    let batch: String = [user, assistant, call, settled, result]
        .iter()
        .map(|l| format!("{}\n", l))
        .collect();
    let last = frame(&batch);
    if torn_tail {
        let cut = last.len() / 2;
        bytes.extend(&last[..cut]);
    } else {
        bytes.extend(&last);
    }
    std::fs::write(&path, bytes).expect("write log");
    path
}

fn run(args: &[&str], env: &[(&str, &str)], cwd: Option<&Path>) -> (bool, String, String) {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let out = cmd.output().expect("spawn agtrace");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn dsh_session_renders_agent_timeline() {
    let dir = std::env::temp_dir().join("agtrace_dsh_e2e_render");
    let _ = std::fs::remove_dir_all(&dir);
    let path = make_session(&dir, false);
    let (ok, stdout, stderr) = run(
        &[
            "--adapter",
            "dsh",
            "-S",
            path.to_str().unwrap(),
            "--no-color",
        ],
        &[],
        None,
    );
    assert!(ok, "stdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(stdout.contains("session=e2e"), "session id must be shown: {}", stdout);
    assert!(stdout.contains("agent"), "{}", stdout);
    // prompt / thinking / request / call / result 都在同一条时间线上。
    for needle in [
        "prompt",
        "model.request",
        "model.thinking",
        "tool.call",
        "tool.result",
        "pwsh",
        "pytest -q",
    ] {
        assert!(stdout.contains(needle), "missing `{}` in:\n{}", needle, stdout);
    }
    // job/settled 的退出码必须被采信：isError=false 也不能算成功。
    assert!(
        stdout.contains("Failure"),
        "non-zero job exit must be reported as Failure:\n{}",
        stdout
    );
    assert!(
        stdout.contains("--- failures (1)"),
        "a failed tool call must produce the failure footer:\n{}",
        stdout
    );
}

#[test]
fn dsh_json_output_is_structured_and_lossless() {
    let dir = std::env::temp_dir().join("agtrace_dsh_e2e_json");
    let _ = std::fs::remove_dir_all(&dir);
    let path = make_session(&dir, false);
    let (ok, stdout, stderr) = run(
        &[
            "--adapter",
            "dsh",
            "-S",
            path.to_str().unwrap(),
            "--output",
            "json",
        ],
        &[],
        None,
    );
    assert!(ok, "stderr:\n{}", stderr);
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("every stdout line must be valid JSON"))
        .collect();
    assert!(lines.len() >= 3, "header + events + summary: {}", stdout);
    let header = &lines[0];
    assert_eq!(header["agtrace"], "header");
    assert_eq!(header["session"], "e2e-test");
    assert_eq!(header["sources"], serde_json::json!(["agent"]));
    assert!(
        header["notes"]
            .as_array()
            .is_some_and(|n| !n.is_empty() && n.iter().any(|x| x.as_str().is_some_and(|s| s.contains("dsh")))),
        "header notes must carry the dsh transcript path: {}",
        stdout
    );
    let summary = lines.last().unwrap();
    assert_eq!(summary["agtrace"], "summary");
    // 失败归因在 json 里也必须是可数的字段，而不是只印在文本 footer 上。
    assert_eq!(summary["extra"]["failures"]["count"], 1);
    assert!(lines.iter().any(|l| l["kind"] == "derived.fail"));
}

#[test]
fn dsh_max_events_caps_offline_output() {
    let dir = std::env::temp_dir().join("agtrace_dsh_e2e_max");
    let _ = std::fs::remove_dir_all(&dir);
    let path = make_session(&dir, false);
    let (ok, stdout, stderr) = run(
        &[
            "--adapter",
            "dsh",
            "-S",
            path.to_str().unwrap(),
            "--output",
            "json",
            "--max-events",
            "2",
        ],
        &[],
        None,
    );
    assert!(ok, "stderr:\n{}", stderr);
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let events = lines
        .iter()
        .filter(|l| l.get("agtrace").is_none())
        .count();
    assert!(
        events <= 2,
        "--max-events must cap the emitted stream in offline/replay batches too, got {} events:\n{}",
        events,
        stdout
    );
    assert!(
        stderr.contains("reached --max-events 2"),
        "the run must say it stopped on purpose:\n{}",
        stderr
    );
}

#[test]
fn dsh_auto_discovers_own_session_from_env() {
    let root = std::env::temp_dir().join("agtrace_dsh_e2e_auto");
    let _ = std::fs::remove_dir_all(&root);
    let session_dir = root.join("--some-workspace--").join("session-e2e-test");
    make_session(&session_dir, false);
    // DSH 在工具 shell 里导出这两个变量；auto 必须优先使用 DSH_SESSION_ID。
    let (ok, stdout, stderr) = run(
        &["--adapter", "dsh", "-S", "auto", "--no-color", "--max-events", "2"],
        &[
            ("DSH_SESSIONS_ROOT", root.to_str().unwrap()),
            ("DSH_SESSION_ID", "session-e2e-test"),
        ],
        None,
    );
    assert!(ok, "stdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("session=e2e-test"),
        "auto must find the session named by DSH_SESSION_ID:\n{}",
        stdout
    );
}

/// header 帧 + 一个**完整**批帧 + 半个尾帧：完整帧必须解出来，尾帧安静等待。
fn make_session_with_torn_tail(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir");
    let path = dir.join("session.v4.jsonl.zstd");
    let user = r#"{"type":"user/message","seq":0,"time":1792268094774,"data":{"content":[{"type":"text","text":"run the tests"}],"source":{"kind":"user","rpcId":"r1"},"role":"user","id":"m1"}}"#;
    let assistant = r#"{"type":"assistant/message","seq":1,"time":1792268095000,"data":{"turn":1,"step":1,"message":{"role":"assistant","content":[{"type":"reasoning","text":"I should run the suite."}],"source":{"kind":"model","provider":"deepseek-account","model":"deepseek-flash"}}}}"#;
    let mut bytes = frame(&format!("{}\n", header_line()));
    // 完整批帧
    bytes.extend(frame(&format!("{}\n{}\n", user, assistant)));
    // 写到一半的批帧（模拟 append 进行中）
    let torn_batch = format!(
        "{}\n{}\n",
        r#"{"type":"tool/call","seq":2,"time":1792268095100,"data":{"turn":1,"step":1,"callId":"call_1","name":"pwsh","arguments":"{\"command\":\"pytest -q\"}"}}"#,
        r#"{"type":"tool/result","seq":3,"time":1792268096001,"data":{"turn":1,"step":1,"message":{"role":"tool","toolCallId":"call_1","content":[{"type":"text","text":"ok"}],"isError":false}}}"#
    );
    let last = frame(&torn_batch);
    bytes.extend(&last[..last.len() / 2]);
    std::fs::write(&path, bytes).expect("write log");
    path
}

#[test]
fn dsh_torn_tail_is_waited_for_not_fatal() {
    let dir = std::env::temp_dir().join("agtrace_dsh_e2e_torn");
    let _ = std::fs::remove_dir_all(&dir);
    let path = make_session_with_torn_tail(&dir);
    let (ok, stdout, stderr) = run(
        &["--adapter", "dsh", "-S", path.to_str().unwrap(), "--no-color"],
        &[],
        None,
    );
    // 完整帧已经提交：它们必须被解出来；半个尾帧安静等待，不是错误。
    assert!(ok, "stdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("prompt"),
        "events from the complete frame must be decoded:\n{}",
        stdout
    );
    assert!(
        !stderr.contains("corrupt"),
        "a torn (incomplete) final frame is not corruption: {}",
        stderr
    );
}

#[test]
fn dsh_corrupt_frame_is_reported_not_silently_empty() {
    let dir = std::env::temp_dir().join("agtrace_dsh_e2e_corrupt");
    let _ = std::fs::remove_dir_all(&dir);
    let path = make_session(&dir, false);
    let mut bytes = std::fs::read(&path).unwrap();
    // 第二个帧的魔数写坏：这是"完整结构非法"，DSH 自己也把它当 corruption。
    let first_frame_len = {
        // 用与适配器相同的结构扫描逻辑（这里只需找到第二个魔数）。
        let magic = [0x28u8, 0xB5, 0x2F, 0xFD];
        bytes
            .windows(4)
            .enumerate()
            .filter(|(_, w)| *w == magic)
            .nth(1)
            .map(|(i, _)| i)
            .expect("second frame magic")
    };
    bytes[first_frame_len] = 0;
    std::fs::write(&path, bytes).unwrap();
    let (ok, _stdout, stderr) = run(
        &["--adapter", "dsh", "-S", path.to_str().unwrap(), "--no-color"],
        &[],
        None,
    );
    assert!(!ok, "corruption must fail the run, not print an empty timeline");
    assert!(
        stderr.contains("corrupt Zstandard session log"),
        "the error must name the problem:\n{}",
        stderr
    );
}
