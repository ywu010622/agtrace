//! 内核行离线回放（v0.6 `--kernel-lines <PATH>`）。
//!
//! 输入：一份**已经采到的**内核行协议文本 —— aya/bpftrace 采集器的 stdout 逐字
//! 存盘即可，格式就是 [`KernelLineParser`] 认的那几种 `TAG|…` 行。
//! 输出：与实时采集**逐字节相同**的事件流，因为解析器是同一个 `KernelLineParser`，
//! 这里没有第二条解析路径（协议一行也没改）。
//!
//! 为什么需要它：内核采集要 root，CI 和大多数开发机上跑不动。把一份真实采集的文本
//! 存下来，"transcript + 内核行"就能在没有权限的机器上完整重放一遍 ——
//! `tests/inject.rs` 的故障注入正是靠这条路径把**真实二进制**跑起来的，
//! 而不是在测试里另写一个假的归因器。
//!
//! ## 诚实边界（帮助文本与 `-v` 里必须说清）
//!
//! 1. 回放**不产生**任何新证据。文件里没有那一行，就没有那次 `openat` ——
//!    这正是故障注入想要的东西（"内核里没有这条写"必须是可控的），但**不是**
//!    内核当时真的没写。
//! 2. 文件里的 `nsecs` 是**采集时那台机器**的 CLOCK_MONOTONIC。同机同一次启动
//!    的回放当然对得上；跨启动/跨机器回放时它不是本机的钟，跨层排序因此不可信 ——
//!    合并器会照常给出它的 `check_mono` 警告，我们**不**去把它静音。
//! 3. 所以它与 `-f` 互斥：回放是一个离线动作（`main.rs` 在解析 CLI 时就拒绝组合），
//!    不会被当成"实时采集"。

use super::bpftrace::MAX_STRLEN;
use super::{Collector, CollectorError, KernelLineParser, ParseStats};
use crate::event::Event;
use crate::poll::PollOutcome;
use crate::redact::RedactMode;

pub struct KernelReplay {
    /// 已经切好的行（非空行）。整份文件一次读完 —— 它是回放，不是 tail。
    lines: Vec<String>,
    pos: usize,
    parser: KernelLineParser,
    /// `-v` 里的指纹：回放的是哪份文件、多少行。
    pub rendered_script: String,
    done: bool,
}

impl KernelReplay {
    pub fn open(path: &str, file_all: bool, redact: RedactMode) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("--kernel-lines {}: {}", path, e))?;
        let lines: Vec<String> = text
            .lines()
            .map(|l| l.trim_end_matches('\r').to_string())
            .filter(|l| !l.trim().is_empty())
            .collect();
        if lines.is_empty() {
            // 空文件必须当场报错：一条内核行都没有的回放，和"目标什么都没干"
            // 在输出上**长得一模一样**（§4.3 的不静默原则）。
            return Err(format!(
                "--kernel-lines {}: the file has no non-empty lines. A replay of an empty capture \
                 is indistinguishable from a run where the target did nothing, so it is refused \
                 rather than rendered as an empty timeline",
                path
            ));
        }
        let n = lines.len();
        let mut parser = KernelLineParser::with_redact(MAX_STRLEN, redact);
        parser.set_file_all(file_all);
        // 这批行的来源是**那份文件**，不是本机的内核。标成 `replay` 之后，
        // `-v` 与 `--output json` 里的 `source` 就不会谎称我们 attach 过。
        // (The label is a &'static str in the parser; "replay" is one of the
        // closed set of labels the renderer knows.)
        parser.set_source_label("replay");
        Ok(KernelReplay {
            lines,
            pos: 0,
            parser,
            rendered_script: format!("replay {} ({} lines)", path, n),
            done: false,
        })
    }

    pub fn exited(&self) -> bool {
        self.done
    }

    /// 回放没有退出状态可言 —— 它不是进程。`None` 而不是 `Some(0)`：
    /// 一条"退出码 0"会被读成"采集器正常结束"，那是我们没资格说的话。
    pub fn exit_code(&self) -> Option<i32> {
        None
    }

    pub fn redacted_events(&self) -> u64 {
        self.parser.redacted_events
    }

    pub fn parse_stats(&self) -> &ParseStats {
        &self.parser.stats
    }

    /// 回放没有子进程，因此没有 stderr 尾巴。空切片而不是 `None`：
    /// 调用点只关心"有没有话要说"。
    pub fn stderr_tail(&self) -> &[String] {
        &[]
    }

    pub fn unfinished_line_bytes(&self) -> usize {
        0
    }
}

impl Collector for KernelReplay {
    fn id(&self) -> &'static str {
        "replay"
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, CollectorError> {
        if self.done {
            return Ok(PollOutcome::Eof);
        }
        // 一次喂完：整份文件都已经在内存里，分片喂只会在批次之间制造
        // "看起来像实时"的假象（而且会让内核行插到 agent 行前面，见 main.rs 里
        // 回放分支的注释）。
        let start = out.len();
        while self.pos < self.lines.len() {
            let line = self.lines[self.pos].clone();
            self.pos += 1;
            self.parser.feed_line(&line, out);
        }
        // 收尾：最后一条 EXEC/FAIL 的 ARGV 行可能正好在文件末尾。
        self.parser.finish(out);
        self.done = true;
        Ok(if out.len() > start {
            PollOutcome::Progress
        } else {
            PollOutcome::Eof
        })
    }

    fn shutdown(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Kind, Payload};

    fn write(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("agtrace_replay_{}", name));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("kernel.txt");
        std::fs::write(&p, body).unwrap();
        p
    }

    /// 回放走的是同一个解析器：`EXEC|` + `ARGV|` 必须产出与实时采集同样的事件，
    /// 而且**必须**带 `replay` 这个来源标签。
    #[test]
    fn replay_parses_the_same_lines_as_a_live_capture() {
        let p = write(
            "same",
            "EXEC|1000000000|4242|4242|1|0|3|curl|/usr/bin/curl\n\
             ARGV|1000000000|4242|4242|0|curl\n\
             ARGV|1000000000|4242|4242|1|-o\n\
             ARGV|1000000000|4242|4242|2|/tmp/x.pdf\n\
             OPEN|1000000100|4242|4242|1|0|241|4294967295|3|/tmp/x.pdf\n",
        );
        let mut r = KernelReplay::open(p.to_str().unwrap(), false, RedactMode::Off).unwrap();
        let mut out = Vec::new();
        assert!(matches!(r.poll(&mut out).unwrap(), PollOutcome::Progress));
        assert_eq!(out.len(), 2, "一条 exec + 一条 open，argv 行不单独成行");
        assert_eq!(out[0].kind, Kind::RuntimeProcExec);
        assert_eq!(out[0].source, "replay");
        match &out[0].payload {
            Payload::ProcExec { filename, argv, .. } => {
                assert_eq!(filename, "/usr/bin/curl");
                assert_eq!(argv, &vec!["curl".to_string(), "-o".into(), "/tmp/x.pdf".into()]);
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert_eq!(out[1].kind, Kind::InfraFileOpen);
        // 第二次 poll 是 EOF：回放有自然结尾（与实时采集不同）。
        let mut out2 = Vec::new();
        assert!(matches!(r.poll(&mut out2).unwrap(), PollOutcome::Eof));
        assert!(r.exited());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// 空文件必须报错，不能安静地变成一条空时间线。
    #[test]
    fn an_empty_capture_is_refused() {
        let p = write("empty", "\n\n");
        // `unwrap_err` 需要 `T: Debug`，而解析器不是 Debug —— 用 match 更直白。
        let e = match KernelReplay::open(p.to_str().unwrap(), false, RedactMode::Off) {
            Ok(_) => panic!("an empty capture must be refused"),
            Err(e) => e,
        };
        assert!(e.contains("no non-empty lines"), "{}", e);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn a_missing_file_is_reported_with_the_path() {
        let e = match KernelReplay::open("/tmp/agtrace_nope_12345/kernel.txt", false, RedactMode::Off) {
            Ok(_) => panic!("a missing capture file must be reported"),
            Err(e) => e,
        };
        assert!(e.contains("/tmp/agtrace_nope_12345/kernel.txt"), "{}", e);
    }

    /// 未知 tag 与半行一律降级计数，绝不 panic（回放的是**别人的**文件）。
    #[test]
    fn garbage_lines_degrade_to_counters() {
        let p = write(
            "garbage",
            "Attaching 4 probes...\nNOPE|1|2\nEXEC|not-a-number|1|1|0|0|0|sh|/bin/sh\n\
             EXEC|2000000000|7|7|1|0|0|true|/usr/bin/true\n",
        );
        let mut r = KernelReplay::open(p.to_str().unwrap(), false, RedactMode::Off).unwrap();
        let mut out = Vec::new();
        r.poll(&mut out).unwrap();
        assert_eq!(out.len(), 1, "只有最后一行是合法的 EXEC");
        let st = r.parse_stats();
        assert_eq!(st.lines_total, 4);
        // `Attaching 4 probes...` 是 bpftrace 的横幅：实时采集时它走 stderr，从来
        // 不会进解析器；但**存盘时被一起重定向进来的**那份文件会带着它，那时它
        // 落进 "未知 tag" 这一格 —— 这条断言就是在钉住这个行为（降级、不 panic）。
        assert_eq!(st.lines_unknown_tag, 2);
        assert_eq!(st.lines_non_protocol, 0);
        assert_eq!(st.lines_malformed, 1);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
