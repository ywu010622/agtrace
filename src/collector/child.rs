//! Shared plumbing for a privileged child that speaks the kernel line protocol.
//!
//! Both collectors end up doing exactly the same thing with their child: read
//! stdout as non-blocking lines, hand them to [`KernelLineParser`], drain stderr
//! looking for a loss signal, notice when the child dies, and tear the whole
//! process group down on shutdown. Only *what* gets spawned differs. Keeping one
//! copy of this matters more than it looks: the process-group kill and the
//! "blocking buffered output looks like a hang" fix were both found by hitting
//! the bug, and a second copy would be a second place to lose them.
//!
//! Nothing here is bpftrace- or aya-specific.

use super::{CollectorError, KernelLineParser, LineBuffer};
use crate::event::{Binding, Corr, Event, Kind, Layer, Payload, TsSource};
use crate::poll::PollOutcome;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::{Child, Command, Stdio};

/// A spawned child whose stdout is the kernel line protocol.
pub struct LineChild {
    child: Child,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    out_buf: LineBuffer,
    err_buf: LineBuffer,
    /// Loss count harvested from the child's stderr.
    lost: u64,
    /// How much of `lost` has already been reported as an event (so the timeline
    /// gets one `!! lost_events` row per increment rather than one per poll).
    lost_reported: u64,
    eof: bool,
    child_exited: Option<i32>,
    /// Raw stderr lines, capped, for `-v`.
    pub stderr_tail: Vec<String>,
    /// Name used in the events and notes this module produces.
    label: &'static str,
}

impl LineChild {
    /// Spawn `cmd`, wiring up pipes, a private process group and non-blocking reads.
    ///
    /// `what` is the human-readable command line used in the spawn error — the
    /// failure this most often reports is "you are missing a tool or passwordless
    /// sudo", and the user needs to know which tool.
    pub fn spawn(mut cmd: Command, label: &'static str, what: &str) -> Result<Self, CollectorError> {
        // stdin is closed so the child cannot block reading a terminal, and so
        // it notices a parent death through the pipe rather than hanging.
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

        // Put the child in its own process group. This is not cosmetic: `sudo`
        // forks the real tracer in some configurations, and killing only sudo's
        // pid leaves a **root-owned orphan** still holding the probes attached.
        // Killing the negative pid takes the whole group down.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .map_err(|e| CollectorError::Spawn(format!("cannot start `{}`: {}", what, e)))?;

        let stdout_fd = child.stdout.as_ref().expect("stdout piped").as_raw_fd();
        let stderr_fd = child.stderr.as_ref().expect("stderr piped").as_raw_fd();
        set_nonblocking(stdout_fd).map_err(|e| CollectorError::Io(e.to_string()))?;
        set_nonblocking(stderr_fd).map_err(|e| CollectorError::Io(e.to_string()))?;

        Ok(LineChild {
            child,
            stdout_fd,
            stderr_fd,
            out_buf: LineBuffer::new(),
            err_buf: LineBuffer::new(),
            lost: 0,
            lost_reported: 0,
            eof: false,
            child_exited: None,
            stderr_tail: Vec::new(),
            label,
        })
    }

    /// Whether the child has exited (this, not EOF, is what ends a capture).
    pub fn exited(&self) -> bool {
        self.child_exited.is_some()
    }

    /// Exit code, once [`Self::exited`] is true.
    pub fn exit_code(&self) -> Option<i32> {
        self.child_exited
    }

    pub fn lost_events(&self) -> u64 {
        self.lost
    }

    pub fn finished(&self) -> bool {
        self.eof && self.child_exited.is_some()
    }

    /// Bytes sitting in the stdout buffer that never became a whole line.
    ///
    /// Non-zero at the end of a capture means the last line was cut in half
    /// (the child was signalled mid-write). That line is *not* parsed into an
    /// event, so the caller has to say so out loud — otherwise it is a silent
    /// loss, which is the one thing this project refuses to do.
    pub fn unfinished_line_bytes(&self) -> usize {
        self.out_buf.pending_bytes()
    }

    /// One poll step: stdout → parser, stderr → loss count, child → exit status.
    pub fn poll_lines(
        &mut self,
        parser: &mut KernelLineParser,
        out: &mut Vec<Event>,
    ) -> Result<PollOutcome, CollectorError> {
        let mut progress = false;

        // --- stdout: kernel events ---
        let mut buf = [0u8; 32768];
        loop {
            let n = unsafe { libc::read(self.stdout_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                progress = true;
                for line in self.out_buf.push(&buf[..n as usize]) {
                    parser.feed_line(&line, out);
                }
                continue;
            }
            if n == 0 {
                // EOF: the child is gone. A leftover half-line is counted, never
                // parsed — a truncated `OPEN|...` must not become a fake event.
                self.eof = true;
                if self.out_buf.take_remainder().is_some() {
                    parser.stats.lines_malformed += 1;
                }
                break;
            }
            // EAGAIN/EINTR: nothing more right now. Anything else is also just
            // "stop reading"; the child's exit status is read below either way.
            break;
        }

        self.drain_stderr();

        // --- loss is reported, never swallowed ---
        if self.lost > self.lost_reported {
            let delta = self.lost - self.lost_reported;
            self.lost_reported = self.lost;
            out.push(self.lost_event(delta));
            progress = true;
        }

        // --- child status ---
        //
        // `Err` from `try_wait` is a reaped-elsewhere race and `Ok(None)` just
        // means "still running"; neither is progress, and neither is retried away.
        if self.child_exited.is_none()
            && let Ok(Some(st)) = self.child.try_wait()
        {
            self.child_exited = Some(st.code().unwrap_or(-1));
            // Anything the parser is still holding (a half-finished argv stash,
            // say) has to come out before the capture is declared over, or the
            // last exec of a run is silently dropped.
            parser.finish(out);
            progress = true;
        }

        if progress {
            Ok(PollOutcome::Progress)
        } else if self.finished() {
            Ok(PollOutcome::Eof)
        } else {
            Ok(PollOutcome::Idle)
        }
    }

    /// SIGTERM the process group, wait briefly, then SIGKILL.
    ///
    /// The grace period is not politeness for its own sake: bpftrace needs it to
    /// run `END{}` and detach its probes. Aya's loader uses it to flush records
    /// still sitting in the ring buffer.
    pub fn shutdown(&mut self) {
        let pid = self.child.id() as i32;
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
            libc::kill(pid, libc::SIGTERM);
        }
        for _ in 0..50 {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// True when the child is still running (used by `Drop`).
    pub fn alive(&self) -> bool {
        self.child_exited.is_none()
    }

    fn lost_event(&self, count: u64) -> Event {
        Event {
            seq: 0,
            ts_ns: 0,
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Derived,
            kind: Kind::CollectorLostEvents,
            source: self.label.into(),
            pid: None,
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr::default(),
            payload: Payload::LostEvents { count },
            trunc: Vec::new(),
            notes: Vec::new(),
            late: false,
            watch: true,
            binding: Binding::None,
            retry: false,
        }
    }

    /// Read stderr to exhaustion, harvesting loss counts and keeping a capped
    /// tail for `-v`.
    fn drain_stderr(&mut self) {
        let mut buf = [0u8; 8192];
        loop {
            let n = unsafe { libc::read(self.stderr_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            for line in self.err_buf.push(&buf[..n as usize]) {
                if let Some(c) = parse_lost(&line) {
                    self.lost += c;
                }
                if self.stderr_tail.len() < 64 {
                    self.stderr_tail.push(line);
                }
            }
        }
    }
}

impl Drop for LineChild {
    fn drop(&mut self) {
        if self.alive() {
            self.shutdown();
        }
    }
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Extract a loss count from one line of a child's stderr.
///
/// Two shapes are accepted, because the two collectors report loss differently
/// and neither is going to change to suit the other:
///
///  * bpftrace's own text — `Lost 142 events` (and the JSON envelope
///    `{"type": "lost_events", "data": {"lost": 142}}`, whose exact field layout
///    has never been observed in practice; see BUILD_LOG.md);
///  * the aya loader's summary — `agtrace-ebpf: lost 142 events`.
///
/// Both are "the word `lost` followed by the first run of digits after it",
/// which is why one function covers them. A line that merely mentions loss
/// without a number yields `None` rather than a fabricated zero.
pub fn parse_lost(line: &str) -> Option<u64> {
    let l = line.to_ascii_lowercase();
    let pos = l.find("lost")?;
    let rest = &line[pos..];
    let mut num = String::new();
    let mut started = false;
    for c in rest.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            started = true;
        } else if started {
            break;
        }
    }
    num.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_is_parsed_from_both_dialects() {
        assert_eq!(parse_lost("Lost 142 events"), Some(142));
        assert_eq!(parse_lost("agtrace-ebpf: lost 7 events (ring buffer full)"), Some(7));
        assert_eq!(
            parse_lost(r#"{"type": "lost_events", "data": {"lost": 9}}"#),
            Some(9)
        );
    }

    #[test]
    fn lost_without_a_number_is_not_zero() {
        // "we do not know how many" must never be reported as "none were lost".
        assert_eq!(parse_lost("attaching 10 probes..."), None);
        assert_eq!(parse_lost("lost events?"), None);
    }
}
