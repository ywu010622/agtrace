//! The aya collector (v0.5): in-process eBPF, replacing the `sudo bpftrace` child.
//!
//! Deliberately symmetric with [`super::bpftrace`] — both produce the same line
//! protocol for the same [`KernelLineParser`]. All that differs is who emits the
//! lines:
//!
//! * bpftrace runs `sudo -n bpftrace -q -B none <generated script>`;
//! * aya runs `sudo -n <agtrace itself> __ebpf-collect --mode ...`.
//!
//! **Why re-exec ourselves rather than just running under `sudo agtrace`**:
//! loading eBPF needs CAP_BPF/CAP_SYS_ADMIN, but agtrace normally runs as the
//! invoking user. Confining the privileged part to a child that only loads,
//! attaches and prints protocol lines keeps merging, redaction, rendering and
//! writing on the unprivileged side. That child is this same binary, so after
//! `cargo install` there is no external program to install — which is the whole
//! point of v0.5.
//!
//! Failures always fall back to bpftrace **visibly** (see [`spawn_with_fallback`]),
//! never silently.

use super::bpftrace::{MAX_STRLEN, SourceFilter, Target};
use super::child::LineChild;
use super::{Collector, CollectorError, KernelLineParser};
use crate::ebpf;
use crate::event::Event;
use crate::poll::PollOutcome;
use crate::redact::RedactMode;
use std::process::Command;

/// Hidden subcommand: this binary's "privileged loader" mode.
///
/// The leading underscores are deliberate — it should be recognisable as an
/// internal invocation in `ps`, and it can never collide with a user argument
/// (`-p`, `--pid`, ...), none of which start with an underscore.
pub const SUBCOMMAND: &str = "__ebpf-collect";

pub struct AyaCollector {
    child: LineChild,
    parser: KernelLineParser,
    /// The aya-side counterpart of bpftrace's `rendered_script`: a fingerprint of
    /// what was actually attached. There is no script to reproduce, so this
    /// records the attach configuration itself.
    pub rendered_script: String,
}

/// Expand `Target` + `--source` into the loader's command line.
///
/// A separate function so it can be unit-tested: this is the only place where
/// "what the parent believes it is tracing" and "what the kernel is actually
/// tracing" can disagree, and a mis-spelled argument raises no runtime error at
/// all — it just yields an empty timeline.
pub fn loader_args(target: &Target, sources: &SourceFilter, argv_max: usize) -> Vec<String> {
    let mut args = vec![SUBCOMMAND.to_string()];
    match target {
        Target::PidTree { root, seeds } => {
            args.push("--mode".into());
            args.push("pid-tree".into());
            args.push("--root".into());
            args.push(root.to_string());
            args.push("--seeds".into());
            let mut all = seeds.clone();
            if !all.contains(root) {
                all.push(*root);
            }
            args.push(
                all.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        Target::Cgroup { id, .. } => {
            args.push("--mode".into());
            args.push("cgroup".into());
            args.push("--cgroup-id".into());
            args.push(id.to_string());
        }
    }
    let mut mask = 0u64;
    if sources.exec {
        mask |= agtrace_ebpf_common::SRC_EXEC;
    }
    if sources.file {
        mask |= agtrace_ebpf_common::SRC_FILE;
    }
    if sources.net {
        mask |= agtrace_ebpf_common::SRC_NET;
    }
    args.push("--sources".into());
    args.push(mask.to_string());
    args.push("--argv-max".into());
    args.push(argv_max.to_string());
    args
}

/// Whether this configuration can be served by the aya collector at all.
///
/// `Err` carries the reason to show the user; the caller turns it into the visible
/// fallback note. Kept separate from `spawn` so the *reason* survives even when the
/// fallback itself fails.
pub fn precheck(argv_max: usize) -> Result<(), String> {
    // The argument check comes first on purpose. `argv_max` is a property of the
    // *request*, so it holds whether or not this build has eBPF programs; and
    // when both are wrong, "you asked for more arg slots than we compile in" is
    // the one the user can act on.
    if argv_max > agtrace_ebpf_common::ARGV_MAX {
        return Err(format!(
            "--argv-max {} exceeds the {} slots the compiled eBPF programs capture \
             (the bpftrace fallback expands its script instead)",
            argv_max,
            agtrace_ebpf_common::ARGV_MAX
        ));
    }
    if !ebpf::available() {
        return Err(
            "this build has no eBPF programs embedded (build.rs could not run the nightly \
             bpf-linker build for bpfel-unknown-none)"
                .to_string(),
        );
    }
    Ok(())
}

impl AyaCollector {
    /// Start the privileged loader and wire its stdout into the shared parser.
    pub fn spawn(
        target: &Target,
        argv_max: usize,
        file_all: bool,
        sources: &SourceFilter,
        redact: RedactMode,
    ) -> Result<Self, CollectorError> {
        let args = loader_args(target, sources, argv_max);
        let exe = std::env::current_exe()
            .map_err(|e| CollectorError::Spawn(format!("cannot locate this executable: {}", e)))?;

        // Under `sudo agtrace ...` we are already root and a second sudo would be
        // both pointless and, on a `requiretty`-configured sudoers, a failure.
        let mut cmd = if unsafe { libc::geteuid() } == 0 {
            Command::new(&exe)
        } else {
            let mut c = Command::new("sudo");
            c.arg("-n").arg(&exe);
            c
        };
        cmd.args(&args);

        let what = format!("{} {}", exe.display(), args.join(" "));
        let child = LineChild::spawn(cmd, "aya", &what)?;

        let mut parser = KernelLineParser::with_redact(MAX_STRLEN, redact);
        parser.set_file_all(file_all);
        parser.set_source_label("aya");

        Ok(AyaCollector {
            child,
            parser,
            rendered_script: describe(target, argv_max, sources),
        })
    }

    pub fn exited(&self) -> bool {
        self.child.exited()
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.child.exit_code()
    }

    pub fn redacted_events(&self) -> u64 {
        self.parser.redacted_events
    }

    pub fn parse_stats(&self) -> &super::ParseStats {
        &self.parser.stats
    }

    pub fn stderr_tail(&self) -> &[String] {
        &self.child.stderr_tail
    }

    pub fn unfinished_line_bytes(&self) -> usize {
        self.child.unfinished_line_bytes()
    }
}

/// The `-v` fingerprint. There is no script to reproduce an aya run, so what is
/// recorded instead is the exact attach configuration — same purpose (prove that
/// the `-p` filter really made it into the kernel), different artefact.
fn describe(target: &Target, argv_max: usize, sources: &SourceFilter) -> String {
    let t = match target {
        Target::PidTree { root, seeds } => format!("pid-tree root={} seeds={}", root, seeds.len()),
        Target::Cgroup { path, id } => format!("cgroup {} (id {})", path, id),
    };
    format!(
        "// === loaded by agtrace's aya collector ===\n\
         // target={} argv_max={} sources(exec={} file={} net={})\n\
         // object: {} bytes, embedded at build time from agtrace-ebpf/\n\
         // no script to reproduce: `sudo agtrace {} {}` is the equivalent command line.\n",
        t,
        argv_max,
        sources.exec as u8,
        sources.file as u8,
        sources.net as u8,
        ebpf::object_len(),
        std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "agtrace".into()),
        SUBCOMMAND
    )
}

impl Collector for AyaCollector {
    fn id(&self) -> &'static str {
        "aya"
    }

    fn poll(&mut self, out: &mut Vec<Event>) -> Result<PollOutcome, CollectorError> {
        self.child.poll_lines(&mut self.parser, out)
    }

    fn shutdown(&mut self) {
        self.child.shutdown();
    }

    fn lost_events(&self) -> u64 {
        self.child.lost_events()
    }
}

/// Decide which collector to use, and start it.
///
/// Returns the collector plus an optional **visible** note when the requested one
/// could not be used. The note is never suppressed: a run that silently used
/// bpftrace would make "why is startup taking 3 seconds" and "why does `-v` say
/// bpftrace" mysteries, and would hide a broken aya build indefinitely.
pub fn spawn_with_fallback(
    prefer_aya: bool,
    target: &Target,
    argv_max: usize,
    file_all: bool,
    sources: &SourceFilter,
    redact: RedactMode,
    template: &str,
) -> Result<(super::KernelCollector, Option<String>), String> {
    if prefer_aya {
        match precheck(argv_max) {
            Ok(()) => match AyaCollector::spawn(target, argv_max, file_all, sources, redact) {
                Ok(c) => return Ok((super::KernelCollector::Aya(c), None)),
                Err(e) => {
                    let note = format!(
                        "the aya collector could not start ({}); falling back to bpftrace",
                        e
                    );
                    let b = super::bpftrace::BpftraceCollector::spawn(
                        template, target, argv_max, file_all, sources, redact, None,
                    )
                    .map_err(|e2| format!("{}\nand the bpftrace fallback also failed: {}", note, e2))?;
                    return Ok((super::KernelCollector::Bpftrace(b), Some(note)));
                }
            },
            Err(reason) => {
                let note = format!("aya is unavailable ({}); falling back to bpftrace", reason);
                let b = super::bpftrace::BpftraceCollector::spawn(
                    template, target, argv_max, file_all, sources, redact, None,
                )
                .map_err(|e| format!("{}\nand the bpftrace fallback also failed: {}", note, e))?;
                return Ok((super::KernelCollector::Bpftrace(b), Some(note)));
            }
        }
    }
    // The other direction of the same promise. `--collector bpftrace` with the
    // binary absent used to run to completion with an empty timeline and no
    // explanation anywhere outside `-v`; probe first, and prefer a working aya
    // over an empty run. Either way the user is told, on stderr, at startup.
    if let Err(reason) = super::bpftrace::precheck() {
        return match precheck(argv_max) {
            Ok(()) => match AyaCollector::spawn(target, argv_max, file_all, sources, redact) {
                Ok(c) => Ok((
                    super::KernelCollector::Aya(c),
                    Some(format!("bpftrace is unavailable ({}); using aya instead", reason)),
                )),
                Err(e) => Err(format!(
                    "bpftrace is unavailable ({}) and the aya collector could not start either ({})",
                    reason, e
                )),
            },
            Err(a) => Err(format!(
                "bpftrace is unavailable ({}) and aya is unavailable too ({})",
                reason, a
            )),
        };
    }
    let b = super::bpftrace::BpftraceCollector::spawn(template, target, argv_max, file_all, sources, redact, None)
        .map_err(|e| e.to_string())?;
    Ok((super::KernelCollector::Bpftrace(b), None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::format;
    use crate::ebpf::{LoaderCfg, Mode};

    #[test]
    fn the_string_cap_matches_the_ebpf_side() {
        // Load-bearing: the parser decides "truncated" from the `..` tail the
        // loader appends, and `str_limit` words the note. If the two caps drift,
        // the same path would be described differently by the two collectors.
        assert_eq!(MAX_STRLEN, agtrace_ebpf_common::STR_MAX);
    }

    #[test]
    fn pid_tree_arguments_carry_every_seed() {
        let t = Target::PidTree {
            root: 100,
            seeds: vec![100, 101, 102],
        };
        let a = loader_args(&t, &SourceFilter::all(), 8);
        assert_eq!(a[0], SUBCOMMAND);
        assert!(a.windows(2).any(|w| w == ["--mode", "pid-tree"]));
        assert!(a.windows(2).any(|w| w == ["--root", "100"]));
        assert!(a.windows(2).any(|w| w == ["--seeds", "100,101,102"]));
        assert!(a.windows(2).any(|w| w == ["--sources", "7"]));
        assert!(a.windows(2).any(|w| w == ["--argv-max", "8"]));
    }

    #[test]
    fn the_root_is_seeded_even_when_the_scan_missed_it() {
        let t = Target::PidTree {
            root: 100,
            seeds: vec![101],
        };
        let a = loader_args(&t, &SourceFilter::all(), 8);
        assert!(a.iter().any(|x| x == "101,100"));
    }

    #[test]
    fn source_flags_become_a_bitmask_the_loader_understands() {
        let t = Target::Cgroup {
            path: "/x".into(),
            id: 7,
        };
        let f = SourceFilter::parse("exec,net").unwrap();
        let a = loader_args(&t, &f, 4);
        assert!(a.windows(2).any(|w| w == ["--mode", "cgroup"]));
        assert!(a.windows(2).any(|w| w == ["--cgroup-id", "7"]));
        // SRC_EXEC | SRC_NET
        assert!(a.windows(2).any(|w| w == ["--sources", "5"]));
    }

    #[test]
    fn the_hidden_subcommand_cannot_be_mistaken_for_a_flag() {
        // `main` intercepts it before the CLI parser runs, so it must not be
        // something a user could plausibly type as a real argument.
        assert!(SUBCOMMAND.starts_with("__"));
        assert!(!SUBCOMMAND.starts_with('-'));
        assert!(!SUBCOMMAND.contains('='));
    }

    #[test]
    fn the_loader_accepts_exactly_what_we_generate() {
        // The two sides of the re-exec disagreeing is the one failure mode with no
        // runtime error attached: the loader would exit, the ring would be empty,
        // and the timeline would say nothing happened.
        let cases = [
            Target::PidTree {
                root: 5,
                seeds: vec![5, 6],
            },
            Target::Cgroup {
                path: "/sys/fs/cgroup/x".into(),
                id: 9,
            },
        ];
        for t in cases {
            let mut args = loader_args(&t, &SourceFilter::all(), 16);
            args.remove(0); // the subcommand itself is consumed by main()
            let cfg = LoaderCfg::parse(&args).expect("the loader must accept our own arguments");
            match (&t, &cfg.mode) {
                (Target::PidTree { root, .. }, Mode::PidTree { root: r, seeds }) => {
                    assert_eq!(root, r);
                    assert!(seeds.contains(r));
                }
                (Target::Cgroup { id, .. }, Mode::Cgroup { id: c }) => assert_eq!(id, c),
                _ => panic!("mode mismatch for {:?}", t),
            }
            assert_eq!(cfg.sources, 7);
        }
    }

    #[test]
    fn precheck_reports_the_reason_not_just_a_boolean() {
        // argv_max beyond the compiled slot count must be refused *with a reason*:
        // the caller shows it, and a bare "false" would be an unexplained fallback.
        match precheck(agtrace_ebpf_common::ARGV_MAX + 1) {
            Err(e) => assert!(e.contains("--argv-max"), "{}", e),
            Ok(()) => panic!("oversized argv-max must be refused"),
        }
    }

    #[test]
    fn the_config_encoder_is_readable_by_the_ebpf_side() {
        // Same bit layout as `agtrace_ebpf_common::field`.
        let f = format::Field {
            offset: 32,
            width: agtrace_ebpf_common::W4,
            signed: true,
            data_loc: false,
        };
        let enc = f.encode();
        assert_eq!(enc >> 8, 32);
        assert_eq!(enc & 0xf, agtrace_ebpf_common::W4 as u64);
        assert_ne!(enc & 0x10, 0, "signed bit");
    }
}
