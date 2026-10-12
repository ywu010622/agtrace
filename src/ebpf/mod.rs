//! The in-process eBPF loader (v0.5).
//!
//! Replaces the `sudo bpftrace` subprocess: the programs are compiled from
//! `agtrace-ebpf/` at build time, embedded in this binary, loaded through `aya`,
//! and their ring-buffer records are translated into the *same* line protocol
//! `scripts/agtrace.bt` produced. Nothing downstream of the line protocol knows
//! which collector ran.
//!
//! ## Why a separate process at all
//!
//! Loading eBPF needs `CAP_BPF`/`CAP_SYS_ADMIN`. agtrace is normally run as the
//! user who owns the agent session, so the privileged part is confined to a
//! re-exec of this same binary under `sudo -n` (see `src/collector/aya.rs`), which
//! does nothing but load, attach and print protocol lines. The timeline — merging,
//! redaction, rendering, file output — stays unprivileged.
//!
//! ## Privileged surface
//!
//! Everything here runs as root, so the inputs it trusts are deliberately few:
//! the CONFIG values are resolved from tracefs files this process reads itself
//! (not passed in), the seeds and the mode come from the parent's own `/proc`
//! scan, and the embedded object is a build artefact of this repository.

pub mod btf;
pub mod format;
pub mod record;

use agtrace_ebpf_common as abi;
use agtrace_ebpf_common::RawEvent;
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader};
use record::EmitCfg;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The eBPF object, produced by `build.rs`. Empty when the eBPF toolchain was
/// missing at build time; `available()` reports that rather than loading garbage.
static OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agtrace-ebpf.o"));

/// How often the `.bt` script's `interval:s:30` printed a heartbeat. Kept
/// identical because `TICK` is what tells the rest of agtrace "the collector is
/// still alive"; a different period would change when a stalled capture is
/// noticed.
const TICK_PERIOD: Duration = Duration::from_secs(30);

/// Longest an idle capture may sleep between liveness checks.
///
/// The wait itself is a `poll` on the ring buffer's fd, so a new event wakes this
/// process immediately — this only bounds how long it takes to notice a `TICK`
/// is due. It is *not* a poll interval: `TICK` is checked on every wakeup, and an
/// idle capture wakes about four times a second instead of spinning.
const IDLE_POLL: Duration = Duration::from_millis(250);

static STOP: AtomicBool = AtomicBool::new(false);

/// Whether the eBPF programs were built into this binary.
pub fn available() -> bool {
    !OBJECT.is_empty()
}

/// Duration of the object, for `-v` diagnostics.
pub fn object_len() -> usize {
    OBJECT.len()
}

/// What to trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `-p/--pid`: the root process and the descendants scanned before attach.
    PidTree { root: u32, seeds: Vec<u32> },
    /// `-C/--cgroup`.
    Cgroup { id: u64 },
}

/// Everything the loader needs, resolved by the parent before the re-exec.
#[derive(Debug, Clone)]
pub struct LoaderCfg {
    pub mode: Mode,
    /// Bitmask of `agtrace_ebpf_common::SRC_*` — mirrors `--source`.
    pub sources: u64,
    /// argv slots to capture and print; the eBPF side always fills `ARGV_MAX`.
    pub argv_max: usize,
}

impl LoaderCfg {
    /// Parse the loader's own command line.
    ///
    /// Hand-rolled rather than clap: this parser runs as root, and a hand-written
    /// one over a fixed, tiny argument set is easier to audit than a generic
    /// framework that accepts abbreviations, `--`, response files and so on.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut mode: Option<Mode> = None;
        let mut root: Option<u32> = None;
        let mut seeds: Vec<u32> = Vec::new();
        let mut cgroup: Option<u64> = None;
        let mut sources: u64 = 0;
        let mut saw_sources = false;
        let mut argv_max: usize = 8;

        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut take = |what: &str| -> Result<String, String> {
                it.next().cloned().ok_or_else(|| format!("{} needs a value", what))
            };
            match a.as_str() {
                "--mode" => match take("--mode")?.as_str() {
                    "pid-tree" => mode = Some(Mode::PidTree { root: 0, seeds: Vec::new() }),
                    "cgroup" => mode = Some(Mode::Cgroup { id: 0 }),
                    other => return Err(format!("unknown --mode `{}`", other)),
                },
                "--root" => root = Some(take("--root")?.parse().map_err(|_| "--root must be a pid".to_string())?),
                "--seeds" => {
                    let v = take("--seeds")?;
                    seeds = v
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.parse::<u32>().map_err(|_| format!("--seeds: `{}` is not a pid", s)))
                        .collect::<Result<Vec<_>, _>>()?;
                }
                "--cgroup-id" => {
                    cgroup = Some(take("--cgroup-id")?.parse().map_err(|_| "--cgroup-id must be a number".to_string())?)
                }
                "--sources" => {
                    saw_sources = true;
                    sources = take("--sources")?.parse().map_err(|_| "--sources must be a bitmask".to_string())?;
                }
                "--argv-max" => {
                    argv_max = take("--argv-max")?.parse().map_err(|_| "--argv-max must be a number".to_string())?
                }
                other => return Err(format!("unknown loader argument `{}`", other)),
            }
        }

        if !saw_sources {
            return Err("--sources is required (0 would capture nothing)".to_string());
        }
        if argv_max == 0 || argv_max > abi::ARGV_MAX {
            return Err(format!("--argv-max must be between 1 and {}", abi::ARGV_MAX));
        }
        let mode = match mode {
            Some(Mode::PidTree { .. }) => {
                let root = root.ok_or_else(|| "--mode pid-tree needs --root".to_string())?;
                if seeds.is_empty() {
                    seeds.push(root);
                }
                if !seeds.contains(&root) {
                    seeds.push(root);
                }
                Mode::PidTree { root, seeds }
            }
            Some(Mode::Cgroup { .. }) => Mode::Cgroup {
                id: cgroup.ok_or_else(|| "--mode cgroup needs --cgroup-id".to_string())?,
            },
            None => return Err("--mode is required".to_string()),
        };
        Ok(LoaderCfg { mode, sources, argv_max })
    }
}

extern "C" fn on_stop(_sig: libc::c_int) {
    // async-signal-safe: one relaxed store.
    STOP.store(true, Ordering::Relaxed);
}

/// Entry point for the hidden `__ebpf-collect` subcommand.
///
/// Returns the process exit status. Everything that is not the line protocol goes
/// to stderr; stdout carries records only, because the parent parses it as the
/// kernel event stream.
pub fn loader_main(args: &[String]) -> i32 {
    let cfg = match LoaderCfg::parse(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agtrace-ebpf: {}", e);
            return 2;
        }
    };
    match run(&cfg) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("agtrace-ebpf: {}", e);
            1
        }
    }
}

/// Load, attach, and stream protocol lines to stdout until signalled or killed.
pub fn run(cfg: &LoaderCfg) -> Result<(), String> {
    if !available() {
        return Err(
            "this binary was built without the eBPF programs (build.rs could not run the nightly \
             eBPF build); rebuild with the toolchain installed, or use --collector bpftrace"
                .to_string(),
        );
    }
    install_signal_handlers();

    let events = format::events_dir()?;
    let config = resolve_config(&events, cfg)?;

    let mut bpf: Ebpf = EbpfLoader::new()
        .load(OBJECT)
        .map_err(|e| format!("loading the eBPF object failed: {}", e))?;

    // --- CONFIG: every field offset the programs read ---
    {
        let map = bpf
            .map_mut("CONFIG")
            .ok_or_else(|| "the eBPF object has no CONFIG map".to_string())?;
        let mut arr: Array<&mut MapData, u64> =
            Array::try_from(map).map_err(|e| format!("CONFIG map has the wrong shape: {}", e))?;
        for (i, v) in config.iter().enumerate() {
            arr.set(i as u32, *v, 0)
                .map_err(|e| format!("cannot set CONFIG[{}]: {}", i, e))?;
        }
    }

    // --- seeds: the tree as it stands *now* ---
    //
    // Same approximation the bpftrace path makes, and for the same reason: a
    // process forked between this scan and `attach` is invisible until its own
    // fork fires. Documented rather than papered over.
    if let Mode::PidTree { seeds, .. } = &cfg.mode {
        let map = bpf
            .map_mut("IN_TREE")
            .ok_or_else(|| "the eBPF object has no IN_TREE map".to_string())?;
        let mut m: BpfHashMap<&mut MapData, u32, u8> =
            BpfHashMap::try_from(map).map_err(|e| format!("IN_TREE map has the wrong shape: {}", e))?;
        for p in seeds {
            m.insert(*p, 1u8, 0)
                .map_err(|e| format!("cannot seed IN_TREE with pid {}: {}", p, e))?;
        }
    }

    // --- attach ---
    //
    // Timed because it *is* the startup latency: nothing can be captured before
    // the last `attach` returns, so this duration is the floor on how fast a
    // short-lived target can be observed at all. The dominant cost is the
    // kernel's verifier on `load`, not the attach itself — see `attach_ms` in the
    // summary line, and `--collector bpftrace` for the measure it replaced.
    let attach_started = Instant::now();
    for (prog, cat, name) in PROGRAMS {
        let p = bpf
            .program_mut(prog)
            .ok_or_else(|| format!("the eBPF object has no program `{}`", prog))?;
        let tp: &mut TracePoint = p
            .try_into()
            .map_err(|e| format!("`{}` is not a tracepoint program: {}", prog, e))?;
        tp.load().map_err(|e| format!("loading `{}` was rejected: {}", prog, e))?;
        tp.attach(cat, name)
            .map_err(|e| format!("attaching `{}` to {}:{} failed: {}", prog, cat, name, e))?;
    }
    let attach_ms = attach_started.elapsed().as_millis();

    // --- stream ---
    let map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| "the eBPF object has no EVENTS map".to_string())?;
    let mut ring = RingBuf::try_from(map).map_err(|e| format!("EVENTS is not a ring buffer: {}", e))?;

    let emit = EmitCfg { argv_max: cfg.argv_max };
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::with_capacity(64 * 1024, stdout.lock());
    let mut text = String::with_capacity(64 * 1024);
    let rec_size = std::mem::size_of::<RawEvent>();
    let mut skipped = 0u64;
    let mut next_tick = Instant::now() + TICK_PERIOD;
    // Wall-clock time from `attach` completing to the first record out of the
    // ring. Reported in the summary line: it is the other half of the startup
    // figure, and on a busy box it is what turns "attached" into "capturing".
    let mut first_event_ms: Option<u128> = None;

    while !STOP.load(Ordering::Relaxed) {
        let mut wrote = false;
        // Drain everything the ring has: one write syscall per burst rather than
        // per event.
        while let Some(data) = ring.next() {
            if data.len() != rec_size {
                // A size mismatch means the eBPF crate and this binary disagree
                // about the record layout. Emitting a partly-read record would be
                // worse than dropping it, so it is dropped — and counted.
                skipped += 1;
                continue;
            }
            let rec: &RawEvent = unsafe { &*(data.as_ptr() as *const RawEvent) };
            if first_event_ms.is_none() {
                first_event_ms = Some(attach_started.elapsed().as_millis());
            }
            record::format_record(rec, &emit, &mut text);
            wrote = true;
        }
        if wrote {
            out.write_all(text.as_bytes())
                .map_err(|e| format!("writing protocol output failed: {}", e))?;
            out.flush().map_err(|e| format!("flushing protocol output failed: {}", e))?;
            text.clear();
        }

        let now = Instant::now();
        if now >= next_tick {
            next_tick = now + TICK_PERIOD;
            out.write_all(record::tick_line(monotonic_ns()).as_bytes())
                .map_err(|e| format!("writing TICK failed: {}", e))?;
            out.flush().ok();
        }

        // Sleep until the kernel says there is something to read, or until it is
        // time to print the heartbeat. This is the whole reason the aya path
        // starts in well under a second where bpftrace took seconds: there is no
        // interpreter to boot and no script to compile — the first `poll` after
        // `attach` already returns on the first event.
        let until_tick = next_tick.saturating_duration_since(Instant::now());
        wait_readable(&ring, until_tick.min(IDLE_POLL));
    }

    // The parent SIGTERMs this process when it is done. Report what the kernel
    // could not deliver *before* exiting: a loss count that never reaches the
    // timeline is exactly the silent gap this project refuses to ship.
    let _ = out.flush();
    drop(out);
    report(cfg, ring_lost(&mut bpf), skipped, attach_ms, first_event_ms);
    Ok(())
}

/// Print the exit summary on stderr. `stderr` is not part of the protocol; the
/// parent scans it for the word `lost` (see `collector::child::parse_lost`).
fn report(
    cfg: &LoaderCfg,
    lost: u64,
    skipped: u64,
    attach_ms: u128,
    first_event_ms: Option<u128>,
) {
    let target = match &cfg.mode {
        Mode::PidTree { root, seeds } => format!("pid-tree root={} seeds={}", root, seeds.len()),
        Mode::Cgroup { id } => format!("cgroup id={}", id),
    };
    let first = match first_event_ms {
        Some(ms) => format!("{}ms to first event", ms),
        None => "no event captured before exit".to_string(),
    };
    eprintln!(
        "agtrace-ebpf: {} tracepoints attached in {}ms ({}), object {} bytes, target {}",
        PROGRAMS.len(),
        attach_ms,
        first,
        OBJECT.len(),
        target
    );
    if skipped > 0 {
        eprintln!(
            "agtrace-ebpf: dropped {} record(s) whose size did not match this binary's \
             RawEvent ({} bytes) — the eBPF object and the loader are out of step",
            skipped,
            std::mem::size_of::<RawEvent>()
        );
    }
    if lost > 0 {
        eprintln!("agtrace-ebpf: lost {} events (ring buffer full)", lost);
    }
}

fn ring_lost(bpf: &mut Ebpf) -> u64 {
    let Some(map) = bpf.map_mut("LOST") else {
        return 0;
    };
    let Ok(arr) = PerCpuArray::<&mut MapData, u64>::try_from(map) else {
        return 0;
    };
    match arr.get(&0, 0) {
        Ok(values) => values.iter().copied().sum(),
        Err(_) => 0,
    }
}

/// Block until the ring buffer has data, the timeout expires, or a signal arrives.
///
/// `poll(2)` rather than `epoll`: there is exactly one fd, and this thread does
/// nothing else. The signal handler is installed without `SA_RESTART`, so a
/// `SIGTERM` from the parent returns `EINTR` immediately and the `STOP` flag is
/// seen on the next loop test — shutdown does not wait for the timeout.
fn wait_readable(ring: &RingBuf<MapData>, timeout: Duration) {
    use std::os::fd::AsRawFd;
    let mut pfd = libc::pollfd {
        fd: ring.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
    // A negative return means `EINTR` (the parent's signal) or a dead fd; both
    // send us back around the loop, where `STOP` and the ring are re-checked.
    unsafe { libc::poll(&mut pfd, 1, ms) };
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_stop as *const () as usize;
        sa.sa_flags = 0; // no SA_RESTART: a blocked call should return so we notice
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

/// The programs and the tracepoints they attach to, in attach order.
const PROGRAMS: &[(&str, &str, &str)] = &[
    ("on_fork", "sched", "sched_process_fork"),
    ("on_exit", "sched", "sched_process_exit"),
    ("on_execve_enter", "syscalls", "sys_enter_execve"),
    ("on_exec", "sched", "sched_process_exec"),
    ("on_execve_exit", "syscalls", "sys_exit_execve"),
    ("on_openat_enter", "syscalls", "sys_enter_openat"),
    ("on_openat_exit", "syscalls", "sys_exit_openat"),
    ("on_connect_enter", "syscalls", "sys_enter_connect"),
    ("on_connect_exit", "syscalls", "sys_exit_connect"),
    ("on_sendto", "syscalls", "sys_enter_sendto"),
];

/// Resolve every field offset the programs read, from this kernel's tracefs.
///
/// Nothing here is passed in from the parent: the offsets are read from the
/// kernel by the process that will use them, so a hostile or stale parent cannot
/// make a root-owned loader read the wrong bytes.
fn resolve_config(events: &std::path::Path, cfg: &LoaderCfg) -> Result<Vec<u64>, String> {
    let mut c = vec![0u64; abi::CFG_COUNT as usize];

    c[abi::CFG_MODE as usize] = match &cfg.mode {
        Mode::PidTree { .. } => abi::MODE_PID_TREE,
        Mode::Cgroup { .. } => abi::MODE_CGROUP,
    };
    if let Mode::Cgroup { id } = &cfg.mode {
        c[abi::CFG_CGROUP_ID as usize] = *id;
    }
    c[abi::CFG_SRC as usize] = cfg.sources;

    let f = |cat: &str, name: &str| -> Result<format::EventFormat, String> {
        format::read_format(events, cat, name).map_err(|e| {
            format!(
                "{} — this kernel does not expose the tracepoint agtrace needs; \
                 use --collector bpftrace",
                e
            )
        })
    };
    let f_fork = f("sched", "sched_process_fork")?;
    let f_exec = f("sched", "sched_process_exec")?;
    let f_exit = f("sched", "sched_process_exit")?;
    let f_execve_in = f("syscalls", "sys_enter_execve")?;
    let f_execve_out = f("syscalls", "sys_exit_execve")?;
    let f_open_in = f("syscalls", "sys_enter_openat")?;
    let f_open_out = f("syscalls", "sys_exit_openat")?;
    let f_conn_in = f("syscalls", "sys_enter_connect")?;
    let f_conn_out = f("syscalls", "sys_exit_connect")?;
    let f_sendto = f("syscalls", "sys_enter_sendto")?;

    let mut set = |slot: u32, ev: &format::EventFormat, id: &str, field: &str| -> Result<(), String> {
        c[slot as usize] = ev.field(field, id)?.encode();
        Ok(())
    };

    set(abi::CFG_SYS_RET, &f_execve_out, "sys_exit_execve", "ret")?;
    set(abi::CFG_SYS_RET, &f_open_out, "sys_exit_openat", "ret")?;
    set(abi::CFG_SYS_RET, &f_conn_out, "sys_exit_connect", "ret")?;

    set(abi::CFG_FORK_PARENT_PID, &f_fork, "sched_process_fork", "parent_pid")?;
    set(abi::CFG_FORK_CHILD_PID, &f_fork, "sched_process_fork", "child_pid")?;
    set(abi::CFG_FORK_CHILD_COMM, &f_fork, "sched_process_fork", "child_comm")?;
    set(abi::CFG_FORK_PARENT_COMM, &f_fork, "sched_process_fork", "parent_comm")?;

    set(abi::CFG_EXEC_FILENAME, &f_exec, "sched_process_exec", "filename")?;
    set(abi::CFG_EXECVE_FILENAME, &f_execve_in, "sys_enter_execve", "filename")?;
    set(abi::CFG_EXECVE_ARGV, &f_execve_in, "sys_enter_execve", "argv")?;

    set(abi::CFG_OPENAT_DFD, &f_open_in, "sys_enter_openat", "dfd")?;
    set(abi::CFG_OPENAT_FILENAME, &f_open_in, "sys_enter_openat", "filename")?;
    set(abi::CFG_OPENAT_FLAGS, &f_open_in, "sys_enter_openat", "flags")?;

    set(abi::CFG_CONNECT_FD, &f_conn_in, "sys_enter_connect", "fd")?;
    set(abi::CFG_CONNECT_ADDR, &f_conn_in, "sys_enter_connect", "uservaddr")?;

    set(abi::CFG_SENDTO_FD, &f_sendto, "sys_enter_sendto", "fd")?;
    set(abi::CFG_SENDTO_LEN, &f_sendto, "sys_enter_sendto", "len")?;

    set(abi::CFG_EXIT_GROUP_DEAD, &f_exit, "sched_process_exit", "group_dead")?;

    // The exit status of a signal death is not on any syscall tracepoint; it is
    // read off `task_struct`, whose layout comes from the kernel's own BTF.
    match btf::task_exit_code_offset() {
        Ok(Some(off)) => c[abi::CFG_TASK_EXIT_CODE as usize] = off as u64,
        Ok(None) => eprintln!(
            "agtrace-ebpf: task_struct.exit_code is not in this kernel's BTF; \
             EXIT rows will report status 0 (the signal is still visible in the timeline)"
        ),
        Err(e) => eprintln!("agtrace-ebpf: {} — EXIT rows will report status 0", e),
    }

    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn pid_tree_arguments_round_trip() {
        let cfg = LoaderCfg::parse(&v(&[
            "--mode",
            "pid-tree",
            "--root",
            "42",
            "--seeds",
            "42,43,44",
            "--sources",
            "7",
            "--argv-max",
            "4",
        ]))
        .unwrap();
        assert_eq!(
            cfg.mode,
            Mode::PidTree {
                root: 42,
                seeds: vec![42, 43, 44]
            }
        );
        assert_eq!(cfg.sources, 7);
        assert_eq!(cfg.argv_max, 4);
    }

    #[test]
    fn the_root_is_always_a_seed() {
        // Otherwise a `--pid` run whose /proc scan came back empty would attach
        // to an empty filter and produce a timeline of "nothing happened".
        let cfg = LoaderCfg::parse(&v(&["--mode", "pid-tree", "--root", "9", "--sources", "1"])).unwrap();
        assert_eq!(cfg.mode, Mode::PidTree { root: 9, seeds: vec![9] });
    }

    #[test]
    fn cgroup_mode_needs_an_id() {
        assert!(LoaderCfg::parse(&v(&["--mode", "cgroup", "--sources", "1"])).is_err());
        let cfg = LoaderCfg::parse(&v(&["--mode", "cgroup", "--cgroup-id", "3", "--sources", "2"])).unwrap();
        assert_eq!(cfg.mode, Mode::Cgroup { id: 3 });
    }

    #[test]
    fn missing_or_absurd_arguments_are_refused() {
        assert!(LoaderCfg::parse(&v(&[])).is_err(), "--mode is required");
        assert!(LoaderCfg::parse(&v(&["--mode", "pid-tree", "--root", "1"])).is_err(), "--sources is required");
        assert!(
            LoaderCfg::parse(&v(&["--mode", "pid-tree", "--root", "1", "--sources", "1", "--argv-max", "99"])).is_err(),
            "argv-max above what the eBPF side captures must not be accepted"
        );
        assert!(LoaderCfg::parse(&v(&["--mode", "nope", "--sources", "1"])).is_err());
        assert!(LoaderCfg::parse(&v(&["--wat", "1"])).is_err());
    }

    #[test]
    fn every_program_name_is_distinct() {
        let mut names: Vec<&str> = PROGRAMS.iter().map(|p| p.0).collect();
        names.sort_unstable();
        let n = names.len();
        names.dedup();
        assert_eq!(names.len(), n);
        assert_eq!(n, 10, "the .bt script's probe set has 10 tracepoints");
    }
}
