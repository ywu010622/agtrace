//! eBPF programs replicating `scripts/agtrace.bt`.
//!
//! Everything bpftrace used to do at the probe level lives here: the PID-tree
//! filter map, the per-tid stashes that pair a `sys_enter_*` with its
//! `sys_exit_*`, and the decision of *what* to emit for `--source`.
//!
//! Two deliberate departures from the `.bt` script, both documented where they
//! happen and both closing a real capture loss rather than changing the protocol:
//!
//!  1. `ppid` comes from a `PARENT_OF` map instead of `curtask->real_parent->pid`.
//!     Reading `task_struct` would need BTF-resolved field offsets inside the
//!     verifier's reach; the map is seeded from `/proc` at attach and extended on
//!     every fork, which is race-free because `sched_process_fork` completes
//!     before the child can issue a syscall.
//!  2. A thread exit no longer evicts its whole process from the tree. The `.bt`
//!     script did `delete(@in_tree[pid])` on *every* `sched_process_exit`, where
//!     `pid` is the tgid — so any multi-threaded target silently dropped out of
//!     the filter the first time one of its threads exited. Here the eviction is
//!     gated on the tracepoint's own `group_dead` flag.
//!
//! The one thing that *is* read out of `task_struct` is `exit_code`, because no
//! syscall tracepoint reports the exit status of a signal death.

#![no_std]
#![no_main]
#![allow(nonstandard_style)]

use agtrace_ebpf_common::*;
use aya_ebpf::{
    EbpfContext as _,
    cty::c_void,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user, bpf_probe_read_user_buf, gen,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};

// ===========================================================================
// Maps
// ===========================================================================

/// All kernel → userspace traffic. One buffer, so the kernel-side ordering of the
/// records is total; two buffers would let an `openat` overtake the `exec` that
/// preceded it and the loader would have to re-derive an order it was just handed.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Loader-supplied constants: field descriptors, filter mode, `--source`.
#[map]
static CONFIG: Array<u64> = Array::with_max_entries(CFG_COUNT, 0);

/// Reservations that failed because the ring was full.
///
/// A ring buffer drops silently — `bpf_ringbuf_reserve` returning NULL is the only
/// signal, and nothing userspace-side can observe it after the fact. Counting it
/// here is what lets the loader report a truthful loss number instead of a
/// hardcoded zero. Per-CPU to avoid a read-modify-write race between CPUs; the
/// loader sums the slots.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// The PID-tree filter (`@in_tree` in the `.bt` script). Keyed by tgid.
#[map]
static IN_TREE: HashMap<u32, u8> = HashMap::with_max_entries(16384, 0);

/// tgid → parent tgid. Seeded from `/proc` for processes that predate attach.
#[map]
static PARENT_OF: LruHashMap<u32, u32> = LruHashMap::with_max_entries(16384, 0);

/// Strings stashed by `sys_enter_execve` for `sched_process_exec` /
/// `sys_exit_execve` to pick up, keyed by (tid, slot).
///
/// Stashed as *text*, not as pointers, and that is the entire point of the map.
/// `sys_enter_execve` is the last moment the argument vector exists: by the time
/// `sched_process_exec` fires the process has a new address space and the old
/// `char **` points into memory that has been thrown away. (The `.bt` script
/// stringified at the same instant — `@argv_N[tid] = str($a[N], 64)` — which is
/// why its argv was never empty.)
///
/// One entry per slot rather than one wide record per thread, because of the eBPF
/// stack: a struct holding all 17 strings is ~1.1 KiB and a program gets 512.
/// The `.bt` script ran into the same wall and answered it the same way, one map
/// per index — its "8 × 64 = 512" comment is about exactly this limit.
///
/// LRU rather than a plain hash so that a stash orphaned by some path I cannot
/// foresee evicts instead of accumulating until inserts start failing; at 17
/// slots per exec this holds ~120 execs in flight, and the real window is the
/// handful of microseconds an `execve` call takes.
#[map]
static STR_STASH: LruHashMap<u64, StrSlot> = LruHashMap::with_max_entries(2048, 0);

/// `sys_enter_openat` → `sys_exit_openat`.
#[map]
static OPEN_STASH: LruHashMap<u32, OpenStash> = LruHashMap::with_max_entries(8192, 0);

/// `sys_enter_connect` → `sys_exit_connect`.
#[map]
static CONN_STASH: LruHashMap<u32, ConnStash> = LruHashMap::with_max_entries(8192, 0);

// ===========================================================================
// Stash records (built as stack locals, then inserted by reference)
// ===========================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct StrSlot {
    /// Packed length: payload byte count in bits 0..6, [`LEN_TRUNC`] in bit 7.
    len: u8,
    buf: [u8; STR_MAX],
}

/// The `filename` slot: one past the last argument slot, so a tid's argv and its
/// filename share one flat per-tid slot space. Also the "we saw the entry side"
/// marker that gates the failure path — the `.bt` script spelled that as a
/// separate `@argv_has[tid]`.
const SLOT_FNAME: usize = ARGV_MAX;

#[repr(C)]
struct OpenStash {
    flags: u64,
    dirfd: i64,
    len: u8,
    buf: [u8; STR_MAX],
}

#[repr(C)]
struct ConnStash {
    fd: i64,
    family: u16,
    port: u16,
    alen: u8,
    addr: [u8; 16],
}

// ===========================================================================
// Field access
// ===========================================================================

#[inline(always)]
fn cfg(slot: u32) -> u64 {
    CONFIG.get(slot).copied().unwrap_or(0)
}

/// Read a tracepoint field described by `CONFIG[slot]`.
///
/// The width and signedness travel with the offset (see the `field` constructor in
/// the shared crate) because the record's declared `size` is *not* the width of
/// the value: `field:int flags; offset:32; size:8;` stores 8 bytes of which 4 are
/// the value. Reading all 8 would fold the next field in and, for `openat`'s
/// `flags`, make every read-only open look like a write.
#[inline(always)]
fn field(ctx: &TracePointContext, slot: u32) -> i64 {
    let enc = cfg(slot);
    if enc == 0 {
        return 0;
    }
    let off = (enc >> 8) as usize;
    let signed = enc & 0x10 != 0;
    match (enc & 0xF, signed) {
        (0, false) => unsafe { ctx.read_at::<u8>(off) }.unwrap_or(0) as i64,
        (0, true) => unsafe { ctx.read_at::<i8>(off) }.unwrap_or(0) as i64,
        (1, false) => unsafe { ctx.read_at::<u16>(off) }.unwrap_or(0) as i64,
        (1, true) => unsafe { ctx.read_at::<i16>(off) }.unwrap_or(0) as i64,
        (2, false) => unsafe { ctx.read_at::<u32>(off) }.unwrap_or(0) as i64,
        (2, true) => unsafe { ctx.read_at::<i32>(off) }.unwrap_or(0) as i64,
        (3, false) => unsafe { ctx.read_at::<u64>(off) }.unwrap_or(0) as i64,
        _ => unsafe { ctx.read_at::<i64>(off) }.unwrap_or(0),
    }
}

#[inline(always)]
fn ids() -> (u32, u32) {
    let v = bpf_get_current_pid_tgid();
    ((v >> 32) as u32, v as u32)
}

#[inline(always)]
fn ts() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

#[inline(always)]
fn cgroup_id() -> u64 {
    unsafe { bpf_get_current_cgroup_id() }
}

#[inline(always)]
fn src_on(bit: u64) -> bool {
    cfg(CFG_SRC) & bit != 0
}

/// Is this task inside the trace target? Mirrors the `FILTER` placeholder.
#[inline(always)]
fn matches(tgid: u32) -> bool {
    if cfg(CFG_MODE) == MODE_CGROUP {
        cgroup_id() == cfg(CFG_CGROUP_ID)
    } else {
        unsafe { IN_TREE.get(&tgid) }.is_some()
    }
}

#[inline(always)]
fn parent_of(tgid: u32) -> u32 {
    unsafe { PARENT_OF.get(&tgid) }.copied().unwrap_or(0)
}

/// Read a NUL-terminated string of at most `dst.len()` bytes into `dst` and pack
/// the outcome for a [`RawEvent::lens`] slot. 0 means "nothing readable here",
/// which is what bpftrace's `str(NULL)` rendered as too.
///
/// Calls `bpf_probe_read_{user,kernel}_str` through `gen` rather than using aya's
/// `*_str_bytes` wrapper, because the wrapper discards the one number that
/// carries the truncation signal. It trims the NUL and hands back a slice, so a
/// caller cannot tell "the string ended after 63 bytes" from "the buffer ran out
/// at 64" — while the raw helper returns the byte count *including* the NUL, and
/// that count equals the buffer size exactly when the buffer filled up. That case
/// is the one bpftrace printed as 63 bytes plus `..`, so it is the case this
/// returns [`LEN_TRUNC`] for. (aya's own raw-count helper is `#[deprecated]` in
/// favour of the lossy one, hence going through `gen` directly.)
///
/// # Safety
///
/// `src` is untrusted: a user pointer from a tracepoint context, or an address
/// inside the trace record. The helper validates it and reports failure rather
/// than faulting, which is why this is sound even for an arbitrary value.
#[inline(always)]
unsafe fn read_str(kernel: bool, dst: &mut [u8], src: u64) -> u8 {
    let p = src as *const u8;
    if p.is_null() || dst.is_empty() {
        return 0;
    }
    let raw = if kernel {
        gen::bpf_probe_read_kernel_str(
            dst.as_mut_ptr() as *mut c_void,
            dst.len() as u32,
            p as *const c_void,
        )
    } else {
        gen::bpf_probe_read_user_str(
            dst.as_mut_ptr() as *mut c_void,
            dst.len() as u32,
            p as *const c_void,
        )
    };
    if raw <= 0 {
        return 0;
    }
    // Clamped to the buffer, which the kernel guarantees anyway; stating it keeps
    // the arithmetic below in range from the verifier's point of view, the same
    // reason aya's own wrapper ends in `.min(dest.len())`.
    let raw = core::cmp::min(raw as usize, dst.len());
    RawEvent::pack_len(raw - 1, raw >= dst.len())
}

/// Read a NUL-terminated user string into `dst`; an unreadable slot reads as an
/// empty field, and an empty argv slot is how the parser knows the argument
/// vector ended.
#[inline(always)]
fn read_ustr(dst: &mut [u8], p: u64) -> u8 {
    unsafe { read_str(false, dst, p) }
}

/// Follow a user pointer to another user pointer (`argv` is `char **`).
#[inline(always)]
fn deref_user(p: u64) -> u64 {
    if p == 0 {
        return 0;
    }
    unsafe { bpf_probe_read_user(p as *const u64) }.unwrap_or(0)
}

#[inline(always)]
fn argv_at(argv_ptr: u64, i: usize) -> u64 {
    if argv_ptr == 0 {
        return 0;
    }
    deref_user(argv_ptr + (i as u64) * 8)
}

/// Read the string behind a tracepoint `__data_loc char[]` field.
///
/// The encoded length is used only as a validity check, never as the buffer size:
/// it counts the NUL, so handing the helper a buffer of exactly that size would
/// leave no room for the terminator and turn every exact-length string into a
/// truncated one ("bash" read as "bash.."). The helper is given the whole
/// destination and stops at the NUL the kernel wrote into the record, which also
/// makes it — not the data_loc length — the thing that reports truncation.
#[inline(always)]
fn read_data_loc(ctx: &TracePointContext, slot: u32, dst: &mut [u8]) -> u8 {
    let enc = cfg(slot);
    if enc == 0 {
        return 0;
    }
    let Ok(raw) = (unsafe { ctx.read_at::<u32>((enc >> 8) as usize) }) else {
        return 0;
    };
    if raw == 0 {
        return 0;
    }
    let d = data_loc_offset(raw);
    let l = data_loc_len(raw);
    if d == 0 || l == 0 {
        return 0;
    }
    let src = ctx.as_ptr() as u64 + d as u64;
    unsafe { read_str(true, dst, src) }
}

/// Key for [`STR_STASH`]: the thread id in the high bits, the slot index in the
/// low byte. A stash is always read back by the tid that wrote it, and tids are
/// bounded by `pid_max` (2^22 on every kernel that can run this), so the two
/// halves cannot collide.
#[inline(always)]
fn stash_key(tid: u32, slot: usize) -> u64 {
    ((tid as u64) << 8) | slot as u64
}

/// Stringify `p` at syscall-entry time and stash it under `slot`.
///
/// A failed read yields an empty slot, which is what bpftrace's `str(NULL)`
/// produced as well, so the two collectors agree byte for byte. `keep_empty`
/// forces the entry to be written anyway; the `filename` slot needs that, since
/// its *presence* is the failure path's proof that the entry side ran.
#[inline(always)]
fn stash_ustr(tid: u32, slot: usize, p: u64, keep_empty: bool) {
    let mut s = StrSlot {
        len: 0,
        buf: [0u8; STR_MAX],
    };
    s.len = read_ustr(&mut s.buf, p);
    if s.len == 0 && !keep_empty {
        return;
    }
    let _ = STR_STASH.insert(&stash_key(tid, slot), &s, 0);
}

/// Copy a stashed string into a record's string slot, dropping the entry.
///
/// Returns the packed length, or 0 when nothing was stashed — the same empty
/// field an unreadable pointer produced on the way in.
///
/// The copy is a fixed-width slot assignment rather than `put(dst, &s.buf[..n])`.
/// The two are equivalent on the wire — the loader reads `strs[i][..len_of(i)]`
/// and never looks at the tail — but a runtime-length copy compiles to a byte
/// loop of up to `STR_MAX` iterations *nested inside* the `ARGV_MAX` slot loop
/// below, and the verifier has to explore every one of those states. This single
/// call site was the bulk of `on_exec`'s 377ms and `on_execve_exit`'s 231ms of
/// load time; a constant-size copy has no back edge, so there is nothing to
/// explore.
#[inline(always)]
fn take_str(tid: u32, slot: usize, dst: &mut [u8; STR_MAX]) -> u8 {
    let k = stash_key(tid, slot);
    let len = match unsafe { STR_STASH.get(&k) } {
        Some(s) => {
            *dst = s.buf;
            s.len
        }
        None => 0,
    };
    let _ = STR_STASH.remove(&k);
    len
}

/// The task's 16-byte comm, NUL included, plus a NUL-only fallback for the
/// (practically impossible) failure case.
#[inline(always)]
fn comm_buf() -> ([u8; STR_MAX], u8) {
    let mut out = [0u8; STR_MAX];
    let raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let mut n = 0usize;
    while n < 16 && raw[n] != 0 {
        n += 1;
    }
    out[..n].copy_from_slice(&raw[..n]);
    (out, RawEvent::pack_len(n, false))
}

/// `task_struct.exit_code >> 8`, the same expression the `.bt` script used.
#[inline(always)]
fn task_exit_code() -> i64 {
    let off = cfg(CFG_TASK_EXIT_CODE);
    if off == 0 {
        return 0;
    }
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return 0;
    }
    match unsafe { bpf_probe_read_kernel::<i32>((task + off) as *const i32) } {
        Ok(v) => (v >> 8) as i64,
        Err(_) => 0,
    }
}

/// Copy the first `src.len()` bytes of `src` into a record's string slot.
///
/// Only the connect path needs this: its source is the 16-byte address buffer,
/// not a `STR_MAX` string slot, so the widths differ and a slot assignment would
/// not typecheck. It is the only remaining runtime-length copy, and it lives in
/// the cheapest program to load (10ms) — the hot copies in `on_exec` /
/// `on_execve_exit` are fixed-width assignments instead; see [`take_str`].
#[inline(always)]
fn put(dst: &mut [u8], src: &[u8]) {
    let n = core::cmp::min(src.len(), dst.len());
    dst[..n].copy_from_slice(&src[..n]);
}

/// Reserve a record, fill in the common header, run `$body`, and submit.
///
/// Deliberately a macro rather than a function: handing a live `RingBufEntry` back
/// across a call boundary makes the verifier's release analysis harder, and a
/// reserved-but-never-submitted entry is a verifier error — so every call site has
/// to "compute everything first, then emit", and that shape is easiest to keep
/// when the reservation is visibly inline.
macro_rules! emit {
    ($kind:expr, $e:ident, $body:block) => {{
        if let Some(mut __entry) = EVENTS.reserve::<RawEvent>(0) {
            let $e: &mut RawEvent = unsafe { &mut *__entry.as_mut_ptr() };
            $e.clear();
            $e.kind = $kind;
            $e.ts_ns = ts();
            let (__pid, __tid) = ids();
            $e.pid = __pid;
            $e.tid = __tid;
            $e.cgroup = cgroup_id();
            $body
            __entry.submit(0);
        } else if let Some(__c) = LOST.get_ptr_mut(0) {
            unsafe { *__c += 1 };
        }
    }};
}

// ===========================================================================
// GROUP: process tree — always on, independent of --source
//
// The tree filter is the precondition for the file and net groups, so fork and
// the seed initialisation can never be switched off; `--source` only controls what
// is *emitted*, never what is *filtered*.
// ===========================================================================

#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn on_fork(ctx: TracePointContext) -> u32 {
    let (pid, _tid) = ids();
    if !matches(pid) {
        return 0;
    }
    let child_pid = field(&ctx, CFG_FORK_CHILD_PID);
    if child_pid == 0 {
        return 0;
    }
    let child_pid = child_pid as u32;

    // Read the comms before reserving anything.
    let mut child_comm = [0u8; STR_MAX];
    let mut parent_comm = [0u8; STR_MAX];
    let child_len = read_data_loc(&ctx, CFG_FORK_CHILD_COMM, &mut child_comm);
    let parent_len = read_data_loc(&ctx, CFG_FORK_PARENT_COMM, &mut parent_comm);

    let _ = IN_TREE.insert(&child_pid, &1u8, 0);
    let _ = PARENT_OF.insert(&child_pid, &pid, 0);

    if !src_on(SRC_EXEC) {
        return 0;
    }
    let grandparent = parent_of(pid);
    emit!(KIND_FORK, e, {
        e.ppid = grandparent;
        // The protocol's FORK row has no tid column; child_pid rides in n0.
        e.n0 = child_pid as i64;
        e.n_str = 2;
        e.lens[0] = child_len;
        e.lens[1] = parent_len;
        e.strs[0] = child_comm;
        e.strs[1] = parent_comm;
    });
    0
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn on_exit(ctx: TracePointContext) -> u32 {
    let (pid, _tid) = ids();
    if !matches(pid) {
        return 0;
    }
    let (comm, clen) = comm_buf();
    let code = task_exit_code();
    let group_dead = field(&ctx, CFG_EXIT_GROUP_DEAD) != 0;

    if src_on(SRC_EXEC) {
        emit!(KIND_EXIT, e, {
            e.ppid = parent_of(pid);
            e.n0 = code;
            e.n_str = 1;
            e.lens[0] = clen;
            e.strs[0] = comm;
        });
    }

    // Only the last thread of a group evicts it. See the module comment: the `.bt`
    // script evicted on every thread exit and silently lost multi-threaded targets
    // from the filter.
    if group_dead {
        let _ = IN_TREE.remove(&pid);
        let _ = PARENT_OF.remove(&pid);
    }
    // No stash cleanup here: `STR_STASH` is an LRU, so anything a dying thread
    // left behind evicts on its own. Draining 17 slots on every exit would cost
    // more than the leak it prevents — and there is no leak to prevent, since a
    // task cannot leave `execve` without passing through one of the two readers.
    0
}

// ===========================================================================
// GROUP: exec
// ===========================================================================

/// argv (and the filename, for the failure path) can only be read on the way in;
/// `comm` on the way in is still the *parent's*, so no event is produced here.
#[tracepoint(name = "sys_enter_execve", category = "syscalls")]
pub fn on_execve_enter(ctx: TracePointContext) -> u32 {
    let (pid, tid) = ids();
    if !matches(pid) || !src_on(SRC_EXEC) {
        return 0;
    }
    let fname_ptr = field(&ctx, CFG_EXECVE_FILENAME) as u64;
    let argv_ptr = field(&ctx, CFG_EXECVE_ARGV) as u64;

    stash_ustr(tid, SLOT_FNAME, fname_ptr, true);
    // Stopping at the first null slot is what `argv[argc] == NULL` means, and it
    // is also what keeps the common case cheap: a two-word command writes two
    // entries instead of sixteen. The rows the parser sees are unchanged — a slot
    // with no stash reads back as the empty field bpftrace's `str(NULL)` produced
    // for the same slot, and the parser stops at the first empty one either way.
    let mut i = 0usize;
    while i < ARGV_MAX {
        let p = argv_at(argv_ptr, i);
        if p == 0 {
            break;
        }
        stash_ustr(tid, i, p, false);
        i += 1;
    }
    0
}

/// The real producer of EXEC rows: by the time this fires, `comm` is already the
/// new binary's name, and it only fires when the exec actually succeeded.
#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn on_exec(ctx: TracePointContext) -> u32 {
    let (pid, tid) = ids();
    if !matches(pid) || !src_on(SRC_EXEC) {
        return 0;
    }

    let mut fname = [0u8; STR_MAX];
    let flen = read_data_loc(&ctx, CFG_EXEC_FILENAME, &mut fname);
    let (comm, clen) = comm_buf();
    let ppid = parent_of(pid);

    emit!(KIND_EXEC, e, {
        e.ppid = ppid;
        e.n0 = ARGV_MAX as i64;
        e.n_str = MAX_STRS as u32;
        e.lens[0] = clen;
        e.strs[0] = comm;
        e.lens[1] = flen;
        e.strs[1] = fname;
        let mut i = 0usize;
        while i < ARGV_MAX {
            e.lens[2 + i] = take_str(tid, i, &mut e.strs[2 + i]);
            i += 1;
        }
    });
    // The ARGV loop above drains slots 0..ARGV_MAX; the filename sits one past
    // them, so it needs evicting on its own. (The failure path reads it instead.)
    let _ = STR_STASH.remove(&stash_key(tid, SLOT_FNAME));
    0
}

/// A failed execve never reaches `sched_process_exec`, so this is the only place an
/// exec failure can be reported. The presence of the stashed filename is the proof
/// that we saw the entry side — the same filter the `.bt` script expressed as
/// `@argv_has[tid]`.
#[tracepoint(name = "sys_exit_execve", category = "syscalls")]
pub fn on_execve_exit(ctx: TracePointContext) -> u32 {
    let (pid, tid) = ids();
    if !matches(pid) {
        return 0;
    }
    if unsafe { STR_STASH.get(&stash_key(tid, SLOT_FNAME)) }.is_none() {
        return 0;
    }
    // A successful execve never returns, so this is nearly always the failure
    // path; the check keeps the two producers mutually exclusive regardless.
    let ret = field(&ctx, CFG_SYS_RET);
    if ret >= 0 {
        return 0;
    }
    let mut fname = [0u8; STR_MAX];
    let flen = take_str(tid, SLOT_FNAME, &mut fname);
    let (comm, clen) = comm_buf();
    let ppid = parent_of(pid);

    emit!(KIND_FAIL, e, {
        e.ppid = ppid;
        e.n0 = ARGV_MAX as i64;
        e.n1 = ret;
        e.n_str = MAX_STRS as u32;
        e.lens[0] = clen;
        e.strs[0] = comm;
        e.lens[1] = flen;
        e.strs[1] = fname;
        let mut i = 0usize;
        while i < ARGV_MAX {
            e.lens[2 + i] = take_str(tid, i, &mut e.strs[2 + i]);
            i += 1;
        }
    });
    0
}

// ===========================================================================
// GROUP: file
// ===========================================================================

/// Entry side only stashes: `sys_exit_openat` has no filename field.
///
/// The write-intent / sensitive-path filter is *not* applied here — it lives in
/// `KernelLineParser::handle_open`, shared with the bpftrace collector. Every open
/// is streamed to userspace even with `--file-all` off, which is what the v0.4.2
/// design already does (`@@FILE_PRED@@` renders as the constant `1`).
#[tracepoint(name = "sys_enter_openat", category = "syscalls")]
pub fn on_openat_enter(ctx: TracePointContext) -> u32 {
    let (pid, tid) = ids();
    if !matches(pid) {
        return 0;
    }
    if !src_on(SRC_FILE) {
        return 0;
    }
    let dirfd = field(&ctx, CFG_OPENAT_DFD);
    let fname_ptr = field(&ctx, CFG_OPENAT_FILENAME) as u64;
    let flags = field(&ctx, CFG_OPENAT_FLAGS);

    let mut st = OpenStash {
        flags: flags as u64,
        dirfd,
        len: 0,
        buf: [0u8; STR_MAX],
    };
    st.len = read_ustr(&mut st.buf, fname_ptr);
    let _ = OPEN_STASH.insert(&tid, &st, 0);
    0
}

#[tracepoint(name = "sys_exit_openat", category = "syscalls")]
pub fn on_openat_exit(ctx: TracePointContext) -> u32 {
    let (pid, tid) = ids();
    if !matches(pid) {
        return 0;
    }
    if unsafe { OPEN_STASH.get(&tid) }.is_none() {
        return 0;
    }
    let Some(st) = (unsafe { OPEN_STASH.get(&tid) }) else {
        return 0;
    };
    let ret = field(&ctx, CFG_SYS_RET);
    let (flags, dirfd, len) = (st.flags, st.dirfd, st.len);
    let buf = st.buf;
    let ppid = parent_of(pid);

    emit!(KIND_OPEN, e, {
        e.ppid = ppid;
        e.n0 = flags as i64;
        e.n1 = dirfd;
        e.n2 = ret;
        e.n_str = 1;
        e.lens[0] = len;
        e.strs[0] = buf;
    });
    let _ = OPEN_STASH.remove(&tid);
    0
}

// ===========================================================================
// GROUP: net
// ===========================================================================

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
pub fn on_connect_enter(ctx: TracePointContext) -> u32 {
    let (pid, tid) = ids();
    if !matches(pid) || !src_on(SRC_NET) {
        return 0;
    }
    let fd = field(&ctx, CFG_CONNECT_FD);
    let sa = field(&ctx, CFG_CONNECT_ADDR) as u64;

    let mut st = ConnStash {
        fd,
        family: 0,
        port: 0,
        alen: 0,
        addr: [0u8; 16],
    };
    if sa != 0 {
        st.family = unsafe { bpf_probe_read_user(sa as *const u16) }.unwrap_or(0);
        match st.family {
            2 => {
                // AF_INET: sin_port at offset 2, sin_addr at 4, 4 bytes. The port is
                // kept in network order here and byte-swapped by the loader.
                st.port = unsafe { bpf_probe_read_user((sa + 2) as *const u16) }.unwrap_or(0);
                let mut a = [0u8; 4];
                if unsafe { bpf_probe_read_user_buf((sa + 4) as *const u8, &mut a) }.is_ok() {
                    st.addr[..4].copy_from_slice(&a);
                    st.alen = 4;
                }
            }
            10 => {
                // AF_INET6: sin6_port at offset 2, sin6_addr at 8, 16 bytes.
                st.port = unsafe { bpf_probe_read_user((sa + 2) as *const u16) }.unwrap_or(0);
                let mut a = [0u8; 16];
                if unsafe { bpf_probe_read_user_buf((sa + 8) as *const u8, &mut a) }.is_ok() {
                    st.addr = a;
                    st.alen = 16;
                }
            }
            // AF_UNIX and friends have no address; the protocol says so by printing
            // a literal instead of an address (see the loader's `format_record`).
            _ => {}
        }
    }
    let _ = CONN_STASH.insert(&tid, &st, 0);
    0
}

#[tracepoint(name = "sys_exit_connect", category = "syscalls")]
pub fn on_connect_exit(ctx: TracePointContext) -> u32 {
    let (pid, tid) = ids();
    if !matches(pid) {
        return 0;
    }
    let Some(st) = (unsafe { CONN_STASH.get(&tid) }) else {
        return 0;
    };
    let ret = field(&ctx, CFG_SYS_RET);
    let (fd, family, port, alen) = (st.fd, st.family, st.port, st.alen);
    let addr = st.addr;
    // `alen` comes out of a map, so its range is not tracked by the verifier —
    // and `addr` is exactly 16 bytes. Clamp before slicing; the value is 4 or 16
    // for every family this program records, so nothing is ever cut short.
    let alen = core::cmp::min(alen as usize, addr.len());
    let ppid = parent_of(pid);

    emit!(KIND_CONN, e, {
        e.ppid = ppid;
        e.n0 = fd;
        e.n1 = family as i64;
        e.n2 = port as i64;
        e.n3 = ret;
        e.n_str = 1;
        e.lens[0] = alen as u8;
        put(&mut e.strs[0], &addr[..alen]);
    });
    let _ = CONN_STASH.remove(&tid);
    0
}

/// `sendto` coverage is not expected to be high: modern HTTP clients use
/// `sendmsg`/`write`. Collected for parity with the `.bt` script, not relied on.
#[tracepoint(name = "sys_enter_sendto", category = "syscalls")]
pub fn on_sendto(ctx: TracePointContext) -> u32 {
    let (pid, _tid) = ids();
    if !matches(pid) || !src_on(SRC_NET) {
        return 0;
    }
    let fd = field(&ctx, CFG_SENDTO_FD);
    let len = field(&ctx, CFG_SENDTO_LEN);
    let ppid = parent_of(pid);

    emit!(KIND_SEND, e, {
        e.ppid = ppid;
        e.n0 = fd;
        e.n1 = len;
        e.n_str = 0;
    });
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
