//! ABI shared by the eBPF programs (`agtrace-ebpf`) and their userspace loader.
//!
//! This crate is deliberately dependency-free and `no_std` so that the *same* type
//! definitions compile both for `bpfel-unknown-none` (inside the kernel verifier's
//! view) and for the host. The ring-buffer record is hand-rolled rather than
//! derived, because the two sides must agree byte for byte: a field inserted on one
//! side and forgotten on the other would silently shift every offset after it.
//!
//! Nothing here knows about the line protocol in `src/collector/mod.rs`. The eBPF
//! side ships *structured* records; the loader is what turns them into
//! `OPEN|...` / `CONN|...` / ... lines, so that the parser, merger, views and
//! render layers are shared with the bpftrace collector rather than duplicated.

#![no_std]

/// Bytes available per string field.
///
/// Deliberately equal to the bpftrace side's effective cap (`MAX_STRLEN` in
/// `src/collector/bpftrace.rs`). Keeping the two collectors on the same cap means
/// the truncation marker `..` and every `trunc` note in the output stay identical
/// no matter which collector produced the run — a difference here would silently
/// change what "truncated" means between two runs of the same command line.
pub const STR_MAX: usize = 64;

/// argv slots the eBPF side always captures. `--argv-max` above this falls back to
/// bpftrace, which can expand the script to any width.
pub const ARGV_MAX: usize = 16;

/// String slots per record: `[0]` comm/first, `[1]` filename/second, `[2..]` argv.
pub const MAX_STRS: usize = ARGV_MAX + 2;

// ---- record kinds ----
pub const KIND_EXEC: u32 = 1;
pub const KIND_FAIL: u32 = 2;
pub const KIND_FORK: u32 = 3;
pub const KIND_EXIT: u32 = 4;
pub const KIND_OPEN: u32 = 5;
pub const KIND_CONN: u32 = 6;
pub const KIND_SEND: u32 = 7;

// ===========================================================================
// CONFIG map
// ===========================================================================
//
// The tracepoints this program attaches to do **not** expose a generic
// `args[6]` array. Each one declares its syscall arguments as *named* fields at
// kernel-version-specific offsets (`field:int dfd; offset:16;`, `field:int flags;
// offset:32;`), so every field the program reads has to be looked up in
// `/sys/kernel/{debug/,}tracing/events/<cat>/<name>/format` at load time and
// handed over as an offset. Hardcoding them would break on the next kernel
// release, and no compile step would catch it.
//
// A field slot is encoded as a bitfield rather than a bare offset, because the
// *declared C type* of a field decides how to read it — `field:int flags;
// offset:32; size:8;` declares 8 bytes of storage but only 4 bytes of value, and
// bpftrace reads the declared type (`int dfd` printed as `-100` through `%d`
// while the format file says `signed:0`, which pins this down). Reading 8 bytes
// there would fold the neighbouring field into the value and, for `flags`, turn
// read-only opens into apparent writes.
//
//   bits  0..3  width code: 0 = 1 byte, 1 = 2, 2 = 4, 3 = 8
//   bit   4     signed: sign-extend when widening
//   bits  8..   byte offset within the tracepoint record
//
// Offset 0 is never a field we read, so an all-zero slot reliably means "the
// loader did not fill this in" and the read degrades to 0 instead of garbage.
pub const CFG_MODE: u32 = 0;
/// cgroup id, only meaningful when `CFG_MODE == MODE_CGROUP`.
pub const CFG_CGROUP_ID: u32 = 1;
/// Bitmask of `SRC_*`: which groups are allowed to *emit* (mirrors `--source`).
pub const CFG_SRC: u32 = 2;
/// `sys_exit_*` → `ret`.
pub const CFG_SYS_RET: u32 = 3;
/// `sched_process_fork` → `parent_pid`, `child_pid`, `child_comm`, `parent_comm`.
pub const CFG_FORK_PARENT_PID: u32 = 4;
pub const CFG_FORK_CHILD_PID: u32 = 5;
pub const CFG_FORK_CHILD_COMM: u32 = 6;
pub const CFG_FORK_PARENT_COMM: u32 = 7;
/// `sched_process_exec` → `filename` (a `__data_loc char[]`).
pub const CFG_EXEC_FILENAME: u32 = 8;
/// `sys_enter_execve` → `filename`, `argv`.
pub const CFG_EXECVE_FILENAME: u32 = 9;
pub const CFG_EXECVE_ARGV: u32 = 10;
/// `sys_enter_openat` → `dfd`, `filename`, `flags`.
pub const CFG_OPENAT_DFD: u32 = 11;
pub const CFG_OPENAT_FILENAME: u32 = 12;
pub const CFG_OPENAT_FLAGS: u32 = 13;
/// `sys_enter_connect` → `fd`, `uservaddr`.
pub const CFG_CONNECT_FD: u32 = 14;
pub const CFG_CONNECT_ADDR: u32 = 15;
/// `sys_enter_sendto` → `fd`, `len`.
pub const CFG_SENDTO_FD: u32 = 16;
pub const CFG_SENDTO_LEN: u32 = 17;
/// `sched_process_exit` → `group_dead`. Gates eviction from `IN_TREE`: it is true
/// only for the last thread of a thread group, so a target that spawns and reaps
/// threads stays in the filter. The `.bt` script evicted on every thread exit and
/// silently lost multi-threaded targets; see `agtrace-ebpf/src/main.rs`.
pub const CFG_EXIT_GROUP_DEAD: u32 = 18;
/// Byte offset of `task_struct.exit_code`, resolved from `/sys/kernel/btf/vmlinux`.
/// No syscall tracepoint sees the exit status of a signal death, so this is read
/// off the task the way bpftrace's `curtask->exit_code` was.
pub const CFG_TASK_EXIT_CODE: u32 = 19;
/// `1` when this kernel's `sched_process_exit` tracepoint has **no** `group_dead`
/// field (mainline added it in 6.8; LTS kernels such as 5.15 — and WSL2's kernel —
/// do not have it). The probe then falls back to "the group leader is exiting"
/// (`tgid == tid`, from `bpf_get_current_pid_tgid`), which is equivalent for the
/// single-threaded commands agent tool calls spawn. Present in the ABI from the
/// start (default 0) so the record layout and the config array never disagree.
pub const CFG_EXIT_GROUP_DEAD_FALLBACK: u32 = 20;
pub const CFG_COUNT: u32 = 21;

pub const MODE_PID_TREE: u64 = 0;
pub const MODE_CGROUP: u64 = 1;

pub const SRC_EXEC: u64 = 1 << 0;
pub const SRC_FILE: u64 = 1 << 1;
pub const SRC_NET: u64 = 1 << 2;

/// Encode a field descriptor for a `CONFIG` slot.
///
/// `width_code`: 0 = 1 byte, 1 = 2, 2 = 4, 3 = 8. Offsets are record-relative and
/// always non-zero for the fields this program reads.
pub const fn field(offset: u32, width_code: u32, signed: bool) -> u64 {
    ((offset as u64) << 8) | (width_code as u64) | if signed { 0x10 } else { 0 }
}

pub const W1: u32 = 0;
pub const W2: u32 = 1;
pub const W4: u32 = 2;
pub const W8: u32 = 3;

/// One record on the eBPF → userspace ring buffer.
///
/// Deliberately one flat struct for every kind: a single ring buffer keeps the
/// kernel-side ordering total (two buffers would let an `openat` overtake the
/// `exec` that preceded it), and `reserve`/`submit` then costs one memcpy-free
/// reservation per emitted event.
///
/// Which numeric slots mean what is decided by `kind`; the loader owns that
/// mapping. `strs[0]`/`strs[1]` are comm/filename, `strs[2..]` are argv.
#[repr(C)]
pub struct RawEvent {
    pub kind: u32,
    /// Number of `strs` entries the producer actually filled.
    pub n_str: u32,
    pub ts_ns: u64,
    /// Thread-group id == the userspace-visible "pid".
    pub pid: u32,
    /// Kernel thread id == tid.
    pub tid: u32,
    /// Parent thread-group id, sourced from the `PARENT_OF` map.
    pub ppid: u32,
    /// ABI 哨兵；见 [`RAW_MAGIC`]。
    ///
    /// 这个位置本来就是对齐用的填充（4 字节），拿它当哨兵是**零代价**的：
    /// 结构体大小不变，两侧的内存布局也不变，内核侧只多一条 store。
    pub magic: u32,
    pub cgroup: u64,
    /// Kind-specific numbers; see the loader's `format_record`.
    pub n0: i64,
    pub n1: i64,
    pub n2: i64,
    pub n3: i64,
    pub strs: [[u8; STR_MAX]; MAX_STRS],
    /// Meaningful byte count per string, with the truncation flag folded into the
    /// top bit — see [`LEN_MASK`] / [`LEN_TRUNC`]. `0` means "absent or
    /// unreadable", which the loader renders as an empty field exactly the way
    /// `str(NULL)` did under bpftrace.
    ///
    /// Two facts have to travel per string: how many bytes are real, and whether
    /// the value was cut short. The second one cannot be re-derived downstream —
    /// "a 63-byte path" and "a 200-byte path truncated to 63 bytes" are identical
    /// byte sequences — and the parser needs it to print its `..` tail and its
    /// `trunc` note. One `u8` per string holds both, since a string never exceeds
    /// `STR_MAX` = 64 and the count therefore never needs more than 7 bits.
    pub lens: [u8; MAX_STRS],
}

impl RawEvent {
    /// Zero the record in place.
    ///
    /// Written as a `write_bytes` rather than `*self = RawEvent::ZERO` so that no
    /// ~1.2 KiB temporary is materialised on the 512-byte eBPF stack.
    #[inline(always)]
    pub fn clear(&mut self) {
        unsafe {
            core::ptr::write_bytes(
                self as *mut Self as *mut u8,
                0,
                core::mem::size_of::<Self>(),
            )
        }
    }

    /// The `i`-th string as a byte slice, or `&[]` when the producer filled nothing.
    #[inline(always)]
    pub fn str_bytes(&self, i: usize) -> &[u8] {
        &self.strs[i][..self.len_of(i) as usize]
    }

    /// Length of string `i` in bytes, with the truncation bit masked off.
    #[inline(always)]
    pub fn len_of(&self, i: usize) -> u8 {
        self.lens[i] & LEN_MASK
    }

    /// Whether string `i` was cut short at [`STR_MAX`] bytes.
    #[inline(always)]
    pub fn is_trunc(&self, i: usize) -> bool {
        self.lens[i] & LEN_TRUNC != 0
    }

    /// Pack a byte count and a truncation flag into one `lens` slot.
    #[inline(always)]
    pub fn pack_len(n: usize, trunc: bool) -> u8 {
        let n = if n > LEN_MASK as usize {
            LEN_MASK
        } else {
            n as u8
        };
        if trunc { n | LEN_TRUNC } else { n }
    }
}

/// [`RawEvent::magic`] 的取值：`AGT` + 版本低 8 位。
///
/// 内核侧和用户态各自从同一份 crate 编译，所以**正常情况下**布局一定一致。
/// 这个哨兵防的是"不一致却看不出来"：环缓冲里的记录是按内核那份结构体
/// `reserve` 出来的，用户态再按自己这份解释。两者大小不同时已有长度检查兜底
///（见 loader 的 `skipped`），但**大小相同而字段挪了位置**（重排、互换两个
/// 同宽字段）是静默的 —— 那条路只能靠一个显式写在记录里的常量堵上。
///
/// 改布局就改这个数：让陈旧的内核对象自己撞死，而不是把字段读成别的意思。
pub const RAW_MAGIC: u32 = 0x4147_5401; // "AGT" | 版本 1

/// Payload-length bits of a [`RawEvent::lens`] slot.
pub const LEN_MASK: u8 = 0x7f;
/// Set in a [`RawEvent::lens`] slot when the string was truncated at [`STR_MAX`].
pub const LEN_TRUNC: u8 = 0x80;

/// Byte offset of the string data behind a tracepoint `__data_loc char[]` field.
///
/// This is the kernel's `__get_dynamic_array`, spelled out:
///
/// ```c
/// #define __get_dynamic_array(field) \
///     ((void *)__entry + (__entry->__data_loc_##field & 0xffff))
/// ```
///
/// So the **offset is the low half** and the length the high half — the opposite
/// of the "natural" reading order, and worth stating twice because getting it
/// backwards does not fault: it just reads a plausible-looking string out of the
/// wrong part of the record.
#[inline(always)]
pub fn data_loc_offset(raw: u32) -> usize {
    (raw & 0xFFFF) as usize
}

/// Length, in bytes including the NUL, encoded in a `__data_loc` field.
///
/// The kernel's `__get_dynamic_array_len` is `(loc >> 16)`.
#[inline(always)]
pub fn data_loc_len(raw: u32) -> usize {
    (raw >> 16) as usize
}
