//! Ring-buffer record → line-protocol text (v0.5).
//!
//! This is the *only* place that knows how an aya record maps onto the wire
//! format documented at the top of `scripts/agtrace.bt`. Everything downstream —
//! `KernelLineParser`, the merger, views, collapse, render — is shared with the
//! bpftrace collector and never learns which one produced a line.
//!
//! Two conventions are load-bearing:
//!
//! * **Truncation is re-materialised as `..`.** The eBPF side knows a string was
//!   cut short (it filled its buffer), but that fact cannot be recovered from the
//!   bytes: a 63-byte path and a 200-byte path cut to 63 bytes look identical.
//!   The parser detects truncation *only* by the trailing `..` that bpftrace
//!   printed, and uses it to emit a `trunc` note — so the marker travels with the
//!   record and is reproduced here. Measured against bpftrace v0.20.2: a
//!   truncated `str()` yields 63 content bytes followed by `..`.
//!
//! * **`ARGV` lines are emitted unconditionally, `slots` of them.** The `.bt`
//!   template prints one `ARGV` row per slot whether or not a value was captured,
//!   and the parser's `flush_pending` reports "ARGV lines incomplete" only when it
//!   receives *fewer* than `slots` of them. Emitting only the non-empty ones would
//!   therefore turn every partially-populated argv into a spurious warning.

use agtrace_ebpf_common::{
    ARGV_MAX, KIND_CONN, KIND_EXEC, KIND_EXIT, KIND_FAIL, KIND_FORK, KIND_OPEN, KIND_SEND, RawEvent,
};

/// Configuration the loader was started with; only `argv_max` reaches the wire.
#[derive(Debug, Clone, Copy)]
pub struct EmitCfg {
    pub argv_max: usize,
}

/// Byte appended to a string the kernel had to cut short.
const TRUNC_MARK: &str = "..";

impl EmitCfg {
    fn slots(&self, rec: &RawEvent) -> usize {
        let declared = rec.n0.clamp(0, ARGV_MAX as i64) as usize;
        declared.min(self.argv_max)
    }
}

/// The string in slot `i`, with the truncation marker restored.
fn s(rec: &RawEvent, i: usize) -> String {
    let raw = rec.str_bytes(i);
    if raw.is_empty() {
        return String::new();
    }
    let mut v: String = raw.iter().map(|&b| safe_char(b)).collect();
    if rec.is_trunc(i) {
        v.push_str(TRUNC_MARK);
    }
    v
}

/// One byte of a kernel string, with the two characters that would break line
/// framing replaced.
///
/// A filename may legally contain a newline. bpftrace printed it verbatim, which
/// tore the line in half and cost that event (the parser counts it as malformed).
/// Replacing only `\n` and `\r` keeps every line exactly one line without
/// touching anything a path can legitimately contain.
fn safe_char(b: u8) -> char {
    match b {
        b'\n' | b'\r' => '?',
        _ => b as char,
    }
}

/// IPv4/IPv6 from the raw address bytes the eBPF side copied out of the sockaddr.
fn addr_text(family: i64, bytes: &[u8]) -> String {
    match family {
        2 if bytes.len() >= 4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        10 if bytes.len() >= 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&bytes[..16]);
            std::net::Ipv6Addr::from(o).to_string()
        }
        // The `.bt` script printed this exact literal for AF_UNIX and friends,
        // which have no address at all (and for a v4/v6 address that could not be
        // read, where "no address" is the honest answer).
        _ => "non-IP family".to_string(),
    }
}

fn argv_lines(out: &mut String, rec: &RawEvent, slots: usize, cfg: &EmitCfg) {
    debug_assert!(slots <= cfg.argv_max);
    for i in 0..slots {
        out.push_str(&format!(
            "ARGV|{}|{}|{}|{}|{}\n",
            rec.ts_ns,
            rec.pid,
            rec.tid,
            i,
            s(rec, 2 + i)
        ));
    }
}

/// Append the protocol text for one record. Unknown kinds produce nothing.
pub fn format_record(rec: &RawEvent, cfg: &EmitCfg, out: &mut String) {
    match rec.kind {
        KIND_FORK => out.push_str(&format!(
            "FORK|{}|{}|{}|{}|{}|{}|{}\n",
            rec.ts_ns,
            rec.pid,
            rec.ppid,
            rec.cgroup,
            rec.n0,
            s(rec, 0),
            s(rec, 1)
        )),
        KIND_EXIT => out.push_str(&format!(
            "EXIT|{}|{}|{}|{}|{}|{}\n",
            rec.ts_ns,
            rec.pid,
            rec.ppid,
            rec.cgroup,
            rec.n0,
            s(rec, 0)
        )),
        KIND_EXEC => {
            out.push_str(&format!(
                "EXEC|{}|{}|{}|{}|{}|{}|{}|{}\n",
                rec.ts_ns,
                rec.pid,
                rec.tid,
                rec.ppid,
                rec.cgroup,
                cfg.slots(rec),
                s(rec, 0),
                s(rec, 1)
            ));
            argv_lines(out, rec, cfg.slots(rec), cfg);
        }
        KIND_FAIL => {
            out.push_str(&format!(
                "FAIL|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
                rec.ts_ns,
                rec.pid,
                rec.tid,
                rec.ppid,
                rec.cgroup,
                cfg.slots(rec),
                rec.n1,
                s(rec, 0),
                s(rec, 1)
            ));
            argv_lines(out, rec, cfg.slots(rec), cfg);
        }
        KIND_OPEN => {
            // `flags` is a declared `int`: mask to 32 bits so a high bit cannot
            // smear into the printed hex. The parser tests it against
            // O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND, so a sign-extended
            // `ffffffff…` would look like a write on a read-only open.
            let flags = (rec.n0 as u64) & 0xffff_ffff;
            out.push_str(&format!(
                "OPEN|{}|{}|{}|{}|{}|{:x}|{}|{}|{}\n",
                rec.ts_ns,
                rec.pid,
                rec.tid,
                rec.ppid,
                rec.cgroup,
                flags,
                rec.n1,
                rec.n2,
                s(rec, 0)
            ));
        }
        KIND_CONN => {
            // The port arrives in network order (as it sits in the sockaddr);
            // the `.bt` script printed `bswap(sin_port)`.
            let port = (rec.n2 as u16).swap_bytes();
            out.push_str(&format!(
                "CONN|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
                rec.ts_ns,
                rec.pid,
                rec.tid,
                rec.ppid,
                rec.cgroup,
                rec.n0,
                rec.n1,
                port,
                rec.n3,
                addr_text(rec.n1, rec.str_bytes(0))
            ));
        }
        KIND_SEND => out.push_str(&format!(
            "SEND|{}|{}|{}|{}|{}|{}|{}\n",
            rec.ts_ns, rec.pid, rec.tid, rec.ppid, rec.cgroup, rec.n0, rec.n1
        )),
        _ => {}
    }
}

/// `TICK|<nsecs>` — the heartbeat that proves the collector is still alive.
pub fn tick_line(ts_ns: u64) -> String {
    format!("TICK|{}\n", ts_ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agtrace_ebpf_common::MAX_STRS;

    fn rec(kind: u32) -> RawEvent {
        let mut r: RawEvent = unsafe { std::mem::zeroed() };
        r.kind = kind;
        r.ts_ns = 1_000;
        r.pid = 42;
        r.tid = 43;
        r.ppid = 7;
        r.cgroup = 99;
        r
    }

    fn set(r: &mut RawEvent, i: usize, v: &str) {
        r.strs[i][..v.len()].copy_from_slice(v.as_bytes());
        r.lens[i] = RawEvent::pack_len(v.len(), false);
    }

    fn fmt(r: &RawEvent) -> String {
        let mut out = String::new();
        format_record(r, &EmitCfg { argv_max: 3 }, &mut out);
        out
    }

    #[test]
    fn exec_is_followed_by_one_argv_line_per_slot() {
        let mut r = rec(KIND_EXEC);
        r.n0 = ARGV_MAX as i64;
        r.n_str = MAX_STRS as u32;
        set(&mut r, 0, "sleep");
        set(&mut r, 1, "/usr/bin/sleep");
        set(&mut r, 2, "sleep");
        set(&mut r, 3, "1");
        let text = fmt(&r);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "EXEC|1000|42|43|7|99|3|sleep|/usr/bin/sleep"
        );
        // Exactly `slots` rows, the empty ones included.
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[1], "ARGV|1000|42|43|0|sleep");
        assert_eq!(lines[2], "ARGV|1000|42|43|1|1");
        assert_eq!(lines[3], "ARGV|1000|42|43|2|");
    }

    #[test]
    fn truncation_is_materialised_as_the_parser_expects() {
        let mut r = rec(KIND_OPEN);
        r.n0 = 0x241; // O_WRONLY|O_CREAT|O_TRUNC
        r.n1 = -100;
        r.n2 = 3;
        r.strs[0][..3].copy_from_slice(b"abc");
        r.lens[0] = RawEvent::pack_len(3, true);
        let text = fmt(&r);
        assert_eq!(text, "OPEN|1000|42|43|7|99|241|-100|3|abc..\n");
    }

    #[test]
    fn flags_are_masked_to_the_declared_width() {
        // A sign-extended 32-bit flags value must not print as 64 bits of f's.
        let mut r = rec(KIND_OPEN);
        r.n0 = -1; // 0xffffffff sign-extended to i64
        let text = fmt(&r);
        assert!(text.contains("|ffffffff|"), "{}", text);
    }

    #[test]
    fn connect_ports_are_byte_swapped_and_addresses_rendered() {
        let mut r = rec(KIND_CONN);
        r.n0 = 5; // fd
        r.n1 = 2; // AF_INET
        r.n2 = 0x901F; // 8080 in network order, read as a little-endian u16
        r.n3 = 0; // ret
        r.strs[0][..4].copy_from_slice(&[93, 184, 216, 34]);
        r.lens[0] = RawEvent::pack_len(4, false);
        assert_eq!(fmt(&r), "CONN|1000|42|43|7|99|5|2|8080|0|93.184.216.34\n");
    }

    #[test]
    fn a_unix_socket_says_so_instead_of_printing_an_address() {
        let mut r = rec(KIND_CONN);
        r.n1 = 1; // AF_UNIX
        r.n2 = 0;
        assert!(fmt(&r).ends_with("|1|0|0|non-IP family\n"));
    }

    #[test]
    fn ipv6_is_canonical() {
        let mut r = rec(KIND_CONN);
        r.n1 = 10;
        r.n2 = 0x1F90u16.swap_bytes() as i64; // 8080 as it would sit in the sockaddr
        let mut b = [0u8; 16];
        b[15] = 1;
        r.strs[0][..16].copy_from_slice(&b);
        r.lens[0] = RawEvent::pack_len(16, false);
        assert_eq!(fmt(&r), "CONN|1000|42|43|7|99|0|10|8080|0|::1\n");
    }

    #[test]
    fn fork_and_exit_and_send_shapes() {
        let mut r = rec(KIND_FORK);
        r.n0 = 77;
        set(&mut r, 0, "child");
        set(&mut r, 1, "parent");
        assert_eq!(fmt(&r), "FORK|1000|42|7|99|77|child|parent\n");

        let mut r = rec(KIND_EXIT);
        r.n0 = 1; // exit code
        set(&mut r, 0, "sleep");
        assert_eq!(fmt(&r), "EXIT|1000|42|7|99|1|sleep\n");

        let mut r = rec(KIND_SEND);
        r.n0 = 9;
        r.n1 = 1400;
        assert_eq!(fmt(&r), "SEND|1000|42|43|7|99|9|1400\n");
    }

    #[test]
    fn a_newline_in_a_path_cannot_tear_the_line() {
        let mut r = rec(KIND_OPEN);
        set(&mut r, 0, "a\nb");
        let text = fmt(&r);
        assert_eq!(text.lines().count(), 1, "{:?}", text);
        assert!(text.contains("a?b"));
    }

    #[test]
    fn argv_slots_are_capped_by_the_configured_argv_max() {
        // The eBPF side always fills ARGV_MAX slots; the run asked for 3.
        let mut r = rec(KIND_EXEC);
        r.n0 = ARGV_MAX as i64;
        let text = fmt(&r);
        assert_eq!(text.lines().count(), 4); // EXEC + 3 ARGV
    }
}
