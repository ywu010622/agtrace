//! Tracepoint field-offset resolution (v0.5).
//!
//! The syscall tracepoints do **not** hand the program a generic `args[6]` array.
//! Each one declares its arguments as *named* fields at offsets that differ
//! between tracepoints and between kernel versions:
//!
//! ```text
//! field:int dfd;                            offset:16; size:8;  signed:0;
//! field:const char * filename;              offset:24; size:8;  signed:0;
//! field:int flags;                          offset:32; size:8;  signed:0;
//! ```
//!
//! Hardcoding those numbers would work exactly until the next kernel release and
//! then fail *silently* — the program would read a neighbouring argument and
//! attribute the wrong path to the wrong syscall. So every offset is resolved
//! here, at load time, from `/sys/kernel/tracing/events/<cat>/<name>/format`, and
//! a field that cannot be resolved is a hard error rather than a zero.
//!
//! ## Why the declared type, and not `size`
//!
//! `field:int flags; ... size:8;` declares eight bytes of *storage* (syscall
//! arguments sit in an `unsigned long[]`) but only four bytes of *value*. Reading
//! all eight would fold the next argument into `flags`, and since the parser
//! decides "was this a write?" from `flags & (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|
//! O_APPEND)`, that would turn read-only opens into apparent writes — silently
//! defeating the v0.4.2 "sensitive read-only opens" behaviour.
//!
//! bpftrace reads the *declared type*: this was pinned down by observation, not
//! by reading its source — `dfd` printed as `-100` through `%d` while the format
//! file says `signed:0` for that field. So the width and signedness below come
//! from the type name, and `size` is deliberately ignored.

use std::collections::HashMap;
use std::path::PathBuf;

/// Field descriptor handed to the eBPF side in a `CONFIG` slot.
///
/// Encoding lives in `agtrace-ebpf-common::field`; this type is just a readable
/// stand-in until it is packed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Byte offset within the tracepoint record.
    pub offset: u32,
    /// 0 = 1 byte, 1 = 2, 2 = 4, 3 = 8.
    pub width: u32,
    pub signed: bool,
    /// The field is a `__data_loc char[]`: the four bytes hold
    /// `(offset << 16) | len`, and the characters live elsewhere in the record.
    pub data_loc: bool,
}

impl Field {
    pub fn encode(&self) -> u64 {
        if self.data_loc {
            return agtrace_ebpf_common::field(self.offset, agtrace_ebpf_common::W4, false);
        }
        agtrace_ebpf_common::field(self.offset, self.width, self.signed)
    }
}

/// The parsed `format` file of one tracepoint.
#[derive(Debug, Default, Clone)]
pub struct EventFormat {
    pub fields: HashMap<String, Field>,
}

impl EventFormat {
    /// Look up a field, failing loudly when it is absent.
    ///
    /// A missing field means the kernel does not expose what this program needs.
    /// Returning a default of `0` would make the program read byte 0 of the
    /// record — the event's `common_type` — and emit that as, say, a filename.
    pub fn field(&self, name: &str, id: &str) -> Result<Field, String> {
        self.fields.get(name).copied().ok_or_else(|| {
            let mut known: Vec<&str> = self.fields.keys().map(|s| s.as_str()).collect();
            known.sort_unstable();
            format!(
                "tracepoint {} has no field `{}` (fields present: {})",
                id,
                name,
                known.join(", ")
            )
        })
    }
}

/// Locate the `events` directory of tracefs.
///
/// Two mount points are in use in the wild: the dedicated tracefs mount and the
/// older debugfs layout. `CONFIG_TRACEFS_AUTO_MOUNT` makes `/sys/kernel/tracing`
/// appear on first access on most distributions, so trying it first is not just
/// a preference — reading the directory *is* what mounts it.
pub fn events_dir() -> Result<PathBuf, String> {
    let mut tried = Vec::new();
    for base in ["/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"] {
        let p = PathBuf::from(base);
        // Checking a file we are certain to need beats checking the directory:
        // an empty-but-present directory would pass a weaker test.
        if p.join("syscalls/sys_enter_openat/format").exists() {
            return Ok(p);
        }
        tried.push(base);
    }
    // Two very different causes look identical from here, and only one of them is
    // the kernel's fault. `/sys/kernel/tracing` is mode 0700, so for an
    // unprivileged process *every* path below it reports "not found" and the
    // kernel-config diagnosis is confidently wrong. The loader is normally
    // reached through sudo, so when we lack privilege that is the thing to name.
    let cause = if unsafe { libc::geteuid() } == 0 {
        "is tracefs mounted and is CONFIG_FTRACE/CONFIG_TRACEPOINTS enabled in this kernel?"
    } else {
        "this process is not root and tracefs is root-only, which alone would explain this \
         (run the loader under sudo) — if you are root, check that tracefs is mounted and \
         CONFIG_FTRACE/CONFIG_TRACEPOINTS is enabled"
    };
    Err(format!(
        "no tracefs events directory found (tried {}) — {}",
        tried.join(", "),
        cause
    ))
}

/// Read and parse one tracepoint's `format` file.
pub fn read_format(events: &std::path::Path, category: &str, name: &str) -> Result<EventFormat, String> {
    let path = events.join(category).join(name).join("format");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    parse(&text).map_err(|e| format!("cannot parse {}: {}", path.display(), e))
}

/// Parse the body of a `format` file.
///
/// Only `field:` lines matter; the header (`name:`, `ID:`, `format:`) is skipped.
pub fn parse(text: &str) -> Result<EventFormat, String> {
    let mut out = EventFormat::default();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else {
            continue;
        };
        // `field:<type> <name>;\toffset:N;\tsize:N;\tsigned:N;`
        let mut parts = rest.split(';');
        let decl = parts.next().unwrap_or("").trim();
        let (ty, name) = split_decl(decl)?;
        let mut offset = None;
        for attr in parts {
            let a = attr.trim();
            if let Some(v) = a.strip_prefix("offset:") {
                offset = v.trim().parse::<u32>().ok();
            }
            // `size:` and `signed:` are intentionally not read — see the module
            // comment. `size` is the storage width (a 4-byte `int` reports 8 when
            // the tracepoint packs it into an 8-byte slot) and `signed` describes
            // that storage, not the declared C type. Reading either would make
            // `dfd` an unsigned 8-byte value, and a `-100` AT_FDCWD would print as
            // 18446744073709551516.
        }
        let offset = offset.ok_or_else(|| format!("field `{}` has no parseable offset", decl))?;
        let (width, ty_signed, data_loc) = resolve_type(ty)?;
        out.fields.insert(
            name.to_string(),
            Field {
                offset,
                width,
                signed: ty_signed,
                data_loc,
            },
        );
    }
    if out.fields.is_empty() {
        return Err("no `field:` lines found".to_string());
    }
    Ok(out)
}

/// Split `const char * filename` / `char comm[16]` into type and bare field name.
fn split_decl(decl: &str) -> Result<(&str, &str), String> {
    let decl = decl.trim();
    // The name is the last whitespace-separated token; the type is everything
    // before it. `char comm[16]` keeps its array suffix here and loses it below.
    let split = decl
        .rfind(char::is_whitespace)
        .ok_or_else(|| format!("field declaration `{}` has no name", decl))?;
    let ty = decl[..split].trim();
    let raw_name = decl[split..].trim();
    let name = raw_name.split('[').next().unwrap_or(raw_name).trim();
    if ty.is_empty() || name.is_empty() {
        return Err(format!("field declaration `{}` is malformed", decl));
    }
    Ok((ty, name))
}

/// Map a declared C type to `(width code, signed, is_data_loc)`.
///
/// An unrecognised type is an error. Guessing a width here is exactly the failure
/// mode this module exists to prevent: a four-byte `int` read as eight bytes does
/// not crash, it produces a plausible-looking wrong number.
pub fn resolve_type(ty: &str) -> Result<(u32, bool, bool), String> {
    let t = ty.trim();
    // `__data_loc char[]` / `__data_loc char *`: the kernel's own packed string.
    if t.starts_with("__data_loc") {
        return Ok((agtrace_ebpf_common::W4, false, true));
    }
    // Pointers are 8 bytes on every architecture this runs on, and never signed.
    if t.ends_with('*') {
        return Ok((agtrace_ebpf_common::W8, false, false));
    }
    // Fixed-size arrays (e.g. `char comm[16]`) are read as their element type;
    // nothing in this loader reads one, but resolving them is free.
    let t = t.split('[').next().unwrap_or(t).trim();
    let t = t.strip_prefix("const ").unwrap_or(t).trim();

    // (width code, signed) per declared type. Both spellings the kernel emits for
    // each width are listed, because the type string comes straight from the
    // syscall prototype and is not normalised.
    use agtrace_ebpf_common::{W1, W2, W4, W8};
    let r = match t {
        "char" | "signed char" => (W1, true),
        "unsigned char" | "bool" | "_Bool" | "u8" => (W1, false),
        "short" | "short int" | "signed short" | "signed short int" | "s16" | "int16_t" => {
            (W2, true)
        }
        "unsigned short" | "unsigned short int" | "u16" | "uint16_t" | "umode_t" => (W2, false),
        "int" | "signed int" | "int32_t" | "s32" | "pid_t" | "key_t" => (W4, true),
        "unsigned int" | "unsigned" | "uint32_t" | "u32" | "uid_t" | "gid_t" | "mode_t" => {
            (W4, false)
        }
        "long" | "long int" | "signed long" | "int64_t" | "s64" | "loff_t" | "ssize_t"
        | "__kernel_loff_t" | "time_t" => (W8, true),
        "unsigned long" | "unsigned long int" | "uint64_t" | "u64" | "size_t" | "uptr" => {
            (W8, false)
        }
        other => {
            return Err(format!(
                "unsupported tracepoint field type `{}` — refusing to guess a width, because a \
                 wrong width reads a neighbouring argument instead of failing",
                other
            ));
        }
    };
    Ok((r.0, r.1, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_format_fragment() {
        // Verbatim from /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
        // on Linux 7.0.0-31-generic.
        let text = "\
name: sys_enter_openat
ID: 675
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;
\tfield:int dfd;\toffset:16;\tsize:8;\tsigned:0;
\tfield:const char * filename;\toffset:24;\tsize:8;\tsigned:0;
\tfield:int flags;\toffset:32;\tsize:8;\tsigned:0;
\tfield:umode_t mode;\toffset:40;\tsize:8;\tsigned:0;
\tfield:__data_loc char[] __filename_val;\toffset:48;\tsize:4;\tsigned:0;
";
        let f = parse(text).unwrap();
        // `int` is 4 bytes signed even though the record stores 8 — the whole
        // reason `size` is ignored.
        assert_eq!(
            f.field("flags", "sys_enter_openat").unwrap(),
            Field {
                offset: 32,
                width: agtrace_ebpf_common::W4,
                signed: true,
                data_loc: false
            }
        );
        assert_eq!(
            f.field("filename", "sys_enter_openat").unwrap(),
            Field {
                offset: 24,
                width: agtrace_ebpf_common::W8,
                signed: false,
                data_loc: false
            }
        );
        // `umode_t` is `unsigned short` in this kernel
        // (/usr/src/linux-headers-7.0.0-31-generic/include/linux/types.h:23),
        // so it resolves to two bytes — not to the four the `mode` name suggests.
        assert_eq!(
            f.field("mode", "sys_enter_openat").unwrap(),
            Field { offset: 40, width: agtrace_ebpf_common::W2, signed: false, data_loc: false }
        );
        let dl = f.field("__filename_val", "sys_enter_openat").unwrap();
        assert!(dl.data_loc);
        assert_eq!(dl.offset, 48);
    }

    #[test]
    fn a_missing_field_is_an_error_not_a_zero() {
        let f = parse("\tfield:int fd;\toffset:16;\tsize:8;\tsigned:0;\n").unwrap();
        let e = f.field("dfd", "sys_enter_openat").unwrap_err();
        assert!(e.contains("no field `dfd`"), "{}", e);
        assert!(e.contains("fd"), "the error must list what is available: {}", e);
    }

    #[test]
    fn unknown_types_are_refused() {
        let e = resolve_type("struct sockaddr_storage").unwrap_err();
        assert!(e.contains("refusing to guess"), "{}", e);
    }

    #[test]
    fn pointers_arrays_and_dataleaks_resolve() {
        assert_eq!(resolve_type("const char *").unwrap(), (3, false, false));
        assert_eq!(resolve_type("struct sockaddr *").unwrap(), (3, false, false));
        assert_eq!(resolve_type("char[16]").unwrap(), (0, true, false));
        assert_eq!(resolve_type("__data_loc char[]").unwrap(), (2, false, true));
        assert_eq!(resolve_type("pid_t").unwrap(), (2, true, false));
        assert_eq!(resolve_type("bool").unwrap(), (0, false, false));
        assert_eq!(resolve_type("size_t").unwrap(), (3, false, false));
    }

    #[test]
    fn an_unprivileged_run_is_not_told_to_check_the_kernel_config() {
        // Reproduced for real rather than by mocking: `events_dir` probes
        // root-only paths, so an unprivileged test binary cannot see them and
        // lands on exactly the branch the loader hits when sudo did not happen.
        // (Run as root with tracefs mounted, the call succeeds and there is
        // nothing to assert.)
        match events_dir() {
            Ok(_) => {}
            Err(e) => {
                assert!(!e.contains("is tracefs mounted and is CONFIG_FTRACE"),
                        "unprivileged failure must not blame the kernel config first: {}", e);
                assert!(e.contains("not root"), "{}", e);
            }
        }
    }

    #[test]
    fn decl_with_array_suffix_keeps_bare_name() {
        assert_eq!(split_decl("char comm[16]").unwrap(), ("char", "comm"));
        assert_eq!(
            split_decl("__data_loc char[] parent_comm").unwrap(),
            ("__data_loc char[]", "parent_comm")
        );
    }
}
