//! Just enough BTF to find one struct member (v0.5).
//!
//! `sched_process_exit` carries `pid`, `prio` and `group_dead` — but not the exit
//! status. The `.bt` script read it off the task itself
//! (`curtask->exit_code >> 8`), and there is no way to reproduce that without
//! knowing where `exit_code` sits in `task_struct` on *this* kernel. That offset
//! is layout-dependent, so it is read from `/sys/kernel/btf/vmlinux` rather than
//! hardcoded.
//!
//! This is a hand-rolled reader for the handful of record kinds that have to be
//! skipped to reach a `STRUCT` named `task_struct`. A full BTF library would be
//! another dependency for one integer — but the skipping has to be *correct*,
//! because a single mis-sized record silently shifts every subsequent type id and
//! yields a plausible wrong offset rather than an error. Hence the explicit
//! per-kind trailing-size table below and a test that walks a synthetic section.
//!
//! If the file is missing (a kernel built without `CONFIG_DEBUG_INFO_BTF`) or the
//! member cannot be found, the caller gets `None` and degrades to exit code 0 —
//! which is exactly what `EXIT|...|0|` means in the protocol. That is reported on
//! stderr rather than passed off as a real status.

/// BTF magic, little-endian at the head of the file.
const BTF_MAGIC: u16 = 0xeb9f;

const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_ENUM64: u32 = 19;

/// Find `struct_name.member` and return its byte offset.
///
/// Returns `Ok(None)` when the type or member simply is not there (a legitimate
/// "this kernel does not tell us") and `Err` when the file is malformed — two
/// different situations that must not be conflated.
pub fn struct_member_offset(data: &[u8], struct_name: &str, member: &str) -> Result<Option<u32>, String> {
    if data.len() < 24 {
        return Err("BTF blob is shorter than its header".to_string());
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != BTF_MAGIC {
        return Err(format!("bad BTF magic 0x{:04x} (expected 0x{:04x})", magic, BTF_MAGIC));
    }
    let hdr_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let type_off = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let type_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
    let str_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
    let str_len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;

    let types = slice(data, hdr_len + type_off, type_len, "type section")?;
    let strs = slice(data, hdr_len + str_off, str_len, "string section")?;
    let name_at = |off: u32| -> Result<&str, String> {
        let off = off as usize;
        if off >= strs.len() {
            return Err(format!("BTF string offset {} is out of range", off));
        }
        let end = strs[off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| off + p)
            .unwrap_or(strs.len());
        Ok(std::str::from_utf8(&strs[off..end]).unwrap_or("<non-utf8>"))
    };

    let mut pos = 0usize;
    while pos < types.len() {
        let (name_off, info, size_or_type) = read_type_header(types, pos)?;
        let vlen = (info & 0xffff) as usize;
        let kind = (info >> 24) & 0x1f;
        let extra = extra_len(kind, vlen);
        let members_at = pos + 12;

        if kind == KIND_STRUCT && name_at(name_off)? == struct_name {
            for m in 0..vlen {
                let off = members_at + m * 12;
                let (m_name, _m_type, m_off) = read_member(types, off)?;
                if name_at(m_name)? == member {
                    // `kind_flag` packs a bitfield width into the top byte; the low
                    // 24 bits stay the bit offset, so the mask works either way.
                    return Ok(Some((m_off & 0x00ff_ffff) / 8));
                }
            }
            let _ = size_or_type;
            return Ok(None); // the struct is here, the member is not
        }

        pos = members_at + extra;
    }
    Ok(None)
}

/// Trailing bytes after a type's 12-byte header, by kind.
fn extra_len(kind: u32, vlen: usize) -> usize {
    match kind {
        KIND_INT => 4,
        KIND_ARRAY => 12,
        KIND_STRUCT | KIND_UNION => vlen * 12,
        KIND_ENUM => vlen * 8,
        KIND_FUNC_PROTO => vlen * 8,
        KIND_VAR => 4,
        KIND_DATASEC => vlen * 12,
        KIND_DECL_TAG => 4,
        KIND_ENUM64 => vlen * 12,
        // PTR, FWD, TYPEDEF, the three qualifiers (CONST/VOLATILE/RESTRICT), FUNC,
        // FLOAT and TYPE_TAG: all of them are a bare 12-byte header.
        _ => 0,
    }
}

fn read_type_header(t: &[u8], pos: usize) -> Result<(u32, u32, u32), String> {
    if pos + 12 > t.len() {
        return Err(format!("BTF type at offset {} runs past the type section", pos));
    }
    Ok((
        u32::from_le_bytes([t[pos], t[pos + 1], t[pos + 2], t[pos + 3]]),
        u32::from_le_bytes([t[pos + 4], t[pos + 5], t[pos + 6], t[pos + 7]]),
        u32::from_le_bytes([t[pos + 8], t[pos + 9], t[pos + 10], t[pos + 11]]),
    ))
}

fn read_member(t: &[u8], pos: usize) -> Result<(u32, u32, u32), String> {
    if pos + 12 > t.len() {
        return Err(format!("BTF member at offset {} runs past the type section", pos));
    }
    Ok((
        u32::from_le_bytes([t[pos], t[pos + 1], t[pos + 2], t[pos + 3]]),
        u32::from_le_bytes([t[pos + 4], t[pos + 5], t[pos + 6], t[pos + 7]]),
        u32::from_le_bytes([t[pos + 8], t[pos + 9], t[pos + 10], t[pos + 11]]),
    ))
}

fn slice<'a>(data: &'a [u8], off: usize, len: usize, what: &str) -> Result<&'a [u8], String> {
    data.get(off..off + len)
        .ok_or_else(|| format!("BTF {} (offset {}, length {}) is outside the file", what, off, len))
}

/// Read `/sys/kernel/btf/vmlinux` and look up `task_struct.exit_code`.
pub fn task_exit_code_offset() -> Result<Option<u32>, String> {
    let path = "/sys/kernel/btf/vmlinux";
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            return Err(format!(
                "cannot read {} ({}): the exit status of a signal death will be reported as 0",
                path, e
            ));
        }
    };
    struct_member_offset(&data, "task_struct", "exit_code")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny BTF blob: one INT (to prove the skip arithmetic), one STRUCT.
    fn synthetic() -> Vec<u8> {
        let mut strings: Vec<u8> = vec![0]; // offset 0 is the empty string
        let mut intern = |s: &str| -> u32 {
            let off = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            off
        };
        let s_task = intern("task_struct");
        let s_comm = intern("comm");
        let s_exit = intern("exit_code");

        // type 1: INT (12 + 4 trailing bytes) — if the skip is wrong, the STRUCT
        // below is never reached and the test fails rather than silently passing.
        let mut ty: Vec<u8> = Vec::new();
        ty.extend_from_slice(&0u32.to_le_bytes()); // name_off
        ty.extend_from_slice(&(KIND_INT << 24).to_le_bytes()); // vlen 0
        ty.extend_from_slice(&4u32.to_le_bytes()); // size
        ty.extend_from_slice(&0u32.to_le_bytes()); // int encoding

        // type 2: STRUCT task_struct { char comm[16]; int exit_code; }
        ty.extend_from_slice(&s_task.to_le_bytes());
        ty.extend_from_slice(&((KIND_STRUCT << 24) | 2).to_le_bytes()); // vlen 2
        ty.extend_from_slice(&512u32.to_le_bytes()); // size
        ty.extend_from_slice(&s_comm.to_le_bytes());
        ty.extend_from_slice(&1u32.to_le_bytes()); // type: some int
        ty.extend_from_slice(&0u32.to_le_bytes()); // bit offset 0
        ty.extend_from_slice(&s_exit.to_le_bytes());
        ty.extend_from_slice(&1u32.to_le_bytes());
        ty.extend_from_slice(&128u32.to_le_bytes()); // bit offset 128 -> byte 16

        let hdr_len = 24usize;
        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(1); // version
        out.push(0); // flags
        out.extend_from_slice(&(hdr_len as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off
        out.extend_from_slice(&(ty.len() as u32).to_le_bytes());
        out.extend_from_slice(&(ty.len() as u32).to_le_bytes()); // str_off
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&ty);
        out.extend_from_slice(&strings);
        out
    }

    #[test]
    fn finds_a_member_after_skipping_other_kinds() {
        let blob = synthetic();
        assert_eq!(
            struct_member_offset(&blob, "task_struct", "exit_code").unwrap(),
            Some(16)
        );
        assert_eq!(struct_member_offset(&blob, "task_struct", "comm").unwrap(), Some(0));
    }

    #[test]
    fn absent_member_and_absent_struct_are_not_errors() {
        let blob = synthetic();
        assert_eq!(struct_member_offset(&blob, "task_struct", "nope").unwrap(), None);
        assert_eq!(struct_member_offset(&blob, "other_struct", "exit_code").unwrap(), None);
    }

    #[test]
    fn a_bad_magic_is_an_error() {
        let mut blob = synthetic();
        blob[0] = 0;
        assert!(struct_member_offset(&blob, "task_struct", "exit_code").is_err());
    }
}
