//! Builds the eBPF programs and hands the resulting object to `include_bytes!`.
//!
//! `cargo build --release` at the repository root has to produce a *working*
//! aya collector, but the eBPF crate needs a different toolchain (nightly), a
//! different target (`bpfel-unknown-none`) and `-Z build-std=core`. Rather than
//! making the caller learn any of that, this script drives the nested build and
//! copies the linked object into `OUT_DIR`.
//!
//! Failure policy — deliberately not "abort the world":
//!
//! * a *hard* error here would make `cargo test` impossible on any machine
//!   without the eBPF toolchain, including CI, for a component those runs never
//!   touch;
//! * a *silent* fallback would be worse: the user would get a binary that
//!   quietly cannot use its default collector.
//!
//! So a failed nested build emits a `cargo:warning=` naming exactly what is
//! missing and writes a zero-byte object. The loader treats an empty object as
//! "not built into this binary" and `--collector aya` degrades to bpftrace with
//! a visible stderr note (see `src/collector/aya.rs`). Nothing is silent, and
//! nothing is fatal for a run that was not going to use eBPF anyway.
//!
//! Two environment details this script exists to get right:
//!
//!  * `.cargo/config.toml` is discovered from the *current directory*, not from
//!    `--manifest-path`. The nested cargo therefore runs with `current_dir` set
//!    to `agtrace-ebpf/`, or the target triple and linker are silently ignored.
//!  * `CARGO_TARGET_DIR` is inherited by child processes. Left in place, the
//!    nested build would try to lock the same target directory the outer cargo
//!    already holds and deadlock. It is removed so the eBPF crate uses its own
//!    `target/` (already covered by the repository's `.gitignore`).
//!  * A build script's environment carries the *outer* toolchain's identity:
//!    `RUSTC`/`RUSTDOC` are absolute paths into the stable toolchain, and
//!    `LD_LIBRARY_PATH` points at its `lib/`. `rustup run nightly` only picks the
//!    toolchain for the binaries it resolves itself — an explicit `RUSTC` wins,
//!    and the nested build then dies with "unable to build with the standard
//!    library" while naming a path inside the *stable* toolchain. All of them are
//!    stripped below (`strip_foreign_lib_path` keeps any `LD_LIBRARY_PATH` entry
//!    that does not belong to a rustup toolchain).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Relative location of the eBPF crate within the repository.
const EBPF_DIR: &str = "agtrace-ebpf";
/// Target triple the eBPF crate builds for; also names its output directory.
const EBPF_TARGET: &str = "bpfel-unknown-none";
/// File name the embedded object lands under inside `OUT_DIR`.
const OBJ_NAME: &str = "agtrace-ebpf.o";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let obj_path = out_dir.join(OBJ_NAME);

    // Rebuild the object whenever the programs or their shared ABI change. The
    // nested cargo cannot express this to the outer one, so it is declared here.
    for p in [
        "agtrace-ebpf/src",
        "agtrace-ebpf/Cargo.toml",
        "agtrace-ebpf/.cargo/config.toml",
        "agtrace-ebpf-common/src",
        "agtrace-ebpf-common/Cargo.toml",
    ] {
        println!("cargo:rerun-if-changed={}", manifest_dir.join(p).display());
    }
    println!("cargo:rerun-if-env-changed=AGTTRACE_EBPF_ONLY");
    println!("cargo:rerun-if-env-changed=AGTTRACE_SKIP_EBPF");

    // Escape hatch for environments that genuinely cannot run nightly (packaging
    // for a fixed toolchain, docs.rs, a stripped CI image). Explicitly requested
    // by the caller, so it does not need to announce itself.
    if env::var_os("AGTTRACE_SKIP_EBPF").is_some() {
        write_stub(&obj_path);
        return;
    }

    match build_ebpf(&manifest_dir) {
        Ok(built) => {
            if let Err(e) = std::fs::copy(&built, &obj_path) {
                warn(&format!(
                    "could not copy {} to {}: {e}; the aya collector will not be available",
                    built.display(),
                    obj_path.display()
                ));
                write_stub(&obj_path);
            }
        }
        Err(msg) => {
            warn(&msg);
            warn("the aya collector will not be available in this binary; `--collector bpftrace` still works");
            write_stub(&obj_path);
        }
    }
}

/// Run the nested build and return the path of the linked object.
fn build_ebpf(manifest_dir: &Path) -> Result<PathBuf, String> {
    let dir = manifest_dir.join(EBPF_DIR);
    if !dir.join("Cargo.toml").exists() {
        return Err(format!("{} does not exist", dir.display()));
    }

    // `rustup run nightly` rather than `cargo +nightly`: the `+toolchain` syntax
    // is a rustup *shim* feature, and CARGO may point straight at a real cargo
    // binary (that is exactly what happens under some CI setups).
    let mut cmd = Command::new("rustup");
    cmd.current_dir(&dir)
        .arg("run")
        .arg("nightly")
        .arg("cargo")
        .arg("build")
        .arg("--release")
        // See the module comment: inheriting either of these breaks the nested
        // build (target-dir deadlock / flags meant for the host).
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        // Agents and CI commonly set this; the eBPF crate is not a workspace
        // member of anything, so it must not be inherited.
        .env_remove("CARGO_PRIMARY_PACKAGE")
        // The outer toolchain's identity, which must not leak into the nested
        // one. `RUSTC` alone is enough to break `-Z build-std`: cargo runs the
        // binary named there instead of the one belonging to `nightly`.
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER");
    // The outer cargo's jobserver describes *its* build graph; the fds mean
    // nothing here, and the nested build is one crate.
    cmd.env_remove("CARGO_MAKEFLAGS");
    if let Some(v) = strip_foreign_lib_path() {
        cmd.env("LD_LIBRARY_PATH", v);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("cannot run `rustup run nightly cargo build` in {}: {e}", dir.display()))?;

    // Surface the nested build's diagnostics even on success. This build runs in
    // a separate cargo with its own target dir, so its warnings would otherwise
    // reach the user only when it *fails* — `cargo build` could then report a
    // clean build while the eBPF crate warned, and the "0 warnings" property
    // would not be checkable by anyone but the person who happened to run the
    // nested build by hand. Filtered to diagnostic lines so the outer log stays
    // as readable as a normal cargo run.
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        if line.starts_with("warning") || line.starts_with("error") {
            println!("cargo:warning=agtrace-ebpf: {}", line);
        }
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Keep the tail: the useful line (missing bpf-linker, missing core, a
        // verifier rejection) is at the end, and build logs are long.
        let tail: Vec<&str> = stderr.lines().rev().take(6).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        return Err(format!(
            "failed to build the eBPF programs (`cargo +nightly build --release` in {}/):\n{}",
            EBPF_DIR,
            tail.join("\n")
        ));
    }

    let built = dir
        .join("target")
        .join(EBPF_TARGET)
        .join("release")
        .join("agtrace-ebpf");
    if !built.exists() {
        return Err(format!(
            "the eBPF build reported success but {} is missing",
            built.display()
        ));
    }
    Ok(built)
}

/// Drop `LD_LIBRARY_PATH` entries that belong to a rustup toolchain.
///
/// The outer cargo exports its own `rustlib/<target>/lib` so that dylib
/// artefacts of *its* build are found. That directory holds the stable
/// `libstd.so`; leaving it on the search path for a nightly `rustc` is a
/// version mismatch waiting to happen. Entries pointing anywhere else (a
/// distribution's lld, a locally built linker) are kept.
///
/// Returns `None` when nothing is left, which clears the variable.
fn strip_foreign_lib_path() -> Option<String> {
    let cur = env::var("LD_LIBRARY_PATH").ok()?;
    let kept: Vec<&str> = cur
        .split(':')
        .filter(|e| !e.is_empty() && !e.contains("/toolchains/"))
        .collect();
    Some(kept.join(":"))
}

/// Zero-byte object standing in for "the eBPF programs are not in this build".
fn write_stub(obj_path: &Path) {
    let _ = std::fs::write(obj_path, b"");
}

fn warn(msg: &str) {
    for line in msg.lines() {
        println!("cargo:warning=agtrace: {line}");
    }
}
