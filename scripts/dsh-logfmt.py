#!/usr/bin/env python3
"""Read a DeepSeek Harness session log like syslog: one record = one line.

DSH stores each session as an append-only ``session.v4.jsonl.zstd`` (a
concatenation of independent zstandard frames, one per append batch).  That
container is great for a tracer and terrible for eyeballing: a single
``assistant/message`` record is a page of nested JSON, and pretty-printing it
explodes into dozens of lines.

This tool flattens every record into exactly **one line**:

    2026-10-17T20:14:54.774Z #0   session         cwd=C:\\Users\\me\\proj id=session-...
    2026-10-17T20:14:54.774Z #8   user/message     https://github.com/...
    2026-10-17T20:15:00.768Z #19  assistant/message [thinking] Let me start... [text] on it
    2026-10-17T20:15:00.769Z #20  tool/call         pwsh call_00_x $ Get-Location; ...
    2026-10-17T20:15:02.100Z #23  tool/result       pwsh OK: Path ---- C:\\...
    2026-10-17T20:15:02.101Z #24  job/settled       completed "exit code: 0"

* Newlines inside message bodies become the two characters ``\\n``; tabs become
  ``\\t``. No record ever produces a line break, so ``grep``, ``awk``,
  ``tail -f`` and normal terminal scrollback behave like syslog.
* Content is printed **in full** by default (``--max-chars N`` truncates if you
  want a bounded width).
* ``--follow`` / ``-f`` keeps emitting new records while the harness writes.
* Harness-internal bookkeeping (step/start, request/header, delivery-accepted,
  ...) is hidden by default; ``--all`` shows every record type.
* ``--raw`` prints the flattened JSON payload instead of the human summary, for
  when you want to diff records byte-wise.

No third-party Python packages: zstd is decompressed with the system ``zstd``
CLI (already present on any machine that built agtrace; ``apt install zstd``
otherwise), and JSON comes from the standard library.

Usage:
    python3 scripts/dsh-logfmt.py auto
    python3 scripts/dsh-logfmt.py -f auto
    python3 scripts/dsh-logfmt.py --all --max-chars 240 session.v4.jsonl.zstd
    python3 scripts/dsh-logfmt.py -f "$DSH_HOME/sessions/--C-Users-me-proj--/<id>/session.v4.jsonl.zstd"
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Record types that are harness bookkeeping rather than agent behavior.  The
# same split as the agtrace DSH adapter: hidden by default, visible with --all.
# ---------------------------------------------------------------------------
INTERNAL_TYPES = {
    "step/start",
    "step/end",
    "turn/start",
    "turn/end",
    "job/registered",
    "request/header",
    "request/context",
    "session/title",
    "session/title-llm-request",
    "session/end-seed",
    "session-log-deepseek/delivery-accepted",
    "agent/inbox/spliced",
    "system/message",
    "permission/preset",
    "sandbox/mode",
    "approval/policy",
    "approval/asked",
    "approval/decided",
    "team/member",
    "team/task",
    "subagent/catalog",
    "subagent/descriptor",
    "todo/write",
    "workspace/changes",
    "deliverables/presented",
    "web/deepseek-search-llm-request",
    "command/run",
    "command/done",
    "model/selection",
}

SHELL_TOOLS = {"pwsh", "powershell", "pwsh.exe", "powershell.exe", "cmd", "cmd.exe",
               "bash", "bash.exe", "sh", "zsh", "fish", "shell", "exec"}


def sessions_roots(explicit: str | None) -> list[Path]:
    """Candidate DSH session roots, in priority order (mirrors the adapter)."""
    roots: list[Path] = []
    if explicit:
        roots.append(Path(explicit).expanduser())
    for var, sub in (("DSH_SESSIONS_ROOT", ""), ("DSH_HOME", "sessions")):
        val = os.environ.get(var)
        if val:
            p = Path(val).expanduser()
            roots.append(p if not sub else p / sub)
    roots.append(Path.home() / ".dsh" / "sessions")
    # WSL reading a Windows-side harness: C:\Users\<user>\.dsh\sessions is
    # /mnt/c/Users/<user>/.dsh/sessions.
    for drive in "cdef":
        for user_dir in glob.glob(f"/mnt/{drive}/Users/*/.dsh/sessions"):
            roots.append(Path(user_dir))
    seen, out = set(), []
    for r in roots:
        try:
            key = str(r.resolve())
        except OSError:
            key = str(r)
        if key not in seen and r.is_dir():
            seen.add(key)
            out.append(r)
    return out


def newest_session(roots: list[Path]) -> Path:
    candidates: list[Path] = []
    for root in roots:
        # <root>/<project-key>/<session-id>/session.vN.jsonl[.zstd]
        patterns = ("*/*/session*.jsonl.zstd", "*/*/session*.jsonl",
                    # also accept a project directory (or a flat root) directly
                    "*/session*.jsonl.zstd", "*/session*.jsonl")
        for pattern in patterns:
            candidates += [Path(p) for p in glob.glob(str(root / pattern))]
    if not candidates:
        raise SystemExit(
            "dsh-logfmt: no session log found. Tried:\n  "
            + "\n  ".join(str(r) for r in roots)
            + "\nPass a path explicitly, or set DSH_HOME / DSH_SESSIONS_ROOT."
        )
    return max(candidates, key=lambda p: p.stat().st_mtime)


def resolve(path: str, explicit_root: str | None) -> Path:
    if path and path != "auto":
        p = Path(path).expanduser()
        if not p.is_file():
            raise SystemExit(f"dsh-logfmt: file not found: {p}")
        return p
    return newest_session(sessions_roots(explicit_root))


def read_bytes(path: Path, quiet: bool = False) -> bytes:
    """Decompress a DSH log. A torn final frame is not fatal: complete frames
    before it are still returned (the same crash-recovery rule as the harness)."""
    if path.suffix == ".zstd" or path.suffix == ".zst":
        zstd = shutil.which("zstd")
        if not zstd:
            raise SystemExit("dsh-logfmt: `zstd` CLI not found (apt install zstd)")
        proc = subprocess.run([zstd, "-d", "-c", str(path)], capture_output=True)
        if proc.returncode != 0 and not proc.stdout:
            msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            hint = msg[-1] if msg else f"zstd exited {proc.returncode}"
            raise SystemExit(f"dsh-logfmt: cannot decode {path}: {hint}")
        return proc.stdout
    return path.read_bytes()


def iso_ms(ms: int | float | None) -> str:
    if ms is None:
        return "-".ljust(24)
    dt = datetime.fromtimestamp(float(ms) / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def esc(value: object) -> str:
    """One physical line, always: newlines/tabs/controls become escapes."""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    out: list[str] = []
    for ch in value:
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def blocks_text(content: object, tool_calls: bool = False) -> str:
    """Flatten DSH content blocks (text / reasoning / tool-call / image).

    Tool-call blocks are skipped by default: the following ``tool/call`` record
    repeats them with full arguments, and printing both doubles every command.
    """
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            parts.append(str(block))
            continue
        kind = block.get("type")
        if kind == "text":
            parts.append(str(block.get("text", "")))
        elif kind == "reasoning":
            parts.append("[thinking] " + str(block.get("text", "")))
        elif kind == "tool-call":
            if tool_calls:
                parts.append(f"[tool-call {block.get('name', '?')}]")
        elif kind == "image":
            parts.append("[image]")
        else:
            parts.append(f"[{kind}]")
    return " ".join(p for p in parts if p)


def tool_arguments(data: dict) -> str:
    raw = data.get("arguments")
    if raw is None:
        return ""
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return raw
    else:
        parsed = raw
    if not isinstance(parsed, dict):
        return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
    name = str(data.get("name", ""))
    if name in SHELL_TOOLS:
        return str(parsed.get("command") or parsed.get("cmd") or parsed)
    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))


def summarize(rec: dict) -> tuple[str, str] | None:
    """(label, detail) for one record, or None when it should be hidden."""
    rtype = str(rec.get("type", "?"))
    data = rec.get("data") if isinstance(rec.get("data"), dict) else {}

    if rtype == "session":
        cwd = rec.get("cwd") or "?"
        return "session", f"id={rec.get('id', '?')} cwd={cwd} version={rec.get('version', '?')}"

    if rtype == "user/message":
        src = data.get("source") or {}
        kind = src.get("kind") if isinstance(src, dict) else None
        # Harness-injected context (runtime context, skill catalog, time
        # context) is not something a human said. Hide it like syslog hides
        # daemon chatter unless --all is given.
        if kind not in (None, "user"):
            return None
        return rtype, blocks_text(data.get("content"))

    if rtype == "assistant/message":
        msg = data.get("message") or {}
        source = msg.get("source") or {}
        model = source.get("model") or "?"
        where = f"turn {data.get('turn', '?')}/step {data.get('step', '?')} model={model}"
        return rtype, f"{where} {blocks_text(msg.get('content'))}"

    if rtype == "tool/call":
        return rtype, f"{data.get('name', '?')} {data.get('callId', '?')} $ {tool_arguments(data)}"

    if rtype == "tool/result":
        msg = data.get("message") or {}
        call_id = msg.get("toolCallId") or data.get("toolCallId") or "?"
        status = "ERROR" if msg.get("isError") else "OK"
        out = blocks_text(msg.get("content"))
        err = data.get("error")
        if isinstance(err, dict) and err:
            out = f"{out} error={err.get('name', '?')}/{err.get('code', '?')}"
        return rtype, f"{call_id} {status} {out}"

    if rtype == "job/settled":
        call_id = (data.get("toolCall") or {}).get("callId", "?")
        return rtype, f"{call_id} {data.get('status', '?')} {data.get('detail', '')}"

    if rtype == "job/registered":
        call_id = (data.get("toolCall") or {}).get("callId", "?")
        return rtype, f"{call_id} {data.get('kind', '?')} start"

    if rtype == "step/start":
        return rtype, f"turn {data.get('turn', '?')}/step {data.get('step', '?')}"
    if rtype == "step/end":
        return rtype, f"turn {data.get('turn', '?')}/step {data.get('step', '?')}"
    if rtype == "turn/start":
        return rtype, f"turn {data.get('turn', '?')}"
    if rtype == "turn/end":
        return rtype, f"turn {data.get('turn', '?')} {json.dumps(data.get('reason', {}), ensure_ascii=False)}"

    return rtype, json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def format_record(rec: dict, args: argparse.Namespace) -> str | None:
    rtype = str(rec.get("type", "?"))
    if not args.all and rtype != "session" and rtype in INTERNAL_TYPES:
        return None
    if args.only and rtype not in args.only:
        return None

    ts = iso_ms(rec.get("time") if rtype != "session" else rec.get("createdAt"))
    seq = rec.get("seq")
    seq_s = f"#{seq}" if isinstance(seq, int) else "#-"
    summary = summarize(rec)
    if summary is None:
        if not args.all:
            return None
        data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
        summary = (rtype, json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    label, detail = summary
    if args.raw:
        detail = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        # flatten even when --raw: the whole record is the message
        label = "RAW"

    line = f"{ts} {seq_s:<6} {label:<18} {esc(detail)}"
    if args.max_chars and len(line) > args.max_chars:
        line = line[: max(0, args.max_chars - 1)] + "…"
    if args.tasks:
        line = f"{line}  [turn/step tag]"
    return line


def split_complete_lines(text: str) -> list[str]:
    """Lines ending in newline are complete; a trailing fragment is held back."""
    if not text:
        return []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def emit_lines(lines: list[str], state: dict, follow: bool, tail: int | None) -> None:
    start = state["emitted"]
    fresh = lines[start:]
    state["emitted"] = len(lines)
    if not follow and tail:
        fresh = fresh[-tail:]
    for line in fresh:
        print(line, flush=True)


def run(path: Path, args: argparse.Namespace) -> int:
    state = {"emitted": 0}
    text = read_bytes(path).decode("utf-8", "replace")
    lines: list[str] = []
    for raw in split_complete_lines(text):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            lines.append(f"{iso_ms(None)} #-     malformed-json    {esc(raw)}")
            continue
        line = format_record(rec, args)
        if line is not None:
            lines.append(line)
    emit_lines(lines, state, args.follow, args.tail)
    if not args.follow:
        return 0

    sys.stderr.write(f"dsh-logfmt: following {path} (Ctrl-C to stop)\n")
    sys.stderr.flush()
    seen_size = path.stat().st_size if path.exists() else 0
    while True:
        time.sleep(0.25)
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            continue
        if size == seen_size:
            continue
        seen_size = size
        text = read_bytes(path, quiet=True).decode("utf-8", "replace")
        lines = []
        for raw in split_complete_lines(text):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                lines.append(f"{iso_ms(None)} #-     malformed-json    {esc(raw)}")
                continue
            line = format_record(rec, args)
            if line is not None:
                lines.append(line)
        emit_lines(lines, state, True, None)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="dsh-logfmt",
        description="One-line syslog-style view of a DeepSeek Harness session log "
        "(plain JSONL or session.vN.jsonl.zstd).",
    )
    parser.add_argument("path", nargs="?", default="auto",
                        help="session log path, or `auto` (default) for the newest session")
    parser.add_argument("-f", "--follow", action="store_true",
                        help="keep printing new records while the harness appends")
    parser.add_argument("-a", "--all", action="store_true",
                        help="also show harness-internal records (step/request/job/...)")
    parser.add_argument("-r", "--raw", action="store_true",
                        help="print each record as flattened raw JSON instead of a summary")
    parser.add_argument("-m", "--max-chars", type=int, default=0,
                        help="truncate each line at N characters (0 = full content)")
    parser.add_argument("-n", "--tail", type=int, default=None,
                        help="with a static file: only print the last N lines")
    parser.add_argument("--only", default="",
                        help="comma-separated record types to keep (e.g. tool/call,tool/result)")
    parser.add_argument("--root", default=None,
                        help="sessions root to search for `auto` (default: DSH_HOME/DSH_SESSIONS_ROOT/~/.dsh)")
    parser.add_argument("--tasks", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    args.only = {t.strip() for t in args.only.split(",") if t.strip()}
    try:
        path = resolve(args.path, args.root)
        return run(path, args)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
