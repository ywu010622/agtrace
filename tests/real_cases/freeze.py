#!/usr/bin/env python3
"""Freeze a real `claude -p` transcript into a replayable fixture.

Why this exists
---------------
Synthetic fixtures missed the v0.3 binding bug: they were written to match the
rules, so they could not show that the rules never fire on what the harness
really execs. The fixtures in this directory are *captured* transcripts of real
`claude -p` runs on this machine, then frozen.

What is sanitized, and what is deliberately kept
------------------------------------------------
* Sanitized (secrets / private bulk): `sessionId`, every `uuid` / `parentUuid`
  (rewritten to stable synthetic ids, parent links preserved), and the bulky
  private attachments (`prompt_snapshot` holds the whole system prompt).
* Kept verbatim: the command shapes. `message.content[].input.command`,
  `toolUseResult.dangerouslyDisableSandbox`, timestamps and line order are
  exactly as captured. A fixture that prettifies the command is worthless:
  the whole point is to keep the shape that broke the binder.

Usage:
    freeze.py <raw-transcript.jsonl> <out.jsonl> --session-id <label>
"""

import argparse
import json
import sys

# Fields whose content is either a secret or private bulk. They are replaced by
# a tiny stub that keeps the line's identity (uuid/parentUuid chain) intact —
# the claude-code adapter walks that chain to resolve turns, so dropping the
# line entirely would change what the fixture means.
STUB_KEYS = ("attachment",)
BIG = 4096


def shorten(obj):
    """Recursively stub heavy private payloads, keep everything else."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in STUB_KEYS and isinstance(v, dict):
                # keep only the attachment *kind*: enough for the adapter's
                # "attachment is environment noise" classification, and nothing
                # of the system prompt that rides along with it.
                out[k] = {"type": v.get("type")}
            else:
                out[k] = shorten(v)
        return out
    if isinstance(obj, list):
        return [shorten(x) for x in obj]
    if isinstance(obj, str) and len(obj) > BIG:
        return obj[:200] + f"...[frozen: {len(obj)} chars dropped]"
    return obj


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("raw")
    ap.add_argument("out")
    ap.add_argument("--session-id", required=True)
    a = ap.parse_args()

    ids: dict[str, str] = {}

    def sid(x):
        if not isinstance(x, str):
            return x
        if x not in ids:
            ids[x] = f"{a.session_id}-u{len(ids) + 1:04d}"
        return ids[x]

    kept = dropped = 0
    with open(a.raw, errors="replace") as fh, open(a.out, "w") as out:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                dropped += 1
                continue
            if not isinstance(d, dict):
                dropped += 1
                continue
            # The adapter skips lines without a parseable timestamp, so a line
            # that has none is pure weight: keep it only if it carries a uuid
            # link (attachments do, and they matter for the chain).
            if "timestamp" not in d and "uuid" not in d:
                dropped += 1
                continue
            for k in ("uuid", "parentUuid", "leafUuid"):
                if k in d:
                    d[k] = sid(d[k])
            if "sessionId" in d:
                d["sessionId"] = a.session_id
            d = shorten(d)
            out.write(json.dumps(d, ensure_ascii=False) + "\n")
            kept += 1
    print(f"froze {kept} line(s), dropped {dropped} unparsable/empty", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
