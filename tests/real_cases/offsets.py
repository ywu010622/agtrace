#!/usr/bin/env python3
"""Print where the tool calls sit in a (rebased) fixture.

The runner must time its live workload against the *fixture's* clock, not
against a number copied out of the capture. The fixture origin is the minimum
timestamp in the file, which is not the user prompt — in RC1 the two calls are
at +4.536 s and +7.815 s, while the prompt is at +2.037 s. Hard-coding the
prompt-relative numbers put the first live exec 330 ms *before* the first call,
and the binder (correctly, `ev.ts_ns < c.ts_ns` is not a match) refused it.

Output: one line, `<o1> <o2> ... <line_of_2nd_call>` (seconds from origin with
millisecond resolution, then the 0-based line index of the second tool call so
the caller can widen the gap before it).
"""

import json
import sys
from datetime import datetime, timezone


def parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def main() -> int:
    rows = [json.loads(x) for x in open(sys.argv[1], errors="replace") if x.strip()]
    stamps = [parse(d["timestamp"]) for d in rows if "timestamp" in d]
    origin = min(stamps)
    offs = []
    for i, d in enumerate(rows):
        if "timestamp" not in d or d.get("type") != "assistant":
            continue
        content = (d.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        ids = [b.get("id") for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
        if ids:
            offs.append((i, (parse(d["timestamp"]) - origin).total_seconds(), ids[0]))
    if len(offs) < 2:
        print(f"offsets: expected 2 tool calls, found {len(offs)}", file=sys.stderr)
        return 2
    print(f"{offs[0][1]:.3f} {offs[1][1]:.3f} {offs[1][0]} {offs[1][2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
