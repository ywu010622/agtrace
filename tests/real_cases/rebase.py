#!/usr/bin/env python3
"""Rebase a frozen transcript onto the current wall clock.

The claude-code adapter takes transcript timestamps at face value
(`src/adapter/claude_code.rs`: `parse_iso8601_ns(t)`), unlike the openshell
adapter's `--time-base now`. A fixture frozen yesterday therefore sits hours
away from the live kernel events and the 120 s binding window can never
overlap — so replaying a frozen transcript against a *live* workload requires
rebasing it to now first.

Offsets between lines are preserved exactly: only the origin moves. That keeps
"call #1 at +2.499 s, call #2 at +5.778 s" true, which is what the runner's
sleep-then-exec workload is timed against.

Usage:
    rebase.py <in.jsonl> <out.jsonl> [--gap-before <line> <seconds>]

`--gap-before N S` adds S seconds to line N and everything after it. The
runner uses it for one purpose: with two *byte-identical* retries, the binder
pairs "earliest unmatched call wins", so to prove that a call that never exec'd
stays unbound, the two calls have to be pulled more than the 120 s window apart.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone


def parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def fmt(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--gap-before", nargs=2, metavar=("LINE", "SEC"), default=None)
    a = ap.parse_args()

    lines = [json.loads(x) for x in open(a.src, errors="replace") if x.strip()]
    stamps = [parse(d["timestamp"]) for d in lines if "timestamp" in d]
    if not stamps:
        print("rebase: fixture has no timestamps", file=sys.stderr)
        return 2
    origin = min(stamps)
    now = datetime.now(timezone.utc)

    gap_line, gap_sec = (int(a.gap_before[0]), float(a.gap_before[1])) if a.gap_before else (None, 0.0)
    with open(a.dst, "w") as out:
        for i, d in enumerate(lines):
            if "timestamp" in d:
                t = now + (parse(d["timestamp"]) - origin)
                if gap_line is not None and i >= gap_line:
                    t += timedelta(seconds=gap_sec)
                d["timestamp"] = fmt(t)
            out.write(json.dumps(d, ensure_ascii=False) + "\n")
    span = (max(stamps) - origin).total_seconds()
    print(f"rebased {len(lines)} line(s), span {span:.3f}s, origin -> {fmt(now)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
