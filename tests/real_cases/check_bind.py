#!/usr/bin/env python3
"""Assert the bind accounts of one `agtrace --output json` run.

Reads the JSONL stream agtrace emits (`--output json` is lossless: one object
per line, last line the summary) and checks the `extra.bind` counters plus the
rule label on every `derived.bind` row that was actually produced.

Everything here is an *assertion*, never a re-implementation of the binder: the
counters come from the binary, and the run fails loudly if the shape is not
what the case expects.

Usage:
    check_bind.py <out.jsonl> --label RC1 [--calls-seen N] [--calls-matched N]
                   [--by-segment N] [--by-substring N] [--by-exact N]
                   [--by-overlap N] [--rules "argv segment"] [--tool-id ID]
"""

import argparse
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--label", default="case")
    for k in ("calls-seen", "calls-matched", "by-segment", "by-substring", "by-exact", "by-overlap"):
        ap.add_argument(f"--{k}", type=int, default=None)
    ap.add_argument("--rules", default=None, help="comma-separated rule labels every bind row must use")
    ap.add_argument("--tool-id", default=None, help="the bind must be attributed to this tool_use_id")
    a = ap.parse_args()

    lines = [x for x in open(a.out, errors="replace") if x.strip()]
    if not lines:
        print(f"FAIL {a.label}: empty output")
        return 1
    events = []
    for x in lines:
        try:
            events.append(json.loads(x))
        except json.JSONDecodeError:
            continue
    summary = events[-1]
    bind = (summary.get("extra") or {}).get("bind")
    if bind is None:
        print(f"FAIL {a.label}: summary has no extra.bind block")
        return 1

    fails = []

    def eq(want, got, what):
        if want is not None and want != got:
            fails.append(f"{what}: want {want}, got {got}")

    eq(a.calls_seen, bind["calls_seen"], "calls_seen")
    eq(a.calls_matched, bind["calls_matched"], "calls_matched")
    eq(a.by_segment, bind["by_argv_segment"], "by_argv_segment")
    eq(a.by_substring, bind["by_argv_substring"], "by_argv_substring")
    eq(a.by_exact, bind["by_argv_exact"], "by_argv_exact")
    eq(a.by_overlap, bind["by_argv_overlap"], "by_argv_overlap")

    rows = [e for e in events if (e.get("payload") or {}).get("type") == "bind"]
    if bind["calls_matched"] != len(rows):
        fails.append(f"calls_matched {bind['calls_matched']} != bind rows {len(rows)}")
    if a.rules is not None:
        want = [r.strip() for r in a.rules.split(",")]
        got = [r["payload"]["rule"] for r in rows]
        if got != want:
            fails.append(f"rules: want {want}, got {got}")
    if a.tool_id is not None:
        got = [r.get("corr", {}).get("tool_use_id") for r in rows]
        if got != [a.tool_id]:
            fails.append(f"tool_use_id: want [{a.tool_id}], got {got}")

    if fails:
        print(f"FAIL {a.label}: " + "; ".join(fails))
        return 1
    print(
        f"PASS {a.label}: calls_seen={bind['calls_seen']} calls_matched={bind['calls_matched']} "
        f"rules={[r['payload']['rule'] for r in rows]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
