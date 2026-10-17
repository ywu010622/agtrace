---
name: agtrace
description: Observe a DeepSeek Harness session with agtrace — tail the live session log (`session.v4.jsonl.zstd`), render one timeline of prompts, model steps, tool calls and results, attribute failed tool calls, and replay a finished session offline.
whenToUse: When the user asks to trace, watch, inspect, replay, or debug an agent session (tool calls, command output, failures, timing), or asks why a tool call claims success while something else happened.
metadata:
  version: 0.1.0
---

# agtrace for DSH

`agtrace` is a single static CLI that joins what the agent *claims* with what the
kernel *actually did*. The agent half is a transcript adapter: for DSH it tails
`session.v4.jsonl.zstd` (a concatenation of independent Zstandard frames that the
harness appends, one frame per 200 ms batch) and renders prompts, model
reasoning/text, tool calls and results on one clock.

Read-only by design: it never edits the session log, never configures or
throttles the agent.

## Find the installed binary

- If `agtrace --version` works, use it.
- Otherwise build from a checkout: `cargo build --release` (Linux) — see
  `README.md`. Do not install anything globally without asking the user.

## Locate the current session (no guessing)

A DSH tool shell exports the session identity, so `auto` works without paths:

```bash
# $DSH_HOME = <harness home>, $DSH_SESSION_ID = current session id
agtrace --adapter dsh -S auto -f
```

`-S auto` resolves in this order: `$DSH_SESSION_ID` (if set) → newest session of
the current workspace → newest session under the sessions root. The sessions root
is `$DSH_SESSIONS_ROOT`, else `$DSH_HOME/sessions`, else `~/.dsh/sessions`
(on WSL it also finds `<drive>:\Users\<user>\.dsh\sessions`).

Explicit forms accepted by `-S`:

| Form | Example |
|---|---|
| log file | `-S "$DSH_HOME/sessions/--C-Users-me-proj--/session-…/session.v4.jsonl.zstd"` |
| session directory | `-S .../session-<id>/` |
| session id (exact or unique prefix) | `-S session-e8694b65` |
| workspace directory | `-S "$PWD"` |
| latest of everything | `-S latest` |

## Recipes

```bash
# 1. offline: render a finished session once, then exit
agtrace --adapter dsh -S auto

# 2. live: follow the session while the agent works
agtrace --adapter dsh -S auto -f

# 3. only failures (failed tool chains + attribution + footer)
agtrace --adapter dsh -S auto --failures-only

# 4. machine-readable JSONL (one event per line, summary last)
agtrace --adapter dsh -S auto --output json | jq -c 'select(.kind=="agent.tool.call")'

# 5. bounded watch (never leave the trace running forever)
agtrace --adapter dsh -S auto -f --duration 60 --max-events 500

# 6. merged timeline with kernel evidence — only when the harness and agtrace
#    run on the same Linux host with eBPF: point -p at the harness process.
agtrace --adapter dsh -S auto -p "$(pgrep -nf 'dsh|DeepSeek Harness')" -f
```

Useful notes:

- A failed shell command in DSH leaves `tool.result.isError=false`; the exit
  code lives in `job/settled.detail` (`exit code: N`). agtrace reads that
  authoritative field and reports the call as `Failure`, with the disagreement
  spelled out in the event's `notes` (`-v` / JSON).
- `--redact argv` (default) masks credential-shaped command lines; add
  `--redact argv+content` to also mask prompt/thinking/tool-result text.
- `--max-events N` counts collected events; with an offline session it stops
  after N and says so on stderr.
- On Windows, run agtrace from WSL and point it at the Windows session root
  (`-S auto` already looks there). The transcript half works; kernel evidence
  is Linux-only (WSL cannot see Windows processes' syscalls).

## Reporting back

Give the user: the exact command, the session path from the banner
(`transcript: … (dsh)`), a short summary of what failed (tool, command, verdict),
and any `transcript: …` artifact paths. Prefer `--output json` when the user
wants to post-process, and quote the `derived.fail` rows verbatim rather than
paraphrasing their evidence claims.
