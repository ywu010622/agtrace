# agtrace

**strace for AI agents.** One live timeline joining what the agent *claims* with what the kernel *actually did*.

![agtrace demo](demo.gif)

## Why

An agent transcript tells you what the agent *intended* — tool calls, model text, results. The kernel tells you what *actually happened* — processes forked, files opened, connections made, syscalls failed. When the two disagree, the transcript alone cannot explain it:

- a sandbox silently swallowed the command (`bwrap` never initialized — `curl` never ran)
- the agent retried with the sandbox off, `curl` really executed, and exited 7 (connection refused)
- a `tool.result` says "success" while the real work happened in a different process tree

agtrace tails the agent transcript **and** traces the kernel (via bpftrace/eBPF) in real time, binding each `tool.call` to the processes it actually spawned — so you can see the exact point where intent and reality diverge.

agtrace only **presents**. It never throttles, kills, edits config, or auto-remediates. Acting on what you see is a different tool's job.

## Features

- **Unified live timeline** — agent, runtime, infra, and policy layers on a single clock
- **tool.call ↔ exec binding** — every Bash call linked to its real `execve`; the match rule is shown honestly (`exact` / `substring` / `segment`), bound subtrees marked `=`
- **Failure attribution** — each failed call traced to its deepest evidence layer: `BEFORE exec` (sandbox init failed / command not found), `kernel` (exit status + linked syscalls); one red `XX` line per failure, plus a `--- failures (N)` summary footer
- **Watchlist** — sensitive files, exfiltration patterns, destructive commands surface in red (alert-only)
- **Noise folding** — `execvp` PATH probes and fork bursts collapsed to one derived line (`--no-collapse` restores the raw firehose)
- **Credential redaction** on by default (`--redact off|argv|argv+content`)

## Quickstart

Requirements: Linux, `bpftrace`, `sudo`, and an agent session to watch.

```bash
cargo install --git https://github.com/ywu010622/agtrace
```

Attach to a running Claude Code session:

```bash
P=$(pgrep -nx claude)                             # the agent process
T=$(ls -t ~/.claude/projects/*/*.jsonl | head -1) # its transcript
sudo agtrace -p "$P" -S "$T" -f
```

What to look for: `derived bind` (call ↔ process linked), red `XX` (failure attribution), `>>` (suspected retry), `!!` (watchlist hit).

Show only the failures:

```bash
sudo agtrace -p "$P" -S "$T" -f --failures-only
```

## Example

A real session — the agent runs three commands, two fail. agtrace binds each call to its kernel evidence and attributes each failure to its deepest layer:

```text
2.025000  agent    a740509c  tool.call   Bash  cmd="foobarxyz123 --version; ls /nonexistent-dir-abc; ..." ?
4.615000  XX       -         fail        tool.call Bash "foobarxyz123 --version" -> BEFORE exec: command not found (no execve)
4.616000  XX       -         fail        tool.call Bash "ls /nonexistent-dir-abc" -> kernel: exit(2), 35 linked events
--- failures (2):
    BEFORE exec: command not found (no execve) x1
    kernel: exit(2) x1
```

Machine-readable when you need it: `--output json` emits JSONL (one event per line, summary last) with `jq` recipes in `--help`.

## How it works

```
agent transcript (JSONL, live tail) ─┐
                                     ├─► merge (200 ms window, one clock) ─► render
kernel events (bpftrace probes) ─────┘        execve / fork / exit / openat / connect / sendto
```

- **Collector**: a single bpftrace script (4 probe groups) compiled into the binary; filters by PID tree or cgroup — agtrace never traces system-wide.
- **Adapters**: `claude-code` (default; transcript JSONL as a live feed), `openshell` (stub on the same event interface), `jsonl` (generic: tails a file of agent events — one JSON object per line — so custom agents can plug in; see below).
- **Derived views**: binding, failure attribution, retry detection, watchlist — computed from evidence, never asserted without it. A failed call with no kernel evidence is reported as `no-kernel-source`, not guessed at.

See [DESIGN.md](DESIGN.md) for the full design (event model, clock discipline, evidence rules).

## Custom agents (LangChain, LangGraph, ...)

The kernel half (`-p`/`-C`) needs no adapter — it follows any process tree.
To get the agent layer (tool calls, model I/O) for binding and failure
attribution, emit events as JSONL and tail them with `--adapter jsonl`:

```bash
# 1. emit events from your agent (see examples/langchain_callback.py):
from langchain_callback import AgtraceCallbackHandler
handler = AgtraceCallbackHandler("/tmp/agtrace-events.jsonl")
agent = create_react_agent(model, tools, callbacks=[handler])

# 2. watch it live (PID = your agent process):
sudo agtrace --adapter jsonl -S /tmp/agtrace-events.jsonl -p <pid> -f
```

One JSON object per line; `ts` is ISO8601 or epoch seconds (missing = read time):

```json
{"type": "prompt",      "text": "do X", "ts": "2026-10-11T20:00:00.123Z"}
{"type": "tool.call",   "id": "call_1", "tool": "Bash", "command": "ls /tmp"}
{"type": "tool.result", "id": "call_1", "status": "success", "output": "..."}
{"type": "model.text",  "text": "I'll list /tmp"}
```

`id` correlates a call with its result (this is what `--failures-only` selects on).
For `tool.call`, `command` carries the shell command so argv binding works; other
tools correlate by time. Full schema: `src/adapter/jsonl.rs`.

## Status

v0.4.1. Adapters: Claude Code (live), generic jsonl (LangChain/LangGraph/any). Single static Rust binary; `cargo test` green (174 tests) plus a `tests/real_cases.sh` regression suite replaying real captured sessions.

## License

MIT — see [LICENSE](LICENSE).
