# Real-case fixtures (v0.3.1)

Three transcripts captured from real `claude -p` runs on this machine, plus the
helpers that replay them against a live workload. The point of this directory is
the bug v0.3 shipped with: every synthetic test passed, and the binder still
never fired on a real `claude -p "run curl ..."`, because the synthetic command
shapes were written to match the rules and the real ones were not.

Run it with:

```
tests/real_cases.sh              # all cases, all modes (~4 min; `window` dominates)
tests/real_cases.sh rc1          # one case
tests/real_cases.sh --fast       # skip the slow `window` mode (~1 min)
```

The live modes need passwordless `sudo` (kernel capture is bpftrace). The
`offline` mode does not. Without passwordless `sudo` the runner prints a note and
marks the privileged modes `skip` rather than `fail`, and exits on `fail` alone —
a missing privilege is not a binding regression, and reporting it as one would
train the reader to ignore the exit code.

## The cases

| tag | command the session ran | shape | why it is here |
|-----|------------------------|-------|----------------|
| rc1 | `curl -s -m 3 http://127.0.0.1:9/ ; echo "exit=$?"` | compound `;` | the original failure: 62.5 % whole-command token overlap, under the 80 % bar. Its first call also died in `bwrap` and never exec'd — the built-in false-positive probe. |
| rc2 | `ls -la /tmp \| head -5` | pipe | two execs from one call (`ls`, `head`); `head` is the segment that is not segment 1. |
| rc3 | `printf 'hi' > /tmp/rc3.txt && cat /tmp/rc3.txt` | `&&` | `printf` is a shell builtin and never execs; only `cat` is bindable. |

Provenance (raw transcripts live in `~/.claude/projects/-home-viktor/`):

| tag | raw session | captured |
|-----|-------------|----------|
| rc1 | `578651c4-4475-4d12-86c4-f26900b9d0b3` | 2026-10-11 13:10 |
| rc2 | `dae01835-4e08-4c0d-b392-b6e37df19058` | 2026-10-11 13:39 |
| rc3 | `14059d99-5750-4795-a02b-ab87dc1dba2e` | 2026-10-11 13:39 |

Re-freeze (after re-capturing) with:

```
python3 tests/real_cases/freeze.py <raw.jsonl> rc1_compound_semicolon.jsonl --session-id rc1
```

## What is sanitized, and what is deliberately not

Sanitized: `sessionId`, every `uuid`/`parentUuid` (rewritten to stable synthetic
ids with the parent links preserved), and the bulky private attachments — a
`prompt_snapshot` attachment carries the entire system prompt, ~330 KB per line.
Filesystem paths and usernames are left alone: they are not secrets, and the
runner needs the real paths to reproduce the real shapes.

**Not** sanitized, on purpose: the command shapes. `message.content[].input.command`,
`toolUseResult.dangerouslyDisableSandbox`, the timestamps and the line order are
exactly as captured. A fixture that prettifies the command cannot show anything
about a binder that reads the command.

## The timing contract (why the runner looks the way it does)

Two things were measured while building this, and both are load-bearing:

1. **The claude-code adapter does not rebase transcript timestamps**
   (`src/adapter/claude_code.rs` takes them at face value, unlike the openshell
   adapter's `--time-base now`). A frozen fixture therefore sits hours away from
   the live kernel events and the 120 s window can never overlap — so
   `rebase.py` moves the fixture's origin onto the current wall clock, preserving
   every offset between lines.

2. **The fixture origin is not the user prompt.** It is the minimum timestamp in
   the file, and in rc1 that is a `queue-operation` line 2.5 s *before* the
   prompt: the two tool calls are at **+4.536 s** and **+7.815 s**. Timing the
   live workload against the prompt-relative numbers (the ones you read off the
   transcript) put the first exec 330 ms *before* the first call, and the binder
   correctly refused it (`exec before the call never matches`). `offsets.py`
   reads the offsets out of the rebased fixture at run time instead.

Each measured mode:

| mode | live workload | what it proves |
|------|---------------|----------------|
| `live` | the case's own command, once per call, each in its own subshell | the bind fires, labelled `argv segment`, one call per exec |
| `unrelated` | a live `sleep` exec in the same process tree | no false positive from an exec that only *resembles* the call |
| `offline` | nothing | no exec, no bind, no `derived.bind` row |
| `window` (rc1) | one exec, for the second call only, with the first call pushed past the 120 s window | the call whose sandbox never ran stays unbound; the one that ran binds |

`window` exists because rc1's two calls carry a **byte-identical** command, and
with identical strings the binder's tie rule ("earliest unmatched wins") is the
only thing that can tell them apart. Widening the gap past `EXEC_AFTER_CALL_NS`
is the one arrangement that makes the false-positive assertion meaningful rather
than decorative. It costs ~2 minutes; `--fast` skips it.

The `live` mode gives each call its own subshell deliberately: an exec whose pid
is already inside a bound subtree claims nothing (`src/exact.rs`, `on_exec`), so
two execs from one shell would bind only once.

## Files

| file | role |
|------|------|
| `freeze.py` | raw transcript -> sanitized fixture |
| `rebase.py` | fixture -> current wall clock (`--gap-before` widens one gap) |
| `offsets.py` | where the tool calls sit, read out of the rebased fixture |
| `check_bind.py` | assert the `extra.bind` counters and the rule label from `--output json` |
| `rc*.jsonl` | the frozen fixtures |
