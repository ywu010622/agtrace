# agtrace — v0 design

> Make agent behavior debuggable like system calls.
> Correlate model requests, tool calls, shell commands, network access, file changes and
> permission denials into one unified timeline, so you can investigate what happened
> between **what the model decided** and **what the system actually did**.

Status: v0.1 (implemented). Every fact tagged `[verified]` in this document was measured on
this machine and comes with evidence; entries tagged `[unverified]` / `[uncertain]` have no
supporting evidence and must be re-checked before being relied on.

---

## 0. Architecture in one picture

```
                    ┌──────────────────────────────────────────┐
   agent layer      │  Adapter: claude-code (tail transcript)  │──┐
   (model/tool call)│  Adapter: openshell  (stub, fixture)     │  │
                    └──────────────────────────────────────────┘  │
                                                                  ▼
                    ┌──────────────────────────────────────────┐  ┌──────────────┐
   kernel layer     │  Collector: bpftrace script (one process)│─▶│  Merger      │
   (execve/net/file)│  swappable for aya / C+libbpf, same wire │  │ reorder+norm │
                    └──────────────────────────────────────────┘  └──────┬───────┘
                                                                       ▼
                    ┌────────────────────────────────────────────────────────────┐
   derived layer    │ bind (argv join) → collapse → fail attribution (§11/12/13) │─▶ timeline
                    └────────────────────────────────────────────────────────────┘    (text/json)
```

Two key constraints (they drive everything downstream):

1. **bpftrace scripts cannot share state** (each is its own process with its own maps).
   But pid-tree filtering needs shared state → v0 uses a **single bpftrace process**,
   internally sectioned by probe group.
2. **`nsecs` is CLOCK_MONOTONIC and system-wide consistent** `[verified]` → kernel-event
   timestamps from all collectors on one machine are **inherently comparable, with no clock
   alignment needed**. Only the agent layer (wall-clock ISO8601) needs a one-off
   monotonic→wall offset conversion.

---

## 1. Unified event schema

### 1.1 Record structure

Every event source normalizes into the same `Event`. Fields fall into four groups: time,
classification, process context, correlation keys.

```rust
struct Event {
    // ---- time ----
    seq: u64,            // monotonic sequence assigned by the merger; stable sort tiebreak on equal ts
    ts_ns: u64,          // CLOCK_MONOTONIC nanoseconds. **Primary sort key**. Kernel events come straight from bpftrace nsecs [verified]
    ts_wall_ns: u64,     // CLOCK_REALTIME nanoseconds (ts_ns + offset). **Display and cross-layer join only**
    ts_src: TsSource,    // Kernel | Converted | WallOnly  -- see the precision notes in §1.4

    // ---- classification ----
    layer: Layer,        // agent | runtime | infra | policy
    kind:  Kind,         // concrete event type, see §1.2
    source: String,      // producer id: "claude-code" / "bpftrace" / "openshell"

    // ---- process context (present for kernel events, None for pure agent events) ----
    pid:  Option<u32>,
    tid:  Option<u32>,
    ppid: Option<u32>,   // from curtask->real_parent->pid [verified]
    comm: Option<String>,
    cgroup_id: Option<u64>,   // bpftrace `cgroup` builtin [verified]

    // ---- correlation keys (see §1.3) ----
    corr: Corr,

    // ---- payload ----
    payload: Payload,    // kind selects the variant, see §1.2

    // ---- fidelity ----
    trunc: Vec<TruncNote>,   // which fields were truncated, and their original sizes
}

struct Corr {
    session_id:   Option<String>,  // Claude Code sessionId
    run_id:       Option<String>,  // openshell run_id
    agent_id:     Option<String>,  // openshell agent_id
    turn_id:      Option<String>,  // Claude Code promptId (one user turn)
    tool_use_id:  Option<String>,  // tool_use.id / tool_result.tool_use_id -- the only reliable key joining call and result
    uuid:         Option<String>,  // transcript line uuid
    parent_uuid:  Option<String>,  // transcript line parentUuid (rebuilds the causal chain)
    pid_root:     Option<u32>,     // the root process given to --pid
    pid_binding:  Binding,         // Exact | Heuristic | None -- **the core honesty field**, see §3.5
}
```

### 1.2 layer / kind table

`layer` says **which layer the evidence came from** (the layered-evidence idea borrowed from
jx, PIPELINE_V2.md "evidence chain": layered evidence + join key + timestamp). `kind` uses a
dotted namespace.

| layer | kind | meaning | event source | key payload fields |
|---|---|---|---|---|
| `agent` | `agent.prompt` | user / upstream input | transcript `user` (string content) | `text_preview`, `chars` |
| `agent` | `agent.prompt.queued` | queued input | transcript `queue-operation` | `text_preview` |
| `agent` | `agent.model.request` | start of one model call | derived (see §3.3) | `model`, `input_tokens`, `turn_id` |
| `agent` | `agent.model.thinking` | thinking block | transcript `assistant`→`thinking` | `preview`, `duration_ms` |
| `agent` | `agent.model.text` | text output block | transcript `assistant`→`text` | `preview` |
| `agent` | `agent.model.usage` | token / cost accounting | `assistant.message.usage` | `input_tokens`,`output_tokens`,`cache_read`,`model` |
| `agent` | `agent.tool.call` | the model decided to call a tool | transcript `assistant`→`tool_use` | `tool`, `input_preview`, `input_bytes` |
| `agent` | `agent.tool.result` | the tool returned | transcript `user`→`tool_result` | `tool`, `status`, `result_preview` |
| `agent` | `agent.sandbox.disabled` | **sandbox explicitly turned off** | `toolUseResult.dangerouslyDisableSandbox` | `true` |
| `runtime` | `runtime.proc.fork` | process created | `sched_process_fork` | `child_pid`, `child_comm` |
| `runtime` | `runtime.proc.exec` | command executed | `sys_enter_execve` | `filename`, `argv[]` |
| `runtime` | `runtime.proc.exec_fail` | exec failed | `sys_exit_execve` retval<0 | `filename`, `errno` |
| `runtime` | `runtime.proc.exit` | process exited | `sched_process_exit` | `exit_code` |
| `infra` | `infra.file.open` | file opened | `sys_enter_openat` (+exit) | `path`, `flags`, `dirfd`, `ok` |
| `infra` | `infra.net.connect` | connection initiated | `sys_enter_connect` (+exit) | `family`, `addr`, `port`, `ok` |
| `infra` | `infra.net.sendto` | datagram sent | `sys_enter_sendto` | `fd`, `len` |
| `policy` | `policy.deny` | permission denied (kernel verdict) | `sys_exit_*` retval ∈ {EACCES=-13, EPERM=-1} | `syscall`, `path`/`addr`, `errno` |
| `policy` | `policy.deny.agent` | permission denied (agent-layer verdict) | transcript tool_result text match | `tool`, `reason_preview` **`[unverified]`** |

**`agent.sandbox.disabled` gets its own kind**: it is one of the "decision vs actual behavior"
gaps this tool exists to catch — the model actively asking for the sandbox to be turned off.
On this machine the field appears **248 times** in transcripts (all `true`) `[verified]`.

### 1.3 Correlation keys: what connects, and what does not

| link | key | reliability |
|---|---|---|
| tool_use ↔ tool_result | `tool_use_id` | **exact** (carried by the transcript) |
| transcript line ↔ previous line | `parent_uuid`/`uuid` | **exact** |
| multiple events in one turn | `turn_id` (promptId) | **exact** |
| transcript session ↔ itself | `session_id` | **exact** |
| **transcript session ↔ OS process tree** | —— | **no reliable key; this is the design's biggest weakness, see §3.5** |
| sub-agent ↔ parent agent | `isSidechain` + `parentUuid` | approximate (`isSidechain=true` marks a sub-agent) `[verified]` |
| all processes in one container | `cgroup_id` | exact, but see the granularity warning in §2.4 |

### 1.4 Timestamp precision and conversion

- **Kernel events**: `ts_ns = nsecs` (CLOCK_MONOTONIC nanoseconds, measured to ns resolution)
  `[verified]`. One clock for the whole system, so collectors can be compared directly.
- **Agent events**: the transcript only has wall-clock ISO8601 (millisecond precision, e.g.
  `2026-10-03T15:16:53.634Z`). Conversion:
  ```
  offset = wall_at_start - mono_at_start     // Rust samples this once when starting each collector
  ts_ns  = wall_event - offset               // used for sorting
  ```
  Marked `ts_src = Converted`.
- **Error sources of that conversion** (stated honestly):
  1. NTP adjusting the wall clock mid-session → one-way drift; this design does **not**
     continuously correct for it (v0). The longer the session, the larger the error.
     `[uncertain]` Typical magnitude: under normal NTP slew, <1 ms per minute, but a step
     adjustment makes the error jump.
  2. The conversion samples once; it does not re-sync.
  - Mitigation: `--resync-interval` (default 30 s) re-samples the offset and corrects
    gradually. **v0 turns this on by default**; the cost is negligible.

---

## 2. Collection architecture

### 2.1 Why a single bpftrace process

`--pid` mode needs a **pid tree** maintained inside the script (see §2.3), and bpftrace
processes **cannot share maps**. Splitting into 3 scripts by event source would force each
one to reimplement fork detection and maintain its own tree, and the three trees could
disagree at boundary moments.

→ **v0 uses one bpftrace script**, internally sectioned by probe group. Swappability lives in
the **collector interface** (§2.5), not in the number of scripts.

### 2.2 Probe inventory

All probes below were verified loadable on this machine `[verified]` (kernel
7.0.0-31-generic, bpftrace v0.20.2, BTF present).

#### Group A — processes and commands (`runtime`)

```
tracepoint:sched:sched_process_fork        // maintain the pid tree + emit fork events
tracepoint:sched:sched_process_exit        // prune the tree + emit exit
tracepoint:syscalls:sys_enter_execve       // command + argv
tracepoint:syscalls:sys_exit_execve        // failure detection
```

Output line format (`|`-separated, so it cannot collide with argv content):
```
E|A|<nsecs>|<pid>|<tid>|<ppid>|<cgroup_id>|<comm>|<filename>|<argc>|<argv_json_escaped>
```

**Important measured findings**:
- At `sys_enter_execve`, `comm` is **still the parent's name**; it only becomes the new name
  after exec completes `[verified]`. So **you cannot filter commands by `comm`** (that is
  exactly how my first test failed). To filter by command name you must look at the basename
  of `filename`.
- argv is read via `(uint64*)args->argv` + **constant indices**; `str()` returns an empty
  string for a NULL pointer (safe) `[verified]`:
  ```
  $a = (uint64*)args->argv;
  printf("... |%s|%s|%s", str($a[0]), str($a[1]), str($a[2]));
  ```
- **`unroll(N)` does not provide an index variable `$i`** `[verified]` (it errors with
  `Undefined or undeclared variable: $i`), so indices must be written as constants. → v0 uses
  `--argv-max` (default 8) to control how many arguments are expanded; anything beyond that is
  dropped and recorded in `trunc`.
- Casting to `(char **)` fails on this machine's BTF with
  `Cannot resolve unknown type "char"` `[verified]` → `(uint64*)` is mandatory.

#### Group B — files (`infra`)

```
tracepoint:syscalls:sys_enter_openat   // grab filename/flags/dirfd, stash it
tracepoint:syscalls:sys_exit_openat    // grab retval, pair it with the stash
```

**Key measured constraint**: the `sys_exit_openat` tracepoint **has no filename argument**
`[verified]` (it errors with `does not contain a field named 'filename'`). You must use a
**per-tid stash map**: store on enter, fetch on exit:

```
tracepoint:syscalls:sys_enter_openat /@in_tree[pid]/
{ @stash[tid] = str(args->filename, 256); @flags[tid] = args->flags; }

tracepoint:syscalls:sys_exit_openat /@in_tree[pid]/
{
  printf("F|...|%s|%x|%d\n", @stash[tid], @flags[tid], args->ret);
  delete(@stash[tid]); delete(@flags[tid]);
}
```

**Noise control (mandatory)**: openat is an extremely high-frequency event — measured, in 3
seconds docker/containerd alone produced hundreds of them `[verified]`. v0 by default **only
records opens with write intent**:
```
/@in_tree[pid] && (args->flags & (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND))/
```
`--file-all` disables that filter (it is very noisy, and the user is warned explicitly).

**Stash leaks**: if a process is killed between enter and exit (e.g. `exit_group` in a stub),
the stash entry is never cleared. → `sched_process_exit` clears the stash for every tid of
that process (precise per-tid cleanup inside bpftrace needs extra bookkeeping, so v0 uses
**periodic cleanup**: `interval:s:30` empties the stash, at the cost of losing the very rare
syscall pair that spans 30 s). `[approximate]`

#### Group C — network (`infra` / `policy`)

```
tracepoint:syscalls:sys_enter_connect   // destination address
tracepoint:syscalls:sys_exit_connect    // success/failure -> policy.deny
tracepoint:syscalls:sys_enter_sendto    // UDP / unconnected-socket sends
```

**Measured constraints**:
- `((struct sockaddr_in*)args->uservaddr)->sin_port` reads back as **network-order bytes
  interpreted as host order**; you **must `bswap()`** to get the real port. Measured evidence:
  redis-cli read as `60184`, and `bswap(60184)=6379` = redis's default port `[verified]`.
- Addresses print as dotted-quad directly via the `ntop()` builtin `[verified]`.
- `sa_family`: 2=AF_INET, 10=AF_INET6, 1=AF_UNIX. **AF_UNIX is a substantial share** (measured:
  lots of AF_INET6 and AF_UNIX connections from mc/pg_isready on this machine) `[verified]` →
  they need separate handling; AF_UNIX has no notion of "address", so only the `policy.deny`
  part applies.
- IPv6 addresses need a different decode path via `sockaddr_in6`; v0 only decodes the first 16
  bytes of `sin6_addr` + `ntop`.

Output line format:
```
C|<nsecs>|<pid>|<tid>|<cgroup_id>|<comm>|<fd>|<family>|<addr>|<port>|<ret>
```

#### Group D — permission denials (`policy`)

v0 **decides from errno only**, with no LSM/kprobe hooks:
- `sys_exit_openat` retval == -13 (EACCES) or -1 (EPERM) → `policy.deny` (emitted as a side
  effect of Group B)
- `sys_exit_execve` retval < 0 → `runtime.proc.exec_fail`
- `sys_exit_connect` retval < 0 → `policy.deny`

Rationale: the errno path was measured to compile and load, and it reflects **a real verdict
the kernel already made**, which is more stable than an LSM hook. The cost is that you cannot
tell **which** LSM/policy denied it. `[trade-off]`

### 2.3 Filtering: the `--pid` tree and `--cgroup`

**First, a common misconception**: bpftrace's `-p PID` is **not** syscall filtering; its
semantics are "enable USDT probes on PID" `[verified]` (help text, and measured: `-p $$` still
printed unrelated runc/pgrep processes). **You must filter inside the probe body yourself.**

`--pid` mode (the equivalent of strace `-f`):
```
BEGIN {
  // Rust passes the seed pid list as positional arguments (scanned from /proc at startup)
  @in_tree[<seed...>] = 1;
}
tracepoint:sched:sched_process_fork
{
  if (@in_tree[pid]) { @in_tree[args->child_pid] = 1; }
}
```
- Positional parameters `$1/$2/...` were measured to work `[verified]`
  (`bpftrace -e '...' 4242 "/tmp/x"` → `$1=4242, $2="/tmp/x"`) → Rust uses them to pass the
  seed pids and the cgroup id.
- Seeds come from walking `/proc/*/stat` at startup for the pid's existing descendants
  (otherwise children forked before attach would be missed).
  `[approximate: there is a race window before attach]`

`--cgroup` mode: `/cgroup == $1/`, needs no shared state at all, and is the cleanest option.

### 2.4 Clocks and out-of-order merging (the merger)

**Within a stream**: a single bpftrace process's printf output is **executed in order**, so
events on the same CPU are naturally ordered; cross-CPU events are written to the perf ring
buffer by the kernel in occurrence order, and are **mostly but not strictly ordered** (CPU
concurrency).

**Across streams**: the kernel stream (monotonic ns) and the agent stream (converted ns) are
merged on the same `ts_ns` axis.

**Strategy: bounded reorder window**

```
merge_window (default 200ms, tunable with --merge-window)
events go into a min-heap (keyed by ts_ns)
when now - heap.min.ts_ns > merge_window, pop and emit
```

**Key design decision: agent events never block the timeline.**
The transcript is **written after the fact** (a tool_result line lands only once the tool has
finished), with delays of seconds or more, unpredictably. Waiting strictly on timestamps would
stall a live tail.
→ Rules:
- Kernel events: participate in the reorder window normally.
- Agent events: **emitted immediately**, never waiting on the window; if their `ts_ns` is
  earlier than the watermark of already-emitted events, mark `late=true` and append a `(late)`
  marker to the output line.
- This is a **lossy ordering guarantee**: the output order is "approximately chronological",
  not strictly chronological. It **must be presented honestly** (see the `late` marker in §4.3).

**Measured real-time conclusions**: bpftrace's output is **not** delayed by stdout being a pipe
— measured, `interval:s:1` TICK lines arrived at the other end of the pipe on a ~1.000 s
cadence `[verified]`.
But there are two **operational constraints you must respect** (both measured the hard way):
1. **You must pass `-B none`** (bpftrace's `-B MODE` = output buffering, values
   `full`/`none`) `[verified]`.
2. **Rust must read bpftrace's stdout directly; no shell pipeline in between**. Measured:
   `bpftrace ... | grep ... | head` makes output disappear for a long time because of grep's
   **block buffering**, which looks like a hang `[verified]` (that was the cause of my first
   few "no output" tests, not a bpftrace problem). → Use `std::process::Command` and read line
   by line from a directly held stdout handle.

**Graceful shutdown**: when bpftrace is SIGTERM'd, a partially written printf line can be
truncated → the parser **must tolerate an incomplete final line** (drop it or wait for the
rest) and must never panic on half a JSON line.

### 2.5 The swappable collector interface

bpftrace is just one implementation of `Collector`. The interface is a **line protocol**:

```
trait Collector: once started, continuously writes '\n'-terminated UTF-8 lines to stdout.
Each line = one kernel event, in the "output line format" of the relevant group in §2.2.
Process exit = collection finished.
```

A future aya/C+libbpf implementation only has to emit **the same line format**; the Rust-side
parser and merger need no changes at all. This is also why v0 uses a **custom compact text line
format** instead of bpftrace's `-f json`.

> On `-f json`: measured, it merely wraps printf content in an envelope
> `{"type": "printf", "data": "<raw output>"}` `[verified]` and **provides no structured
> fields**. Its value is that the envelope can distinguish event types — the envelope types
> extracted from the bpftrace binary are: `printf`, `attached_probes`, `lost_events`,
> `helper_error` `[verified, extracted via strings]`.
> → **v0 decision: keep the text line protocol** (the custom format is more compact and
> friendlier at high frequency), but **also use the `-f json` envelope for loss detection**: if
> bpftrace can surface `lost_events` while in json mode, report it as a loss signal; otherwise
> fall back to parsing the "Lost N events" warning on stderr.
> `[uncertain]`: the **exact field structure** of the `lost_events` envelope is unverified
> (a perf buffer overflow could not be triggered reliably). Implementers must trigger one for
> real (`BPFTRACE_PERF_RB_PAGES=1` can force an overflow) before writing the parser.

---

## 3. Adapter interface

### 3.1 trait definition

```rust
/// One agent event source. Non-blocking, poll-based, so it can be multiplexed with the
/// bpftrace stdout reader in a single event loop (avoiding a thread + channel per adapter).
pub trait EventAdapter: Send {
    /// Stable identifier, used for --adapter selection and the event's source field
    fn id(&self) -> &'static str;

    /// Capability declaration: which kinds are produced, whether live tail is supported,
    /// whether an external path must be supplied.
    /// The merger uses it to decide whether some kinds need special handling (e.g. pid_binding).
    fn capabilities(&self) -> Capabilities;

    /// Non-blocking pull. Returns the events added since the last call (possibly empty).
    /// Must not block for more than ~10ms, or it will slow the whole timeline down.
    fn poll(&mut self, out: &mut Vec<RawAgentEvent>) -> Result<PollOutcome, AdapterError>;

    /// Graceful shutdown (flush, close file handles)
    fn shutdown(&mut self);
}

pub enum PollOutcome {
    /// No new lines this round (normal, not an error)
    Idle,
    /// New events arrived
    Progress,
    /// The source is finished (file deleted and not reappearing / offline fixture exhausted)
    Eof,
}
```

`Capabilities`:
```rust
struct Capabilities {
    kinds: Vec<Kind>,          // which kinds this adapter produces
    live: bool,                // can it tail live (the openshell stub is false; fixture-only)
    needs_pid_binding: bool,   // does it need the merger to bind a pid for it (the Claude Code adapter does)
}
```

**Why `poll` rather than an `async Stream`**: v0 does not pull in tokio. A simple `mio`/polling
main loop suffices:
```
loop {
    if let Some(line) = bpf_stdout.try_read_line()? { merge_kernel(line) }
    for a in &mut adapters { a.poll(&mut buf)?; merge_agent(buf.drain(..)) }
    merger.flush_due(now)
    if quit { break }
    sleep(2ms)   // kernel events are covered by the min-heap window; 2ms polling latency is acceptable
}
```

### 3.2 agent event JSONL protocol (the adapters' unified output)

Internally each adapter parses its source format into this unified JSONL. The format **is also
the `--output json` output format** (one less conversion):

```json
{"ts":"2026-10-03T15:16:53.634Z","layer":"agent","kind":"agent.tool.call",
 "source":"claude-code","corr":{"session_id":"65a34ef2-...","turn_id":"162ece46-...",
 "tool_use_id":"call_00_P8gW34gerrE9RwZSl9Vp0202","uuid":"31d70c12-..."},
 "payload":{"tool":"Read","input_preview":"{\"file_path\":\"/home/viktor/opc/PROJECT.md\"}",
 "input_bytes":47},"trunc":[]}
```

Conventions:
- `ts` is ISO8601 UTC (milliseconds), matching the transcript's native format, to avoid
  precision illusions.
- Every string field in `payload` whose name ends in `_preview` is **already truncated**, and
  `trunc` carries `{"field":"input_preview","orig_bytes":4712,"kept_bytes":512}` alongside it.
- **Never put an unescaped newline inside `payload`.**

### 3.3 Claude Code adapter parsing rules

**Input**: `~/.claude/projects/<slug>/<sessionId>.jsonl`, where slug is the cwd path with `/`
replaced by `-`.
**Read mode**: `tail -f` semantics. Keep (inode, offset), `read` to EOF each round; reset the
offset if the inode changes or the file is truncated. **Note**: the session file is appended to
while the session runs, but **writes are not guaranteed to end on a line boundary** → the
parser must keep an incomplete trailing line buffered for the next round.
`[unverified: whether a partial line can actually occur]`

**Line type mapping table** (types measured in this machine's transcripts: `queue-operation`,
`user`, `assistant`, `attachment`, `atis-latch`, `last-prompt`, `cost-state`) `[verified]`:

| transcript line | condition | → kind | notes |
|---|---|---|---|
| `queue-operation` | `operation=="enqueue"` | `agent.prompt.queued` | payload from `content` |
| `user` | `message.content` is a **string** | `agent.prompt` | real user input |
| `user` | `message.content` contains a `tool_result` block | `agent.tool.result` | correlated via `tool_use_id`; `sourceToolAssistantUUID` points at the assistant line that issued it |
| `assistant` | content block `type=="thinking"` | `agent.model.thinking` | payload: `thinking` (truncated), `thinkingDurationMs` |
| `assistant` | content block `type=="text"` | `agent.model.text` | |
| `assistant` | content block `type=="tool_use"` | `agent.tool.call` | payload: `name`, `input` (truncated) |
| `assistant` | `message.usage` present | `agent.model.usage` | `input_tokens`/`output_tokens`/`cache_read_input_tokens`/`message.model` |
| any line | `toolUseResult.dangerouslyDisableSandbox == true` | `agent.sandbox.disabled` | high-value safety signal |
| `attachment` | —— | **dropped in v0** | appears 27 times; system-reminder environment snapshots, noise |
| `atis-latch` / `last-prompt` / `cost-state` | —— | **dropped in v0** | internal state, not behavioral events |
| any other unknown type | —— | counted, **no event, no error** | forward compatibility: 8 different versions already seen on this machine |

**`agent.model.request` is derived, not read directly** `[approximate]`:
there is **no** standalone "request started" line in the transcript. v0 treats "a new
`assistant` line appears whose `message.id` differs from the previous one" as the start of a
model call, with `ts` taken from that assistant line's timestamp.
→ **This conflates "request sent" with "response finished writing"**: an assistant line's
timestamp is when the **response was recorded**, not when the request went out. So
`agent.model.request` has a **systematic offset** relative to kernel events, roughly equal to
the model's thinking + generation time. This is an important approximation of the design and
**must not be used to infer "the model thought for N seconds before running the command"**.

**`tool_use` argument truncation**:
- `input` is a JSON object → `serde_json::to_string`, then truncated to `--tool-arg-max`
  (default 512 bytes).
- **Special case**: the `Bash` tool's `input.command` is extracted separately with a larger
  `--bash-cmd-max` (default 1024), because it is the most-read field. Measured tool
  distribution on this machine: `Bash` 361, `Read` 83, `Write` 58, `Edit` 33, `TaskUpdate` 30,
  `TaskCreate` 20 `[verified]` → Bash dominates, and deserves special treatment.
- Truncation method: cutting by **bytes** can split a multi-byte UTF-8 sequence → the
  implementation must cut on **character boundaries** (`char_indices`), otherwise a Chinese
  prompt produces invalid UTF-8. **This is a bug class that must be avoided.**

**Handling multi-line content**:
- In the transcript's `toolUseResult`, `Read` returns the whole file content and `Bash` returns
  stdout/stderr — measured, `Read`'s `toolUseResult.file.content` is the entire PROJECT.md,
  thousands of characters.
- → `payload` carries **only `_preview` (512 bytes by default)**, with **newlines escaped to
  literal `\n`**, guaranteeing one event always occupies exactly one line.
- Full content is emitted only with `--output json --full` (with an explicit warning that it
  will be large).
- `toolUseResult`'s **type is not fixed**: measured `dict` 586 times, `str` 24, `list` 5
  `[verified]` → the parser must match all three and must not assume a dict.
- Known dict shapes (by frequency) `[verified]`:
  - `{stdout, stderr, interrupted, isImage, noOutputExpected, dangerouslyDisableSandbox}` ← Bash (244)
  - `{file:{filePath,content}, type}` ← Read (83)
  - `{content, filePath, originalFile, structuredPatch, userModified, type}` ← Write (54)
  - `{filePath, newString, oldString, originalFile, replaceAll, structuredPatch}` ← Edit (31)
  - `{statusChange, success, taskId, updatedFields}` ← TaskUpdate (29)
  → write one `normalize_result(tool, toolUseResult) -> preview` function per tool, with an
  unknown-shape fallback to truncated `serde_json`. **Unknown shapes must degrade, never panic.**

### 3.4 OpenShell adapter (stub)

Same trait; the input is `~/jx/fixtures/openshell_*.jsonl` (offline, `live: false`).
Measured fixture fields: `time` (float seconds — not wall clock, but **relative time**),
`agent_id`, `run_id`, `activity`, `tool`, `status`, `status_detail`, `tokens` `[verified]`.
`activity` has only 4 values: `llm.call` (37), `tool.invoke` (42), `tool.result` (42),
`token.usage` (15) `[verified]`.

Mapping:
| activity | → kind |
|---|---|
| `llm.call` | `agent.model.request` |
| `tool.invoke` | `agent.tool.call` (the `tool` field + `status_detail` as the preview) |
| `tool.result` | `agent.tool.result` (`status` ∈ {Success, Failure} → our status) |
| `token.usage` | `agent.model.usage` (`tokens`) |

**Key difference**: the fixture's `time` is **relative seconds (float)**, e.g. `4003.0`,
`8004.0` — **not absolute time comparable across fixtures** (different fixtures have different
time origins). → The stub must support `--time-base wall|<now>|epoch`, defaulting to anchoring
the minimum value at `now`. **Never treat fixture time as a real wall clock**, or the timeline
will be absurdly misaligned with kernel events. This is the easiest mistake to make during
offline verification.

### 3.5 The biggest weakness: binding agent events to kernel events

The transcript contains **no pid field at all** `[verified: the assistant line's key list has
no pid]`. Yet "what the model decided vs what the system actually did" is exactly what requires
connecting agent events to a concrete process tree.

There are **two different questions** here, with different evidence and different answers, and
conflating them is how a tool starts lying. agtrace asks them separately and reports both:

| | question | field | levels |
|---|---|---|---|
| **L1–L2, session level** | which process tree is this *session*? | `corr.pid_binding` | Exact / Heuristic / None |
| **L3, event level** | which *tool.call* produced this kernel event? | `event.binding` | Exact / Heuristic / None |

An agent event starts at its session level (L1–L2) and can be upgraded to `Exact` by L3. A
kernel event starts at `None` and only L3 can move it. **Nothing else ever promotes a row**,
and a level is never inferred from the level next to it.

#### L1–L2 — session ↔ process tree (unchanged since v0.1)

1. **`Exact`**: `/proc/<pid>/cmdline` contains `claude --resume <sessionId>`, and `<sessionId>`
   equals the transcript's `sessionId`.
   `[verified]` this machine really does have processes of the form
   `claude --resume ba284a2a-6a00-4bc1-b890-8a16d98e5b1a`, and the transcript has the
   `--resume` sessionId form.
   **Limitation**: only holds for `--resume` sessions; a fresh session's cmdline is just
   `claude`, with no sessionId to match.

2. **`Heuristic`**: match `/proc/<pid>/cwd` (`readlink`, measured readable `[verified]`)
   against the transcript's `cwd` field `[verified]` (e.g. `/home/viktor/opc`), plus the
   process start time falling inside the session window and `comm`/cmdline containing `claude`.
   With multiple candidates it **does not guess** — it flags the ambiguity.

3. **`None`**: if it cannot bind, it says so honestly as `pid_binding: None`. The timeline is
   still emitted, but the user is **explicitly told that the link between agent events and
   kernel events is "time proximity only", not "causal identity"**.

#### L3 — tool.call ↔ exec (v0.3, the argv join key)

The insight is that the *same string* crosses the boundary:

```
agent   tool.call  Bash  cmd="curl -s -m 3 http://127.0.0.1:9/"
kernel  proc.exec        /bin/bash  argv=["bash" "-c" "curl -s -m 3 http://127.0.0.1:9/"]
```

argv is therefore a **join key**, not a resemblance. Everything below is the rule as shipped
(`src/exact.rs`), not an aspiration.

**Record.** On an `agent.tool.call` for a shell tool (Claude Code `Bash`; the input is read
from `command`, then `cmd`) with a non-empty string command, record
`(session_id, tool_use_id, cmd, ts)`. If the collector had to truncate the command string, the
truncation flag travels with it. At most 4096 unclaimed calls are held; the oldest are dropped
first, so a pathological call flood cannot grow memory without bound.

**Match.** On every `proc.exec` with a non-empty argv, against the unclaimed calls inside the
window, in this order:

- **Rule D — direct substring** (`argv exact`): `argv.join(" ")` contains the command string on
  a **token boundary** (the character before/after the match is a separator or an end), so
  `…/bin/ls` does not match `…/bin/lsblk`. Catches the `bash -c "<cmd>"` and
  `<cmd>` forms.
- **Rule S — substring inside a `-c` payload** (`argv substring`, v0.3.1): when the exec is a
  shell (`bash`, `sh`, `dash`, `zsh`, `ksh`) with `-c`, the command string is tested as a plain
  substring of the **`-c` payload** (`argv[i]`), not of the joined line. This is the shape the
  real harness produces — `bash -c "source …/snapshot-*.sh …; <cmd>"` — where the command never
  appears as its own argv token. Guards: the payload must **not** be kernel-truncated (a 64-byte
  cut turns `lsblk` into `ls`, and matching that would be a false positive), and the match is
  always labelled `argv substring`, never `exact`.
- **Rule G — segment** (`argv segment`, v0.3.1): the command is split on `;`, `&&`, `||`, `|`
  (quote-aware — a `;` inside quotes does not split), and **any** segment is offered to rule T's
  token test. This is what rescues compound commands: for
  `curl -s -m 3 http://127.0.0.1:9/ ; echo "exit=$?"` the whole string overlaps the `curl` exec
  by only 62.5 % and fails, while segment 1 overlaps by 100 %. Only fires when the command really
  splits into ≥ 2 segments, so it can never loosen the single-command case.
- **Rule T — token overlap** (`argv overlap NN%`): both sides tokenized with a hand-written
  POSIX `shlex` (no crate); require `basename(cmd[0]) == basename(argv[0])` **and**
  `NN = 100 * |multiset intersection| / max(|cmd tokens|, |argv|) ≥ 80`. Catches PATH
  completion (`git` → `/usr/bin/git`) and re-quoting. Order-insensitive; the executable-name
  check is what stops `curl evil.sh` from matching `bash evil.sh`.
- **Truncated command** (`argv prefix NN%`): if the recorded command was cut, its last token
  matches as a *prefix*, and argv tokens that the cut hid still count in the denominator — so a
  truncation that could hide a whole argument **fails to match** rather than matching on the
  visible part. A truncated command is **never** labelled `argv exact`.
- A `***` (a token masked by `--redact argv`) is a **wildcard on both sides**; that is what
  keeps a masked run bindable, and it is also why a match involving `***` cannot come out as
  `argv exact`.
- An exec with **no argv** is never matched. There is no join key, so there is no claim.

The rule **priority** is `D > S > G > T`: the parenthetical names the strongest rule that fired,
and a command that D can match is never reported as S or G. The order is strictness — D demands
the whole string on a token boundary, S demands the whole string anywhere in the payload, G
demands one segment to token-match, T accepts a fuzzy 80 % overlap.

**Window.** The exec must occur **within 120 s after** the call
(`EXEC_AFTER_CALL_NS = 120 * 10^9`). An exec *before* the call never matches: the kernel cannot
have run an intent that had not been formed yet. A call stays claimable for the whole window,
which is what makes retries bind (the same command is often exec'd again after a failure).

**Order.** Among the calls that match, **the longest command wins; ties go to the earliest**.
A call is claimed at most once, an exec claims at most one call, and an exec that is already
inside a bound subtree claims nothing. The tie rule is the retry rule of the task statement —
two identical commands, two identical execs, first-to-first, second-to-second, no
cross-wiring — while the length rule exists because the retrofit is otherwise wrong in a way
that matters: with strict earliest-first, a `ls` call would swallow the exec of a later
`ls -la` (both match it; only the longer one is the real join). This deviation is deliberate
and is recorded here rather than silently shipped.

**Effect.** The matched pid **and its whole subtree** (every later fork descendant) become
`binding: exact`; `corr.tool_use_id` is filled in on those kernel rows; the `proc.fork` row
that created the bound child is marked too (which is why that row is held back a batch — see
the end of this section). Agent rows of that `tool_use_id` are
upgraded to `exact` **only if they are still ahead of the binder when the match happens**.

One derived row is emitted, and exactly one:

```
     4.004108  derived  1121950   bind            tool.call Bash "/bin/echo hello-v0..." <-> exec /bin/echo (argv exact)
```

Its payload is `{tool, cmd_preview, exec_filename, rule, delta_ms, pid, subtree_pids}`, its
`ts` is the exec's, so it lands immediately after the exec it explains and inside the same
`corr.tool_use_id`. **The parenthetical names the rule that actually fired** — `argv exact`
for rule D, `argv substring` for rule S, `argv segment` for rule G, `argv overlap NN%` or
`argv prefix NN%` for the token rules, with the computed percentage in the label. Claiming `exact` for a fuzzy match is the one thing this feature must
never do.

**Honest limits** (measured, and printed rather than hidden):

- `bash -c "<cmd>"` and plain `<cmd>` bind by rule D. A command whose kernel argv genuinely
  differs from its text — `python3 - <<EOF` heredocs, `VAR=x cmd` where the shell rewrites argv,
  a path that only exists after `cd` — binds by rule T or not at all.
- **On this machine's Claude Code, real Bash calls bind by rule G, not rule S.** The harness
  execs `/bin/bash -c "source ~/.claude/shell-snapshots/snapshot-bash-*.sh … && eval '<cmd>'"`,
  and the kernel caps a captured argument at 64 bytes (`MAX_STRLEN`, §5.5 pitfall 9), so
  `argv[2]` is the *truncated prelude* and contains no trace of the command. S is skipped by
  design on a truncated payload; the inner command then exec's on its own (`curl`, `ls`, `cat`)
  and G matches its segment. Measured on all three real cases in `tests/real_cases/`: `argv
  segment`, never `substring`, never `exact`. S still earns its place for short payloads
  (`sh -c '<cmd>'`, other agents' shell wrappers) and is the stricter of the two.
- **A call whose sandbox never ran the command keeps its `?`.** In the captured RC1 session the
  first `curl` died in `bwrap` ("Failed RTM_NEWADDR") and never exec'd; only the retry ran. The
  suite asserts that shape directly: with the first call pushed past the 120 s window and a
  single live exec for the second, exactly one call binds and it is the second
  (`tests/real_cases.sh`, mode `window`).
- A shell builtin (`cd`, `export`, `[[`) never execs, so there is nothing to bind; the call
  keeps its `?` forever. That is correct: no process ran.
- Two *different* calls carrying the same command inside one window are distinguishable only by
  order (the tie rule), and only if they exec in the same order.
- **In `-S` replay, a matched `tool.call` row keeps its `?`.** The transcript is replayed in
  the first batch, before any kernel event exists, so the row is already on screen when the
  match happens; only rows that are still ahead of the binder can be upgraded. The
  `derived.bind` row is the authoritative statement of the match, and `--output json` carries
  `binding` + `corr.tool_use_id` on every event for a lossless view. Retro-printing a
  correction row for an already-rendered line would be noise, and *un*-printing is impossible.
- `--no-bind` turns L3 off entirely (`--output json` keeps the raw events; the summary block
  reports `"enabled": false`), so the pre-v0.3 rendering is reproducible with one binary.

Output layer: whenever `pid_binding != Exact`, agent event lines for that session get a `?`
marker, and a one-line caveat is printed at startup. A kernel row that L3 has bound gets ` =`
(§4.2). **Presenting a Heuristic as established fact is not allowed** — this is the credibility
floor of the tool.

#### Why the fork row is held back one batch

A `proc.fork` row says "I created pid N", and whether N belongs to a tool.call is only known
once **N itself execs**. Measured while building acceptance #1: fork and exec were 7 ms apart,
and the merger's `take_ready()` cut exactly between them — so the fork row rendered as
unbound and, 7 ms later, its child's exec row rendered with `=`. A self-contradicting pair is
exactly what §4.3 forbids. The binder therefore runs in two passes over each batch (judge, then
stamp) and holds back the undecided **suffix** of a batch by one poll cycle; the next batch
re-stamps it with the child's now-known binding. The whole suffix is held, not just the fork
row, because releasing a fork row's younger siblings ahead of it would invert their order —
that defect was found and fixed during acceptance #3 (BUILD_LOG §15.4).

---

## 4. CLI shape

### 4.1 Options

```
agtrace [OPTIONS]

Target (give at least one; -p and -C are mutually exclusive):
  -p, --pid <PID>          follow this process and its descendants (like strace -f)
  -C, --cgroup <PATH>      follow every process in this cgroup (e.g. /sys/fs/cgroup/xxx)
  -S, --session <ID|PATH>  follow the agent layer (Claude Code session id or transcript path)

  (with no target, agtrace exits with an error -- it never does system-wide tracing,
   which amounts to tracing without a filter; openat would drown everything)

Behavior:
  -f, --follow             live tail (the v0 default behavior; without it, exit at EOF, for offline fixtures)
      --adapter <NAME>     claude-code | openshell     (default claude-code)
      --transcript <PATH>  explicit transcript file or directory
      --time-base <MODE>   fixture time anchor: now | wall | epoch   (default now)
      --source <LIST>      comma-separated: exec,file,net,agent      (default all)
      --merge-window <MS>  reorder window                            (default 200)
      --resync-interval <S> clock offset resample, 0=off             (default 30)

Output:
      --output <text|json> default text (json keeps untruncated fields)
      --failures-only      print only failing tool.call chains + the footer (§13); for piping
      --full               expand truncation details (it can NOT restore lost data)
      --no-color           disable color (auto-off when stdout is not a tty)
      --max-events <N>
      --duration <SEC>

Fidelity / privacy (see §5.2 -- these are not optional):
      --redact <MODE>      off | argv | argv+content    (default argv)
                           argv masks credential-shaped command-line arguments as ***,
                           but leaves agent prompt/thinking/tool text unmasked
                           (pass argv+content to mask that too).
      --file-all           log every openat (default: write intent only)
      --argv-max <N>       max argv entries captured                  (default 8)
      --tool-arg-max <N>   truncate tool_use input                    (default 512)
      --bash-cmd-max <N>   truncate Bash command                      (default 1024)
  -v, --verbose            show dropped/unknown events, loss stats, truncation details
```

**Why the target must be explicit**: measured, unfiltered openat produces hundreds of noisy
lines in 3 seconds `[verified]`. Without target filtering, "watch the behavior stream live" is
unusable.

### 4.2 Timeline output format (text, strace style)

Design principle: **one event per line**, left-aligned relative timestamps, fixed column widths
for easy visual scanning. The block below is a layout illustration, not a capture — every real
capture quoted anywhere in this document names the file it came from.

```
agtrace: target=pid 644607 (tree), session=65a34ef2 (binding: exact), 6 sources, following

     0.000000  agent    65a34ef2  model.request   deepseek-v4-pro  in=37382
     0.000000  agent    65a34ef2  tool.call       Bash  cmd="cat /etc/shadow"
     6.240913  runtime  644607    proc.exec       /usr/bin/cat  argv=["cat","/etc/shadow"]
     6.241100  policy   644607    deny            openat /etc/shadow  EACCES(-13)
     6.241150  agent    65a34ef2  tool.result     Bash  Failure  "Permission denied"
     6.500000  agent    65a34ef2  model.usage     out=46  cost=$0.1504
     7.100000  agent    65a34ef2  sandbox.disabled  !! dangerouslyDisableSandbox=true
```

Column definition:
```
{rel_ts:>13.6}  {layer:<8} {key:<9} {kind:<15} {payload}
```
- `rel_ts`: seconds since the first event, 6 decimals (microseconds, matching strace).
- `layer`: `agent` / `runtime` / `infra` / `policy`, fixed width 8.
- `key`: the correlation identifier — the first 8 chars of session_id on the agent layer, the
  pid on the kernel layer. This is the slot strace uses for `[pid 123]`.
- `kind`: fixed width 15, for vertical scanning.
- Fidelity markers (ASCII only, so columns line up in every terminal):
  - `?` suffix = `pid_binding != Exact` (§3.5 L1–L2; agent rows only)
  - ` =` suffix = this kernel/collapse row was **argv-bound to a tool.call** (§3.5 L3). It is
    the positive counterpart of `?`, and it is deliberately not printed on the `derived.bind`
    row itself — that row *is* the binding, so marking it would be self-reference. The marker
    reports a match, not a level: it is never printed for a Heuristic-downgraded row, and the
    rule that produced it (`argv exact` / `argv overlap NN%` / `argv prefix NN%`) is named in
    the `derived.bind` line.
  - `(late)` = the agent event arrived after the reorder window had already passed (§2.4)
  - `~` = some field of this event was truncated (`trunc` non-empty; `-v` expands the details)
  - `>>` in the derived layer = retry view; `!!` = watchlist / wedge / loss alert
  - `XX` in the **layer** column = a failure attribution row (§13): the only derived row that
    takes the layer slot instead of the word `derived`. It is a scan target, not a summary.
- **Column cap**: in the default text mode no line exceeds **120 columns** (measured by display
  width, so CJK counts as 2). Anything longer is cut on a character boundary and marked with a
  trailing `~`; `-v` prints the "display-capped at 120 cols" note, and `--output json` keeps the
  full, untruncated field. The `-v` diagnostics dump is deliberately exempt from the cap (it is
  a key=value dump meant for grepping).
- Color: per-layer (agent cyan / runtime yellow / infra blue / policy red); disabled by
  `--no-color` or when stdout is not a tty.
- Loss: when `lost_events`/a stderr loss warning is detected, **insert an explicit record into
  the timeline**:
  `   12.003000  !!        lost_events  N=142  (kernel buffer overflow, this span is incomplete)`
  — loss **must be visible**, never silent.

### 4.3 Output fidelity promises

- The timeline is **not** strictly chronological (§2.4); it is a bounded-reorder approximation
  plus `(late)` markers.
- Every line is self-contained and understandable without context.
- Any truncated or approximated field must be discoverable inline or under `-v`.
  **Nothing is lost silently.**

---

## 5. Honesty list

### 5.1 Explicitly out of scope for v0

- **Not the full syscall set.** Only execve / openat / connect / sendto. No
  read/write/stat/mmap/unlinkat/renameat.
- **No TLS/HTTP layer parsing.** `connect` gives you `IP:port` and **nothing about SNI, URL or
  request body**. So "network access" in v0 means "the destination endpoint of a TCP
  connection", not "which service was used". This is one of the biggest capability gaps.
- **No write-content capture.** It records "opened some file with write intent" (openat +
  flags), **not what was written, nor whether anything was written at all**. A file opened but
  never written and a file written heavily look identical in v0.
- **No file deletion/rename** (unlinkat/renameat are not hooked).
- **No kernel stacks / USDT / uprobes.**
- **No namespace awareness.** pids are host pids; processes inside containers are shown from
  the host's point of view.
- **No continuous clock correction** (only periodic offset resampling).
- **No alerting/rule engine.** v0 only emits the timeline; it makes no judgments.
- **No Windows/macOS.** Linux + BTF only.

### 5.2 Lossy / approximate points, one by one

| # | approximation | impact | mitigation |
|---|---|---|---|
| 1 | `str()` truncates at 64 bytes by default; long paths show `..` `[verified]` | incomplete paths | explicit `str(x, 256)`; still truncated → recorded in `trunc` |
| 2 | openat's filename is resolved relative to `dirfd` | relative paths cannot be restored to absolute | v0 records the raw `dirfd` and marks the path as relative; it **does not guess** |
| 3 | argv capture cap `--argv-max` (default 8), and `unroll` has no index variable `[verified]` | later arguments of long command lines are lost | recorded in `trunc`; raising the cap requires editing the script |
| 4 | stash map is cleaned periodically (30s) | a syscall not returned within 30s loses its pair | very rare; visible under `-v` |
| 5 | `--pid` seeds come from scanning /proc at attach | descendants forked and exec'd before attach may be missed | re-scan once immediately after attach |
| 6 | agent event timestamps are the **record time**, not the **occurrence time** | see §3.3: `agent.model.request` is systematically offset from the real request | documented; must not be used to infer model latency |
| 7 | clock offset is sampled once + resampled periodically | cross-layer time comparison drifts during NTP steps | `--resync-interval` |
| 8 | bounded reorder window | output is not strictly chronological | `(late)` marker |
| 9 | perf buffer overflow drops events | holes in the timeline | explicit `lost_events` row |
| 10 | token counts are per **assistant message** | cannot be attributed to a single tool call | that attribution is not offered |
| 11 | `policy.deny` is decided from errno only | cannot tell which LSM rule denied it | v0 trade-off |

### 5.3 Privacy: this is not optional

**Measured finding**: capturing argv writes credentials straight into the timeline — while
verifying argv reading, my output contained `redis-cli -a myredissecret`
`[verified: measured output on this machine]`.

Likewise, the transcript adapter captures whole prompts, thinking content, and file content
(`Read`'s `toolUseResult` is the entire file).

→ **`--redact` defaults to `argv`**: credential-shaped patterns in argv and Bash commands
(`-a`/`--password`/`--token`/`-H "Authorization:..."`/long random-looking strings) are masked
as `***`. `argv+content` additionally masks the agent-layer previews.
→ **This is a design decision, not an implementation detail**: a tool built for security
investigation that writes keys into logs by default is itself a new leak surface.

**v0.1 change**: the old multi-line startup privacy banner was removed, because six lines of
boilerplate on every launch destroyed readability. The protection behavior is unchanged
(`--redact argv` is still on by default and still silent); the explanation moved into
`--help`, and `-v` prints a single line: `redact mode: argv (credential-shaped command-line
args masked; agent content passes through)`.

### 5.4 Uncertain / unverified (must be re-checked before relying on them)

1. **`[unverified]` agent-layer permission-denial mapping.** I searched every transcript on
   this machine for 6 common denial phrasings (`doesn't want to proceed`,
   `haven't granted it yet`, `Request interrupted by user`, `tool use was rejected`,
   `Permission to use`, `user rejected`) — **0 hits**. Reason: the `permissionMode` distribution
   in this machine's transcripts is `bypassPermissions` 98 / `auto` 19 / `plan` 7 `[verified]`,
   so almost no session actually triggered a denial.
   → `policy.deny.agent`'s parsing rules are **pure speculation at this point** and must be
   re-validated on a session that really did deny a tool. **Until then, do not treat that kind
   as a trustworthy signal.**

2. **`[uncertain]` the field structure of the `lost_events` envelope.** The type string was
   extracted from the binary `[verified]`, but a perf buffer overflow could not be triggered
   reliably, so **no real sample was ever seen**. During implementation, force an overflow with
   `BPFTRACE_PERF_RB_PAGES=1` and observe it before writing the parser.

3. **`[uncertain]` whether a Claude Code transcript can contain a half line** (read mid-write).
   The file is append-written and a single `write` should be atomic in theory, but this is
   unverified. The parser is written to tolerate it.

4. **`[uncertain]` the version stability of the transcript format.** 8 versions were observed on
   this machine (2.1.209 ~ 2.1.289) `[verified]`. The format is **undocumented and internal**,
   and can change at any time. → The adapter must be tolerant of unknown types (count them, do
   not crash) and **validate that key fields exist at startup**, failing loudly rather than
   emitting empty events when they are missing.

5. **`[uncertain]` the real coverage of `sys_enter_sendto`.** The probe is confirmed to exist,
   but it was not verified what it catches in real agent traffic (modern HTTP clients mostly use
   `sendmsg`/`write` rather than `sendto`). → `infra.net.sendto` may be nearly empty in v0.
   **That does not reduce the value of connect, but it should be expected.**

6. **`[uncertain]` whether `--cgroup` is usable in this machine's desktop scenario.** Measured,
   all user processes here live in `user.slice/user-1000.slice/session-N.scope` `[verified]` —
   **too coarse to distinguish agent sessions**. `--cgroup` only discriminates when the agent
   runs in its own cgroup (container/sandbox).
   - The path→id conversion is verified: the first 8 bytes of the kernfs handle returned by
     `name_to_handle_at(AT_FDCWD, <cgroup_path>, ...)`, interpreted **little-endian**, equal
     bpftrace's `cgroup` builtin (both are 1 for the root cgroup) `[verified]`. So the
     implementation path works; it is simply **not useful on this desktop**.

7. **`[verified]` the referenced document is missing (re-checked).** Section 4 of the
   `~/jx/DESIGN.md` cited in the task — measured, both `~/jx/DESIGN.md` and
   `~/jx/docs/DESIGN.md` are **0 bytes** (a local checkout from 2026-10-08; the real document
   lives under docs/ in GitHub usher233/jx and is not visible here). The "layered evidence +
   join key + timestamp" idea in this design actually comes from the "the output of
   discernment: the evidence chain" section of `~/jx/docs/PIPELINE_V2.md`; the citation is
   valid and needs no further alignment.

### 5.5 Concrete pitfalls that must be avoided in the implementation (all measured)

1. **Do not filter exec events by `comm`** — at enter time `comm` is still the parent's name `[verified]`.
2. **Do not use bpftrace `-p` for syscall filtering** — it only handles USDT `[verified]`; write your own `@in_tree` / `cgroup` filter.
3. **Do not use `unroll`'s index** — `$i` is undefined `[verified]`.
4. **Do not cast to `(char**)`** — it reports an unknown type under this machine's BTF `[verified]`; use `(uint64*)`.
5. **You must `bswap()` ports** — otherwise 6379 shows up as 60184 `[verified]`.
6. **You must use `-B none` with Rust reading stdout directly** — inserting `grep`/`head` in between causes a fake hang from block buffering `[verified]`.
7. **`sys_exit_openat` has no filename** — a stash map pairing is mandatory `[verified]`.
8. **Truncation must respect character boundaries** — otherwise a Chinese prompt produces invalid UTF-8.
9. **An argv capture is capped at 64 bytes, and `sudo` eats the environment variable that would
   raise it.** The probe stashes 8 argv slots; 8 × 64 = exactly the 512-byte BPF stack limit, so
   `BPFTRACE_MAX_STRLEN=200` is rejected by the verifier ("Looks like the BPF stack limit is
   exceeded") `[verified]`, and `sudo`'s `env_reset` drops the `Command::env(...)` anyway, so the
   collector stops pretending and sets `MAX_STRLEN = 64` — the value the kernel was already
   enforcing, which keeps the `kept N bytes` note in every truncation honest. The visible
   consequence: `bash -c "source …/snapshot-*.sh … && eval '<cmd>'"` arrives as a
   **64-byte-truncated `argv[2]` containing no trace of the command** `[verified]` — that is why
   §3.5's rule S cannot fire on this harness's real Bash calls and rule G is what binds them.

---

## 6. Directory layout (as built)

```
agtrace/
├── DESIGN.md
├── BUILD_LOG.md
├── Cargo.toml
├── scripts/
│   └── agtrace.bt        # the single bpftrace script, 4 probe groups
├── src/
│   ├── main.rs                # entry point + main loop + diagnostics
│   ├── cli.rs                 # hand-written argument parser
│   ├── event.rs               # Event / Layer / Kind / Corr / Payload
│   ├── binding.rs             # transcript session -> OS process tree binding
│   ├── collector/
│   │   ├── mod.rs             # Collector trait (line protocol)
│   │   └── bpftrace.rs        # spawn + line parsing + loss detection
│   ├── adapter/
│   │   ├── mod.rs             # EventAdapter trait
│   │   ├── claude_code.rs     # transcript tail + line mapping + result normalization
│   │   └── openshell.rs       # fixture stub
│   ├── merger.rs              # min-heap reorder + clock conversion
│   ├── exact.rs               # v0.3: exact binding by argv join key
│   ├── collapse.rs            # v0.2: logical-call collapsing (derived events)
│   ├── fail.rs                # v0.4: failure attribution (derived.fail)
│   ├── views.rs               # derived views 4/5 (gap / retry / dangling / wedge / watchlist)
│   ├── render/
│   │   ├── mod.rs             # display-width model, truncation, markers
│   │   ├── text.rs            # strace style
│   │   └── json.rs
│   └── redact.rs              # credential masking
├── evidence/                  # raw acceptance-run captures
└── tests/
    ├── fixtures/              # copied from ~/jx/fixtures (read-only reference; jx is not modified)
    ├── transcripts/           # sanitized transcript samples
    ├── real_cases.sh          # v0.3.1: replay the captured real cases live (see tests/real_cases/)
    ├── real_cases/            # frozen real `claude -p` transcripts + freeze/rebase/assert helpers
    └── real_cases/            # frozen real `claude -p` transcripts + freeze/rebase/assert helpers
```

**Offline verifiability** (how v0 is accepted): the OpenShell adapter + fixture runs end to end
fully offline (`--adapter openshell --session <fixture> -f`), validating schema, merger,
rendering and truncation without root/bpftrace. The kernel side is validated by running known
commands (`cat`, `curl`) under `--pid $$` and checking the probes. The two paths are verified
separately and do not block each other.

---

## 7. Acceptance criteria (the definition of v0 done)

1. `agtrace -p <pid> -f` prints, live, the commands that process tree executes (with argv),
   write-intent file opens, and connection targets (IP:port correct, **with the port verified
   via bswap to be a known value such as 6379**).
2. `agtrace --session <claude-transcript> -f` parses the transcript live into an agent event
   stream, pairing tool_use ↔ tool_result correctly by `tool_use_id`.
3. `agtrace -p <pid> -S <session> -f` emits a merged timeline where agent events carry a
   `pid_binding` marker and **are never falsely reported as Exact**.
4. `agtrace --adapter openshell --session ~/jx/fixtures/openshell_toolloop.jsonl` runs fully
   offline over all of its lines.
5. When a perf buffer overflow is manufactured, a visible `lost_events` line **appears** in the
   timeline (it cannot be silent).
6. Under `--redact=argv`, secrets in commands of the form `redis-cli -a <secret>` are masked.
7. Every truncation is discoverable under `-v`; nothing is lost silently.

---

*Every `[verified]` conclusion in this document comes from measurement on this machine
(kernel 7.0.0-31-generic / bpftrace v0.20.2 / 2026-10-11). Entries marked
`[unverified]`/`[uncertain]` are risks that must be re-checked before being relied on.*
---

## 8. Product framing: 5 observation dimensions

agtrace answers 5 questions a developer has while debugging an agent. ①②③ are the unified
timeline itself; ④⑤ are derived views on top of it (they surface, they never act).

| # | dimension | question | corresponding kind / view |
|---|---|---|---|
| ① | what it is trying to do | which task, which step is it on | `agent.prompt`, `agent.model.thinking`, `agent.model.text` (aggregated by turn_id) |
| ② | what it is calling | LLM, Tool, MCP, Shell | `agent.model.request`, `agent.tool.call`, `runtime.proc.exec`. MCP note: in the Claude Code transcript, MCP tools appear in tool_use as `mcp__server__tool`; identify them by that prefix and mark `via_mcp: true` separately in the payload |
| ③ | what it did in the system | spawned processes, read/wrote files, made network requests | `runtime.proc.*`, `infra.file.open`, `infra.net.connect` |
| ④ | why it is stuck | slow model response, tool timeout, blocked child process, repeated retries | derived: a row marking a large tool call→result gap; repeated identical tool_use (high input similarity) marked `>> retry`; a long-lived child producing no output marked `!! possible hang`. **Honesty constraint**: transcript timestamps are record time, not occurrence time (§5.2 #6), so only the gap can be marked — never an exact "the model took N seconds" |
| ⑤ | whether it overstepped | touching sensitive files, connecting to unknown domains, running dangerous commands | derived: watchlist rules; on a hit, mark the row with `!!` plus a count. **Alert-only: never blocks, never kills, never changes configuration** |

### 8.1 The watchlist format for ⑤

```toml
[watchlist]
sensitive_paths = ["/etc/shadow", "/etc/passwd", "~/.ssh/", "*.pem", "~/.aws/credentials"]
dangerous_cmd_patterns = ["rm -rf /", "curl * | sh", "wget * | sh", ":(){ :|:& };:"]

[watchlist.domains]
allow = ["api.internal", "*.company.com"]   # connections not in the table are marked "unknown domain"
```

`policy.deny` (errno-based) counts toward ⑤ automatically; `agent.sandbox.disabled` counts
directly toward ⑤ (a model actively disabling the sandbox is the strongest overstepping
harbinger) `[verified: this field appears 248 times in this machine's transcripts, see §1.2]`.

---

## 9. Division of labor with Jingxu

The bottom line in one sentence: **agtrace is only responsible for "making it legible to a
human" and never takes action on its own** (no rate limiting, no killing, no config changes, no
auto-repair); the closed loop of autonomous detect → diagnose → remediate → verify is Jingxu's
territory.

The two can share the event-schema design ideas (layering + join key + timestamp), but the
product boundary is clear: agtrace does not expand toward SRE / agent governance, and Jingxu
does not do the interactive form factor of single-session real-time debugging. The `!!`
highlighting of ④⑤ is always a presentation-layer annotation, never the execution of a policy
engine.

---

## 10. Competitive positioning

### 10.1 Direct competitors

**eunomia-bpf/agentsight** (735★, MIT, has an arXiv paper, still under active development as of
2026-10) — "local-first top/strace-like observability", eBPF + TLS plaintext capture
(SSL_read/SSL_write to grab model payloads), correlating prompt / model call / tool decision
with actual system behavior. Command surface: `top` / `record -- <cmd>` / `report` / `vis` /
`debug`. This is the closest project to agtrace `[verified: checked its GitHub README and
docs/usage.md on 2026-10-11]`.

**Siddhant-K-code/agent-trace** (96★, PyPI package `agent-strace`) — "strace for AI agents", but
all collection is at the agent layer (CLI hooks / MCP proxy / Python decorator), so it never
sees kernel ground truth; its core UX is post-hoc `replay`. Very different positioning, weak
direct competition `[verified: checked its README on 2026-10-11]`.

### 10.2 agtrace's wedge (honest version)

1. **debugger vs profiler.** AgentSight's live form is an aggregate dashboard `top`; agtrace is
   a single-session real-time event stream `agtrace -f`. top and strace are both Unix tools
   because they address different debugging moments. `[unverified]` I have not read all of its
   documentation; if its `debug trace` really is a single-session live tail, this point is void
   and the difference collapses into point 2.
2. **intent structure × kernel, not payload × process.** AgentSight relies on TLS plaintext +
   process-tree correlation; agtrace relies on the transcript's native structure (thinking
   blocks, tool_use_id causal pairing, turn structure, the sandbox-disabled signal) × kernel
   events. Payload tells you what the model said; intent structure tells you why it thought so —
   a dimension outside the home turf of eBPF infrastructure teams.
3. **honest binding.** It can attach without wrapping the runtime (`--pid` / `--session`), and
   when it cannot bind it says `pid_binding: None` + `?`, never presenting a heuristic as fact.
   That is a credibility design, not a feature.
4. **a sharp single binary vs platform sprawl.** AgentSight's docs/design already contain plans
   for enterprise / distributed directions; agtrace does no RBAC / SSO / compliance reporting
   and stays one debugger.

### 10.3 v0 acceptance aims at the wedge

v0 must be able to demonstrate at least one case that **only the transcript × kernel combination
can explain**, for example:
- the transcript's tool_use says it read file A, while the kernel actually opened B (path
  resolution / symlink differences);
- a tool_result reports success, but the kernel never actually sent the connect (or connected
  to an unexpected IP);
- the agent's point of view is "everything is fine", but the timeline shows the same tool being
  silently retried 5 times (④).

If such a case cannot be found and reproduced reliably, v0 is just a smaller AgentSight — and
then it is not worth shipping.

---

## 11. Logical-call collapsing (v0.2)

### 11.1 The problem: kernel ground truth is one layer too low

The kernel sees syscalls. The question a reader actually asks is "what is it *calling*, and
why". Three artifacts of that gap, all observed in real sessions (`[verified]`, this machine):

| what the kernel emits | what the user asked |
|---|---|
| 14 `exec_fail ... ENOENT` lines for **one** `execvp("git")` (glibc tries one `execve` per PATH entry until it hits `/usr/bin/git`) | "it ran git" |
| 7 `fork` lines inside 150 µs for **one** worker-pool spawn | "it started 7 workers" |
| `fork -> 819748 (python)` — no way to tell *which* python | "which script is that?" |

None of these are collection bugs. Collapsing them is a **rendering** decision, and it is
reversible: the raw events stay in the stream, `--output json` always carries them, and
`--no-collapse` / `-v` put them back on the screen.

### 11.2 Where it sits

```
collector → merger (reorder window) → collapser → views/renderer → stdout
```

After the merger, for three reasons:

1. the merger stays a pure reorder buffer (no knowledge of event semantics);
2. a fork burst is by construction *inside* the reorder window, so the collapser sees the
   whole burst in one or two batches instead of guessing about the future;
3. §8's views have already stamped `watch` / `retry` on the events, so the collapser can
   honour "never collapse a watch-flagged exec" without re-deriving it.

The collapser is a **bounded-time** stage: it can delay rows (§11.5) but it never drops one,
and `finish()` flushes everything at EOF / `--duration` / Ctrl-C.

### 11.3 execvp collapsing

Grouping rule — consecutive `exec_fail` rows for the **same pid** with

- `errno == ENOENT`, and
- the same `argv[0]` **basename** (glibc builds the probed *path* from `$PATH`, so the paths
  differ while `argv[0]` stays the name the caller asked for — grouping by path would fail on
  the first `$PATH` entry that carries a version suffix, e.g. `git-2.43`), and
- ts within `EXEC_RESOLVE_NS` (2 s) of the group's first row.

Closing rule — the group becomes one row when a successful `exec` of the same basename lands
in the same window:

```
     0.009593  derived  901102    execvp          git -> /usr/bin/git (13 PATH probes)
```

`K = 1` is **not** collapsed: one probe plus a successful exec is an ordinary execution, and
folding it would hide the `/usr/bin/git` that the raw line was carrying. `K >= 2` is what
"PATH search" means.

What ends a search without a success:

| closing event | result |
|---|---|
| 2 s (event time) elapse with no success | `foo -> NOT FOUND (N probes)` — the command is missing |
| an `exec_fail` with **any other errno** (EACCES, EPERM, ...) | group is dropped, every row stays raw — "found it but could not enter" *is* the conclusion, and it ends the search |
| an unrelated syscall from the same pid | group is dropped, rows stay raw — **no guessing**; a probe run has no interleaved syscalls, so this means the assumption is already dead |
| end of capture before the 2 s window elapsed | same `NOT FOUND` wording, plus a note saying the window was never observed |

### 11.4 Fork-burst summary

One parent, `>= MIN_FORK_BURST` (5) children within `FORK_BURST_NS` (10 ms):

```
     0.008572  derived  901101    fork-burst      7 forks in 0.8ms
```

In default mode the individual `fork` rows are **not printed**; in `-v` they are, all of them.
Tree tracking is untouched — descendants are still scanned from /proc and still followed (the
threshold is a display threshold, not a collection one). Fewer than 5 forks in the window is
not a burst: a shell doing `a; b; c` must stay legible as three forks.

### 11.5 Process identity: "which python?"

At seed time (the /proc scan that `-p` already does) each member's `cmdline` is captured and
synthesized into an internal exec record, so attribution also works for processes that existed
before attach (the kernel never reports their `exec`). The table then tracks reality:
a successful `exec` replaces the cmdline with the new argv, a `fork` copies the parent's
cmdline to the child.

Fork rows gain a compact suffix when the parent's argv is known:

```
     0.000269  runtime  900939    fork            fork -> 901101 (v02_repro.sh)  <= "/bin/bash /tmp/v02_repro.sh"
```

The hint is cut to 32 columns with a visible `...`, and — deliberately — it does **not** push a
row into `trunc`: `trunc` means "captured data was lost" (§1), while this is a display hint
whose full text is in the raw event. When the parent's argv is unknown the suffix is omitted
**silently**; `<= "unknown"` would be noise on every fork row.

### 11.6 Merging equivalent summaries

7 workers each doing `execvp("git")` are 7 logical calls, but they say the *same thing*
(same basename, same target, same probe count). Printing 7 identical rows reproduces the exact
problem this section exists to fix — the reader has to diff them by eye to learn they are
equal. So byte-identical details merge:

```
     0.009593  derived  901102    execvp          git -> /usr/bin/git (13 PATH probes), x7 calls
```

The merge window is `MERGE_NS` (2 s) of **event time**, and this choice was forced by a real
failure: with a wall-clock window (the first implementation used 50 ms) the acceptance repro
printed **three** identical summary rows. Instrumentation showed why — the merger released the
7 children in three batches, one of them `lag_ms=5002` after its events. A wall-clock hold is
doomed against a delivery stall that long; "are these two rows the same call" is a question
about *event* time, and answering it in event time costs nothing when the stream is slow.

The price is explicit: an unmerged anchor **holds back the rows behind it** until event time
passes the window, an equivalent row merges into it, or the stream ends (then `finish()`
flushes it). In a live stream that is bounded by ~2 s of event time; in a quiet stream the
held rows are the last thing that happened anyway. A memory guard (`HOLD_MAX_ITEMS` = 4096
buffered rows) gives up on merging rather than growing without bound under `--file-all`.

Holding the anchor back is not enough on its own, and the gap was measured rather than
reasoned about. The anchor is released by the *first* event that lands outside the window;
that same release unblocks the rows behind it, and the equivalent summary can be one of
them — sitting behind a few raw rows of other pids. By then the anchor has already been
written, `pending` is empty, and the summary opens a fresh window: `x6 calls` followed by a
bare duplicate, which is the exact artefact the merge exists to remove. (Reproduced with the
7-child repro: the last child's events were the batch carrying `lag_ms=5002`, so they were
released after the anchor for the other six had already been written.)

So an anchor that has been written is remembered for the rest of the **same** output batch
(`Emitted`, one slot: key, window end, position in that batch's vector), and a later
equivalent summary merges into it by rewriting the count in place. The position is only
valid inside one batch, which is exactly the scope in which the release cascade runs — a
new batch drops the record rather than pointing at the wrong row. Merging stops at the first
*non-equivalent* summary, so "two adjacent summaries that say the same thing" remains the
rule; and `-v` never takes this path, because there each summary must stay attached to its
own raw rows.

`-v` does **not** merge, and that is on purpose: there, each group's raw rows must stay under
their own summary, and a held anchor would have to swallow the raw rows that follow it. So
`-v` shows 7 summaries with their raw lines and the summary block reports
`8 collapsed row(s)` where default mode reports `2`. Both counts are correct; they count
different renderings of the same events.

### 11.7 What is never collapsed

- **`--output json`.** Lossless by contract: raw events only, `extra.collapse` documents what
  the text renderer *would* have done (`"enabled": false`).
- **A watch-flagged exec.** The safety view's whole value is that the line is *seen*; folding
  it into a summary would silently disarm the alert.
- **Any non-ENOENT failure**, any single probe, any fork count below the burst threshold.
- **Anything at all under `--no-collapse`**, which also drops the identity suffix (the
  collapser is off, identity lived in it) — the restore path is total, not partial.

### 11.8 Accounting

Collapsed rows never hide *how much* they replaced:

```
--- 1 truncated row(s) (`-v` expands); 2 collapsed row(s) summarize 105 raw line(s) (`-v` restores them; `--output json` never collapses)
```

and `-v` prints the per-class ledger (`collapse: execvp resolved 7 / not-found 0; fork-burst 1;
merged-equivalent 6; raw lines replaced 105; fork rows with parent cmdline 8`).

A derived row keeps the **first** raw row's `ts_ns`, `pid`, `comm` and `corr`, so it sorts
where the logical call started and §3.5's pairing still works. It renders as layer `derived`,
not as `!!` — `!!` stays reserved for §8's suspicion views (`gap`, `retry`, `watchlist`,
`wedge`), and a summary of normal activity must not look like a suspicion.

---

## 12. Exact binding by argv join key (v0.3)

### 12.1 The gap it closes

Up to v0.2 the tool could say *when* things happened on both sides of the boundary, and could
not say *which* kernel event belonged to *which* tool call. The same workload, run with
`--no-bind` (`evidence/acc1_v03_nobind.txt` — the pre-v0.3 rendering):

```
     0.000000  agent    v03_fixt  tool.call       Bash  cmd="/bin/echo hello-v03-bind" ?
     1.000000  agent    v03_fixt  tool.result     Bash  Success  "stdout: hello-v03-bind\n" ?
     4.004372  runtime  1123589   exit            exit(0)
     4.004606  runtime  1123587   fork            fork -> 1123719 (run_acc1_v03.sh)  <= "/bin/bash ./run_acc1_v03.sh ac~
     4.004877  runtime  1123719   exec            /bin/echo  argv=["/bin/echo" "hello-v03-bind"]
     4.005108  runtime  1123719   exit            exit(0)
     4.005439  runtime  1123587   exec            /usr/bin/sleep  argv=["sleep" "5"]
     9.005863  runtime  1123587   exit            exit(0)
```

Eight rows, and not one statement about which of them belongs to the call above. The `?` is
honest and the ordering is suggestive, but "the model asked for X and the kernel did Y" — the
one thing this tool exists to establish — is left as an exercise for the reader. Everyone who
reads the output does the join by eye; anyone who does not, gets nothing.

v0.3 (`evidence/acc1_v03.txt`, same workload and fixture, default mode):

```
     0.000000  agent    v03_fixt  tool.call       Bash  cmd="/bin/echo hello-v03-bind" ?
     1.000000  agent    v03_fixt  tool.result     Bash  Success  "stdout: hello-v03-bind\n" ?
     4.003655  runtime  1121789   exit            exit(0)
     4.003893  runtime  1121787   fork            fork -> 1121950 (run_acc1_v03.sh)  <= "/bin/bash ./run_acc1_v03.sh ~ =
     4.004108  runtime  1121950   exec            /bin/echo  argv=["/bin/echo" "hello-v03-bind"] =
     4.004108  derived  1121950   bind            tool.call Bash "/bin/echo hello-v0..." <-> exec /bin/echo (argv exact)
     4.004401  runtime  1121950   exit            exit(0) =
     4.004669  runtime  1121787   exec            /usr/bin/sleep  argv=["sleep" "5"]
     9.005106  runtime  1121787   exit            exit(0)
```

Two runs of the same fixture, so the pids and timestamps differ — the workload does not. The
fork, the exec and the exit of the process that ran the command are marked, the derived row
names the process and the rule, and the unrelated `sleep` rows are left alone.

Note what did *not* change: the `tool.call` row still carries `?` (in `-S` replay it was
rendered before the match existed — §3.5), the unrelated rows carry nothing, and the derived row
states the rule that fired. The levels are in §3.5; this section is about where the mechanism
sits, and what it costs.

The harder shape of the same problem is a command that the shell does not run itself. Here the
tool asks for `curl -s -m 3 http://127.0.0.1:9/`, bash execs `/usr/bin/curl` with that string as
its argv, and the kernel reports a pid that is neither the shell nor the agent — the pid, the
parent and the timing all say nothing, and the repeated argv says everything
(`evidence/acc1b_v03.txt`, default mode):

```
     0.000000  agent    v03b_fix  tool.call       Bash  cmd="curl -s -m 3 http://127.0.0.1:9/" ?
     1.000000  agent    v03b_fix  tool.result     Bash  Success  "stdout: hello-v03-bind\n" ?
     4.003613  runtime  1130960   exit            exit(0)
     4.003831  runtime  1130958   fork            fork -> 1131092 (run_acc1b_v03.s)  <= "/bin/bash ./run_acc1b_v03.sh" =
     4.004022  runtime  1131092   exec            /usr/bin/curl  argv=["curl" "-s" "-m" "3" "http://127.0.0.1:9/"] =
     4.004022  derived  1131092   bind            tool.call Bash "curl -s -m 3 h..." <-> exec /usr/bin/curl (argv exact)
     4.006968  infra    1131092   connect         connect non-IP family  AF_UNIX failed =
     4.006978  infra    1131092   connect         connect non-IP family  AF_UNIX failed =
     4.007140  infra    1131092   connect         connect 127.0.0.1:9  AF_INET  (in progress EINPROGRESS) =
     4.007364  runtime  1131092   exit            exit(7) =
     4.007827  runtime  1130958   exec            /usr/bin/sleep  argv=["sleep" "5"]
     9.008160  runtime  1130958   exit            exit(0)
```

(Twelve rows in the capture; `[tool.result]`'s `stdout` field is the fixture's canned string, not
this command's output — the fixture is synthetic, see `evidence/gen_bind_fixture.py`.)

The three `connect` rows are what v0.2 could not attribute and what this feature exists to
attribute: the target `127.0.0.1:9` is the string inside the tool call, four seconds earlier, on
a different pid. That the connection then *failed* (`exit(7)`) is beside the point — the rule
reads argv, never the outcome. And the two levels stay visibly separate: the header still reports
`(binding: none)` for the session, because no `claude --resume` process owns this fixture
session, while the tool call is bound exactly. L3 being exact does not make L1–L2 exact, and the
tool does not let the first imply the second.

### 12.2 Where it sits

```
collector → merger → [exact binder] → collapser → view rules → renderer
```

- **After the merger**, because it needs time-ordered batches: "the exec came after the call"
  is a statement about event time, not arrival time.
- **Before the collapser**, because the collapser folds raw exec rows into `execvp` /
  `fork-burst` summaries. Binding has to see the raw rows — an `execvp` summary hides the argv
  that is the join key. Collapsed rows inherit the binding of the row they summarize, so a
  summary of a bound call keeps its ` =` (`collapse.rs` copies `binding` from its source row).
- **Before the view rules** for the same reason: §8's `gap`/`wedge` views ask "did this
  tool.call have any kernel effect", which is a much sharper question once L3 exists.
- The binder owns `kind` `derived.bind` (`Layer::Derived`, §1.2) and the `Payload::Bind`
  variant. `derived.bind` renders as layer `derived`, not `!!`: a successful binding is not a
  suspicion.

### 12.3 Two passes per batch, one held suffix

The binder runs two passes over every batch. Pass 1 advances the state machine (records calls,
matches execs, marks subtrees, remembers forks) and queues the derived rows; pass 2 stamps each
row with the **end-of-batch** state and splices the derived rows in. One pass would leave a
fork row judged before the exec inside the same batch could mark its child.

The batch boundary is still a problem — the merger may release a fork row before its child's
exec arrives — so the binder holds back the **undecided suffix** of a batch by exactly one poll
cycle and re-stamps it next time. Details and the ordering defect that forced the
"suffix, not single row" shape are in §3.5 and BUILD_LOG §15.4. `finish()` flushes the last
held suffix when the stream ends, so no row can be held forever.

### 12.4 What is never claimed

- A row is `exact` only via a real argv rule (§3.5). Ambiguity resolves to no match.
- The `derived.bind` row names the rule that actually fired; a fuzzy match can never print
  `argv exact`.
- A `tool.call` that never matched keeps `?`. A `proc.exec` with no call stays unbound — most
  kernel activity is not attributable to a tool call and is not labelled as if it were.
- `prompt` / `model.*` / `thinking` events stay at session level forever. They are not process
  events; "exact" would be a category error, and blanket-exacting the whole timeline would make
  the marker worthless.

### 12.5 Accounting

`--output json` carries `binding` on every event and the matched `corr.tool_use_id`, and the
footer's `extra.bind` block reports the run:

```json
"bind": {"enabled": true, "calls_seen": 2, "calls_matched": 2, "execs_seen": 4,
         "pids_exact": 2, "by_argv_exact": 2, "by_argv_substring": 0, "by_argv_segment": 0,
         "by_argv_overlap": 0, "derived_rows": 2,
         "window_s": 120, "overlap_threshold_pct": 80}
```

The three per-rule counters are split out rather than summed on purpose: a run whose real
commands bound by `argv segment` is a *different* claim from one that bound by `argv exact`,
and the summary has to be able to say which happened (v0.3.1; measured on
`tests/real_cases/`, where all three real cases report `by_argv_segment`).

`-v` prints the same figures on stderr. `--no-bind` sets `enabled: false` and makes the binder
a pass-through, which is how the before/after captures in BUILD_LOG §15 were produced from a
single binary.

---

## 13. Failure attribution (v0.4)

> "Where did it fail?" is the question people actually open a trace to answer. Before v0.4
> every layer could fail and only `tool.result`'s text said so — the trace showed *what
> happened*, never *which layer gave up*.

### 13.1 The four layers, and the one that leaves no kernel footprint

| layer | what happened | kernel footprint |
|-------|---------------|------------------|
| agent | `bwrap`/sandbox init failed; the command never forked | **none at all** |
| exec | `command not found`; bash reports 127 itself | no `execve` of the command |
| runtime | exec succeeded, process exited non-zero | `proc.exec` + `proc.exit` |
| infra | it ran, but an `openat`/`connect` was refused | failing `file.open` / `net.connect` / `policy.deny` |

The first row is the reason this feature exists. "The command never ran" and "the command ran
and left no trace" look *identical* on a kernel timeline, and they send you in opposite
directions. Naming which one happened requires the agent layer's own text — which is why this
is a **derived** layer, not a kernel one.

### 13.2 Where it sits

```
collector → merger → exact binder → collapser → [fail attribution] → renderer
```

- **After the binder**, because "this kernel row belongs to that tool.call" is exactly what the
  binder's `corr.tool_use_id` says; without it there is no subtree to reason about.
- **After the collapser**, because the reader's screen is the collapsed world and the
  attribution has to explain *that* world (collapsed rows carry the binding of the rows they
  summarize, so they are usable evidence).
- It owns `kind` `derived.fail` (`Layer::Derived`, `Payload::Fail`), which renders with the
  layer column `XX` — the only derived row that does. §11/§12's rows print `derived` because
  they are *summaries*; `XX` is not a different kind of fact, it is a different **use**: this
  column is scanned vertically to find where a session broke, and the word `derived` is
  invisible in a column full of summaries. Two ASCII characters, stable width, same as `!!`
  and `??`.

### 13.3 The classification ladder

A `tool.call` is a failure if its `tool.result` says so (`status` field first; text only when
the status is unrecognizable — `Exit code N` is the harness's own literal protocol, so
`stdout: exit=7` can never be read as a failure). Then, in order:

1. **No kernel source this run** (`-S` only, or `--source` excluded the kernel): the claim is
   qualified — `BEFORE exec: … (no kernel event; this run had no kernel capture)`, class
   `no-kernel-source`. Saying "the kernel saw nothing" while not looking at the kernel would be
   a lie, and json exposes `extra.failures.kernel_available` so a script can tell.
2. **Kernel source on, zero kernel events linked**: the command never got far enough to leave a
   footprint. Sandbox text (`bwrap`) ⇒ `BEFORE exec: sandbox init failed (no kernel event)`;
   `command not found` ⇒ `BEFORE exec: command not found (no execve)`; otherwise class
   `unbound` — "we could not link anything", not "nothing happened".
3. **Kernel source on, events linked**: class `kernel`. The deepest point is, in order:
   1. a failing syscall whose **subject is an argv operand of the bound exec** (`asked_for`);
   2. a failed `execve` of a basename that never exec'd successfully (this is what removes
      glibc's PATH probes — 13 `ENOENT`s that are the *cost* of finding the binary, not a
      failure);
   3. the non-zero **exit** — a symptom, but at least a symptom *of this call*;
   4. failing `openat`/`connect` events unrelated to the command line, as a last resort.
   Otherwise class `bound-no-evidence`: the subtree is bound but contains no failing event, and
   we will not invent one.

Rule (i) is the one real capture forced (§13.6): a normal `ls` produces ~23 failing `openat`
calls in the kernel — the dynamic linker probing `ld.so.cache`, glibc trying twenty locale
directories for `.mo` files. They *are* failures (the kernel really refused them); they are not
why the call failed. Rule (iii) exists for the same reason in the other direction: naming an
unrelated failing `open` as the cause is a **guess**, while "it exited 2" is a **statement**.

### 13.4 Rendering, and the column budget

```
     4.615000  XX       -         fail            tool.call Bash "curl -s -m 3 h..." -> BEFORE exec: sandbox init failed
```

The fixed prefix costs 50 columns (§4.2), leaving ~68 for the payload. The line the v0.4 brief
sketched (`… -> exit 2 (deepest: openat /nonexistent-dir-abc ENOENT)`) is ~144 columns, so
something must be elided and the priority is **conclusion > evidence > command**: the command is
always adjacent (the `tool.call` row above it, and the footer line below it), while "which layer
died" appears nowhere else. `fit_fail` reserves 18 columns for the command, 8 at the floor, and
drops the `(deepest: …)` clause before it drops the verdict; the full sentence is never lost —
the footer and `--output json` carry it intact.

The footer always prints a failures section, including when there are none:

```
--- failures (2):
   2.339s  Bash "ls /nonexistent-dir-abc" -> exit 2 (deepest: exit(2) at pid 1727956 via /usr/bin/ls)
   3.425s  Bash "foobarxyz123" -> BEFORE exec: command not found (no execve)
```

`--- failures (0)` is printed rather than omitted: "no failures" and "this build has no such
feature" have to be distinguishable.

`--failures-only` prints the failed call, the kernel subtree bound to it, the `XX` row and the
footer, and nothing else. It is built for a debug loop; the summary counters then describe the
rows that survived the filter, while the span and the failure times stay session-relative (the
attributor hands the renderer the session's min/max wall clock, otherwise the footer would print
`0.079s` — relative to the first *surviving* row — next to a timeline printing `4.615000`).

### 13.5 When the conclusion is drawn (this is the subtle part)

**A `tool.result` row does not mean the kernel evidence has arrived.** Measured (§13.6): the
`ls` result was row 26 of the stream and its `execve` was row 385, with the two timestamps
4 ms apart. Transcripts are written after the fact and bpftrace delivers in perf-buffer
batches, so "result first, the exec it describes second" is normal, not exceptional.

A v0.4 draft concluded at the result. It classified that `ls` as `unbound` — "no kernel events
linked to this call" — while the kernel was holding the exec, the 23 probes and the exit. The
sentence was true at the instant it was printed and false as an answer.

So the conclusion is **deferred**. A failed result parks the call; it is concluded when the
first of these happens:

1. **evidence arrives** — the call gets kernel events linked, and the deepest point is chosen
   with everything in hand;
2. **the kernel watermark passes `result ts + --merge-window`** — the merger's contract is that
   everything it received with a timestamp older than the watermark minus one window has
   already been released (§2.4), so *now* "nothing was linked" is not a premature answer;
3. **end of stream** — the fallback, when the kernel stream goes quiet or the collector dies.

The wait is skipped when it cannot buy anything: no kernel source this run (nothing will ever
arrive), or the evidence was already linked when the result arrived. That keeps `XX` adjacent to
the `tool.result` in offline replays and in the common live case; only the genuinely late case
moves, and it moves *after* the evidence it cites, which is the order a reader wants anyway.
`tool.result` itself is still emitted immediately — §2.4's "agent events never block the
timeline" is not weakened by this.

Costs, stated plainly:

- An `XX` row can be printed after rows with later timestamps. (`late` is inherited from the
  result rather than recomputed: the row is a conclusion *about* that earlier moment, and
  marking it late would read as "the failure is late".)
- If the kernel stream is idle, the conclusion waits for the next kernel event or for the end of
  the stream. With `-p <agent pid>` this is not a practical wait — the harness's own I/O keeps
  the watermark moving — but it is a real property of the design, not an accident.
- The deferred wait is bounded by evidence, not by a timer: there is no timeout that could
  re-introduce the premature answer this section exists to remove.

### 13.6 Measured: a real `claude -p` error session

`claude -p` asked to run exactly three Bash calls, traced live with
`sudo agtrace -p <claude pid> -S <transcript> --file-all -f`:

| call | what the harness reported | attributed | deepest |
|------|---------------------------|------------|---------|
| `ls /nonexistent-dir-abc` | `Exit code 2` | `kernel` (35 linked events) | `exit(2) at pid 1705478 via /usr/bin/ls` |
| `foobarxyz123` | `Exit code 127` | `before-exec` | `BEFORE exec: command not found (no execve)` |
| `echo hi` | `stdout: hi` | — | no row, no `XX` |

Three findings from that run, all of which changed the code:

1. **The late-evidence defect** of §13.5 (result row 26, exec row 385).
2. **The 23 benign `openat ENOENT`s.** With the naive "last failing syscall" rule the deepest
   point came out as `/usr/share/locale-langpack/en/LC_MESSAGES/libc.mo ENOENT`. The rule in
   §13.3(i) — argv operands only — is what fixed it.
3. **`ls` does not `openat` its argument.** It `stat`s it. The kernel *did* record the failure,
   but as a syscall this collector does not instrument, so there is no ENOENT to name. The
   honest answer is therefore the exit status: the `deepest` field says `exit(2) … via
   /usr/bin/ls`, not the directory. `cat` — which does `openat` — is the case where the ENOENT
   of the operand is available, and it is the shape used in the unit tests.

The numbers above are from two captures of the same task (`pid` differs per run — each is a
fresh process tree): the row indices in §13.5 and the `35 linked events` and `1705478` here come
from the JSONL capture, while the footer in §13.4 (`2.339s`/`3.425s`, pid `1727956`) is the text
capture. Both were checked against the raw event stream.

The offline fixture replays (`tests/real_cases/rc1..rc3`, agent layer only) exercise the other
branch: with no kernel source, each case prints `XX … BEFORE exec: sandbox init failed (no
kernel event; this run had no kernel capture)` and a `--- failures (1):` footer that repeats the
qualifier. The successful retry in rc1 gets no `XX`.

### 13.7 Accounting

Every `XX` row carries `corr.tool_use_id` of the failed call (inherited from its result), so a
chain is one `jq` select; `--help` documents five recipes. The summary line's `extra.failures`
block:

```json
"failures": {"only": false, "kernel_available": true, "count": 2, "attributed": 1,
             "by_class": {"before_exec": 1, "kernel": 1, "bound_no_evidence": 0,
                          "unbound": 0, "no_kernel_source": 0},
             "list": [{"ts_wall_ns": …, "tool": "Bash", "cmd": "ls /nonexistent-dir-abc",
                       "class": "kernel", "head": "exit 2",
                       "deepest": "exit(2) at pid 1727956 via /usr/bin/ls",
                       "kernel_events": 35, "detected_by": "status=Failure",
                       "tool_use_id": "call_00_…"}]}
```

The per-failure `class` is hyphenated (`before-exec`, `bound-no-evidence`), the `by_class` keys are
underscored (`before_exec`, `bound_no_evidence`): one is a value you read, the other a key you
type into `jq`. Both are stable.

`attributed` counts failures with a `deepest`; `detected_by` records *why* a result was judged a
failure (`status=Failure`, or the text signature when the status was unreadable) so that
"is this really a failure?" is auditable rather than asserted. Each `XX` row also carries a note
saying what it waited for before concluding (one of the three cases in §13.5).
