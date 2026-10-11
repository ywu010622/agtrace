#!/usr/bin/env bash
# Real-case replay suite for the third binding level (DESIGN.md section 3.5, v0.3.1).
#
# Why not synthetic fixtures: the v0.3 binder passed every synthetic test and
# still never fired on a real `claude -p "run curl ..."`. The synthetic command
# shapes were written to match the rules; the real ones were not. This suite
# replays *captured* transcripts (tests/real_cases/*.jsonl) against a live
# workload that reproduces what the harness really execs, and asserts the bind
# fires with the honest rule label.
#
# Every case runs in up to four modes:
#
#   live       the case's own command, exec'd once per tool.call  -> must bind
#   unrelated  a live exec that has nothing to do with the call   -> must NOT bind
#   offline    replay only, nothing exec'd                        -> must NOT bind
#   window     live exec for the 2nd call only, with the 1st call pushed past the
#              120 s window (slow, ~2 min)                         -> only the 2nd binds
#
# Usage: tests/real_cases.sh [rc1|rc2|rc3|all] [--fast] [--verbose]
#
# --fast skips `window` (the only slow mode). Requires passwordless sudo for the
# live modes, because kernel capture needs bpftrace.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

BIN=target/release/agtrace
DIR=tests/real_cases
MARGIN=1.5 # seconds between a tool.call and its live exec (absorbs attach latency)

# tag <TAB> fixture <TAB> the exact command the real session ran <TAB> expected rule.
# Tab-separated, not pipe-separated: rc2's command contains a literal `|`.
CASES=(
  $'rc1\trc1_compound_semicolon.jsonl\tcurl -s -m 3 http://127.0.0.1:9/ ; echo "exit=$?"\targv segment'
  $'rc2\trc2_pipe.jsonl\tls -la /tmp | head -5\targv segment'
  $'rc3\trc3_and_chain.jsonl\tprintf \'hi\' > /tmp/rc3.txt && cat /tmp/rc3.txt\targv segment'
)

FAST=0
VERBOSE=0
WANT=all
for arg in "$@"; do
  case "$arg" in
  --fast) FAST=1 ;;
  --verbose) VERBOSE=1 ;;
  rc1 | rc2 | rc3 | all) WANT="$arg" ;;
  *)
    echo "unknown argument: $arg" >&2
    exit 2
    ;;
  esac
done

if [ ! -x "$BIN" ]; then
  echo "build first: cargo build --release" >&2
  exit 2
fi

# Kernel capture needs bpftrace, which needs root. Without passwordless sudo the
# live modes cannot run at all — skip them loudly rather than reporting a
# failure the reader would misread as a binding regression.
HAVE_SUDO=0
sudo -n true 2>/dev/null && HAVE_SUDO=1
if [ "$HAVE_SUDO" = 0 ]; then
  echo "note: no passwordless sudo — live/unrelated/window modes will be skipped"
fi

pass=0
fail=0
skip=0
declare -a TABLE=()
# Ctrl-C must not leave a 130-second workload behind (the window case).
trap 'kill $(jobs -p) 2>/dev/null' EXIT

note() { [ "$VERBOSE" = 1 ] && echo "    $*"; return 0; }

# The harness wraps every Bash tool call as a login-ish shell that sources a
# snapshot and then evals the command. argv[2] is that whole payload, and the
# kernel truncates it at 64 bytes (src/collector/bpftrace.rs: MAX_STRLEN) — so
# argv[0]/argv[1]/argv[2] never contain the command the tool.call names. That
# is precisely the shape v0.3 could not bind.
make_wrap() {
  local cmd="$1" snap
  snap=$(ls /home/viktor/.claude/shell-snapshots/snapshot-bash-*.sh 2>/dev/null | head -1)
  [ -n "$snap" ] || snap=/dev/null
  printf "source %s 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && eval '%s' < /dev/null" \
    "$snap" "$cmd"
}

# Replay one fixture against a live workload and check the bind account.
#   run_mode <mode> <label> <fixture> <cmd> <rule> [gap] [tool_id]
run_mode() {
  local mode="$1" tag="$2" fixture="$3" cmd="$4" rule="$5" gap="${6:-0}"
  local label="$tag/$mode"
  local rebased="/tmp/agtrace_rc_${tag}_${mode}.jsonl"
  local out="/tmp/agtrace_rc_${tag}_${mode}.out"
  local off o1 o2 line2 id_second
  off=$(python3 "$DIR/offsets.py" "$fixture") || {
    echo "FAIL $label: cannot read call offsets"
    fail=$((fail + 1))
    return
  }
  read -r o1 o2 line2 id_second <<<"$off"
  # `gap` widens the distance to the second call (the window mode's whole point).
  if [ "$gap" != "0" ]; then
    python3 "$DIR/rebase.py" "$fixture" "$rebased" --gap-before "$line2" "$gap" 2>/dev/null
    o2=$(python3 -c "print(f'{$o2 + $gap:.3f}')")
  else
    python3 "$DIR/rebase.py" "$fixture" "$rebased" 2>/dev/null
  fi
  # --duration is whole seconds; round up so the last exec is always covered.
  local last
  last=$(python3 -c "import math; print(math.ceil(max($o1, $o2) + $MARGIN + 4))")

  if [ "$mode" != "offline" ] && [ "$HAVE_SUDO" = 0 ]; then
    echo "   SKIP $label (needs sudo)"
    skip=$((skip + 1))
    TABLE+=("$tag"$'\t'"$mode"$'\t'"$cmd"$'\t'"$rule"$'\t'"skip")
    return
  fi

  local wrap root=""
  wrap=$(make_wrap "$cmd")
  if [ "$mode" != "offline" ]; then
    # Each exec gets its own subshell: one call claims one exec, and an exec
    # from a pid already inside a bound subtree is deliberately not re-used
    # (src/exact.rs, on_exec).
    # The workload's own output is not the subject here; keep the terminal clean.
    case "$mode" in
    live)
      (
        (sleep "$(python3 -c "print(f'{$o1 + $MARGIN:.3f}')")"; /bin/bash -c "$wrap") &
        (sleep "$(python3 -c "print(f'{$o2 + $MARGIN:.3f}')")"; /bin/bash -c "$wrap") &
        wait
      ) >/dev/null 2>&1 &
      ;;
    window)
      # Only the second call really ran (its first sibling died in the sandbox,
      # see the fixture's bwrap tool_result), and the first call is out of range.
      (
        sleep "$(python3 -c "print(f'{$o2 + $MARGIN:.3f}')")"
        /bin/bash -c "$wrap"
      ) >/dev/null 2>&1 &
      ;;
    unrelated)
      (
        sleep "$(python3 -c "print(f'{$o1 + $MARGIN:.3f}')")"
        /bin/bash -c "$(make_wrap 'sleep 1')"
      ) >/dev/null 2>&1 &
      ;;
    esac
    root=$!
  fi

  sleep 0.2
  # The watchdog must outlive --duration: at `timeout 60` the window case (whose
  # only exec lands at ~130 s) lost bpftrace 70 s early and reported execs_seen=0.
  local guard=$((last + 30))
  if [ "$mode" = "offline" ]; then
    # No kernel side at all: the adapter alone, no privileges needed.
    timeout "$guard" "$BIN" -S "$rebased" --output json --no-color >"$out" 2>"$out.err"
  else
    timeout "$guard" sudo -n "$BIN" -p "$root" -S "$rebased" --duration "$last" \
      --output json --no-color >"$out" 2>"$out.err"
  fi
  note "root=$root duration=${last}s offsets=${o1}/${o2} line2=$line2"
  [ -z "$root" ] || wait "$root" 2>/dev/null

  local args=() expect=0
  case "$mode" in
  live)
    expect=2
    args=(--calls-seen 2 --calls-matched 2 --by-segment 2 --by-substring 0 --by-exact 0 --by-overlap 0
      --rules "$rule,$rule")
    ;;
  window)
    expect=1
    args=(--calls-seen 2 --calls-matched 1 --by-segment 1 --rules "$rule" --tool-id "$id_second")
    ;;
  unrelated | offline)
    expect=0
    args=(--calls-seen 2 --calls-matched 0 --by-segment 0 --by-substring 0 --by-exact 0 --by-overlap 0)
    ;;
  esac
  local res rc
  res=$(python3 "$DIR/check_bind.py" "$out" --label "$label" "${args[@]}" 2>&1)
  rc=$?
  echo "   $res"
  local bound
  bound=$(sed -n 's/.*calls_matched=\([0-9]*\).*/\1/p' <<<"$res" | head -1)
  [ -n "$bound" ] || bound=?
  if [ "$rc" = 0 ]; then pass=$((pass + 1)); else
    fail=$((fail + 1))
    note "stderr: $(head -3 "$out.err" | tr '\n' ' ')"
  fi
  TABLE+=("$tag"$'\t'"$mode"$'\t'"$cmd"$'\t'"$rule"$'\t'"$bound/$expect")
}

for entry in "${CASES[@]}"; do
  IFS=$'\t' read -r tag fixture cmd rule <<<"$entry"
  [ "$WANT" = all ] || [ "$WANT" = "$tag" ] || continue
  echo "== $tag  ($cmd)"
  run_mode live "$tag" "$DIR/$fixture" "$cmd" "$rule"
  run_mode unrelated "$tag" "$DIR/$fixture" "$cmd" "$rule"
  run_mode offline "$tag" "$DIR/$fixture" "$cmd" "$rule"
  if [ "$FAST" = 0 ] && [ "$tag" = rc1 ]; then
    run_mode window "$tag" "$DIR/$fixture" "$cmd" "$rule" 120
  fi
done

echo
echo "case  mode        rule           binds  command"
for row in "${TABLE[@]}"; do
  awk -F'\t' '{printf "%-5s %-11s %-14s %-6s %s\n", $1, $2, $4, $5, $3}' <<<"$row"
done
echo
if [ "$skip" = 0 ]; then
  echo "passed $pass, failed $fail"
else
  echo "passed $pass, failed $fail, skipped $skip"
fi
[ "$fail" = 0 ]
