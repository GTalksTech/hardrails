# Audit-log integrity: correct under concurrency and honest under faults

**Status:** implemented in the same PR (fix for issue #20)
**Date:** 2026-08-08

## Problem

Three defects in the boundary's decision/persist path weaken invariant 4 (every
guarded call gets an append-only record; the log is the receipt).

1. **Concurrency race.** `guard()` computes the verdict with `check()` and then
   grabs `record = self._log[-1]`, assuming the last-appended record is its own.
   The process is genuinely concurrent — FastMCP runs sync tools in a threadpool
   and dispatches one task per message, and the approval surface is a
   `ThreadingHTTPServer` that also appends to `_log` via `record_event`. Another
   thread can append between this thread's append and its `_log[-1]` read, so the
   result summary is attached to the wrong record (or a block raises on another
   call's record). With no lock, concurrent JSONL appends can also interleave
   into torn lines. This is an audit-integrity bug, not a device-gate bypass —
   the ALLOW/BLOCK verdict comes from `check()`'s return value, never `_log[-1]`.

2. **Fail-open audit on a mutation.** `_persist` swallows write errors and
   returns nothing. For the MUTATE tool the decision line is persisted before
   execution — but if that durable write silently fails, the change runs anyway,
   with no durable receipt. Best-effort is right for reads and blocks; for the
   one action that changes a device it inverts the invariant.

3. **Exception-path leak.** `_summarize` is deliberately shape-only because a
   device payload can carry secrets. The exception path instead persists the
   full `{exc}` string, and device-I/O exceptions (a netmiko read-timeout
   mid-`show running-config`) can embed device output. A test currently locks
   this in.

## Fix

All three live in `boundary.py`; the model gains one transient flag.

1. **Return the record, don't fish for it.** `check()` keeps its public
   `ToolDecision` return, but the decision logic moves to `_evaluate()`, which
   returns the `ToolCallRecord` it appended. `guard()` uses that record directly
   — the misattribution is now *unrepresentable*, not merely unlikely. A
   re-entrant lock (`threading.RLock`) guards the `_log` append and the JSONL
   write so concurrent appends cannot interleave. The lock is held only around
   the in-memory append and the file write — **never** around `execute()`, so
   device I/O is never serialized behind the audit lock.

2. **Fail closed for a mutation with no receipt.** `_persist` returns `True`
   only when the line reached disk (it still never raises). `ToolCallRecord`
   carries a transient `_persisted` flag (a Pydantic `PrivateAttr`, not
   serialized). In `guard()`, an ALLOWED **MUTATE** whose decision line did not
   persist is refused with an "audit unavailable" block — the change never runs.
   Reads and blocks keep the best-effort contract (availability over durability),
   because a read that isn't logged did not change anything.

3. **Shape-only exception summary.** `_summarize_exception()` records the
   exception **type** and withholds the message, mirroring `_summarize`. Enough
   to prove an error of that class happened; nothing device-derived reaches the
   receipt.

## Non-goals

- **Tamper-evidence (hash-chained / signed log).** Out of scope here and
  acknowledged by spec §8 (the boundary does not defend against an attacker who
  can rewrite it). Tracked separately as an enhancement.
- **Cross-process serialization.** The lock is per-`Boundary` (per process).
  Two processes writing the same default `audit-log.jsonl` is a deployment
  choice; an OS file lock would be the fix if that becomes real.
- **Argument redaction / size caps.** A related audit-hygiene item (free-form
  args logged verbatim) is left to its own change.

## Tests

New `tests/test_boundary_integrity.py`:

- **Concurrency:** many threads share one `Boundary` (mixing `guard()` tool calls
  and `record_event` surface events) against a real file; assert every JSONL line
  is well-formed (no torn lines), the call/result counts are exact, and each
  result record links to a real call — no loss, no corruption.
- **Fail-closed mutation:** with `_persist` forced to fail, a MUTATE `guard()`
  raises `BoundaryViolation` and `execute()` never runs; a READ still runs
  (best-effort).
- **Exception non-leak:** an `execute()` that raises with secret-shaped text
  leaves the secret out of both the JSONL and the in-memory `result_summary`,
  while the exception type is recorded.

Existing `test_boundary_audit_log.py::test_execution_error_summary_is_persisted`
is updated to the new contract (type present, message withheld).
