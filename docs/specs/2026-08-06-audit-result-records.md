# Audit result records: persisting the outcome without mutating the receipt

**Status:** implemented in the same PR (fix for issue #6)
**Date:** 2026-08-06

## Problem

The boundary writes each `ToolCallRecord` to the JSONL receipt at decision
time, inside `check()` — deliberately, so the verdict is on disk before the
tool runs and a crash mid-execution cannot lose it. But `guard()` sets
`result_summary` on the in-memory record only *after* execution, which is
after that record's serialization already hit the file. Net effect: every
persisted record carries an empty `result_summary`, permanently. The durable
receipt says what was attempted and what the verdict was, but never what
happened.

A side effect worth naming: the existing no-payload-leak test passed
vacuously — nothing about the result was persisted at all, so asserting the
payload's absence proved nothing about the summarization discipline on disk.

## Constraint

The audit log is append-only. That is a framework invariant, not a style
preference: the receipt's value is that history cannot be rewritten. Any fix
that reopens and edits an existing line is wrong by construction.

## Options considered

1. **Persist the call record after execution instead of at decision time.**
   Rejected: the verdict must be durable before the tool runs. A crash (or a
   kill) mid-execution would leave no trace that the call was ever allowed —
   strictly worse than a missing summary.

2. **Rewrite the record's line in place once the summary is known.**
   Rejected outright: violates append-only.

3. **Append a follow-up result record after execution.** Chosen. The decision
   line stays exactly as written; the outcome becomes a second, later line
   that references the first. This is the standard event-sourcing answer:
   facts are appended, never edited.

## Design

- `ToolCallRecord` gains two fields:
  - `record_type` (constant `"call"`) — discriminator, so readers of the
    JSONL file can tell the two record shapes apart.
  - `call_id` (uuid4 hex, generated per record) — the identity a follow-up
    record links to. Records previously had no identity.
- New model `ToolResultRecord`: `record_type` (constant `"result"`),
  `call_id`, `timestamp`, `result_summary`. Appended by `guard()` after the
  callable returns (summarized via the existing `_summarize`, same no-payload
  discipline) or raises (`ERROR during execution: ...`, same string that goes
  on the in-memory record today).
- Blocked calls are unchanged: nothing executed, so no result record. Their
  reason is complete at decision time.
- The in-memory log is unchanged: `audit_log()` still returns one
  `ToolCallRecord` per call, with `result_summary` set post-execution as
  before. The follow-up record exists on disk only — the in-memory record
  needs no follow-up because mutating an object in memory before anyone reads
  it is not rewriting history.
- Persistence reuses the existing best-effort `_persist` (a disk failure
  never breaks the gate).

## Discovered while fixing: the summary excerpt was itself a leak

`_summarize` previewed the first line of a string result (60 chars) in the
summary. Once summaries persist, that excerpt reaches disk — and the first
line of a `show run` payload can already be a secret (`enable secret 9 ...`).
The strengthened no-leak test caught this immediately. Fix, in the same
change: the summary is shape only (type, size, line count), no content
excerpt. This matches what the function's docstring always claimed was
sufficient ("one line of shape is enough to prove what happened").

## Compatibility

Existing log files contain call-shaped lines without `record_type`/`call_id`.
Nothing in the codebase validates the file back into models; readers that
count or compare lines (the tests) now filter on `record_type == "call"`.
The spec (hardrails-spec.md §Non-negotiables 4) describes the audit record
abstractly — "what, when, verdict, why" — and is unchanged by this: the
follow-up record adds outcome detail without altering any described behavior.
