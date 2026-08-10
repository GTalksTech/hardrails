# Single-use apply must be atomic under concurrency

- Status: accepted
- Date: 2026-08-10
- Scope: `netagent/remediation.py` (`apply_approved`), `netagent/server.py`
  (`apply_remediation`)
- Follows: `2026-08-08-single-use-approval.md` (#19); closes a concurrency gap

## Problem

#19 made an approval single-use: `apply_approved` sets the approval to `APPLIED`
after a successful push, and the boundary refuses an `APPLIED` approval. That is
correct against **sequential** replay. But the check and the transition are not
atomic, so **concurrent** applies of one approval can both push.

`boundary.guard()` evaluates the mutation gate (state must be `APPROVED`) and then
runs `execute()` (= `apply_approved`) outside any lock — deliberately, so device
I/O is not serialized behind the audit lock. `apply_approved` sets `APPLIED` only
*after* `send_config_set`. Two `apply_remediation` calls for the same approval,
dispatched concurrently (FastMCP runs sync tools in a threadpool — the concurrency
model #21 hardened the audit log for), can interleave: both pass the gate while
the approval is still `APPROVED`, both pass `apply_approved`'s own `APPLIED`
check, both push, both set `APPLIED`.

Confirmed offline (real `Boundary.guard`, two threads, synthetic push):

```
applies that reached the wire: 2   (single-use should permit exactly 1)
```

Severity is LOW — it needs the harness to issue two concurrent applies of the same
approval, and canned remediations are idempotent — but "one human yes = one apply"
(invariant 3) should hold under the concurrency the boundary already claims to
withstand.

## Decision

Serialize the sole write path. `apply_approved` runs its state check → device push
→ `APPLIED` transition under one module-level lock, so exactly one push happens per
approval:

- The second concurrent caller acquires the lock only after the first has set
  `APPLIED`, sees the spent state, and refuses — no second push.
- A push that raises leaves the approval `APPROVED` (still retryable): `APPLIED` is
  set only after `send_config_set` returns, inside the lock.
- `apply_remediation` catches `RemediationError` and returns it as a clean
  single-use `blocked` payload, instead of letting the loser surface as an
  unhandled tool error.

A module-level lock (not per-approval) is chosen for legibility: applies are rare
and human-gated, so serializing the one write path costs nothing at lab scale and
is trivial to reason about. It is never held around read-path or audit work — only
the apply critical section.

## Consequences

- Concurrent applies of one approval produce exactly one device push; the loser is
  a single-use refusal.
- No change to the sequential flow, the boundary gate, or invariants 1/2/4.
- The audit log records both calls (the gate allowed both); the loser's result
  line is its refusal. Honest: it shows an attempted second apply that changed
  nothing.

## Tests

`tests/test_single_use_approval.py` gains a concurrency test: two threads apply the
same approval with a latency-injecting fake device; exactly one `send_config_set`
lands, the approval ends `APPLIED`, and the other call raises `RemediationError`.
It fails without the lock (two pushes).
