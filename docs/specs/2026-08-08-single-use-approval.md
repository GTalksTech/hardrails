# Single-use approvals: one human yes authorizes exactly one apply

**Status:** implemented in the same PR (fix for issue #18)
**Date:** 2026-08-08

## Problem

Invariant 3 and the approval page both state an approval is **single-use**
("This decision is single-use" — `trusted_path.py`). But single-use is enforced
only against re-*resolution* (`approval._resolve` refuses a second approve/
reject), never against re-*application*. After a successful `apply_remediation`
nothing consumes the approval:

- `ApprovalState` has only `PENDING/APPROVED/REJECTED` — no consumed state.
- `boundary._check_mutation` allows on `state == APPROVED` + channel + device.
- `remediation.apply_approved` asserts `state is APPROVED` but never transitions
  it after the push.
- `server.apply_remediation` rewrites the artifact but never changes state.

So an `APPROVED` + `TRUSTED_PATH` approval passes the mutation gate on every
call. An offline probe applied the same approval three times, all `allowed`.
One attested human yes becomes an unbounded, re-runnable write for the whole
session. The teeth beyond idempotent lab commands: a human approves a change,
it applies, the human manually reverts it — and the agent silently re-applies
using the still-`APPROVED` approval, with no new human decision.

## Fix

Give an approval a terminal, consumed state and refuse to spend it twice — the
same two-layer shape the rest of the boundary uses:

1. **New terminal state `ApprovalState.APPLIED`** (plus an `applied_at`
   timestamp on `ApprovalRequest`). `apply_approved` sets it after a successful
   `send_config_set`, so the object the server holds in `_approvals` is now
   spent.
2. **The gate refuses a spent approval.** `boundary._check_mutation` blocks a
   mutation whose approval is `APPLIED`, with a single-use reason that teaches
   the flow (build a new proposal, earn a fresh approval). `apply_approved`
   re-asserts the same thing, so it is safe even if called directly.

A second, legitimately-different change is a new proposal → new approval, on
purpose: the human decides once per change.

### Note on the channel check (issue #16/#9 defense-in-depth)

`apply_approved`'s inner re-assert deliberately does **not** check
`channel == TRUSTED_PATH`. That check is *mode-aware* — the testing-only `tool`
mode legitimately resolves with `channel == TOOL` — so it belongs in the
boundary, which knows `require_trusted_channel`. Keeping `apply_approved`
mode-agnostic is correct; this PR does not move that check into it.

## Non-goals

- **Consuming on a failed apply.** `apply_approved` marks the approval `APPLIED`
  only after `send_config_set` returns. A push that raises leaves the approval
  `APPROVED` so a transient failure can be retried; it does not silently
  re-apply a change that already succeeded, which is the abuse this closes.
- **Persisting consumption across restart.** Approvals are process-local
  session state by design (documented in `server.py`); a restart drops
  `_approvals` entirely, which is fail-closed, not a bypass.

## Tests

New `tests/test_single_use_approval.py`:

- **Boundary:** an `APPROVED` approval is allowed; once it is `APPLIED`, the
  gate refuses it with a single-use reason.
- **`apply_approved` (real, netmiko faked):** a successful apply sets
  `state == APPLIED` and `applied_at`; a second call raises `RemediationError`.
- **Server end-to-end (tool mode):** propose → request → approve → apply
  (`applied: true`) → apply again → a single-use `blocked` result.
