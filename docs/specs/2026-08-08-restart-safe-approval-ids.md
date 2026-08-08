# Restart-safe approval ids: a receipt can never be clobbered

**Status:** implemented in the same PR (fix for issue #3)
**Date:** 2026-08-08

## Problem

Approval ids come from a module-level counter (`appr-1`, `appr-2`, ...)
that resets to zero when the server process restarts. The next session's
first `request_approval` mints `appr-1` *again*, and
`artifacts.update_artifact()` rewrites `approvals/appr-1.md` — silently
replacing the previous session's receipt. The artifact is the durable
"who approved what" record; the whole point of writing it to disk is that
it outlives the process, so a restart being able to overwrite one is
wrong by construction.

Issue #3 also names the orphan half: a restart loses the in-memory
`ApprovalRequest`, so a surviving artifact's history can never be
extended. That half is *state lifetime*, which `server.py` documents as
process-local by design for the lab. This change does not alter it, and
says so honestly (see Non-goals).

## Fix

Two independent layers, either of which alone prevents the clobber:

1. **Collision-free ids.** `request_approval` mints
   `appr-<8 hex chars>` from `secrets.token_hex(4)` instead of a
   counter. Four random bytes give ~4 billion values; at lab scale
   (dozens of approvals, ever) collision probability is negligible, and
   layer 2 catches the miracle case. The format stays within the
   artifact sink's safe-id shape (`[A-Za-z0-9][A-Za-z0-9._-]*`).

2. **Foreign-receipt guard at the artifact sink.** `update_artifact`
   already validates the id's shape and the path's containment. It now
   also refuses to touch a file that exists on disk for an id this
   process has no transition history for: that file is another session's
   receipt, and rewriting history is exactly what the artifact layer
   exists to prevent. Same best-effort contract as every other refusal
   in the module — no artifact write, return `None`.

The guard's placement matters: the existence check happens *before* the
id is entered into the in-process history, so a refused id stays foreign
and every subsequent attempt is refused too.

## Non-goals

- **Persisting pending approvals across restart.** An orphaned PENDING
  approval still cannot be resolved after a restart — the id is not in
  `_approvals`, and `resolve_approval` / the approval surface answer
  "Unknown approval". That is session-state lifetime, documented in
  `server.py`, and changing it means designing durable state for
  proposals *and* approvals *and* the artifact history dict together.
  If the lab outgrows process-local sessions, that design gets its own
  doc; nothing in this fix forecloses it.
- **Renaming existing artifacts.** Receipts already on disk keep their
  counter-era names; they are frozen history, which is the point.

## Tests

- A simulated restart (module state cleared, same artifact directory)
  mints a different id and leaves the first session's artifact intact.
- `update_artifact` refuses an id whose file exists but whose history is
  not in-process (returns `None`, file byte-identical), and keeps
  refusing on repeat attempts.
- Minted ids satisfy the sink's safe-id pattern.
- The full existing suite (116 tests) unchanged.
