# Contributing to Hardrails

Thanks for looking at this. Hardrails is a spec plus a reference
implementation of one idea: deterministic boundaries around a
non-deterministic agent. Contributions that sharpen that idea are welcome,
from typo fixes to new boundary checks.

## Dev setup

```bash
git clone https://github.com/GTalksTech/hardrails.git
cd hardrails
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -e ".[lab]" pytest
pytest
```

The full suite must pass before you start (54 tests as of this writing, all
offline, no lab required). If it does not, that is a bug: please open an
issue with your OS and Python version.

## The invariants

These are the point of the project. No change may weaken them, and the test
suite enforces each one:

1. **Read-only by default.** Device access structurally refuses configuration
   commands. New tools register with the boundary as READ unless there is a
   very good reason.
2. **Dry-run only.** The one tool that generates a change produces a diff and
   stops. There is no code path that applies it in the same call.
3. **Nothing reaches a device without a recorded human approval.** The gate
   is single-use, single-device, and audited.
4. **The audit log is append-only.** Every guarded call lands there, allowed
   or blocked.

A PR that trades one of these for convenience will not merge, however clean
the code is. A PR that strengthens one (see the open issues) is the best kind.

## Workflow

- Branch from fresh `main`: `fix/`, `feat/`, `docs/`, or `chore/` plus a
  short slug (for example `fix/approval-identity`).
- Behavior changes come with a test that fails without the change.
- `pytest` green locally before you push. CI runs the same suite on Linux,
  Windows, and macOS across supported Python versions, plus a packaging
  check.
- Small, single-topic PRs merge fastest. The PR template asks what changed,
  why, and how you verified it.
- Non-trivial changes start as a short design doc in `docs/specs/`
  (`YYYY-MM-DD-topic.md`) so the reasoning is on the record before the code.

## Conventions

- Python modules carry the header block you see at the top of every existing
  file. Match it.
- The spec (`hardrails-spec.md`) is normative. If your change alters behavior
  the spec describes, the same PR bumps the spec version and adds a changelog
  entry.
- Lab data uses real RFC1918 addressing and documented placeholder
  credentials on purpose: the lab exists to be replicated. Never commit a
  real secret; there is no legitimate reason for one to exist in this repo.

## Licensing

Inbound contributions are accepted under the project licenses: Apache-2.0 for
code, CC BY 4.0 for the spec and written material. Submitting a PR means you
agree to that. No CLA.
