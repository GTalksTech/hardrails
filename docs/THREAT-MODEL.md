# Hardrails threat model (reference implementation)

The Hardrails spec (§8) sets an obligation: *"Every boundary has a trusted
computing base; the method's obligation is to name it, keep it small, and leave
evidence when it is touched."* This document does that for `netagent`, the
reference implementation. It complements [SECURITY.md](../SECURITY.md) (how to
report a vulnerability) and the design records under [specs/](specs/).

## What the boundary defends

One property, stated three ways (the invariants):

1. The agent's device access is **read-only by default**, enforced on the
   command that reaches the wire — not by the tool's name.
2. A change is **dry-run only**: rendered as a diff, never committed, until a
   human approves it.
3. **No change reaches a device without a human approval that entered through a
   trusted path** — a channel the agent cannot write — and every guarded call,
   allowed or blocked, lands in an **append-only audit log**.

If those hold, a wrong or manipulated agent can read, propose, and be refused;
it cannot push.

## Attacker in scope

The primary adversary is a **co-located, same-user process on the host the agent
runs on** — which includes the agent itself when it is confused or
prompt-injected by text it read (a device banner, a syslog line, an MCP tool
response). Concretely, this attacker can:

- call any MCP tool with any arguments the schema allows;
- read any file the user can read, including the enrollment file and the audit
  log;
- speak to any address the machine can reach, including the machine's own
  addresses and the approval surface;
- run its own subprocesses and write files in the user's writable paths.

The trusted path is designed against exactly this attacker: the approval surface
refuses same-machine sources, and the recorded "yes" is attested by a factor the
same-user attacker does not hold (see per-mode roots below).

## Attacker out of scope

The boundary is software; no software control survives its own code or memory
being rewritten. Out of scope, and defended by the **engineering layer** rather
than the running gate:

- An attacker who can **rewrite the boundary's code or process memory** (edit
  `boundary.py`, patch the running process, or escalate to root/admin).
  Defended by version control, mandatory review, branch protection, and CI — and
  by deployment separation (run the server on hardened, separately-owned
  infrastructure, per the spec's adoption guidance).
- A **supply-chain** compromise of the Python runtime or a dependency.
- Physical access to the host or to the approver's second device.

These are named on purpose. A boundary whose safety story quietly assumed an
uncompromised codebase, without saying so, would be dishonest.

## The trusted computing base

For the boundary to hold, these must be intact:

- **The server process and its reviewed code** — `boundary.py` (the gate + audit
  log), `server.py` (the tool surface), `devices.py` (the read-only command
  allowlist), `remediation.py` (the single write path), and `trusted_path.py`
  (the approval surface). Kept small and in one repo on purpose.
- **The identity root of the approval channel**, which depends on the mode:
  - **Mode A (secret, default).** The enrolled secret. Only its scrypt hash is on
    disk (`approval-secret.json`); the plaintext exists only on the human's
    second device. The same-user attacker can read the hash but cannot reverse
    it, and cannot present the secret from an off-machine source.
  - **Mode B (Tailscale).** The local `tailscaled` and its `whois` attestation,
    plus the approver allowlist. The trust is that the tailnet correctly
    attributes a peer address to a node; the server refuses its **own** node as
    an approver and invokes an absolute-path `tailscale` binary resolved at
    startup, so the attestation oracle cannot be swapped at request time.
  - **Mode C (WebAuthn, future — issue #11).** A hardware authenticator.
- **The host OS process/user boundary.** A same-user attacker is in scope and
  handled; a root/admin attacker is out of scope (see above).

## Honest residual risk

The spec's §8 non-claims apply here in full:

- **Read access is still access.** A manipulated agent with read tools can
  exfiltrate what it can see. Least privilege applies to reads too, and the
  audit log covers reads, not just writes.
- **The audit log's append-only property is enforced by convention and the
  engineering layer, not by the OS.** A same-user attacker can edit
  `audit-log.jsonl` or an approval artifact directly; the code never truncates
  or rewrites it, but the file is as writable as any the user owns.
  Tamper-evidence (a hash chain) is a tracked enhancement, not a current claim.
- **The testing-only `tool` mode** (`NETAGENT_APPROVAL_MODE=tool`) relays the
  approval decision through the agent-callable tool and is explicitly
  non-conformant with invariant 3. It is loud — a startup audit record, a stderr
  warning, and "unattested" stamps on every artifact — but anyone who controls
  the server's spawn environment can set it. Do not run it against a device you
  care about.
- **The boundary does not make the agent right.** It bounds what a wrong answer
  can touch; evaluation and human review exist because of that, not despite it.

## Where to look next

- Reporting a vulnerability: [SECURITY.md](../SECURITY.md).
- The trusted-path design and its alternatives-considered:
  [specs/2026-08-05-trusted-path-approval.md](specs/2026-08-05-trusted-path-approval.md).
- The per-fix design records: the dated files under [specs/](specs/).
