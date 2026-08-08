# Trusted-path approval: closing the identity gap

| | |
|---|---|
| **Status** | Draft — awaiting review. No code until approved. |
| **Date** | 2026-08-05 |
| **Issue** | [#9](https://github.com/GTalksTech/hardrails/issues/9) |
| **Scope** | `netagent` reference implementation + `hardrails-spec.md` normative change |

---

## 1. Problem

`resolve_approval` records *who* approved a change and *why* — but both are
ordinary string arguments supplied by whoever calls the tool, which in the
intended flow is the model relaying the human's words. The server enforces
process (state machine, single-use, single-device, audit, artifact) but
cannot attest identity: it has no way to distinguish a faithfully relayed
human decision from a decision the model composed itself. This is the
documented HONEST LIMITATION at `netagent/approval.py:80`, tracked as
issue #9.

Consequence: for this one property — "a human said yes" — the only
enforcement today is the harness's own permission prompt. That inverts the
method's conformance acid test (`hardrails-spec.md` §5, checklist): removing
the harness's safety prompts *would* remove this part of the boundary.

## 2. Goal and non-goals

**Goal.** The approval decision enters the server through a channel the
agent cannot write. After this change, no sequence of tool calls, shell
commands, file writes, or network requests available to the agent produces
an `APPROVED` state. Approving requires a human acting from outside the
agent's reach.

**Non-goals.**

- Not building a phone app, an account system, or any cloud dependency.
  The approval surface is a page served by the netagent process itself.
- Not making the server invulnerable to an attacker who can rewrite the
  server (see §3, trust root).
- Not multi-user RBAC. One enrolled approver secret is the v1 shape;
  multiple approvers are a straightforward extension, not a redesign.

## 3. Threat model

### 3.1 The attacker

The agent's harness has **arbitrary shell access as the same OS user that
runs the netagent server**, on the same machine. Concretely, the attacker
can:

- run any command that user can run;
- read every file that user can read — including the server's config, the
  approval artifacts, the audit log, and any stored credential material;
- write files in the user's writable paths;
- open network connections to anywhere, including every address the
  machine holds (loopback and non-loopback alike);
- read and set its own environment, and influence the environment of
  processes it spawns;
- call every registered MCP tool with arbitrary arguments.

This is deliberately the strongest honest description of a model driving a
harness with shell access. Designing for a weaker attacker (e.g.
"tool calls only") would make the guarantee depend on the harness's
configuration, which is exactly what the method forbids.

### 3.2 The property that must hold

> No input producible by the attacker in §3.1 — tool call, file, localhost
> or same-host network request, environment variable — causes any
> `ApprovalRequest` to reach the `APPROVED` state.

Rejection is deliberately *not* protected to the same degree: a forged
rejection fails safe (nothing gets applied), so the reject path may remain
tool-callable.

This property is the contract of **trusted mode, the default**. The
explicit legacy mode (§4.6) trades it away — loudly and at startup, never
silently and never at runtime.

### 3.3 Trust root: what is assumed intact

Every software boundary has a trusted computing base — the set of things
that must be intact for its guarantees to mean anything. Hardrails' TCB is
**the netagent server process: its code on disk, its memory, and the
Python/OS underneath it**. The following attacks defeat the entire
framework, not merely this feature, and are out of scope here:

- rewriting the server's source (e.g. editing `boundary.py`) or its
  configuration and restarting it;
- attaching a debugger to the running server or otherwise tampering with
  its memory;
- compromising the OS, the Python interpreter, or the filesystem layer.

They are out of scope because no software control can protect itself from
an attacker who can rewrite the control. They are *countered*, not ignored,
by the layers around the code:

- **Repository discipline.** The boundary is versioned code behind branch
  protection, mandatory PR review, and CI. A rewrite of the enforcement
  layer is a loud, attributable diff — this is why the workflow rules
  exist.
- **The harness gate** (spec §5 principle 7): the outer permission prompt
  makes "edit the server's own code" a visible, deniable act rather than a
  silent one.
- **Deployment separation** (§7): moving the server to a different machine
  removes its code and memory from the attacker's filesystem entirely.
  The architecture below is designed so that this is a deployment choice,
  not a redesign.

Also out of scope for mode A, stated honestly: a **passive attacker on the
local network** can observe the approval secret in transit, because the
surface is plain HTTP on a lab LAN. Mode B (Tailscale, §6) closes this
with an encrypted mesh and device identity; mode C (WebAuthn, §9) closes
it cryptographically. A home-lab LAN is the reference environment; the
limitation is documented in the enrollment output and the README.

### 3.4 Why the obvious alternatives fail this model

- **Localhost approval page + token.** The agent speaks localhost and
  reads files; any token it can be shown, it can replay. Fails.
- **TOTP (standard MFA codes).** The verifier must hold the shared seed.
  The seed lives on the attacker-readable machine, so the attacker can
  mint valid codes. TOTP defeats a *remote* attacker without the seed,
  not a *local* one with it. Fails.
- **Separate OS user holding a plaintext secret.** Sound in principle,
  but heavy to replicate on the reference lab (single-user Windows/macOS
  boxes), and it protects a secret we can avoid storing at all by hashing
  (§4.3). Not taken.

## 4. Design: the trusted path (mode A, normative)

### 4.1 Shape

The netagent server grows a small HTTP listener — the **approval
surface** — bound to the machine's **non-loopback** address(es), never
`127.0.0.1`. `request_approval` keeps doing exactly what it does today
(create the PENDING request, write the artifact) and additionally returns
an `approval_url` such as `http://192.168.1.20:8484/a/appr-1`.

The human opens that URL on a **second device** (any phone or laptop
browser on the same network — not the agent's machine). The page renders
the finding, the device, the exact commands, and the full dry-run diff —
the same content as the approval artifact — plus a form: approver name,
reason, the enrolled approval secret, and Approve / Reject buttons.

On submit, the server applies two independent deterministic checks, in
order:

1. **Local-source rejection.** If the connection's source address is any
   address held by the server's own machine (loopback or otherwise), the
   request is refused and audited. A same-host `curl` — the agent's most
   direct move — dies here *regardless of what credentials it presents*.
   This check is deliberately first: it is cheap, has no false negatives
   for the attack it targets, and keeps secret-guessing traffic from the
   agent's own box out of the verifier entirely.
2. **Secret verification.** The submitted secret is checked against a
   stored **hash** (scrypt, per §4.3) in constant time. Anyone *else* on
   the LAN — a roommate's laptop, an IoT device — dies here.

Only a request that passes both transitions the `ApprovalRequest`, and it
does so with provenance recorded (§4.4).

The URL's approval id is not a secret and not a defense — the agent sees
it in the tool result. Knowing *which* approval is pending buys the
attacker nothing; the gate is where the decision comes from, not whether
the pending decision is known.

### 4.2 Components

- `netagent/trusted_path.py` — new module: the listener (stdlib
  `http.server`, threaded, started by `server.py` at boot), the two-check
  verifier, and the page rendering. Verification logic is pure functions
  taking an explicit source address, so tests never need a real socket.
- `netagent-enroll` (console script) — one-time enrollment, run by the
  human in their own terminal, never by the agent: generates a 128-bit
  random secret, prints it once for storage on the second device (with a
  QR code if the optional `qrcode` package is present, plain text
  otherwise), and writes **only its scrypt hash + salt** to
  `approval-secret.json` beside the audit log (env-overridable via
  `NETAGENT_APPROVAL_SECRET_FILE`, same discipline as
  `NETAGENT_AUDIT_LOG`). Re-running rotates the secret. The printed
  output states the handling rule: *this secret is only ever typed on a
  device that is not the agent's machine.*
- `server.py` — returns `approval_url` from `request_approval`; demotes
  `resolve_approval` (§4.5).
- `models.py` — `ApprovalChannel` enum and a `channel` field on
  `ApprovalRequest` (§4.4).
- `boundary.py` — the mutation gate additionally requires trusted
  provenance (§4.4).

### 4.3 Why a hashed static secret survives §3.1

The attacker reads every file, so no *plaintext* credential may exist on
the machine. A hash is the standard answer: `approval-secret.json` holds
`scrypt(secret, salt)`; reading it does not yield the secret, and scrypt's
memory-hardness makes offline guessing of a 128-bit random value
irrelevant. The plaintext exists in exactly one place — wherever the human
stored it at enrollment (phone browser, password manager on the second
device). This is the same trust shape as a login password, deliberately:
well-understood, stdlib-implementable (`hashlib.scrypt`), zero
dependencies.

What mode A attests is therefore precise: **"someone holding the enrolled
secret, connecting from off this machine, approved this."** The typed
approver name is still self-reported text — but now self-reported by the
secret-holder, through a channel the agent cannot write, instead of by the
agent. §8 states this honestly in the artifact.

### 4.4 Provenance, enforced at the boundary

`ApprovalRequest` gains:

```python
class ApprovalChannel(str, enum.Enum):
    TOOL = "tool"                  # resolved via resolve_approval (legacy)
    TRUSTED_PATH = "trusted_path"  # resolved via the approval surface
```

The trusted-path resolver is the only code path that sets
`TRUSTED_PATH`. `boundary._check_mutation` adds one check: in trusted
mode, an approval whose channel is not `TRUSTED_PATH` is a BLOCK, with a
reason that teaches the flow ("this server accepts approvals only via the
approval page; the URL was returned by request_approval"). Defense in
depth within the server itself: even if some future refactor of
`resolve_approval` regressed and approved a request, the apply gate would
still refuse it.

### 4.5 `resolve_approval` is demoted, not removed

- `decision="approve"` → refused with a teaching message naming the
  trusted path. The state stays PENDING. (In the established pattern:
  blocks teach the correct procedure.)
- `decision="reject"` → still works, tool-callable, either mode. A
  rejection fails safe; letting the model relay "the human said no"
  costs nothing and keeps the abort path fast.

### 4.6 Modes and fail-deny

`NETAGENT_APPROVAL_MODE` selects the behavior at startup:

- **`trusted` (default).** The listener must bind a non-loopback address
  at boot or the server refuses to start — a broken approval surface is a
  startup error, not a silent downgrade. If the surface later becomes
  unavailable, approvals are simply impossible until it returns; rejects
  still work. There is **no runtime fallback to tool-supplied approval
  strings** under any error condition (issue #9, constraint 3).
- **`tool` (legacy).** Current behavior, kept **for testing purposes
  only**: first-run before enrollment, offline demos, CI, and lab
  replication. It is **explicitly not conformant with principle 3**, and
  the red tag is applied everywhere the mode is visible:
  - the README section for the mode opens with *"for testing purposes
    only — never operate this mode against a device you care about"*;
  - the server logs a startup warning to the same effect, and writes the
    mode into the audit log at startup;
  - every approval artifact and ALLOW record produced in this mode is
    stamped `channel: tool (unattested)`.

  The mode exists so newcomers can reach a working gate in minutes; the
  stamps exist so nobody mistakes that rung for the destination. A
  deliberate, logged configuration choice is not a fallback; the deny
  rule above is about *runtime* degradation. This follows the repo's
  existing honesty pattern (the CVE backend names live-API vs
  dated-cache on every result): a weaker claim is permitted only when
  the output itself says the claim is weaker.

The active mode is recorded in the audit log at startup in both cases.

### 4.7 Audit and artifacts

- Every trusted-path resolution is routed through the boundary's record
  path as `trusted_path.resolve` with the decision, approver, channel,
  and source address — the append-only invariant ("every guarded call
  lands in the log") extends to the new surface, including *refused*
  attempts (local-source hits and bad secrets), which are exactly the
  events worth receipts.
- Failed secret attempts are throttled (small lockout after repeated
  failures) and audited; with a 128-bit secret this is hygiene, not a
  load-bearing defense.
- `approvals/<id>.md` gains a **Channel** line (`trusted_path` /
  `tool (unattested)`) and records the source address on resolution.
- The ALLOW reason in `boundary._check_mutation` carries the channel, so
  the one-line receipt distinguishes an attested approval from a legacy
  one.

## 5. What each mode attests (the identity ladder)

| Mode | Attests | Doesn't attest |
|---|---|---|
| `tool` (legacy, non-conformant) | a caller supplied a name and reason | that any human was involved |
| A: trusted path | an off-machine secret-holder decided | *which person* held the secret |
| B: Tailscale identity | a named tailnet device/login decided | that the device wasn't stolen/unlocked |
| C: WebAuthn (future) | a hardware-backed credential + user gesture | — (this is the practical ceiling) |

Each rung reuses the same surface, provenance field, and boundary check;
only the authenticator changes. That is the "build it once" property: A's
architecture is not scaffolding to throw away on the way to C — it is the
frame C bolts into.

## 6. Mode B: Tailscale identity (separate PR)

`NETAGENT_APPROVAL_IDENTITY=tailscale` upgrades check 2: instead of (or in
addition to) the secret, the server resolves the connection's source
address through the local tailscaled API (`whois`) and requires the peer
to be a device in `NETAGENT_TAILNET_APPROVERS` (comma-separated device or
login names). The approver recorded in the artifact becomes the **tailnet
login name — attested, not typed**. Transport is WireGuard-encrypted,
closing the LAN-sniffing gap in §3.3. Binding prefers the Tailscale
interface address.

Fail-deny applies: if tailscaled is unreachable in this mode, approvals
are impossible; there is no silent downgrade to secret-only.

## 7. Privilege separation and deployment

Mode A on one machine gives **channel separation** (the approval enters
through an interface the agent cannot legitimately speak on) but the TCB
(§3.3) still shares the attacker's filesystem. The hardening path is
physical:

- **Teaching configuration (default):** server and harness on one lab
  machine. Honest scope per §3.3.
- **Hardened configuration:** the identical code deployed on a separate
  host (a Pi, a VM, a VPS on the tailnet) with the MCP transport pointed
  at it. The server's code, memory, secret hash, audit log, and approval
  surface all leave the agent's reach; the same-user-shell attacker of
  §3.1 retains exactly one capability against the boundary: calling the
  registered tools. Nothing in this design assumes co-residence — that is
  a property to preserve in review, not an accident.

At startup the server writes its own package version and the active
approval mode into the audit log, so a receipt exists for *which* boundary
was running — tampering per §3.3 is out of scope to prevent, but not to
evidence.

## 8. Failure modes

| Condition | Behavior |
|---|---|
| Listener cannot bind non-loopback at boot (trusted mode) | Server refuses to start, with a message naming the fix (network up, port free, or explicit `tool` mode). |
| Approval surface dies mid-session | Approvals impossible until restart; rejects and all read tools unaffected. No fallback. |
| Same-host request to the surface | Refused + audited (`local-source`), before secret verification. |
| Wrong secret | Refused + audited; lockout after repeated failures. |
| Artifact/audit disk write fails | Best-effort as today (boundary verdicts and in-memory state remain authoritative). |
| `resolve_approval(decision="approve")` in trusted mode | Refused with the teaching message; state unchanged. |

## 9. Testing plan (failing-first, offline)

Verification logic takes the source address and stored hash as explicit
arguments, so every test runs without sockets or devices:

1. Local-source rejection: submissions from every machine-held address
   (loopback and non-loopback) are refused; a foreign address proceeds.
2. Hash verification: correct secret passes; wrong secret fails; the
   secret file contains no plaintext (enrollment writes hash+salt only).
3. Provenance: a trusted-path approval carries `TRUSTED_PATH`; a
   tool-channel approval in trusted mode is BLOCKED at apply by the
   boundary, with the teaching reason.
4. Demotion: `resolve_approval` approve → refused, state stays PENDING;
   reject → works in both modes.
5. Fail-deny: trusted mode with no bindable non-loopback address refuses
   to start; `tool` mode stamps `unattested` into artifact and audit.
6. Receipts: refused attempts (local-source, bad secret) each land one
   audit record; artifact shows the Channel line and source address.
7. The existing suite (59 tests at time of writing) keeps passing, with
   fixtures updated to run in explicit `tool` mode where they exercise
   legacy resolution.

**Verification evidence (beyond the suite).** PR 1 also ships a sandboxed
live run producing reviewable proof without manual reproduction: the
server started with audit log, artifacts, and secret file pointed at a
scratch directory; a disposable secret enrolled; the approval page
captured in a browser; and a same-machine submission refused and audited
— the negative proof is the property itself. Where a genuine second
network vantage exists (a LAN peer with its own address), an over-the-wire
approve is captured end-to-end as well; note that a co-located WSL guest
is NOT such a vantage — its traffic NAT-hairpins through the host and
arrives bearing the host's own address, which the local-source check
correctly refuses. The full approve chain is pinned over a real socket in
the test suite instead, with the refusal set as the injected seam. The evidence bundle (screenshots,
transcripts, audit-log excerpts) attaches to the PR. Honest limit: the
sandbox necessarily plays both roles with a throwaway secret; it proves
the mechanics (local-source refusal, hash-only storage, provenance
enforcement), while real second-device custody is created by the human's
one-time enrollment.

## 10. Changes to `hardrails-spec.md`

This alters spec-described behavior, so the implementing PR bumps the spec
version and changelog (repo rule). A MUST-level change to a normative
principle is breaking by the spec's own versioning rule (§12), so this is
**v2.0.0**.

- **§5 principle 3 (Human approval gate)** gains: "The approval decision
  MUST enter through a trusted path: a channel the agent cannot write,
  verified by the boundary, so that the recorded yes is attested rather
  than relayed. A relayed approval is a claim, not an approval." The
  method's early adoption stage is precisely when a breaking tightening
  is cheapest; deferring it would ossify the weaker gate as the
  ecosystem's baseline.
- **§5 Conformance checklist** adds: "[ ] The approval channel is not
  writable by the agent (trusted path)." No unattested escape hatch: a
  deployment whose approvals are relayed is on the adoption path (§7),
  not conformant.
- **§7 Adoption path, stage 2** gains a sentence: the harness's own
  permission prompt is a legitimate interim gate while standing up the
  trusted path, and a deployment in that state is working toward
  conformance, not in it.
- **§8 (What this method does not claim)** adds the trust-root honesty
  line: the boundary does not protect itself from an attacker who can
  rewrite the boundary; code integrity is defended by the engineering
  layer around it (review, protection, CI), not by the running gate.
- Changelog entry describing all three.

## 11. Delivery

1. **PR 1 — `fix/approval-identity`** (Closes #9): this design doc,
   mode A, provenance enforcement, `resolve_approval` demotion,
   enrollment CLI, tests, `hardrails-spec.md` v2.0.0 bump,
   version bump in `pyproject.toml` + `netagent/__init__.py`, and a
   `.gitignore` entry for `approval-secret.json` (runtime credential
   material, same class as `audit-log.jsonl` and `approvals/`).
2. **PR 2 — `feat/tailscale-approval-identity`**: mode B per §6, its
   tests, README section.
3. **Issue — WebAuthn approval surface (mode C)**: future work; requires
   solving TLS provisioning for LAN secure contexts; the surface,
   provenance model, and boundary check from PR 1 are unchanged by it.

## 12. Alternatives considered

Rejected with reasons in §3.4 (localhost+token, TOTP, separate OS user).
Also considered: **approval file signed on a second machine and copied
over** (clunky UX, easy to misuse, no liveness — the page is strictly
better) and **doing nothing beyond the harness prompt** (fails the
conformance acid test; the point of the method is that the inner gate is
ours).
