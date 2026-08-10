# Changelog

Notable changes to the `netagent` reference implementation. The Hardrails
**specification** keeps its own changelog inside
[`hardrails-spec.md`](hardrails-spec.md); this file tracks the code.

Format follows [Keep a Changelog](https://keepachangelog.com/). The package uses
`0.x` dev versions until the first tagged release. **Note:** only `0.1.0.dev0`
has been published to PyPI so far; the `0.2`/`0.3` versions below are in-repo
version bumps. Until a release catches PyPI up, clone the repo to run the
current build (see [`netagent/README.md`](netagent/README.md)).

## [Unreleased]

Security hardening of the boundary from a deep review pass (2026-08-08). No
normative spec change — these bring the implementation up to what the spec
already requires.

### Fixed
- **Read path is an allowlist, not a denylist.** A newline, `;`, output
  redirect, or abbreviated verb could smuggle a config command through
  `run_show` (a read tool) to the device with no approval. The command guard now
  positively allows only `show`/`ping`/`traceroute`, rejects multi-command
  strings, and refuses output-redirect pipes, and is covered by tests. (#16, #17)
- **Read-path pipe filters are an allowlist too.** #17's pipe check was still a
  full-word blocklist of `redirect`/`tee`/`append`, so IOS abbreviations
  (`| red`, `| te`, `| a`) and a redirect chained behind a legal filter slipped
  through — reopening the unapproved-write / running-config-exfiltration vector on
  the read path. The pipe check is now a positive allowlist: after a `|` only
  `include`/`exclude`/`begin`/`section`/`count` (full word) are permitted, every
  segment checked. (#35)
- **Approvals are single-use at apply.** A resolved approval is consumed
  (`APPLIED`) after a successful push; it can no longer be replayed to re-apply
  the same change. (#18, #19)
- **Audit-log integrity.** Fixed a concurrency race where `guard()` could
  attribute a result to the wrong record; a mutation whose durable receipt
  cannot be written now fails **closed**; and the exception path no longer leaks
  device output into the log (shape-only, like the success path). (#20, #21)
- **Trusted-path mode B (Tailscale).** The agent's own host can no longer
  self-approve (self-node refusal at the attestation layer); the `tailscale`
  binary is resolved to an absolute path at startup; the local-source check
  normalizes IPs. Mode A unaffected. (#22, #23)
- **`hardrails-conformance` degrades cleanly without the `[lab]` extra.** The
  console script installs on a base `pip install hardrails`, but its checks drive
  the runnable agent; it now prints an "install `hardrails[lab]`" hint and exits
  non-zero instead of dying with a bare `ModuleNotFoundError`. (#33)

### Added
- `hardrails-conformance`: a runnable self-test that executes the spec's 8-item
  conformance checklist against the real boundary and prints PASS/FAIL (a
  "verify, don't trust" artifact and a regression guard). (#26)
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md): the trusted computing base and
  in/out-of-scope attackers, as the spec's honesty section obligates.
- [`ROADMAP.md`](ROADMAP.md), a principle→code→test map in `netagent/README.md`,
  and README badges + a peer-comparison table.
- This changelog.

## [0.3.0.dev0] — 2026-08-08

### Added
- Trusted-path identity **mode B**: Tailscale `whois` attests the approver;
  `NETAGENT_APPROVAL_BIND` pins the surface bind address. (#12)
- TLS on the approval surface: cert/key env vars, both-or-neither, TLS 1.2
  floor (a first slice toward the WebAuthn secure-context requirement, #11). (#15)

### Fixed
- Restart-safe approval ids (random, not a resettable counter) plus a
  foreign-receipt guard, so a durable receipt can never be clobbered. (#13)
- `propose_remediation` teaches the `request_approval` step in its success
  payload, so the approval id and artifact mint in the same turn as the diff. (#14)

## [0.2.0.dev0] — 2026-08-08

### Changed
- **Spec v2.0.0 — the trusted path is normative.** The approval decision must
  enter through a channel the agent cannot write. The reference implementation
  adds a non-loopback approval surface with local-source rejection and a
  scrypt-hashed enrolled secret (identity mode A); `resolve_approval` can no
  longer approve in trusted mode (reject stays, fail-safe). (#10)

## [0.1.0.dev0] — 2026-07-11

### Added
- Initial reference implementation: bounded FastMCP server, read-only device
  access that structurally refuses writes, dry-run remediation behind a human
  approval gate, an append-only audit log, and the security-posture sweep — a
  live Cisco PSIRT CVE lookup with a provenance-stamped offline cache, NTP
  hardening, and NetBox intent-drift checks.
- Result-summary audit records appended after execution, and CVE summary-count
  arithmetic stated by the finding itself. (#7, #8)
