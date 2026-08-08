# Roadmap

Ordered by adoption × trust leverage. This tracks the **reference
implementation** (`netagent/`); the method and spec grow on their own cadence
(see `hardrails-spec.md` §12). Nothing here changes a normative principle.

## Next up

1. **Zero-hardware demo mode (`NETAGENT_DEMO=1`).** A mock device backend (canned
   `show version` / `show running-config` output, reusing the sample configs the
   tests already use) so the full loop — `audit → propose → apply (blocked) →
   approve → apply (allowed)` — runs end to end with **no lab, no NetBox, no
   credentials**. This is the "aha" the whole project is built to show, currently
   reachable only with a CML/NetBox setup. Highest adoption leverage.
2. **WebAuthn approval identity — mode C ([#11](https://github.com/GTalksTech/hardrails/issues/11)).**
   Hardware-backed approver identity, building on the TLS / secure-context work
   already shipped. Deepens trust for people already committed.

## Trust & integrity

3. **Tamper-evident audit log.** Hash-chain the JSONL (`h_n = H(h_{n-1} ‖ line)`)
   so an after-the-fact edit is detectable. Today append-only is enforced by code
   convention plus the engineering layer, not the OS — stated honestly in
   [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
4. **Durable session state.** Persist proposals and approvals so an approval can
   be resolved after a restart. Today they are process-local and fail closed
   (a restart drops them); a durable design is its own doc when the lab outgrows
   one session.

## Smaller hardening

5. Defensive parsing of a malformed `psirt_cache.json`; markdown-fence-escape
   device text embedded in approval artifacts; per-tool argument redaction and
   size caps in audit records.

## Adoption & docs

6. A copy-pasteable "Stage 1 in 10 minutes" runbook riding on the demo mode;
   worked examples on harnesses beyond Claude Code; an architecture diagram of
   the agent → tool → boundary → allow/block → audit path.

---

Have a request or a fix? Open an issue. A PR that **strengthens** an invariant is
the best kind — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Shipped changes are in
[`CHANGELOG.md`](CHANGELOG.md).
