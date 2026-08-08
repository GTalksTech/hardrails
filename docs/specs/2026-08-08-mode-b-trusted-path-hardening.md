# Mode B (tailnet identity): the agent's host can't self-approve

**Status:** implemented in the same PR (fix for issue #22)
**Date:** 2026-08-08

## Problem

Identity mode B (`NETAGENT_APPROVAL_IDENTITY=tailscale`) is weaker than the
default mode A against the same-user threat model. Mode A backstops a missed
local address with the enrolled secret; **mode B has no secret** —
`TailscaleIdentity.verify` trusts `whois(source_ip)` alone.

- **B2 (self-approval).** The only backstop is the local-source check, and
  `local_addresses()` is best-effort (`getaddrinfo(hostname)` + a UDP-connect
  trick) that frequently misses the machine's own Tailscale CGNAT (100.64/10)
  address. So the co-located agent POSTs to the surface on the machine's own
  100.x address; the source isn't in the refusal set → check 1 passes;
  `tailscale whois <own-100.x>` resolves the machine's OWN node → its
  `LoginName` is the operator's login → which is exactly what a real allowlist
  contains (every device on an account shares one tailnet login) → attested →
  `channel = TRUSTED_PATH`. No human.
- **B3 (binary planting).** `tailscale_whois` runs `subprocess.run(["tailscale",
  …])` by bare name at request time; on Windows the executable search includes
  the app dir / CWD ahead of PATH, and the attacker can write there, so a
  planted `tailscale` forges the whois oracle.
- **B4 (no normalization).** The local-source check is exact-string membership,
  so IPv4-mapped IPv6 / zone-scoped / format-skewed forms of a local address
  slip it.
- **B5 (self-including allowlist).** A login-based allowlist entry (the natural
  choice) vouches for every device on the account, including the agent's host.

## Fix

- **Self-node refusal (closes B2 and B5) — at the attestation layer, not the
  enumeration layer.** Rather than trying to enumerate every local address
  perfectly (a losing game across platforms), the resolver refuses any peer
  that `whois`-resolves to **this machine's own tailnet node**. The approving
  device must be a *different* node than the one the agent runs on, and that
  holds no matter which addresses `local_addresses()` did or didn't find. The
  server captures its own node's short name once at startup
  (`tailscale status --json` → `Self.ComputedName`) and hands it to
  `TailscaleIdentity`; `verify()` refuses a peer whose name matches.
- **Absolute binary, resolved at startup (closes B3).** `_build_identity`
  resolves `tailscale` to an absolute path with `shutil.which` in the
  operator's environment — before the long-running agent session where planting
  could occur — and binds both `whois` and the self-name lookup to that path.
- **IP normalization (closes B4).** The local-source check compares
  `ipaddress.ip_address()` values, collapsing IPv4-mapped IPv6 and stripping
  zone ids, so divergent spellings of a local address are still caught.

Fail-deny is preserved throughout: if `tailscale status` can't identify the
local node, the server refuses to start rather than run without the self-node
guard.

## Non-goals

- **General cross-platform interface enumeration.** The self-node refusal makes
  a perfect local-address set unnecessary for correctness — enumeration remains
  best-effort defense-in-depth.
- **Mode A.** Untouched. Its secret backstop already resists the same-user
  attacker; these changes are mode-B only (plus the shared IP-normalization,
  which only tightens the local-source refusal).

## Tests

`tests/test_tailscale_identity.py` gains:

- A peer that `whois`-resolves to the local node is refused even when its login
  is on the allowlist (the self-approval exploit, closed at attestation).
- An IPv4-mapped IPv6 form of a local address is refused by the local-source
  check.
- `tailscale_whois` / `tailscale_self_name` invoke the given absolute binary and
  parse the expected fields.
- The server wiring builds a `TailscaleIdentity` carrying the resolved
  self-name (existing wiring test updated).
