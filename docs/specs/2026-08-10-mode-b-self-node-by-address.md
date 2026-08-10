# Mode-B self-node refusal: by address, not only by name

- Status: accepted
- Date: 2026-08-10
- Scope: `netagent/trusted_path.py` (`TailscaleIdentity`), `netagent/server.py`
  (`_build_identity`)
- Follows: `2026-08-08-mode-b-trusted-path-hardening.md` (#23); closes a residual

## Problem

#23 added the self-node refusal so the agent's own host cannot approve in mode B,
even though every device on the account shares one tailnet login. But it fires on
a **device-name match only**:

```python
if self.self_name and device and device.lower() == self.self_name.lower():
    raise TrustedPathError(...)
```

Both operands come from `whois`/`status` `ComputedName`. When `ComputedName` is
empty — possible for some tagged nodes — `device` (or the captured `self_name`)
is falsy, the branch is skipped, and an allowlisted login alone attests the peer.
If the agent's own host ever presents with an empty `ComputedName`, the
self-exclusion silently misses it, and the co-located agent can self-approve from
its own tailnet address. The local-source check (check 1) does not save this
case: #23 itself notes `local_addresses()` enumeration "frequently misses the
machine's own Tailscale CGNAT address."

Confirmed offline:

```
TailscaleIdentity(approvers={"gmasters428@github"}, self_name="")
whois -> {"Node":{"ComputedName":""}, "UserProfile":{"LoginName":"gmasters428@github"}}
verify("100.97.1.36", ...) -> ALLOWED   # self-guard fully disabled
```

## Decision

Add a **name-independent, address-based** self-node refusal, and stop depending
on a non-empty name for the self-exclusion:

- At startup the server captures the local node's tailnet addresses from
  `tailscale status --json` → `Self.TailscaleIPs` (authoritative — unlike the
  best-effort `local_addresses()` enumeration) and hands them to
  `TailscaleIdentity.self_addresses`.
- `verify()` refuses any peer whose **normalized source address** is one of those
  self-addresses, regardless of the allowlist and regardless of the device name.
  The existing name match stays as a second, independent signal.
- Fail-deny: if `tailscale status` yields **neither** a self name **nor** any
  self address, the server refuses to start — it cannot exclude its own node, so
  it will not run mode B blind.

Address comparison reuses `_normalize_addr`, so an IPv4-mapped or zone-scoped form
of a self address is caught too.

## Why address, not StableID

Either would be name-independent. `Self.TailscaleIPs` is chosen because it plugs
directly into the same normalized-address comparison the local-source check
already uses, needs nothing from the per-request `whois` payload shape, and
refuses the agent's host at the address layer even if a future `whois` response
omits the node identity entirely.

## Consequences

- The agent's own host is excluded whether or not `ComputedName` is populated —
  the dangerous case (agent self-approving from its own box) is closed by address.
- A genuinely different device on the same login, even one with an empty
  `ComputedName`, still approves — an empty name is not by itself
  disqualifying, only *being this node* is.
- No change to mode A, the local-source check, provenance, or fail-deny for an
  unreachable tailscaled.

## Tests

`tests/test_tailscale_identity.py`: a peer arriving from the agent host's own
tailnet address is refused even when `ComputedName` is empty and the login is
allowlisted; the IPv4-mapped form of a self address is refused; a different node
with an empty `ComputedName` still approves; `_build_identity` captures
`self_addresses` and fails deny when both name and addresses are empty;
`tailscale_self_addresses` parses `Self.TailscaleIPs`.
