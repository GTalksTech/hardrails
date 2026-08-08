# TLS on the approval surface

**Status:** implemented in the same PR (first slice toward issue #11)
**Date:** 2026-08-08

## Problem

The trusted-path design records two limitations that share one cause:

1. Mode A's threat model (2026-08-05 doc, §3.3) names the **passive LAN
   attacker** as out of scope: the approval secret crosses the wire as
   plain HTTP on the lab network. Mode B closes this only for tailnets.
2. Issue #11 (WebAuthn, identity mode C) is blocked on **secure
   context**: browsers expose `navigator.credentials` only over HTTPS
   with a certificate the phone actually trusts, and WebAuthn's RP ID
   must be a DNS name — a raw LAN IP can never qualify.

Both dissolve if the surface can serve HTTPS under a real hostname.

## Fix

The surface accepts an operator-supplied certificate:

- `NETAGENT_APPROVAL_TLS_CERT` / `NETAGENT_APPROVAL_TLS_KEY` — paths to
  a PEM certificate chain and private key. **Both or neither**: one
  without the other is a startup refusal, and an unloadable pair
  (missing file, key mismatch) is a startup refusal. Fail-deny, same as
  every other misconfiguration on this surface — there is no silent
  fall back to plain HTTP.
- `NETAGENT_APPROVAL_HOSTNAME` — optional DNS name used in generated
  `approval_url`s so the link the human taps matches the certificate
  (e.g. `https://gm-desktop.tailXXXX.ts.net:8484/a/appr-...`). Display
  only; binding is still by address.

Where a home lab gets a real certificate without running a CA:
**`tailscale cert <machine>.<tailnet>.ts.net`** issues a genuine
Let's Encrypt certificate for the machine's MagicDNS name, renewable by
re-running the command, and the name resolves on every tailnet device.
That recipe is documented in the README as the recommended path; any
other real-domain certificate works identically. Self-signed remains
possible for people who manage their own trust stores, but is not the
documented path — phone browsers make it miserable, and WebAuthn later
will not accept it anyway.

The private key lives on the agent's machine and is therefore readable
by the same-user attacker of the threat model. That is stated honestly:
TLS here defends the *wire* (the LAN sniffing gap) and satisfies the
browser's secure-context requirement; it is not, and does not need to
be, a secret the agent can't read. The gate remains the two checks —
local-source rejection and the identity seam — which never depended on
transport secrecy.

## What this unblocks (and what it doesn't)

With HTTPS + a DNS name, mode C's remaining work is the WebAuthn
protocol itself: registration/assertion endpoints (the `fido2` library
as an optional dependency), passkey enrollment bootstrap, and a
`WebAuthnIdentity` plugged into the existing identity seam. This PR
deliberately ships none of that — it removes the infrastructure
blocker, which is separable, useful on its own (encrypted mode A), and
testable offline. Issue #11 stays open.

## Tests

- `tls_from_env`: both unset → None; exactly one set → refusal; both
  set but unloadable → refusal; valid pair → context.
- URL shape: TLS surface with a display hostname yields
  `https://<hostname>:<port>/a/<id>`.
- Full wire test over HTTPS with an ephemeral self-signed certificate
  generated at test time (via `cryptography`, already present through
  the lab extra's Netmiko → Paramiko dependency): approve succeeds over
  TLS with the foreign-source seam, refusals still refuse.
- No plain-HTTP regression: the existing suite runs unchanged without
  the TLS envs.
