# netagent: running the Hardrails reference agent

A bounded network agent you can run in your own lab. It inspects real devices,
runs a security-posture audit, and proposes fixes -- but it cannot change a
device without a human approving one change, on one device, first.

This is the reference implementation of **Hardrails**: *deterministic
boundaries around a non-deterministic agent.* Guardrails ask. Hardrails
enforce. Read the method itself in [`hardrails-spec.md`](../hardrails-spec.md).

> Built for EP010 of [G Talks Tech](https://gtalkstech.com). Home-lab tool, not
> a production platform -- see the honesty note at the bottom.

## The idea in one paragraph

An agent is a **model** plus a **harness**. The model is non-deterministic: it
will occasionally reason its way into a bad tool call. So we don't trust the
model to police itself. Every tool call routes through a deterministic gate --
**the boundary** -- that lives in this MCP server, not in the AI host. Read tools
(show, ping, audit) run freely. Any tool that could change a device is **blocked**
unless it carries a human-approved, single-device approval. Because the boundary
is server-side, it holds no matter which harness drives the agent. Claude Code's
own approval prompt is a nice *second* gate (defense in depth), not the boundary
itself.

## What's inside

| Module | Role |
| --- | --- |
| `netagent/models.py` | Typed schema. The types make "silently apply a change" unrepresentable. |
| `netagent/devices.py` | Read-only Netmiko wrapper. Structurally refuses config/write commands. |
| `netagent/boundary.py` | **The boundary.** Allow/block decision + append-only audit log. |
| `netagent/audit.py` | Posture sweep. Version->CVE lookup via a **pluggable** CVE source. |
| `netagent/cve_source.py` | The CVE backends: live Cisco PSIRT openVuln API, pinned-cache fallback, and the chained default that records which one answered. |
| `netagent/data/` | Home of `psirt_cache.json` -- a frozen, provenance-stamped copy of a real API response. Never hand-edited. |
| `scripts/generate_psirt_cache.py` | Freezes a live PSIRT API response into the cache file. |
| `netagent/remediation.py` | Builds dry-run proposals; one gated path that actually applies a change. |
| `netagent/approval.py` | Human-in-the-loop approve/reject bookkeeping. |
| `netagent/server.py` | FastMCP (stdio) server. Every tool routes through the boundary. |
| `netagent/inventory.yaml` | The 3 lab devices. **No passwords.** |

## Boundary principles (enforced in code, not just documented)

- **Read-only by default.** The read path has no config-mode method at all.
- **Dry-run before any change.** A remediation is a `RemediationProposal` (CLI +
  diff), never "run this."
- **Human-in-the-loop.** Applying a proposal requires an `ApprovalRequest` that a
  named human approved.
- **One device per approval.** A change is never bundled across devices.
- **Append-only audit log.** Every tool call -- allowed or blocked -- is recorded.
- **Schema validation.** Malformed arguments are blocked before a device is touched.
- **Least privilege.** Unknown tool or missing approval -> default deny.

## Setup

```bash
# from the repo root, in a Windows python.exe venv
python -m venv .venv
.venv\Scripts\activate
pip install -e .[lab]
```

Plain `pip install hardrails` gives you the spec + data models only (the name
claim is deliberately light). The `[lab]` extra pulls the runnable-agent stack:
FastMCP, Netmiko, PyYAML, httpx, pynetbox.

### Credentials (never hardcoded)

The server reads the device password from the `NETAGENT_PASSWORD` environment
variable, or prompts for it (getpass) when run interactively. It is never stored
in a file, never passed as a CLI flag, and never written to the audit log.

```bash
# PowerShell
$env:NETAGENT_PASSWORD = "your-lab-password"
```

The live CVE lookup uses the Cisco PSIRT openVuln API, which needs its own
credentials: register an application at the
[Cisco API Console](https://apiconsole.cisco.com/) against the openVuln API,
then export the key and secret the same env-only way:

```bash
# PowerShell
$env:PSIRT_CLIENT_ID = "your-api-console-key"
$env:PSIRT_CLIENT_SECRET = "your-api-console-secret"
```

Same rule as the device password: never in a file, never a CLI flag, no config
key exists for them. Without these the agent falls back to the pinned CVE cache
(see below); if that does not exist either, the CVE lookup fails loudly rather
than pretending the fleet is clean.

The intent-drift check reads your NetBox (the source of truth the sweep diffs
live state against -- see `scripts/seed_netbox.py` for the lab intent):

```bash
# PowerShell
$env:NETBOX_URL   = "http://localhost:8000"   # optional, this is the default
$env:NETBOX_TOKEN = "nbt_..."                  # use a READ-ONLY token
```

Use a **read-only** NetBox token here: the drift check only reads intent, so
its credential should not be able to write (least privilege). NetBox 4.6+
issues v2 tokens as `nbt_<key>.<secret>` -- export the FULL value. Without a
token the sweep fails loudly (`IntentSourceUnavailable`) rather than reporting
a clean bill of intent it never checked -- same honesty rule as the CVE path.

Edit `netagent/inventory.yaml` to match your lab's hostnames and IPs. The
shipped inventory uses the real EP010 home-lab addresses (all RFC1918).

## Wire it into Claude Code

Copy the repo root's `.mcp.json.example` to `.mcp.json` in your project root
and point `command` at your venv's `python.exe`:

```json
{
  "mcpServers": {
    "netagent": {
      "command": "C:\\path\\to\\your\\venv\\Scripts\\python.exe",
      "args": ["-m", "netagent.server"]
    }
  }
}
```

There is deliberately no `env` block for the password. Set `NETAGENT_PASSWORD`
in the shell you launch Claude Code from, and it inherits. A password key in a
config file is one careless commit away from being public -- so this file
never has one.

Restart Claude Code. The `netagent` tools appear. Ask it to run a posture audit,
then to propose and (after you approve) apply a fix. Watch the apply tool get
**blocked** until an approval exists -- that's the boundary doing its job.

## Tools exposed

Read (run autonomously): `list_devices`, `run_show`, `audit_security_posture`,
`propose_remediation`, `request_approval`, `resolve_approval`, `get_audit_log`.

Gated (requires approval): `apply_remediation`.

## What's real vs. stubbed

- **CVE source (real)**: `netagent/cve_source.py`. The primary is the **live
  Cisco PSIRT openVuln API** (a real version-to-advisory lookup, never the
  model reciting CVEs from memory); the fallback is a **pinned cache of the
  API's actual response** -- a frozen copy of the authoritative answer with a
  provenance stamp, never a hand-typed list. The server defaults to the chain
  (live first, cache second) and reports which one answered. The shipped
  `netagent/data/psirt_cache.json` was frozen from a live API call.
- **NTP-auth check (real)**: deterministic config grep for `ntp server`/
  `ntp master` without the full authentication triple. MEDIUM, evidence =
  the offending config lines.
- **NetBox drift check (real)**: diffs NetBox intent against gathered state --
  a VLAN recorded `deprecated` that is still configured on a device fires LOW,
  with the live config lines as evidence. Requires `NETBOX_TOKEN` (above).
- **Cross-device segmentation (agent's job, by design)**: the CRITICAL
  correlation is produced by the AGENT joining configs across devices, not a
  coded grep -- which is why its `FindingSource` is `AGENT_REASONING`. The
  function in `audit.py` documents the seam.
- **Management-plane crypto check (stub)**: the lab this ships against is
  already hardened (no Telnet, no SSHv1, no type-7), so the check stays a
  documented TODO rather than code that never fires.

## Tests

```bash
pip install pytest
pytest tests/
```

Mock-fed, no live devices needed: sample configs in, `Finding` objects out,
plus the honesty-rule cases (a broken NetBox lookup must raise, never read as
"no drift").

## Honesty note

This is a **home-lab teaching tool**, not a production automation platform. It
runs against a handful of Cisco IOL nodes over SSH with in-memory session state.
It is deliberately small so the boundary is easy to read. Before anything like
this touches production you'd want persistent audit storage, real RBAC, secrets
management, change windows, and far more testing. The value here is the
*pattern* -- the boundary -- not the plumbing.
