# Hardrails

[![Tests](https://github.com/GTalksTech/hardrails/actions/workflows/test.yml/badge.svg)](https://github.com/GTalksTech/hardrails/actions/workflows/test.yml)
[![Spec v2.0.0](https://img.shields.io/badge/spec-v2.0.0-2ea44f)](hardrails-spec.md)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![Code: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue)](LICENSE)

**Guardrails ask. Hardrails enforce.**

Hardrails is an open, vendor-neutral method for giving an AI agent real work
on a production network without giving it the ability to take one down:
deterministic boundaries around a non-deterministic agent.

**[Read the specification](hardrails-spec.md)**

## The idea in 60 seconds

An AI agent is a model plus a harness. The model half is genuinely useful
now. It is also non-deterministic, and when it is wrong, it is wrong
confidently, at machine speed.

A prompt is a request. The agent can misread it, forget it, or have it
overridden by injected text in the data it reads. Every "you must never" in
a system prompt is a behavior you are hoping for.

Hardrails puts the rules that matter in the tool layer instead, as running
code that sits in the path of every action the agent takes:

- Tools are read-only by default, enforced per command.
- The one tool that can generate a change produces a dry-run diff and stops.
- Nothing reaches a device without an explicit, recorded human yes.

The agent can propose any change and can push none. Not because the model
promised to behave, but because the capability to misbehave was never
granted.

## The contract: 7 components, 2 tiers

| # | Component | The question it answers | Lives in |
|---|-----------|------------------------|----------|
| 1 | Role | Who is the agent? | Prompt |
| 2 | Context | What does it know? | Prompt |
| 3 | Constraint | What are the rules of engagement? | Prompt |
| 4 | Output Format | What does done look like? | Prompt |
| 5 | Tools | What can it touch? | Code |
| 6 | Boundary | What can it never do, and what enforces that? | Code |
| 7 | Evaluation | How does its work get checked? | Code + human |

The full spec covers the 7 normative boundary principles, the conformance
checklist, and the adoption path: [hardrails-spec.md](hardrails-spec.md).

## Status

- **Specification: v2.0.** Stable, versioned, in this repo. v2 makes the
  trusted path normative: the approval decision must enter through a
  channel the agent cannot write.
- **Reference implementation (`netagent/`): shipped, in this repo.** A
  bounded network agent built as an MCP server (FastMCP, Netmiko, Pydantic,
  NetBox as the intent source of truth), for a 3-node Cisco lab replicable
  on CML Free. Read-only device access that structurally refuses writes, a
  server-side boundary with an append-only audit log, dry-run remediation
  behind a human approval gate, and a posture sweep whose deterministic
  checks (live Cisco PSIRT CVE lookup with a provenance-stamped offline
  cache, NTP hardening, NetBox intent drift) are unit-tested and validated
  against a live lab. **Running it: see [`netagent/README.md`](netagent/README.md).**

**Verify it yourself.** `hardrails-conformance` runs the spec's 8-item
conformance checklist against the real boundary — PASS/FAIL per item, offline,
exit-non-zero on any failure. Project docs:
[threat model](docs/THREAT-MODEL.md) · [changelog](CHANGELOG.md) ·
[roadmap](ROADMAP.md).

**[Watch the full build walkthrough](https://youtu.be/dbkwtuXuPPQ)** on
[G Talks Tech](https://www.youtube.com/@GTalksTechOfficial). Subscribe there
or join the mailing list at [join.gtalkstech.com](https://join.gtalkstech.com)
for what lands next.

## How this compares

Hardrails is one point on a spectrum of serious work converging on the same
problem. The full, fair treatment is in
[the spec's §10](hardrails-spec.md); the short version:

| | Starting point | Form |
| --- | --- | --- |
| **Hardrails** | Assume controls, grant capability deliberately | An open method + a weekend-rebuildable reference, sized for one engineer |
| [NetClaw](https://github.com/automateyournetwork/netclaw) | Assume autonomy, add controls | A maximal-capability network agent |
| [DefenseClaw](https://github.com/cisco-ai-defense/defenseclaw) | Assume autonomy, govern the runtime | Enterprise agent-runtime governance |
| [NautobotAI](https://networktocode.com/nautobot/nautobot-ai/) | AI recommends, a platform executes | An enterprise product |
| [P.E.N.E.](https://sifbaksh.com/) | Behavior contracts at the prompt layer | A peer prompt/workflow method |

## Licensing

- The specification and all written material: [CC BY 4.0](LICENSE-docs).
  Share it, teach it, adapt it, with attribution.
- All source code: [Apache-2.0](LICENSE).

Hardrails™ is a trademark of Garrett Masters (G Talks Tech). See
[NOTICE](NOTICE).
