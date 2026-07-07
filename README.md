# Hardrails

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

- **Specification: v1.0.** Stable, versioned, in this repo.
- **Reference implementation (`netagent/`): in active development.** A
  bounded network agent built as an MCP server (FastMCP, Netmiko, Pydantic,
  NetBox as the intent source of truth), for a 3-node Cisco lab replicable
  on CML Free. The data models that make "silently apply a change"
  unrepresentable are already here; the server, the boundary code, and the
  lab topology ship with the full video walkthrough.

The complete build walkthrough is coming on
[G Talks Tech](https://www.youtube.com/@GTalksTechOfficial). Subscribe there
or join the mailing list at [join.gtalkstech.com](https://join.gtalkstech.com)
if you want it when it lands.

## Licensing

- The specification and all written material: [CC BY 4.0](LICENSE-docs).
  Share it, teach it, adapt it, with attribution.
- All source code: [Apache-2.0](LICENSE).

Hardrails™ is a trademark of Garrett Masters (G Talks Tech). See
[NOTICE](NOTICE).
