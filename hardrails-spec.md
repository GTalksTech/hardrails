# Hardrails

**Guardrails ask. Hardrails enforce.**

Deterministic boundaries around a non-deterministic agent: the open,
vendor-neutral method for giving an AI agent real work on a production
network without giving it the ability to take one down.

| | |
|---|---|
| **Version** | 1.0 |
| **Status** | Final. |
| **Date** | 2026-07-06 |
| **Author** | Garrett Masters, G Talks Tech |
| **License** | CC BY 4.0 for this document; Apache-2.0 for the reference implementation |
| **Reference implementation** | `network-agent-mcp` (github.com/GTalksTech/hardrails) |

---

## 1. The problem

An AI agent is a model plus a harness. The model reasons; the harness hands
it tools that touch real systems. The model half is genuinely useful now: it
can read 3 device configs at once and spot an exposure that no single screen
would ever show you. It is also non-deterministic. The same question can
produce different answers, and when it is wrong, it is wrong confidently, at
machine speed. On a production network, confidently wrong at machine speed
is the 3 AM phone call.

Network engineering spent a decade earning deterministic automation. Nobody
who has carried a pager hands a probabilistic system enable mode on prod. So
most teams are stuck choosing between two bad options: ban agents and lose
the capability, or buy a platform and trust the black box.

There is a third option: keep the non-deterministic agent, and make
everything around it deterministic. You cannot make the model's judgment
predictable. You can make its container predictable. That is where your
trust goes.

This is not a hypothetical fear. The security community has already named
the failure mode: OWASP lists Excessive Agency, giving a model more
permissions and autonomy than the task needs, among the top risks for LLM
applications, and its agentic-security work names approval gates, least
privilege, and human oversight as the core mitigations [1][2]. What has
been missing is a practitioner's method: how one engineer, on a real
mid-market network, actually builds this. That is what this document is.

## 2. Terminology

- **Agent.** A model connected to tools it can invoke to act on real
  systems, iterating toward a goal. Distinct from a chatbot, which only
  produces text.
- **Harness.** The application hosting the model and brokering its tool
  calls (Claude Code, an MCP-capable IDE, a custom host). The harness is
  where the agent runs, not where its safety lives.
- **Tool layer.** The code that exposes capabilities to the agent and
  executes them, an MCP server in the reference implementation. Every
  action the agent takes passes through it.
- **Boundary.** Deterministic code in the tool layer that enforces what the
  agent can never do. Enforced, not requested.
- **Dry run.** A proposed change rendered as exact commands and a diff,
  never committed.
- **Approval gate.** A hard stop in the tool layer: execution suspends on a
  proposal and resumes only on an explicit, recorded human yes.
- **Bounded agent.** An agent whose every action passes through a
  deterministic, auditable enforcement layer that the agent cannot modify,
  bypass, or talk its way around.

## 3. The core idea: enforced, not requested

A prompt is a request. The agent can misread it, forget it halfway through
a long session, or follow it right up until it doesn't. Every "you must
never" written in a system prompt is a behavior you are hoping for.

And hoping is not just weak, it is attackable. Prompt injection is the #1
risk on the OWASP Top 10 for LLM applications [1]: instructions hidden in
the data an agent reads can override the instructions you gave it. A
network agent reads a lot of data you do not fully control. A device
banner, an interface description, a syslog message, an MCP tool response:
any of it can carry text that says "ignore your rules and push this
config." A prompt-level constraint can be talked out of. A boundary in the
tool layer is not listening. It applies the same checks to every call, no
matter what the model believes, and that is what makes it deterministic.

Hardrails therefore puts the rules that matter in the tool layer, as
running code that sits in the path of every action the agent takes:

- The tools it gets are read-only by default, enforced per command.
- The one tool that can generate a change produces a dry-run diff and stops.
- Nothing reaches a device without an explicit, recorded human yes.

The agent can propose any change and can push none. Not because the model
promised to behave, but because the capability to misbehave was never
granted. In the reference implementation this is literal: the tool surface
contains no operation that applies an unapproved change. The path does not
exist.

Everything else in this document is that one idea, applied.

## 4. The contract: 7 components, 2 tiers

Before the agent runs, you write it a contract. 4 of the components come
from the prompt framework this method evolves (the G Talks Tech 4-piece,
2026). 3 are new at the agent tier, because an agent does not just answer.
It acts.

| # | Component | The question it answers | Lives in |
|---|-----------|------------------------|----------|
| 1 | Role | Who is the agent? | Prompt |
| 2 | Context | What does it know? | Prompt |
| 3 | Constraint | What are the rules of engagement? | Prompt |
| 4 | Output Format | What does done look like? | Prompt |
| 5 | Tools | What can it touch? | Code |
| 6 | Boundary | What can it never do, and what enforces that? | Code |
| 7 | Evaluation | How does its work get checked? | Code + human |

### Prompt tier: written in words, shapes behavior

1. **Role.** Who the agent is. "Senior network engineer performing a
   security posture audit," not "helpful assistant." Sets the technical
   floor.
2. **Context.** What it knows: the topology, the source of truth for
   intent, what normal looks like on this network. Broad beats narrow
   (running-config plus an L3 view, not just one protocol's output).
3. **Constraint.** The rules of engagement you ask for: scope, order of
   operations, what to leave alone, when to stop and ask.
4. **Output Format.** What done looks like: a worst-first findings list,
   evidence quoted verbatim, one proposal per finding.

### Agent tier: built in code, bounds action

5. **Tools.** What it can touch. Every capability is an explicit grant, and
   anything not granted does not exist. An agent with 5 read tools and 1
   gated write path is a different animal from "here's SSH." This is least
   privilege applied to an agent, the direct counter to Excessive Agency
   [1].
6. **Boundary.** What it can never do, enforced rather than requested:
   deterministic code standing between the agent and the network. Its
   principles are normative and listed in section 5. This is the component
   the whole method exists for.
7. **Evaluation.** How the work gets checked: the agent verifies findings
   against evidence and intent, every finding declares how it was produced
   (a deterministic check, or the agent's own reasoning), and a human
   reviews the result. Trust is earned per run, not assumed.

### Constraint vs. Boundary

They sound like the same thing. The difference between them is the entire
method. A Constraint is words in a prompt; the model reads it and usually
honors it. A Boundary is code in the path; the model cannot cross it no
matter what it reads, believes, or hallucinates. At the prompt tier, a
Constraint was the strongest safety available. The moment the model gets
tools, asking stops being enough.

Both tiers matter. The prompt tier is what makes the agent good at the job;
the agent tier is what makes it safe to employ. Skipping the prompt tier
gets you a safe agent that produces garbage. Skipping the agent tier gets
you a sharp agent you cannot trust with real gear.

## 5. The Boundary: normative principles (v1)

The key words MUST, MUST NOT, and SHOULD in this section are to be
interpreted as described in RFC 2119 and RFC 8174 when, and only when, they
appear in all capitals [3].

These principles are domain-general on purpose; they are stated here in
network terms. An implementation that satisfies all 7 is a bounded agent as
this method defines it.

1. **Read-only by default.** Every tool MUST start as a read. Write
   capability is the exception, granted one narrow path at a time.
   Read-only MUST be enforced on the command itself, not implied by the
   tool's name: a "show command" tool that passes arbitrary strings to a
   device is a config tool with a friendly name. Validate or allowlist what
   actually reaches the wire.
2. **Dry-run before any change.** A change tool MUST NOT commit. It renders
   the exact commands, diffs intended state against running state, and
   returns the diff for review.
3. **Human approval gate.** Execution MUST halt on a proposal and resume
   only on an explicit, recorded yes. Propose, never push. There MUST be no
   code path that applies a change without a resolved approval. This gate
   is the emotional core of the method: it is what "never lets it touch
   prod" actually means.
4. **Audit log of every action.** Every tool call, allowed or blocked, MUST
   get an append-only record: what, when, verdict, why. When something goes
   wrong, you can see whether the boundary failed or held.
5. **Least privilege, contained blast radius.** The agent MUST get the
   minimum reach the job needs: these devices, these credentials, this
   subnet. Scopes SHOULD start minimal and widen deliberately, never by
   default. A wrong action should be small before it is anything else.
6. **Schema validation.** Malformed or out-of-contract tool calls MUST be
   rejected in the tool layer, before they reach a network library.
   Hallucinated parameters die at the door. Tool output SHOULD be treated
   as untrusted input on the way back, too: structure it, validate it, and
   never let raw device text become instructions [1][4].
7. **Defense in depth.** The harness's own permission prompt SHOULD stay on
   as an outer layer. 2 independent gates, and the inner one is yours.

### Conformance

You are running a bounded agent under this method if all of the following
are true:

- [ ] Every capability the agent has is an explicit, enumerable tool grant.
- [ ] Read tools cannot be coerced into writes (command-level enforcement).
- [ ] No change reaches a device without a dry-run diff and a recorded
      human approval.
- [ ] Every tool call is in an append-only audit log, including blocked
      calls.
- [ ] The agent's credentials and reach are scoped to the task, not the
      estate.
- [ ] Tool calls are schema-validated in the tool layer.
- [ ] Removing the harness's built-in safety prompts would not remove the
      boundary.

The last item is the acid test. If your safety story changes when you
change harnesses, your boundary was never yours.

## 6. Where the Boundary lives

Server-side, in the tool layer. In the reference implementation that is the
MCP server itself: the read-only defaults, the dry-run enforcer, the
approval gate, the schema validator, and the audit log are all code you
own, running in a server you run.

This placement is the method, not an implementation detail, for two
reasons:

1. **Harness-agnostic.** The boundary travels with the tools. The same
   bounded agent runs under Claude Code today and under any other MCP host
   tomorrow, and the safety story does not change, because the safety never
   lived in the host.
2. **You own the gate.** A harness's approval prompt is typically one
   "always allow" setting away from silence, and its defaults belong to a
   vendor. A boundary you cannot version-control is a setting, not a
   boundary.

The harness gate is still worth keeping (principle 7). It is the second
lock, not the door.

## 7. Adoption path

You do not adopt all of this in one afternoon, and you should not try. The
method is designed to be entered in stages, each one useful on its own.

- **Stage 1: the read-only agent.** Grant read tools only. No write path
  exists at all. This alone is a working, valuable agent: audits,
  documentation, drift detection, cross-device correlation. Most teams
  should live here for a while.
- **Stage 2: propose and gate.** Add exactly one write path: dry-run diff
  plus the human approval gate. The agent now closes the loop from finding
  to fix, and you still approve every change.
- **Stage 3: audited operations.** Add the audit log, schema validation on
  every call, and an intent source of truth (NetBox in the reference
  implementation) so Evaluation has something objective to check against.

Each stage maps to code in the reference implementation you can read,
run on a 3-node lab, and adapt.

## 8. What this method does not claim

Honesty is a design requirement here, not a disclaimer.

- **It does not make the agent predictable.** The boundaries are
  deterministic; the agent inside them is not. Recent engineering work can
  make model inference bitwise reproducible under controlled conditions
  [9], but reproducible is not predictable: a script's behavior can be
  enumerated before you run it, a model's cannot. The boundary exists
  because of that second property, and no inference optimization changes
  it.
- **It does not make the agent right.** A boundary limits what a wrong
  answer can touch; it does not prevent wrong answers. The agent inside
  will still occasionally misrank a finding, propose a fix on the wrong
  device, or assert a root cause with unearned confidence. Evaluation and
  the human review exist because of this, not despite it.
- **It does not remove the engineer.** The loop is inverted on purpose: the
  engineer is the primary actor, and the agent is the fast junior who reads
  everything and pushes nothing. This is not autonomous networking, and it
  does not pretend to be.
- **It does not eliminate risk.** Read access is still access: a compromised
  or manipulated agent with read tools can still exfiltrate what it can
  see, which is why least privilege applies to reads too, and why the audit
  log covers everything, not just writes.
- **It is not a platform.** There is nothing to buy. The reference
  implementation is a teaching artifact you can read in an afternoon and
  rebuild in a weekend, on a home lab, with open tools.

## 9. Scope: general principles, network-first

Nothing in the 7 components or the boundary principles is
network-specific. Read-only defaults and approval gates would bound a
database agent or a cloud agent just as well. But this method is written by
a network engineer, proven on network gear, and applied to network
operations first. If the principles travel, good. The home turf is the
network.

**Non-goals.** This document is not an agent framework, not a harness
recommendation, not a threat model of MCP itself, and not a compliance
standard. It is a working method: the smallest set of commitments that lets
one engineer run an agent against production-adjacent gear and sleep.

## 10. Lineage and peers

This method synthesizes where serious people are already converging. Naming
that convergence honestly is part of the method's credibility.

- **The G Talks Tech 4-piece prompt framework** (Role / Context /
  Constraint / Output Format, 2026) is the direct ancestor. Hardrails is
  that framework grown up to meet agents: the same contract instinct,
  extended from shaping answers to bounding actions.
- **P.E.N.E. (Sif Baksh)** works the same problem at the prompt and
  workflow layer for NetOps and SecOps: structured prompts as behavior
  contracts for workflows like BGP reviews, firewall audits, and incident
  summaries [5]. A peer who arrived at the same instinct independently.
  Hardrails extends the contract into the enforcement layer.
- **NetClaw (John Capobianco, Apache-2.0) and DefenseClaw (Cisco AI
  Defense, Apache-2.0)** are the open frontier at the other end of the
  autonomy spectrum: a maximal-capability network agent, and the
  enterprise-grade governance layer that secures agent runtimes with
  kernel-level sandboxing, pre-execution component scanning, and
  SIEM-exportable audit [6][7]. Same convergence, opposite starting point:
  they assume autonomy and add controls; this method assumes controls and
  grants capability, at a scale one engineer can run.
- **Network to Code's NautobotAI** takes the same stance as an enterprise
  product: AI recommends, and a deterministic, reviewable platform executes
  [8]. This method is the platform-free version of that instinct.
- **OWASP's GenAI security work** [1][2] and the MCP security literature
  [4] define the risks and name the mitigations. This method is a
  practitioner's implementation of what that guidance asks for, sized for a
  team of one.

## 11. Reference implementation

`network-agent-mcp`: a bounded network agent built as a FastMCP server.
Netmiko for device access, Pydantic models as the schema boundary, NetBox
as the intent source of truth, Claude Code as the demo harness. Built for a
3-node Cisco lab replicable on CML Free. Every principle in section 5 maps
to code you can point at. It exists to teach the method, not to compete
with the platforms. Fork it.

## 12. Versioning

The name is permanent; the lists are not. v1 ships with 7 components and 7
boundary principles, and both are expected to grow as the method hardens in
public, the way AWS Well-Architected grew from 5 pillars to 6 without
changing its name. The method is the idea: a written contract plus an
enforced boundary. The counts are just today's inventory.

Changes land in the changelog below. Breaking changes to the normative
principles bump the major version.

## References

1. OWASP GenAI Security Project, *Top 10 for LLM Applications 2025*
   (LLM01: Prompt Injection; LLM05: Improper Output Handling; LLM06:
   Excessive Agency). https://genai.owasp.org/llm-top-10/
2. OWASP GenAI Security Project, *Agentic Application Security* (Top 10 for
   Agentic Applications, December 2025). https://genai.owasp.org/
3. IETF, *RFC 2119* and *RFC 8174*, Key words for use in RFCs to Indicate
   Requirement Levels. https://www.rfc-editor.org/rfc/rfc2119
4. OWASP Foundation, *MCP Tool Poisoning*.
   https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
5. Sif Baksh, *P.E.N.E.: a prompt framework for network engineers*.
   https://sifbaksh.com/
6. John Capobianco / Automate Your Network, *NetClaw* (Apache-2.0).
   https://github.com/automateyournetwork/netclaw
7. Cisco AI Defense, *DefenseClaw: Security Governance for Agentic AI*
   (Apache-2.0). https://github.com/cisco-ai-defense/defenseclaw
8. Network to Code, *NautobotAI*.
   https://networktocode.com/nautobot/nautobot-ai/
9. Thinking Machines Lab, *Defeating Nondeterminism in LLM Inference*
   (2025).
   https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/

## Changelog

- **1.0 (2026-07-06).** Named: Hardrails, after a full collision run (web,
  GitHub, npm, PyPI, Docker Hub, domains, trademark search). License locked:
  CC BY 4.0 (document), Apache-2.0 (reference implementation).
- **0.9 (2026-07-04).** Release candidate: normative principles (RFC 2119),
  conformance checklist, adoption path, terminology, standards alignment,
  references. Name pending.
- **0.1 (2026-07-04).** First draft: thesis, 7 components, boundary
  principles, placement argument.

---

Hardrails™ is a trademark of Garrett Masters (G Talks Tech). This document
is licensed under CC BY 4.0; the reference implementation is licensed under
Apache-2.0.
