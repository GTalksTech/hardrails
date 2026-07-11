# ============================================================
# Module:       boundary.py
# Purpose:      The deterministic boundary. Every tool call the agent makes is
#               routed through this layer, which decides ALLOW vs BLOCK and
#               writes an append-only audit record -- server-side, so the
#               framework is harness-agnostic.
# Dependencies: pydantic>=2
# Author:       G Talks Tech
# Episode:      EP010-L-ai-network-agents
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Part of the
#               Hardrails framework reference implementation.
# ============================================================
"""The boundary: deterministic rules around a non-deterministic agent.

This is the heart of Hardrails. The thesis of the whole episode lives in
this file, so it is written to be read aloud on camera.

    An agent is a model plus a harness. The MODEL is non-deterministic -- it
    will occasionally reason its way to a bad tool call. So we do not trust the
    model to police itself. Instead, every tool call passes through a
    deterministic gate that we control, in the SERVER, before anything reaches a
    device. Read tools run freely. Any tool that could change a device is BLOCKED
    unless it carries a human-approved, single-device ApprovalRequest.

Why server-side? Because then the boundary does not depend on which harness is
driving. Claude Code's own approval prompt is a nice SECOND gate (defense in
depth), but it is not THE boundary -- if it were, the guarantee would evaporate
the moment you switched hosts. The guarantee has to live here, where we own it.

Two rules make the boundary legible:

    1. Default deny. Unknown tool, bad arguments, or a mutation without approval
       -> BLOCKED. The agent has to earn ALLOW, not talk its way out of BLOCK.
    2. Append-only audit. Every call -- allowed or blocked -- produces one
       immutable ToolCallRecord. The log is the receipt: after the demo you can
       point at it and show exactly what the agent tried and what we let through.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Callable

from pydantic import BaseModel, ValidationError

from netagent.models import (
    ApprovalRequest,
    ApprovalState,
    ToolCallRecord,
    ToolDecision,
)


class ToolKind(str, enum.Enum):
    """What a tool is allowed to do -- the axis the boundary cares about.

    READ tools observe device state and cannot change it. They run
    autonomously. MUTATE tools would change a device, so they are gated behind
    an approved, single-device ApprovalRequest.
    """

    READ = "read"
    MUTATE = "mutate"


class BoundaryViolation(RuntimeError):
    """Raised by `guard()` when the boundary BLOCKS a call.

    Carrying a distinct exception lets the server turn a block into a clear
    message for the agent ("blocked because ...") instead of a stack trace, and
    keeps blocks visually distinct from genuine device errors on camera.
    """

    def __init__(self, record: ToolCallRecord) -> None:
        self.record = record
        super().__init__(record.reason)


@dataclass
class ToolSpec:
    """Registration for one tool the agent may call.

    arg_schema is an optional Pydantic model used to validate arguments before
    the tool runs -- schema validation IS part of the boundary (a malformed
    argument set never reaches a device).
    """

    name: str
    kind: ToolKind
    arg_schema: type[BaseModel] | None = None


@dataclass
class Boundary:
    """The server-side gate + append-only audit log.

    Register every tool once, then route each call through `guard()` (or the
    lower-level `check()` if you only want the verdict). Nothing else in the
    codebase is allowed to call a device without going through here.
    """

    _tools: dict[str, ToolSpec] = field(default_factory=dict)
    _log: list[ToolCallRecord] = field(default_factory=list)

    # -- registration --------------------------------------------------------

    def register(
        self,
        name: str,
        kind: ToolKind,
        arg_schema: type[BaseModel] | None = None,
    ) -> None:
        """Declare a tool and its blast-radius class (READ vs MUTATE)."""
        self._tools[name] = ToolSpec(name=name, kind=kind, arg_schema=arg_schema)

    # -- the decision --------------------------------------------------------

    def check(
        self,
        tool_name: str,
        arguments: dict,
        approval: ApprovalRequest | None = None,
    ) -> ToolDecision:
        """Decide ALLOW vs BLOCK for one call, and append an audit record.

        This is pure policy -- it never touches a device. It returns the verdict
        and records it; the human-readable reason lives on the appended
        ToolCallRecord (see `last_record` / `audit_log`).

        Order of checks is deliberate (cheapest + most fundamental first):
          1. Is the tool even registered?      (default deny)
          2. Do the arguments validate?         (schema is part of the boundary)
          3. READ tools -> ALLOW.
          4. MUTATE tools -> require an APPROVED, single-device approval whose
             device matches the argument's device.
        """
        spec = self._tools.get(tool_name)

        # 1. Default deny: an unregistered tool is never allowed.
        if spec is None:
            return self._record(
                tool_name, arguments, ToolDecision.BLOCKED,
                f"Unknown tool '{tool_name}'. Not registered with the boundary.",
            )

        # 2. Schema validation. A tool with a declared schema must receive
        #    arguments that satisfy it, or we block before it can run.
        if spec.arg_schema is not None:
            try:
                spec.arg_schema.model_validate(arguments)
            except ValidationError as exc:
                return self._record(
                    tool_name, arguments, ToolDecision.BLOCKED,
                    f"Argument validation failed: {exc.error_count()} error(s). "
                    f"First: {exc.errors()[0]['loc']} -> {exc.errors()[0]['msg']}.",
                )

        # 3. Read tools are safe by construction -- allow them to run freely.
        if spec.kind is ToolKind.READ:
            return self._record(
                tool_name, arguments, ToolDecision.ALLOWED,
                "Read-only tool: no device state changes. Runs autonomously.",
            )

        # 4. Mutating tool. From here everything must be earned.
        return self._check_mutation(spec, arguments, approval)

    def _check_mutation(
        self,
        spec: ToolSpec,
        arguments: dict,
        approval: ApprovalRequest | None,
    ) -> ToolDecision:
        """Gate a MUTATE tool. Every failure path is an explicit BLOCK."""
        if approval is None:
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                "Mutating tool requires an approved ApprovalRequest. None supplied.",
            )

        if approval.state is not ApprovalState.APPROVED:
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                f"ApprovalRequest is '{approval.state.value}', not 'approved'. "
                "A human must approve before any change is applied.",
            )

        # One device per approval -- NEVER bundle a change across devices. The
        # RemediationProposal is single-device by construction, and we re-assert
        # it here so a hand-built approval can't smuggle in a multi-device blast.
        target = arguments.get("device")
        if not target or not isinstance(target, str):
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                "Mutating call must name exactly one 'device' argument.",
            )
        if approval.proposal.device != target:
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                f"Approval is for '{approval.proposal.device}' but the call "
                f"targets '{target}'. One device per approval -- no substitution.",
            )

        return self._record(
            spec.name, arguments, ToolDecision.ALLOWED,
            f"Approved by {approval.approver or 'unknown'} for {target} "
            f"(finding {approval.proposal.finding_id}). Single-device change permitted.",
        )

    # -- execution wrapper ---------------------------------------------------

    def guard(
        self,
        tool_name: str,
        arguments: dict,
        execute: Callable[[], object],
        approval: ApprovalRequest | None = None,
    ) -> object:
        """Check, then run `execute` ONLY if allowed.

        This is what server tools should call. On ALLOW it runs the callable,
        annotates the audit record with a short result summary, and returns the
        result. On BLOCK it raises BoundaryViolation carrying the record, so the
        caller can return the reason to the agent verbatim -- the block itself is
        already logged.
        """
        decision = self.check(tool_name, arguments, approval)
        record = self._log[-1]  # check() always appends exactly one record.

        if decision is ToolDecision.BLOCKED:
            raise BoundaryViolation(record)

        try:
            result = execute()
        except Exception as exc:  # noqa: BLE001 -- we record then re-raise.
            record.result_summary = f"ERROR during execution: {type(exc).__name__}: {exc}"
            raise
        record.result_summary = _summarize(result)
        return result

    # -- audit trail ---------------------------------------------------------

    def audit_log(self) -> list[ToolCallRecord]:
        """Return a copy of the append-only log (newest last).

        A copy, not the live list -- callers can read the receipt but cannot
        rewrite history.
        """
        return list(self._log)

    @property
    def last_record(self) -> ToolCallRecord | None:
        """The most recent record, or None if nothing has been checked yet."""
        return self._log[-1] if self._log else None

    def _record(
        self,
        tool_name: str,
        arguments: dict,
        decision: ToolDecision,
        reason: str,
    ) -> ToolDecision:
        """Append one immutable-by-convention record and echo the decision."""
        self._log.append(
            ToolCallRecord(
                tool_name=tool_name,
                arguments=dict(arguments),
                decision=decision,
                reason=reason,
            )
        )
        return decision


def _summarize(result: object) -> str:
    """Produce a short, non-leaky summary of a tool result for the audit log.

    We never store the full device payload in the audit record -- a running-
    config is large and can contain sensitive lines. One line of shape is
    enough to prove what happened.
    """
    if result is None:
        return "ok (no return value)"
    if isinstance(result, str):
        first = result.strip().splitlines()[0] if result.strip() else ""
        return f"str, {len(result)} chars: {first[:60]}"
    if isinstance(result, (list, tuple)):
        return f"{type(result).__name__} with {len(result)} item(s)"
    return f"{type(result).__name__}"
