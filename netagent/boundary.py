# ============================================================
# Module:       boundary.py
# Purpose:      The deterministic boundary. Every tool call the agent makes is
#               routed through this layer, which decides ALLOW vs BLOCK and
#               writes an append-only audit record -- server-side, so the
#               framework is harness-agnostic.
# Dependencies: pydantic>=2
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Part of the
#               Hardrails framework reference implementation.
# ============================================================
"""The boundary: deterministic rules around a non-deterministic agent.

This is the heart of Hardrails. The whole thesis lives in this file,
so it is written to be read top to bottom.

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
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ValidationError

from netagent.models import (
    ApprovalChannel,
    ApprovalRequest,
    ApprovalState,
    ToolCallRecord,
    ToolDecision,
    ToolResultRecord,
)

# The append-only audit log's on-disk home. Configurable via NETAGENT_AUDIT_LOG
# (same env-only credential/config discipline as NETAGENT_PASSWORD); otherwise
# it lands next to the server so it is discoverable for the on-camera
# "here's the receipt, and here's the file" beat. The server dir is this
# package's parent (where `python -m netagent.server` runs from).
_AUDIT_LOG_ENV = "NETAGENT_AUDIT_LOG"
_DEFAULT_AUDIT_LOG = Path(__file__).resolve().parent.parent / "audit-log.jsonl"


def _resolve_audit_log_path() -> Path:
    """Resolve the audit-log path from the environment, else the default."""
    override = os.environ.get(_AUDIT_LOG_ENV)
    return Path(override) if override else _DEFAULT_AUDIT_LOG


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

    The log is kept two ways, on purpose: `_log` is the fast in-memory list for
    reads within a session, and `audit_log_path` is the durable receipt -- every
    record is also appended to that JSONL file, one object per line, so the trail
    survives a restart and can be pointed at on camera.
    """

    _tools: dict[str, ToolSpec] = field(default_factory=dict)
    _log: list[ToolCallRecord] = field(default_factory=list)
    audit_log_path: Path = field(default_factory=_resolve_audit_log_path)
    # Trusted-path provenance (issue #9): when True -- the default, because
    # the boundary earns ALLOW, it doesn't inherit it -- a mutation's approval
    # must have entered via the approval surface (ApprovalChannel.TRUSTED_PATH),
    # not been relayed through the resolve_approval tool. The server flips
    # this to False only in the testing-only tool mode, loudly.
    require_trusted_channel: bool = True
    # Serializes the _log append and the JSONL write. The process is concurrent
    # -- FastMCP runs sync tools in a threadpool AND the approval surface is a
    # ThreadingHTTPServer that records on this same instance -- so without this
    # two callers could interleave a torn JSONL line. Re-entrant so _record can
    # hold it across append + _persist. Held ONLY around the audit write, never
    # around execute(), so device I/O is not serialized behind it (issue #20).
    _lock: threading.RLock = field(
        default_factory=threading.RLock, compare=False, repr=False
    )

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

        Public verdict API: returns just the decision, so existing callers are
        unchanged. guard() uses _evaluate, which returns the appended record
        itself -- reaching for self._log[-1] was a race under concurrent
        callers (issue #20).
        """
        return self._evaluate(tool_name, arguments, approval).decision

    def _evaluate(
        self,
        tool_name: str,
        arguments: dict,
        approval: ApprovalRequest | None = None,
    ) -> ToolCallRecord:
        """Decide ALLOW vs BLOCK, append the record, and RETURN that record.

        Pure policy -- it never touches a device. The returned record carries
        the verdict (`.decision`) and the reason; guard() uses this exact object
        rather than re-reading self._log[-1] (a race under concurrent callers,
        issue #20).

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

    # Every mutation BLOCK teaches the correct procedure (ENH 5). An agent that
    # shortcuts -- skipping the request, self-approving in the same turn, or
    # inventing an approval id -- is corrected by the boundary itself, in the
    # block reason, harness-independent. The rules above the message are
    # unchanged; only the message got richer.
    _REQUIRED_FLOW = (
        "Required flow: propose_remediation -> request_approval (creates an "
        "approval ID, an on-disk artifact, and an approval_url) -> present the "
        "dry-run diff and the approval_url to the human -> the human decides "
        "on the approval page from a second device (testing-only tool mode: "
        "resolve_approval) -> apply_remediation with that approval_id."
    )

    def _check_mutation(
        self,
        spec: ToolSpec,
        arguments: dict,
        approval: ApprovalRequest | None,
    ) -> ToolCallRecord:
        """Gate a MUTATE tool. Every failure path is an explicit BLOCK."""
        if approval is None:
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                "Mutating tool requires an approved ApprovalRequest, but none "
                "was supplied -- the approval_id is missing or not known to "
                f"this server. {self._REQUIRED_FLOW}",
            )

        # Single-use (issue #18): an approval that was already applied is spent.
        # One human yes authorizes exactly one apply; a replay must build a new
        # proposal and earn a fresh approval. Checked before the generic state
        # test so the block reason names the real reason, not "not approved".
        if approval.state is ApprovalState.APPLIED:
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                "This approval was already applied. Approvals are single-use -- "
                "one human yes authorizes exactly one apply. Build a new "
                "proposal and get a fresh approval for another change. "
                f"{self._REQUIRED_FLOW}",
            )

        if approval.state is not ApprovalState.APPROVED:
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                f"ApprovalRequest is '{approval.state.value}', not 'approved'. "
                f"A human must approve before any change is applied. "
                f"{self._REQUIRED_FLOW}",
            )

        # Provenance (issue #9): an APPROVED state is not enough -- in trusted
        # mode the decision must have ENTERED through the approval surface.
        # An approval relayed through the resolve_approval tool carries
        # channel=TOOL and is refused here even though its state machine is
        # formally satisfied: the state says "approved", the channel says who
        # could have produced it.
        if (
            self.require_trusted_channel
            and approval.channel is not ApprovalChannel.TRUSTED_PATH
        ):
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                "Approval was resolved through the tool channel (relayed "
                "strings), but this server requires trusted-path provenance: "
                "the human decides on the approval page, from a device that "
                f"is not this machine. {self._REQUIRED_FLOW}",
            )

        # One device per approval -- NEVER bundle a change across devices. The
        # RemediationProposal is single-device by construction, and we re-assert
        # it here so a hand-built approval can't smuggle in a multi-device blast.
        target = arguments.get("device")
        if not target or not isinstance(target, str):
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                f"Mutating call must name exactly one 'device' argument. "
                f"{self._REQUIRED_FLOW}",
            )
        if approval.proposal.device != target:
            return self._record(
                spec.name, arguments, ToolDecision.BLOCKED,
                f"Approval is for '{approval.proposal.device}' but the call "
                f"targets '{target}'. One device per approval -- no "
                f"substitution. {self._REQUIRED_FLOW}",
            )

        channel_note = (
            "via trusted path"
            if approval.channel is ApprovalChannel.TRUSTED_PATH
            else "via tool channel (unattested)"
        )
        return self._record(
            spec.name, arguments, ToolDecision.ALLOWED,
            f"Approved by {approval.approver or 'unknown'} for {target} "
            f"{channel_note} (finding {approval.proposal.finding_id}). "
            f"Single-device change permitted.",
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

        On disk the outcome is a follow-up ToolResultRecord: the decision line
        was persisted before execution (append-only -- it is never rewritten),
        so the summary is APPENDED as a second record linked by call_id.
        """
        record = self._evaluate(tool_name, arguments, approval)

        if record.decision is ToolDecision.BLOCKED:
            raise BoundaryViolation(record)

        # Fail-closed audit for mutations (issue #20): a device change with no
        # durable receipt is exactly what the audit log exists to prevent. Reads
        # and blocks stay best-effort (a read that isn't logged changed nothing),
        # but an ALLOWED mutation whose decision line did not reach disk is
        # refused before it can run.
        spec = self._tools.get(tool_name)
        if (
            spec is not None
            and spec.kind is ToolKind.MUTATE
            and not record._persisted
        ):
            blocked = self._record(
                tool_name, arguments, ToolDecision.BLOCKED,
                "Audit unavailable: the durable audit record for this change "
                "could not be written, so the change is refused (fail-closed). "
                "A mutation with no receipt is exactly what the audit log exists "
                "to prevent. Fix the audit-log path/permissions "
                "(NETAGENT_AUDIT_LOG) and retry.",
            )
            raise BoundaryViolation(blocked)

        try:
            result = execute()
        except Exception as exc:  # noqa: BLE001 -- we record then re-raise.
            record.result_summary = _summarize_exception(exc)
            self._persist(
                ToolResultRecord(
                    call_id=record.call_id, result_summary=record.result_summary
                )
            )
            raise
        record.result_summary = _summarize(result)
        self._persist(
            ToolResultRecord(
                call_id=record.call_id, result_summary=record.result_summary
            )
        )
        return result

    # -- audit trail ---------------------------------------------------------

    def record_event(
        self,
        tool_name: str,
        arguments: dict,
        decision: ToolDecision,
        reason: str,
    ) -> ToolDecision:
        """Append a record for a non-tool event on the same append-only log.

        The approval surface uses this so trusted-path resolutions -- and
        REFUSED attempts (local-source hits, bad secrets) -- land in the same
        receipt as every tool call. The invariant is 'every guarded call gets
        a record'; events on the surface are guarded calls in every sense
        that matters.
        """
        return self._record(tool_name, arguments, decision, reason).decision

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
    ) -> ToolCallRecord:
        """Append one record (in memory + durable JSONL) and RETURN it.

        The append and the file write happen under `_lock` so concurrent callers
        -- tool worker threads and the approval-surface thread -- cannot
        interleave lines. The disk write happens HERE, at decision time (before
        any execution), so a crash mid-tool-run can never lose the verdict. The
        record's `_persisted` flag records whether the durable write landed;
        guard() reads it to fail a mutation closed (issue #20). The execution
        outcome cannot appear on this line; `guard()` appends it afterwards as a
        ToolResultRecord.
        """
        record = ToolCallRecord(
            tool_name=tool_name,
            arguments=dict(arguments),
            decision=decision,
            reason=reason,
        )
        with self._lock:
            self._log.append(record)
            record._persisted = self._persist(record)
        return record

    def _persist(self, record: ToolCallRecord | ToolResultRecord) -> bool:
        """Append one record to the JSONL receipt (append-only, never truncate).

        Returns True if the line reached disk, False if the write failed. It
        never RAISES -- a bad path must not crash the gate -- but the boolean
        lets guard() fail a mutation closed when its receipt did not land
        (issue #20); reads and blocks tolerate a miss. The write is serialized
        under `_lock` so concurrent appends cannot interleave into a torn line.
        Same _summarize discipline as the in-memory log: no full device payloads
        reach the file.
        """
        with self._lock:
            try:
                self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.audit_log_path.open("a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            record.model_dump(mode="json"), separators=(",", ":")
                        )
                        + "\n"
                    )
            except (OSError, TypeError, ValueError):
                # Best-effort receipt: never let a bad path OR an unserializable
                # argument value break the boundary. (pydantic's serialization
                # error is a ValueError; json.dumps raises TypeError.) Report the
                # failure so guard() can fail a mutation closed.
                return False
        return True


def _summarize(result: object) -> str:
    """Produce a short, non-leaky summary of a tool result for the audit log.

    We never store device payload in the audit record -- not the full body and
    not an excerpt. A `show run` result's FIRST line can already be a secret
    (`enable secret 9 ...`), so the summary is shape only: type and size.
    Shape is enough to prove what happened.
    """
    if result is None:
        return "ok (no return value)"
    if isinstance(result, str):
        return f"str, {len(result)} chars, {len(result.splitlines())} line(s)"
    if isinstance(result, (list, tuple)):
        return f"{type(result).__name__} with {len(result)} item(s)"
    return f"{type(result).__name__}"


def _summarize_exception(exc: BaseException) -> str:
    """Shape-only summary of an execution error -- type recorded, message WITHHELD.

    Mirrors _summarize's discipline. An exception raised from device I/O can
    carry device output (a netmiko read-timeout embeds the buffer read so far,
    whose first line can be `enable secret ...`), so we record the exception
    TYPE and withhold the message: enough to prove an error of that class
    happened, without leaking payload into the durable receipt.
    """
    return (
        f"ERROR during execution: {type(exc).__name__} "
        "(message withheld to keep device output out of the receipt)"
    )
