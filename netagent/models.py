# ============================================================
# Module:       models.py
# Purpose:      Typed data models for the bounded network-agent MCP server.
#               Every finding, remediation proposal, approval, and tool call
#               is a validated object -- the schema IS part of the boundary.
# Dependencies: pydantic>=2
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Part of the
#               Hardrails framework reference implementation.
# ============================================================
"""Data models for the bounded network-agent.

Design note (this is flagship / on-camera material): these models are not just
plumbing. Two choices here ARE the boundary philosophy:

1. `FindingSource` forces every finding to declare HOW it was produced -- a
   deterministic coded check, or the agent's own reasoning. That keeps us honest
   on camera: the CVE finding must come from a deterministic version->advisory
   lookup, never the model reciting CVE numbers from memory.

2. A remediation is never "run this." It is a `RemediationProposal` (dry-run
   only) that must pass through an `ApprovalRequest` before anything touches a
   device. The type system makes "silently apply a change" unrepresentable.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Timezone-aware UTC timestamp (audit records must be unambiguous)."""
    return datetime.now(timezone.utc)


class Severity(enum.IntEnum):
    """Finding severity. IntEnum so the audit sweep can sort worst-first."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class FindingSource(str, enum.Enum):
    """How a finding was produced -- the honesty axis.

    DETERMINISTIC_CHECK: a coded rule found it (version->CVE lookup, config
        grep, NetBox intent diff). Reproducible; safe to assert on camera.
    AGENT_REASONING: the model correlated across data the checks can't encode
        (e.g. the cross-device security gap). Powerful, but must be presented
        as the agent's assessment, not ground truth.
    """

    DETERMINISTIC_CHECK = "deterministic_check"
    AGENT_REASONING = "agent_reasoning"


class Finding(BaseModel):
    """A single audit finding. Read-only product of the posture sweep."""

    id: str = Field(..., description="Stable slug, e.g. 'cve-2025-20334-core'.")
    severity: Severity
    title: str = Field(..., description="One-line human summary.")
    devices: list[str] = Field(
        ..., description="Hostname(s) the finding implicates. >1 = cross-device."
    )
    category: str = Field(
        ..., description="e.g. 'vulnerability', 'segmentation', 'hardening', 'drift'."
    )
    source: FindingSource
    evidence: list[str] = Field(
        default_factory=list,
        description="Verbatim config/show lines that prove it -- what the viewer sees.",
    )
    rationale: str = Field(
        ..., description="Why it matters, in plain English. The agent's explanation."
    )
    recommended_remediation: str = Field(
        "",
        description="Informational suggestion ONLY. Applying it must go through "
        "RemediationProposal -> ApprovalRequest. This field never executes.",
    )
    references: list[str] = Field(
        default_factory=list, description="Advisory / doc URLs (e.g. the CVE page)."
    )

    def rank_key(self) -> tuple[int, str]:
        """Sort key for worst-first ordering (stable within a severity)."""
        return (-int(self.severity), self.id)


class RemediationProposal(BaseModel):
    """A DRY-RUN change. Generated, diffed, but never committed here.

    The change tool builds one of these and returns the diff. Nothing in this
    object can reach a device -- that path only opens after ApprovalRequest is
    explicitly approved by a human.
    """

    finding_id: str
    device: str
    config_commands: list[str] = Field(
        ..., description="The exact CLI the human would review, in order."
    )
    dry_run_diff: str = Field(
        ..., description="Intended-vs-running diff rendered for human review."
    )
    notes: str = Field(
        "", description="Caveats the human should weigh (blast radius, ordering)."
    )


class ApprovalState(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalRequest(BaseModel):
    """The human-in-the-loop gate. Execution suspends until this resolves."""

    proposal: RemediationProposal
    state: ApprovalState = ApprovalState.PENDING
    requested_at: datetime = Field(default_factory=_utcnow)
    resolved_at: datetime | None = None
    approver: str | None = Field(
        None, description="Who decided. Recorded for the audit trail."
    )
    reason: str | None = Field(None, description="Why approved/rejected.")


class ToolDecision(str, enum.Enum):
    """Boundary verdict for a single tool call."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"


class ToolCallRecord(BaseModel):
    """One line in the append-only audit log. Every tool call gets one."""

    timestamp: datetime = Field(default_factory=_utcnow)
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    decision: ToolDecision
    reason: str = Field(
        "", description="Why the boundary allowed/blocked it (e.g. schema reject)."
    )
    result_summary: str = Field(
        "", description="Short outcome note. Never the full device payload."
    )
