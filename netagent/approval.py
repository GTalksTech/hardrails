# ============================================================
# Module:       approval.py
# Purpose:      Human-in-the-loop gate mechanics. Turns a dry-run
#               RemediationProposal into a PENDING ApprovalRequest and lets a
#               human approve or reject it. This is where execution pauses for a
#               person.
# Dependencies: pydantic>=2 (via models)
# Author:       G Talks Tech
# Episode:      EP010-L-ai-network-agents
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Part of the
#               Hardrails framework reference implementation.
# ============================================================
"""The human-in-the-loop gate.

Simple and synchronous on purpose. A proposal is not a change -- it becomes a
change only after a person says so, on the record. This module is just the
bookkeeping for that decision: who approved, when, and why. The boundary
(boundary.py) is what actually enforces that an unapproved proposal never runs;
this module produces the artifact the boundary checks.
"""

from __future__ import annotations

from netagent.models import (
    ApprovalRequest,
    ApprovalState,
    RemediationProposal,
    _utcnow,
)


class ApprovalError(RuntimeError):
    """Raised on an illegal state transition (e.g. resolving twice)."""


def create_approval_request(proposal: RemediationProposal) -> ApprovalRequest:
    """Open a PENDING gate for a single-device dry-run proposal.

    Nothing is decided here -- this just registers that a human decision is
    owed. Until someone resolves it, the boundary will keep blocking any attempt
    to apply the proposal.
    """
    return ApprovalRequest(proposal=proposal, state=ApprovalState.PENDING)


def approve(
    request: ApprovalRequest,
    approver: str,
    reason: str = "",
) -> ApprovalRequest:
    """Approve a pending request. Records who, when, and why.

    We refuse to re-resolve an already-decided request: an approval is a
    one-way, single-use fact. Requiring a named approver keeps the audit trail
    honest -- "approved" with no name attached is not an approval.
    """
    return _resolve(request, ApprovalState.APPROVED, approver, reason)


def reject(
    request: ApprovalRequest,
    approver: str,
    reason: str = "",
) -> ApprovalRequest:
    """Reject a pending request. The proposal can never be applied afterward."""
    return _resolve(request, ApprovalState.REJECTED, approver, reason)


def _resolve(
    request: ApprovalRequest,
    new_state: ApprovalState,
    approver: str,
    reason: str,
) -> ApprovalRequest:
    if request.state is not ApprovalState.PENDING:
        raise ApprovalError(
            f"Request already {request.state.value}; cannot change it to "
            f"{new_state.value}. Approvals are single-use."
        )
    if not approver or not approver.strip():
        raise ApprovalError("An approver name is required to resolve a request.")

    request.state = new_state
    request.approver = approver
    request.reason = reason
    request.resolved_at = _utcnow()
    return request
