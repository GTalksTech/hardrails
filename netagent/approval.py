# ============================================================
# Module:       approval.py
# Purpose:      Human-in-the-loop gate mechanics. Turns a dry-run
#               RemediationProposal into a PENDING ApprovalRequest and lets a
#               human approve or reject it. This is where execution pauses for a
#               person.
# Dependencies: pydantic>=2 (via models)
# Author:       G Talks Tech
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
    # HONEST LIMITATION (documented, deliberate -- decided 2026-07-18): the
    # approver name and reason below are supplied by whoever calls the tool,
    # which in this demo is the MODEL relaying them. The server enforces
    # PROCESS -- the state machine, single-device scope, the audit log, the
    # on-disk approval artifact -- not human IDENTITY: it cannot prove a person
    # actually typed this. Attesting the human needs a channel the model cannot
    # write to: today, the host's outer approval gate; on the Hardrails
    # roadmap, a server-owned out-of-band approval surface (e.g. a localhost
    # approval page the human clicks directly). Deferred on purpose -- do not
    # quietly "solve" identity here with anything the model could also supply.
    if not approver or not approver.strip():
        raise ApprovalError("An approver name is required to resolve a request.")
    if not reason or not reason.strip():
        raise ApprovalError(
            "A non-empty reason is required to resolve a request -- record the "
            "human's explicit decision (e.g. 'Reviewed the diff on screen; "
            "approved for core-rtr-01 only')."
        )

    request.state = new_state
    request.approver = approver
    request.reason = reason
    request.resolved_at = _utcnow()
    return request
