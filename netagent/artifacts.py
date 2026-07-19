# ============================================================
# Module:       artifacts.py
# Purpose:      On-disk approval artifacts: every ApprovalRequest gets a
#               reviewable markdown file (approvals/<approval-id>.md), written
#               at request time and rewritten at each transition (resolve,
#               apply) with a History section. The durable "who approved what,
#               when" receipt a human can open and read.
# Dependencies: pydantic>=2 (via models); stdlib only otherwise
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets, and NEVER a full
#               device payload -- artifacts hold the reviewed commands and diff,
#               plus a short outcome line. Part of the Hardrails framework
#               reference implementation.
# ============================================================
"""Approval artifacts: the paper trail for the human-in-the-loop gate.

Why this exists (from the second live test): the approval state machine held,
but a resolved approval left nothing behind a human could open afterward -- the
diff the approver supposedly reviewed lived only in the model's context. Each
approval now writes `approvals/<approval-id>.md`: the finding, the device, the
exact commands, the full dry-run diff, the state, and a history of every
transition. The simplest correct persistence: rewrite the whole file at each
transition (request -> resolve -> apply), so the file always shows the complete
current story.

Same best-effort discipline as the audit-log receipt in boundary.py: a failed
artifact write must never break the approval flow itself -- the state machine
and the audit log are the enforcement; this file is the human-readable receipt.
"""

from __future__ import annotations

import os
from pathlib import Path

from netagent.models import ApprovalRequest, _utcnow

# Where artifacts live. Same env-only configuration discipline as
# NETAGENT_AUDIT_LOG; the default keeps the receipt next to the audit log so
# both on-camera "here's the file" beats point at the same folder.
_APPROVALS_DIR_ENV = "NETAGENT_APPROVALS_DIR"

# Transition history per approval id, in memory for the server's lifetime.
# Approvals themselves are in-memory session state (see server.py), so an
# approval id never outlives the process -- this dict matches that lifetime.
_events: dict[str, list[tuple[str, str]]] = {}


def resolve_approvals_dir(audit_log_path: Path) -> Path:
    """Resolve the artifacts directory: env override, else next to the audit log."""
    override = os.environ.get(_APPROVALS_DIR_ENV)
    return Path(override) if override else audit_log_path.parent / "approvals"


def update_artifact(
    approval_id: str,
    request: ApprovalRequest,
    audit_log_path: Path,
    event: str,
) -> Path | None:
    """Record one transition and (re)write the artifact file. Returns the path.

    `event` is a short human line ("requested (pending)", "approved by X: ...",
    "applied to <device>: <short summary>"). Never pass device payloads in --
    the artifact is a receipt, not a capture.

    Best-effort like boundary._persist: on a write failure this returns None
    rather than raising, so a bad path cannot break the approval flow. The
    caller surfaces the None honestly (no path claimed that was not written).
    """
    _events.setdefault(approval_id, []).append((_utcnow().isoformat(), event))
    directory = resolve_approvals_dir(audit_log_path)
    path = directory / f"{approval_id}.md"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path.write_text(_render(approval_id, request), encoding="utf-8")
    except OSError:
        return None
    return path


def _render(approval_id: str, request: ApprovalRequest) -> str:
    """Render the complete current story of one approval as markdown."""
    proposal = request.proposal
    resolved = request.resolved_at.isoformat() if request.resolved_at else "--"
    lines = [
        f"# Approval {approval_id}",
        "",
        f"- **State:** {request.state.value}",
        f"- **Finding:** {proposal.finding_id}",
        f"- **Device:** {proposal.device}",
        f"- **Requested at:** {request.requested_at.isoformat()}",
        f"- **Resolved at:** {resolved}",
        f"- **Approver:** {request.approver or '--'}",
        f"- **Reason:** {request.reason or '--'}",
        "",
        "## Proposed commands",
        "",
        "```",
        *proposal.config_commands,
        "```",
        "",
        "## Dry-run diff",
        "",
        "```diff",
        proposal.dry_run_diff,
        "```",
        "",
        "## History",
        "",
    ]
    for timestamp, event in _events.get(approval_id, []):
        lines.append(f"- {timestamp} -- {event}")
    lines.append("")
    return "\n".join(lines)
