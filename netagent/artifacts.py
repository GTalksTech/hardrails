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
import re
from pathlib import Path

from netagent.models import (
    ApprovalChannel,
    ApprovalRequest,
    ApprovalState,
    _utcnow,
)

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
    # The id becomes a filename, so it is validated at the sink even though
    # callers only pass server-issued ids ('appr-3'): a separator-bearing or
    # otherwise malformed id must never reach path arithmetic, and the
    # normalized file path must land inside the approvals directory. Same
    # best-effort contract as a failed write -- no artifact, return None.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", approval_id):
        return None
    directory = str(resolve_approvals_dir(audit_log_path).resolve())
    fullpath = os.path.normpath(os.path.join(directory, approval_id + ".md"))
    if not fullpath.startswith(directory + os.sep):
        return None
    directory, path = Path(directory), Path(fullpath)
    # Foreign-receipt guard (issue #3): a file that exists on disk for an id
    # this process has NO transition history for is another session's
    # receipt. Receipts are frozen history -- refuse before the id enters
    # _events, so a refused id stays foreign on every retry.
    if approval_id not in _events and path.exists():
        return None
    _events.setdefault(approval_id, []).append((_utcnow().isoformat(), event))
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path.write_text(_render(approval_id, request), encoding="utf-8")
    except OSError:
        return None
    return path


def _longest_backtick_run(text: str) -> int:
    """The longest run of consecutive backticks in `text` (0 if none)."""
    longest = current = 0
    for char in text:
        if char == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _fence(body: str, info: str = "") -> list[str]:
    """Wrap `body` in a fenced code block that device text cannot break out of.

    The dry-run diff is built from the running-config, which is untrusted: a
    line containing a literal ``` would otherwise close a plain ``` fence and
    inject markdown into the human's review receipt. A fence of
    (longest-backtick-run + 1) backticks, minimum 3, contains any run inside
    the body (CommonMark). For content with no backticks this is byte-identical
    to a plain ``` fence.
    """
    delimiter = "`" * max(3, _longest_backtick_run(body) + 1)
    return [f"{delimiter}{info}", body, delimiter]


def _render(approval_id: str, request: ApprovalRequest) -> str:
    """Render the complete current story of one approval as markdown."""
    proposal = request.proposal
    resolved = request.resolved_at.isoformat() if request.resolved_at else "--"
    # The channel line is the identity claim, stated at the artifact's
    # strength: a pending request has no decision yet ('--'); a trusted-path
    # resolution names the channel; a tool-channel resolution is marked
    # unattested so the weaker claim is visible on the receipt itself.
    if request.state is ApprovalState.PENDING:
        channel = "--"
    elif request.channel is ApprovalChannel.TRUSTED_PATH:
        channel = request.channel.value
    else:
        channel = f"{request.channel.value} (unattested)"
    lines = [
        f"# Approval {approval_id}",
        "",
        f"- **State:** {request.state.value}",
        f"- **Channel:** {channel}",
        f"- **Finding:** {proposal.finding_id}",
        f"- **Device:** {proposal.device}",
        f"- **Requested at:** {request.requested_at.isoformat()}",
        f"- **Resolved at:** {resolved}",
        f"- **Applied at:** {request.applied_at.isoformat() if request.applied_at else '--'}",
        f"- **Approver:** {request.approver or '--'}",
        f"- **Reason:** {request.reason or '--'}",
        "",
        "## Proposed commands",
        "",
        *_fence("\n".join(proposal.config_commands)),
        "",
        "## Dry-run diff",
        "",
        *_fence(proposal.dry_run_diff, "diff"),
        "",
        "## History",
        "",
    ]
    for timestamp, event in _events.get(approval_id, []):
        lines.append(f"- {timestamp} -- {event}")
    lines.append("")
    return "\n".join(lines)
