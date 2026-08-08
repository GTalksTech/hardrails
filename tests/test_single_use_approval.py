# ============================================================
# Module:       tests/test_single_use_approval.py
# Purpose:      Pin invariant 3's "single-use" for the APPLY step (issue #18):
#               an approved change can be applied exactly once. After a
#               successful apply the approval is consumed (state -> APPLIED) and
#               the boundary refuses any replay.
# Usage:        pytest tests/test_single_use_approval.py
# Dependencies: pytest, pydantic>=2, fastmcp (via netagent.server)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. REAL lab IPs.
# ============================================================
"""One human yes authorizes exactly one apply.

Single-use was enforced against re-resolution (can't approve then reject) but
not against re-application: the same APPROVED + TRUSTED_PATH approval passed the
mutation gate on every call. These tests pin the consumption: apply flips the
approval to a terminal APPLIED state, and the boundary refuses a spent approval.
"""

from __future__ import annotations

import pytest

from netagent import remediation as remediation_mod
import netagent.server as server
from netagent.boundary import Boundary, ToolKind
from netagent.models import (
    ApprovalChannel,
    ApprovalRequest,
    ApprovalState,
    Finding,
    FindingSource,
    RemediationProposal,
    Severity,
)


def _approval(
    state: ApprovalState = ApprovalState.APPROVED,
    channel: ApprovalChannel = ApprovalChannel.TRUSTED_PATH,
) -> ApprovalRequest:
    proposal = RemediationProposal(
        finding_id="cve-2025-20334-http-api",
        device="core-rtr-01",
        config_commands=["no ip http server"],
        dry_run_diff="- ip http server",
    )
    return ApprovalRequest(
        proposal=proposal, state=state, channel=channel,
        approver="Garrett", reason="Reviewed the diff on my phone.",
    )


class _FakeConnectHandler:
    """Stand-in for netmiko so apply_approved never touches a device."""

    instances: list["_FakeConnectHandler"] = []

    def __init__(self, **params: object) -> None:
        self.params = params
        self.config_sets: list[list[str]] = []
        type(self).instances.append(self)

    def send_config_set(self, commands: list[str]) -> str:
        self.config_sets.append(list(commands))
        return "device output: 2 lines applied"

    def disconnect(self) -> None:
        pass


class TestBoundaryRefusesSpentApproval:
    def test_applied_approval_is_blocked_with_single_use_reason(self, tmp_path):
        boundary = Boundary(audit_log_path=tmp_path / "audit.jsonl")
        boundary.register("apply_remediation", ToolKind.MUTATE)
        approval = _approval()

        # A fresh, approved, trusted-path approval passes the gate...
        first = boundary.check("apply_remediation", {"device": "core-rtr-01"}, approval)
        assert first is not None and boundary.last_record.decision.value == "allowed"

        # ...the apply consumes it (state -> APPLIED); the gate now refuses it.
        approval.state = ApprovalState.APPLIED
        boundary.check("apply_remediation", {"device": "core-rtr-01"}, approval)
        reason = boundary.last_record.reason.lower()
        assert boundary.last_record.decision.value == "blocked"
        assert "single-use" in reason or "already applied" in reason


class TestApplyApprovedConsumesTheApproval:
    def test_successful_apply_marks_applied_and_refuses_replay(self, monkeypatch):
        monkeypatch.setattr(remediation_mod, "ConnectHandler", _FakeConnectHandler)
        monkeypatch.setenv("NETAGENT_PASSWORD", "lab-pw")
        approval = _approval()

        output = remediation_mod.apply_approved(approval.proposal, approval)
        assert "applied" in output.lower()
        assert approval.state is ApprovalState.APPLIED
        assert approval.applied_at is not None

        # The same, now-spent approval cannot be applied again.
        with pytest.raises(remediation_mod.RemediationError):
            remediation_mod.apply_approved(approval.proposal, approval)


class _FakeReadConn:
    def __init__(self, device: object) -> None:
        self._device = device

    def __enter__(self) -> "_FakeReadConn":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get_running_config(self) -> str:
        return "hostname core-rtr-01\nip http server\nip http secure-server\nend\n"


@pytest.fixture()
def server_tool_mode(monkeypatch, tmp_path):
    """Server wired for the testing-only tool mode, real apply_approved, faked
    netmiko -- so the apply path actually transitions the approval state."""
    monkeypatch.setattr(server, "DeviceConnection", lambda dev: _FakeReadConn(dev))
    monkeypatch.setattr(server.remediation_mod, "ConnectHandler", _FakeConnectHandler)
    monkeypatch.setenv("NETAGENT_PASSWORD", "lab-pw")
    monkeypatch.setattr(server.boundary, "audit_log_path", tmp_path / "audit.jsonl")
    monkeypatch.delenv("NETAGENT_APPROVALS_DIR", raising=False)
    monkeypatch.setenv("NETAGENT_APPROVAL_MODE", "tool")
    monkeypatch.setattr(server.boundary, "require_trusted_channel", False)
    for state in (server._findings, server._proposals, server._approvals):
        state.clear()
    yield tmp_path
    for state in (server._findings, server._proposals, server._approvals):
        state.clear()


def test_server_second_apply_is_single_use_blocked(server_tool_mode):
    finding = Finding(
        id="cve-2025-20334-http-api", severity=Severity.HIGH, title="CVE-2025-20334",
        devices=["core-rtr-01"], category="vulnerability",
        remediation_kind="disable_http", source=FindingSource.DETERMINISTIC_CHECK,
        rationale="test",
    )
    server._findings[finding.id] = finding
    server.propose_remediation(finding.id, "core-rtr-01")
    approval_id = server.request_approval(finding.id, "core-rtr-01")["approval_id"]
    server.resolve_approval(approval_id, "approve", "Garrett", "Reviewed on screen.")

    first = server.apply_remediation(approval_id, "core-rtr-01")
    assert first.get("applied") is True

    second = server.apply_remediation(approval_id, "core-rtr-01")
    assert second.get("blocked") is True
    assert "single-use" in second["reason"].lower() or "already applied" in second["reason"].lower()
