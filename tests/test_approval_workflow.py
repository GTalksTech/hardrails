# ============================================================
# Module:       tests/test_approval_workflow.py
# Purpose:      Tests for ENH 5: on-disk approval artifacts (created at
#               request_approval, updated at resolve_approval and after
#               apply_remediation), flow-teaching block reasons, the audited
#               unknown-approval-id block, and the non-empty-reason requirement
#               on resolve_approval.
# Usage:        pytest tests/  (from the network-agent-mcp directory)
# Dependencies: pytest, fastmcp (via netagent.server), pydantic>=2
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. REAL lab IPs.
# ============================================================
"""ENH 5: the approval workflow leaves a paper trail and teaches its own flow.

Why (from the second live test): the agent ran propose -> approve -> apply in a
single turn, recording the user as approver for a diff the user never saw. The
state machine held, but nothing forced the pause and nothing durable was left
behind. These tests pin: every approval gets a reviewable markdown artifact on
disk; every apply block PRESCRIBES the required flow; an unknown approval_id is
an AUDITED block, not a silent error; and a resolution needs an explicit reason.
"""

from __future__ import annotations

import json

import pytest

import netagent.server as server
from netagent.models import Finding, FindingSource, Severity, ToolDecision

_RUNNING = """\
hostname core-rtr-01
!
ip http server
ip http secure-server
!
end
"""

# The fake device output for a successful apply. The DEEP_MARKER must never
# reach the artifact -- the artifact records a short summary, not the payload.
_DEEP_MARKER = "SNMP-SERVER-COMMUNITY-LINE-THAT-MUST-NOT-LEAK"
_FAKE_APPLY_OUTPUT = "config term\n" + ("x" * 500) + _DEEP_MARKER + "\nend\n"


class _FakeConn:
    def __init__(self, device):
        self._device = device

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_running_config(self):
        return _RUNNING


def _seed_http_finding() -> str:
    finding = Finding(
        id="cve-2025-20334-http-api",
        severity=Severity.HIGH,
        title="CVE-2025-20334",
        devices=["core-rtr-01"],
        category="vulnerability",
        remediation_kind="disable_http",
        source=FindingSource.DETERMINISTIC_CHECK,
        rationale="test",
    )
    server._findings[finding.id] = finding
    return finding.id


@pytest.fixture()
def wired(monkeypatch, tmp_path):
    """Fake the device + apply paths, sandbox the audit log and approvals dir."""
    monkeypatch.setattr(server, "DeviceConnection", lambda dev: _FakeConn(dev))
    monkeypatch.setattr(
        server.remediation_mod,
        "apply_approved",
        lambda proposal, approval, password=None: _FAKE_APPLY_OUTPUT,
    )
    monkeypatch.setattr(server.boundary, "audit_log_path", tmp_path / "audit.jsonl")
    monkeypatch.delenv("NETAGENT_APPROVALS_DIR", raising=False)
    server._findings.clear()
    server._proposals.clear()
    server._approvals.clear()
    yield tmp_path
    server._findings.clear()
    server._proposals.clear()
    server._approvals.clear()


def _request(finding_id: str) -> dict:
    server.propose_remediation(finding_id, "core-rtr-01")
    return server.request_approval(finding_id, "core-rtr-01")


def _read_jsonl(path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ----------------------------------------------------------------------------
# 1 + 2: the artifact file and its surfaced path.
# ----------------------------------------------------------------------------


class TestApprovalArtifact:
    def test_request_creates_artifact_with_review_content(self, wired):
        finding_id = _seed_http_finding()
        payload = _request(finding_id)

        path = payload["approval_artifact"]
        assert path is not None
        # Default location: an approvals/ folder next to the audit log.
        assert str(wired / "approvals") in path
        assert path.endswith(f"{payload['approval_id']}.md")

        text = open(path, encoding="utf-8").read()
        assert payload["approval_id"] in text
        assert finding_id in text
        assert "core-rtr-01" in text
        assert "no ip http server" in text        # the exact commands
        assert "running-config (live)" in text    # the dry-run diff header
        assert "pending" in text.lower()

    def test_resolve_updates_state_approver_reason(self, wired):
        finding_id = _seed_http_finding()
        requested = _request(finding_id)
        approval_id = requested["approval_id"]

        resolved = server.resolve_approval(
            approval_id, "approve", "Garrett", "Reviewed the diff; ship it."
        )

        path = resolved["approval_artifact"]
        assert path == requested["approval_artifact"]
        text = open(path, encoding="utf-8").read()
        assert "approved" in text.lower()
        assert "Garrett" in text
        assert "Reviewed the diff; ship it." in text

    def test_apply_appends_summary_but_never_device_payload(self, wired):
        finding_id = _seed_http_finding()
        approval_id = _request(finding_id)["approval_id"]
        server.resolve_approval(approval_id, "approve", "Garrett", "Reviewed.")

        applied = server.apply_remediation(approval_id, "core-rtr-01")

        assert applied["applied"] is True
        path = applied["approval_artifact"]
        text = open(path, encoding="utf-8").read()
        assert "applied" in text.lower()
        # A short receipt of the outcome -- never the device output itself.
        assert _DEEP_MARKER not in text

    def test_history_accumulates_across_transitions(self, wired):
        finding_id = _seed_http_finding()
        approval_id = _request(finding_id)["approval_id"]
        server.resolve_approval(approval_id, "approve", "Garrett", "Reviewed.")
        applied = server.apply_remediation(approval_id, "core-rtr-01")

        text = open(applied["approval_artifact"], encoding="utf-8").read()
        history = text[text.index("## History"):]
        assert "requested" in history
        assert "approved" in history
        assert "applied" in history

    def test_env_override_relocates_artifacts(self, wired, monkeypatch, tmp_path):
        custom = tmp_path / "elsewhere"
        monkeypatch.setenv("NETAGENT_APPROVALS_DIR", str(custom))
        finding_id = _seed_http_finding()
        payload = _request(finding_id)
        assert str(custom) in payload["approval_artifact"]
        assert (custom / f"{payload['approval_id']}.md").exists()

    def test_rejection_is_recorded_too(self, wired):
        finding_id = _seed_http_finding()
        approval_id = _request(finding_id)["approval_id"]
        resolved = server.resolve_approval(
            approval_id, "reject", "Garrett", "Wrong window; not tonight."
        )
        text = open(resolved["approval_artifact"], encoding="utf-8").read()
        assert "rejected" in text.lower()
        assert "Wrong window; not tonight." in text


# ----------------------------------------------------------------------------
# 3: blocked applies PRESCRIBE the required flow.
# ----------------------------------------------------------------------------


class TestFlowTeachingBlocks:
    def test_pending_approval_block_teaches_the_flow(self, wired):
        finding_id = _seed_http_finding()
        approval_id = _request(finding_id)["approval_id"]  # never resolved

        blocked = server.apply_remediation(approval_id, "core-rtr-01")

        assert blocked["blocked"] is True
        for step in (
            "propose_remediation",
            "request_approval",
            "resolve_approval",
            "apply_remediation",
        ):
            assert step in blocked["reason"]

    # 3b: the unknown-id case must be an AUDITED block, not a bare error.
    def test_unknown_approval_id_is_an_audited_block(self, wired):
        blocked = server.apply_remediation("appr-does-not-exist", "core-rtr-01")

        assert blocked.get("blocked") is True
        assert "resolve_approval" in blocked["reason"]  # flow teaching included

        # In-memory record exists and is BLOCKED.
        record = server.boundary.last_record
        assert record.tool_name == "apply_remediation"
        assert record.decision is ToolDecision.BLOCKED

        # And the JSONL receipt on disk carries the same record.
        records = _read_jsonl(server.boundary.audit_log_path)
        assert records[-1]["tool_name"] == "apply_remediation"
        assert records[-1]["decision"] == "blocked"
        assert "resolve_approval" in records[-1]["reason"]


# ----------------------------------------------------------------------------
# 4: resolve_approval requires an explicit non-empty reason.
# ----------------------------------------------------------------------------


class TestResolveRequiresReason:
    def test_empty_reason_is_refused(self, wired):
        finding_id = _seed_http_finding()
        approval_id = _request(finding_id)["approval_id"]

        result = server.resolve_approval(approval_id, "approve", "Garrett", "")

        assert "error" in result
        assert "reason" in result["error"].lower()
        # The approval must still be pending -- the refusal changed nothing.
        assert server._approvals[approval_id].state.value == "pending"

    def test_whitespace_reason_is_refused(self, wired):
        finding_id = _seed_http_finding()
        approval_id = _request(finding_id)["approval_id"]
        result = server.resolve_approval(approval_id, "approve", "Garrett", "   ")
        assert "error" in result

    def test_named_reason_still_resolves(self, wired):
        finding_id = _seed_http_finding()
        approval_id = _request(finding_id)["approval_id"]
        result = server.resolve_approval(
            approval_id, "approve", "Garrett", "Diff reviewed on screen."
        )
        assert result["state"] == "approved"
