# ============================================================
# Module:       tests/test_restart_safe_ids.py
# Purpose:      Tests for issue #3: approval ids survive restarts without
#               collision, and the artifact sink refuses to overwrite a
#               receipt written by another session. A restart must never
#               be able to clobber the durable "who approved what" record.
# Usage:        pytest tests/  (from the repository root)
# Dependencies: pytest, fastmcp (via netagent.server), pydantic>=2
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. REAL lab IPs.
# ============================================================
"""Issue #3: the artifact is a receipt, and receipts don't get rewritten.

The old id scheme was a module-level counter that reset on restart, so a
new session's first approval minted `appr-1` again and rewrote the
previous session's `approvals/appr-1.md`. These tests pin the two-layer
fix: ids are random (collision-free across restarts), and the artifact
sink refuses to touch an on-disk file for an id this process has no
transition history for -- another session's receipt is frozen history.
"""

from __future__ import annotations

import re

import pytest

import netagent.artifacts as artifacts_mod
import netagent.server as server
from netagent import approval as approval_mod
from netagent.models import (
    ApprovalRequest,
    Finding,
    FindingSource,
    RemediationProposal,
    Severity,
)

_RUNNING = "hostname core-rtr-01\n!\nip http server\n!\nend\n"


class _FakeConn:
    def __init__(self, device):
        self._device = device

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_running_config(self):
        return _RUNNING


def _seed_finding() -> str:
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


def _reset_session_state() -> None:
    """What a process restart does to module state (same disk remains).

    Any module-level counters must reset too -- that IS the bug under
    test: a fresh process starts its numbering from scratch while the
    previous session's receipts remain on disk.
    """
    server._findings.clear()
    server._proposals.clear()
    server._approvals.clear()
    artifacts_mod._events.clear()
    for name in ("_approval_counter",):
        if hasattr(server, name):
            setattr(server, name, 0)


@pytest.fixture()
def wired(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "DeviceConnection", lambda dev: _FakeConn(dev))
    monkeypatch.setattr(server.boundary, "audit_log_path", tmp_path / "audit.jsonl")
    monkeypatch.setattr(server.boundary, "require_trusted_channel", False)
    monkeypatch.setenv("NETAGENT_APPROVAL_MODE", "tool")
    monkeypatch.delenv("NETAGENT_APPROVALS_DIR", raising=False)
    _reset_session_state()
    yield tmp_path
    _reset_session_state()


def _request_approval() -> dict:
    finding_id = _seed_finding()
    server.propose_remediation(finding_id, "core-rtr-01")
    return server.request_approval(finding_id, "core-rtr-01")


def _proposal() -> RemediationProposal:
    return RemediationProposal(
        finding_id="cve-2025-20334-http-api",
        device="core-rtr-01",
        config_commands=["no ip http server"],
        dry_run_diff="-ip http server",
    )


class TestCollisionFreeIds:
    def test_restart_mints_a_different_id(self, wired):
        first = _request_approval()
        _reset_session_state()  # the restart
        second = _request_approval()
        assert first["approval_id"] != second["approval_id"]

    def test_restart_leaves_the_first_receipt_intact(self, wired):
        first = _request_approval()
        original = open(first["approval_artifact"], encoding="utf-8").read()
        _reset_session_state()
        second = _request_approval()
        assert second["approval_artifact"] != first["approval_artifact"]
        assert (
            open(first["approval_artifact"], encoding="utf-8").read() == original
        )

    def test_ids_fit_the_artifact_sinks_safe_shape(self, wired):
        approval_id = _request_approval()["approval_id"]
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", approval_id)
        assert approval_id.startswith("appr-")


class TestForeignReceiptGuard:
    def test_sink_refuses_an_existing_file_with_no_local_history(self, tmp_path):
        request = ApprovalRequest(proposal=_proposal())
        approval_mod.approve(request, "Garrett", "Session one's decision.")
        path = artifacts_mod.update_artifact(
            "appr-cafe0001", request, tmp_path / "audit.jsonl", "approved"
        )
        original = path.read_text(encoding="utf-8")

        artifacts_mod._events.clear()  # the restart

        intruder = ApprovalRequest(proposal=_proposal())
        approval_mod.approve(intruder, "someone-else", "Session two colliding.")
        result = artifacts_mod.update_artifact(
            "appr-cafe0001", intruder, tmp_path / "audit.jsonl", "approved again"
        )
        assert result is None
        assert path.read_text(encoding="utf-8") == original

    def test_refusal_repeats_on_retry(self, tmp_path):
        request = ApprovalRequest(proposal=_proposal())
        path = artifacts_mod.update_artifact(
            "appr-cafe0002", request, tmp_path / "audit.jsonl", "requested"
        )
        original = path.read_text(encoding="utf-8")
        artifacts_mod._events.clear()
        for _ in range(2):  # a refused id must stay foreign, not get adopted
            assert (
                artifacts_mod.update_artifact(
                    "appr-cafe0002", request, tmp_path / "audit.jsonl", "retry"
                )
                is None
            )
        assert path.read_text(encoding="utf-8") == original

    def test_own_session_updates_still_work(self, tmp_path):
        """The guard must not break the normal request->resolve->apply story."""
        request = ApprovalRequest(proposal=_proposal())
        artifacts_mod.update_artifact(
            "appr-cafe0003", request, tmp_path / "audit.jsonl", "requested"
        )
        approval_mod.approve(request, "Garrett", "Reviewed.")
        path = artifacts_mod.update_artifact(
            "appr-cafe0003", request, tmp_path / "audit.jsonl", "approved"
        )
        text = path.read_text(encoding="utf-8")
        assert "requested" in text and "approved" in text
