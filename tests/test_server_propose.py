# ============================================================
# Module:       tests/test_server_propose.py
# Purpose:      Server-level tests for propose_remediation: a finding with no
#               canned generator must come back as a CLEAN structured
#               "human must author" payload -- a normal tool result, never an
#               exception the MCP host renders as a tool failure.
# Usage:        pytest tests/  (from the network-agent-mcp directory)
# Dependencies: pytest, fastmcp (via netagent.server), pydantic>=2
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. REAL lab IPs.
# ============================================================
"""The refusal must be a first-class RESULT, not an error.

On camera the agent proposes the NTP finding and the server says "a human must
author this" -- that is the honesty beat working as designed. If the refusal
surfaced as a raised exception, the MCP host would render it as a tool FAILURE
(and the audit record would read 'ERROR during execution'), which looks broken,
not bounded. These tests pin the payload shape and the audit record.
"""

from __future__ import annotations

import pytest

import netagent.server as server
from netagent.models import Finding, FindingSource, Severity, ToolDecision

_RUNNING = """\
hostname core-rtr-01
!
ip http server
ip http secure-server
!
ntp master 1
!
end
"""


class _FakeConn:
    """Read-path stand-in: returns a canned running-config, touches no device."""

    def __init__(self, device):
        self._device = device

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_running_config(self):
        return _RUNNING


@pytest.fixture()
def wired(monkeypatch, tmp_path):
    """Point the module-level server state at fakes; clean up after."""
    monkeypatch.setattr(server, "DeviceConnection", lambda dev: _FakeConn(dev))
    # Keep the test's audit records out of the repo's real receipt file.
    monkeypatch.setattr(server.boundary, "audit_log_path", tmp_path / "audit.jsonl")
    server._findings.clear()
    server._proposals.clear()
    yield
    server._findings.clear()
    server._proposals.clear()


def _seed(finding: Finding) -> None:
    server._findings[finding.id] = finding


class TestProposeRefusalIsCleanResult:
    def test_ntp_finding_returns_structured_refusal(self, wired):
        _seed(
            Finding(
                id="unauth-ntp-core-rtr-01",
                severity=Severity.MEDIUM,
                title="Unauthenticated NTP",
                devices=["core-rtr-01"],
                category="hardening",
                remediation_kind="ntp_auth",
                source=FindingSource.DETERMINISTIC_CHECK,
                rationale="test",
            )
        )

        payload = server.propose_remediation("unauth-ntp-core-rtr-01", "core-rtr-01")

        # A clean, structured refusal -- NOT an exception, NOT HTTP commands.
        assert payload["human_author_required"] is True
        assert "human" in payload["reason"].lower()
        assert "config_commands" not in payload
        assert "no ip http server" not in str(payload)

        # And the audit record is a normal ALLOWED read, not an execution error.
        record = server.boundary.last_record
        assert record.tool_name == "propose_remediation"
        assert record.decision is ToolDecision.ALLOWED
        assert "ERROR" not in record.result_summary

    def test_http_cve_finding_still_returns_proposal(self, wired):
        _seed(
            Finding(
                id="cve-2025-20334-http-api",
                severity=Severity.HIGH,
                title="CVE-2025-20334",
                devices=["core-rtr-01"],
                category="vulnerability",
                remediation_kind="disable_http",
                source=FindingSource.DETERMINISTIC_CHECK,
                rationale="test",
            )
        )

        payload = server.propose_remediation("cve-2025-20334-http-api", "core-rtr-01")

        assert payload["config_commands"] == [
            "no ip http server",
            "no ip http secure-server",
        ]
        assert payload["proposal_id"] == "cve-2025-20334-http-api:core-rtr-01"
        # The refusal marker must NOT leak into a real proposal.
        assert "human_author_required" not in payload

    def test_wrong_device_is_also_a_clean_refusal(self, wired):
        # Naming a device the finding does not implicate refuses cleanly too.
        _seed(
            Finding(
                id="cve-2025-20334-http-api",
                severity=Severity.HIGH,
                title="CVE-2025-20334",
                devices=["edge-rtr-01"],
                category="vulnerability",
                remediation_kind="disable_http",
                source=FindingSource.DETERMINISTIC_CHECK,
                rationale="test",
            )
        )
        payload = server.propose_remediation("cve-2025-20334-http-api", "core-rtr-01")
        assert payload["human_author_required"] is True
        assert "does not implicate" in payload["reason"]
