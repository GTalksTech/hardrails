# ============================================================
# Module:       tests/test_remediation.py
# Purpose:      Unit tests for per-finding remediation dispatch in
#               netagent/remediation.py. Guards BUG 1: the generator must
#               dispatch on each finding's stable `remediation_kind`, NEVER on
#               the coarse `category`, so an NTP (hardening) finding can never
#               emit HTTP-disable commands.
# Usage:        pytest tests/  (from the network-agent-mcp directory)
# Dependencies: pytest, pydantic>=2 (via netagent.models)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. All IPs are
#               REAL lab IPs (RFC1918).
# ============================================================
"""Tests for the remediation dispatch honesty rule.

The rule BUG 1 enforces: a finding gets a canned config fix ONLY when its
detector stamped a `remediation_kind` we have a generator for. Everything else
(NTP auth, non-HTTP CVEs, the cross-device gap, drift) returns an honest
"a human must author this" refusal -- never a fabricated command set, and in
particular never the HTTP-disable commands under an unrelated label.
"""

from __future__ import annotations

import pytest

from netagent.models import Finding, FindingSource, Severity
from netagent.remediation import RemediationError, build_proposal

_HTTP_DISABLE = ["no ip http server", "no ip http secure-server"]

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


def _finding(**overrides) -> Finding:
    """Build a Finding with sane defaults; override what the test cares about."""
    base = dict(
        id="test-finding-core-rtr-01",
        severity=Severity.MEDIUM,
        title="Test finding",
        devices=["core-rtr-01"],
        category="hardening",
        source=FindingSource.DETERMINISTIC_CHECK,
        rationale="Test rationale.",
    )
    base.update(overrides)
    return Finding(**base)


class TestPerFindingDispatch:
    def test_ntp_finding_refuses_with_human_author(self):
        # BUG 1 core: the NTP finding is category 'hardening' but its
        # remediation_kind is 'ntp_auth' -- it must NOT get the HTTP generator.
        ntp = _finding(
            id="unauth-ntp-core-rtr-01",
            category="hardening",
            remediation_kind="ntp_auth",
        )
        with pytest.raises(RemediationError) as excinfo:
            build_proposal(ntp, "core-rtr-01", _RUNNING)
        assert "human" in str(excinfo.value).lower()

    def test_http_cve_finding_yields_http_disable(self):
        http_cve = _finding(
            id="cve-2025-20334-core-rtr-01",
            category="vulnerability",
            remediation_kind="disable_http",
        )
        proposal = build_proposal(http_cve, "core-rtr-01", _RUNNING)
        assert proposal.config_commands == _HTTP_DISABLE

    def test_non_http_cve_does_not_disable_http(self):
        # A non-HTTP CVE (e.g. an SNMP/SSL-VPN advisory) must NOT get the HTTP
        # generator just because it is category 'vulnerability'.
        other_cve = _finding(
            id="cve-2025-20363-core-rtr-01",
            category="vulnerability",
            remediation_kind="upgrade",
        )
        with pytest.raises(RemediationError):
            build_proposal(other_cve, "core-rtr-01", _RUNNING)

    def test_segmentation_finding_refuses(self):
        seg = _finding(
            id="cross-device-segmentation",
            category="segmentation",
            devices=["edge-rtr-01", "core-rtr-01"],
            source=FindingSource.AGENT_REASONING,
            remediation_kind="",
        )
        with pytest.raises(RemediationError):
            build_proposal(seg, "core-rtr-01", _RUNNING)

    def test_only_disable_http_kind_ever_returns_http_commands(self):
        # Regression for the whole bug class: sweep across every remediation_kind
        # a detector can stamp; ONLY 'disable_http' may produce the HTTP commands.
        kinds = ["ntp_auth", "upgrade", "segmentation", "drift", "", "disable_http"]
        for kind in kinds:
            finding = _finding(
                category="vulnerability",
                remediation_kind=kind,
            )
            try:
                proposal = build_proposal(finding, "core-rtr-01", _RUNNING)
            except RemediationError:
                continue  # human-author refusal -- fine, and NOT HTTP commands
            # If a proposal WAS produced, the only legal kind that returns the
            # HTTP-disable commands is 'disable_http'.
            if proposal.config_commands == _HTTP_DISABLE:
                assert kind == "disable_http", (
                    f"remediation_kind {kind!r} must not emit HTTP-disable commands"
                )
