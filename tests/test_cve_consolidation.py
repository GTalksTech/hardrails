# ============================================================
# Module:       tests/test_cve_consolidation.py
# Purpose:      Unit tests for BUG 4: the CVE check must consolidate the ~75-row
#               dump into readable findings -- the two condition-checked heroes
#               (CVE-2025-20334 met, CVE-2025-20363 not met) surfaced distinctly,
#               and every OTHER version-matched advisory collapsed into ONE
#               upgrade-summary finding. Condition-awareness must never fabricate
#               a precondition for an unmapped CVE.
# Usage:        pytest tests/  (from the network-agent-mcp directory)
# Dependencies: pytest, pydantic>=2 (via netagent.models)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. REAL lab IPs.
# ============================================================
"""Tests for CVE consolidation + condition-awareness.

Verified facts these tests pin (from the advisories, 2026-07-18):
  * CVE-2025-20334 (cisco-sa-ios-xe-cmd-inject-rPJM8BGL), CVSS 8.8 -> HIGH.
    Condition = HTTP Server feature enabled. Met here -> elevated hero.
  * CVE-2025-20363 (cisco-sa-http-code-exec-WmfP3h3O), CVSS 9.0. On IOS XE it is
    authenticated + RA-SSL-VPN-gated; RA SSL VPN is NOT configured here, so it
    must be DOWNGRADED (never the top CRITICAL).
"""

from __future__ import annotations

from netagent.audit import CVERecord, _check_cve, _check_segmentation, _DeviceState
from netagent.models import FindingSource, Severity

_CVE_HTTP = "CVE-2025-20334"
_CVE_SSL = "CVE-2025-20363"

HTTP_REC = CVERecord(
    cve_id=_CVE_HTTP,
    cvss=8.8,
    title="Cisco IOS XE Software HTTP API Command Injection Vulnerability",
    fixed_version="17.17.1",
    url="https://sec.cloudapps.cisco.com/.../cisco-sa-ios-xe-cmd-inject-rPJM8BGL",
    condition="HTTP Server feature enabled",
)
SSL_REC = CVERecord(
    cve_id=_CVE_SSL,
    cvss=9.0,
    title="Web Services Remote Code Execution Vulnerability",
    fixed_version="17.18.1",
    url="https://sec.cloudapps.cisco.com/.../cisco-sa-http-code-exec-WmfP3h3O",
)
# 20 unrelated version-matched advisories -- the noise that must collapse to one.
OTHER_RECS = [
    CVERecord(
        cve_id=f"CVE-2026-2{i:04d}",
        cvss=5.0 + (i % 5),
        title=f"Some IOS XE advisory {i}",
        fixed_version="17.18.2",
        url=f"https://sec.cloudapps.cisco.com/.../adv-{i}",
    )
    for i in range(20)
]


class _FakeCVE:
    """CVESource stub: returns the same advisory set for every version query."""

    def __init__(self, records):
        self._records = records

    def lookup(self, os_type, version):
        return list(self._records)


# HTTP server ENABLED (both plain + secure), no RA SSL VPN.
_HTTP_ON = """\
hostname {h}
!
ip http server
ip http secure-server
!
end
"""

# HTTP server NEUTERED (present but active-session-modules none on both).
_HTTP_NEUTERED = """\
hostname {h}
!
ip http server
ip http secure-server
ip http active-session-modules none
ip http secure-active-session-modules none
!
end
"""

# RA SSL VPN configured -> would MEET the 20363 condition.
_SSL_VPN_ON = """\
hostname {h}
!
webvpn
 enable
!
ip http server
!
end
"""


def _states(config_tmpl: str, records) -> tuple[list[_DeviceState], _FakeCVE]:
    hosts = ["core-rtr-01", "edge-rtr-01", "access-sw-01"]
    states = [
        _DeviceState(
            hostname=h,
            os_type="ios-xe",
            version="17.16.1a",
            running_config=config_tmpl.format(h=h),
            version_evidence="Version 17.16.1a",
        )
        for h in hosts
    ]
    return states, _FakeCVE(records)


def _by_id(findings):
    return {f.id: f for f in findings}


class TestHttpApiCondition:
    def test_condition_met_is_distinct_high_with_disable_http(self):
        states, src = _states(_HTTP_ON, [HTTP_REC, SSL_REC] + OTHER_RECS)
        findings = _check_cve(states, src)
        http = _by_id(findings).get("cve-2025-20334-http-api")
        assert http is not None
        assert http.severity == Severity.HIGH
        assert http.remediation_kind == "disable_http"
        assert "MET" in http.title.upper()
        # Honest scope note must be present (not a bare unauth RCE).
        assert "authenticated" in http.rationale.lower()

    def test_condition_not_met_when_web_server_neutered(self):
        states, src = _states(_HTTP_NEUTERED, [HTTP_REC, SSL_REC] + OTHER_RECS)
        findings = _check_cve(states, src)
        http = _by_id(findings).get("cve-2025-20334-http-api")
        assert http is not None
        # Downgraded and NOT auto-fixable via disable_http.
        assert http.severity == Severity.MEDIUM
        assert http.remediation_kind != "disable_http"
        assert "NOT" in http.title.upper()


class TestSslVpnCondition:
    def test_absent_ssl_vpn_downgrades_below_critical(self):
        states, src = _states(_HTTP_ON, [HTTP_REC, SSL_REC] + OTHER_RECS)
        findings = _check_cve(states, src)
        ssl = _by_id(findings).get("cve-2025-20363-ssl-vpn")
        assert ssl is not None
        # CVSS 9.0 would be CRITICAL raw; precondition absent -> must NOT be.
        assert ssl.severity != Severity.CRITICAL
        assert ssl.remediation_kind != "disable_http"
        assert "NOT" in ssl.title.upper()

    def test_present_ssl_vpn_is_not_downgraded(self):
        states, src = _states(_SSL_VPN_ON, [HTTP_REC, SSL_REC] + OTHER_RECS)
        findings = _check_cve(states, src)
        ssl = _by_id(findings).get("cve-2025-20363-ssl-vpn")
        assert ssl is not None
        assert ssl.severity == Severity.CRITICAL  # 9.0, condition now met


class TestConsolidation:
    def test_remainder_collapses_to_one_summary(self):
        states, src = _states(_HTTP_ON, [HTTP_REC, SSL_REC] + OTHER_RECS)
        findings = _check_cve(states, src)
        ids = _by_id(findings)

        # Exactly three CVE findings, not ~66 (22 advisories x 3 devices).
        assert set(ids) == {
            "cve-2025-20334-http-api",
            "cve-2025-20363-ssl-vpn",
            "cve-upgrade-summary",
        }
        summary = ids["cve-upgrade-summary"]
        # The 20 unrelated advisories collapsed; the count is surfaced.
        assert "20" in summary.title
        assert "upgrade" in summary.title.lower()
        # Spans all three devices, needs no canned config fix.
        assert set(summary.devices) == {"core-rtr-01", "edge-rtr-01", "access-sw-01"}
        assert summary.remediation_kind == ""

    def test_summary_does_not_fabricate_a_condition(self):
        # Only mapped advisories (20334/20363) may assert a checkable condition.
        states, src = _states(_HTTP_ON, [HTTP_REC, SSL_REC] + OTHER_RECS)
        summary = _by_id(_check_cve(states, src))["cve-upgrade-summary"]
        text = (summary.title + " " + summary.rationale).lower()
        assert "condition met" not in text
        assert "http server enabled" not in text

    def test_no_cve_records_yields_nothing(self):
        states, src = _states(_HTTP_ON, [])
        assert _check_cve(states, src) == []


class TestRankingAcrossChecks:
    def test_segmentation_critical_outranks_http_high_outranks_ssl(self):
        # Reuse the segmentation fixtures shape inline: a minimal gap.
        edge = _DeviceState(
            hostname="edge-rtr-01",
            os_type="ios-xe",
            version="17.16.1a",
            running_config=(
                "ip access-list extended PROTECT_SERVERS\n"
                " deny ip any 10.10.30.0 0.0.0.255\n"
                "!\n"
                "interface Ethernet0/1\n"
                " ip address 172.16.99.1 255.255.255.0\n"
                " ip access-group PROTECT_SERVERS in\n"
                "!\nend\n"
            ),
            version_evidence="Version 17.16.1a",
        )
        core = _DeviceState(
            hostname="core-rtr-01",
            os_type="ios-xe",
            version="17.16.1a",
            running_config=(
                "interface Ethernet0/2\n"
                " ip address 172.16.99.2 255.255.255.0\n"
                "!\n"
                "ip route 10.10.30.0 255.255.255.0 10.0.12.1\n"
                "!\nend\n"
            ),
            version_evidence="Version 17.16.1a",
        )
        # Give both devices HTTP on so 20334 fires HIGH.
        for s in (edge, core):
            s.running_config += "ip http server\n"

        seg = _check_segmentation([edge, core])
        cve = _check_cve([edge, core], _FakeCVE([HTTP_REC, SSL_REC]))
        combined = sorted(seg + cve, key=lambda f: f.rank_key())

        assert combined[0].category == "segmentation"
        assert combined[0].severity == Severity.CRITICAL
        # HTTP HIGH ranks above the downgraded SSL finding.
        sev_by_id = {f.id: f.severity for f in combined}
        assert sev_by_id["cve-2025-20334-http-api"] == Severity.HIGH
        assert sev_by_id["cve-2025-20363-ssl-vpn"] < Severity.HIGH
