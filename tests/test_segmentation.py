# ============================================================
# Module:       tests/test_segmentation.py
# Purpose:      Unit tests for BUG 3: the cross-device segmentation heuristic in
#               netagent/audit.py must FLAG A CANDIDATE (source AGENT_REASONING)
#               when an edge ACL appears to protect the server subnet but the
#               core is dual-homed into the same untrusted net and routes to the
#               servers unfiltered -- and must stay quiet when there is no gap.
# Usage:        pytest tests/  (from the network-agent-mcp directory)
# Dependencies: pytest, pydantic>=2 (via netagent.models)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. REAL lab IPs
#               (RFC1918): untrusted net 172.16.99.0/24, servers 10.10.30.0/24.
# ============================================================
"""Tests for the cross-device segmentation candidate flag (the CRITICAL hook).

The Option B topology: edge-rtr-01 holds PROTECT_SERVERS inbound on its untrusted
leg (172.16.99.1); core-rtr-01 is dual-homed into the SAME untrusted net
(172.16.99.2) and has a route to 10.10.30.0/24 with no equivalent filter -- an
alternate, unfiltered path the edge ACL does not cover.
"""

from __future__ import annotations

from netagent.audit import _check_segmentation, _DeviceState
from netagent.models import FindingSource, Severity


def _state(hostname: str, running_config: str) -> _DeviceState:
    return _DeviceState(
        hostname=hostname,
        os_type="ios-xe",
        version="17.16.1a",
        running_config=running_config,
        version_evidence="Version 17.16.1a",
    )


# edge-rtr-01: the ACL that "looks like" it protects the servers, applied
# inbound on the untrusted leg.
EDGE_PROTECTED = """\
hostname edge-rtr-01
!
ip access-list extended PROTECT_SERVERS
 permit tcp any 10.10.30.0 0.0.0.255 eq 80
 deny ip any 10.10.30.0 0.0.0.255
 permit ip any any
!
interface Ethernet0/0
 description To server subnet
 ip address 10.10.30.254 255.255.255.0
!
interface Ethernet0/1
 description Untrusted net via unmanaged switch
 ip address 172.16.99.1 255.255.255.0
 ip access-group PROTECT_SERVERS in
!
end
"""

# core-rtr-01: dual-homed into the same untrusted net, routes to the servers,
# NO inbound filter on the untrusted leg. This is the gap.
CORE_EXPOSED = """\
hostname core-rtr-01
!
interface Ethernet0/0
 description Core-to-edge transit
 ip address 10.0.12.2 255.255.255.0
!
interface Ethernet0/2
 description Rogue leg into the untrusted net
 ip address 172.16.99.2 255.255.255.0
!
ip route 10.10.30.0 255.255.255.0 10.0.12.1
!
end
"""

# core-rtr-01, gap ABSENT (filtered): same untrusted leg, but now it carries an
# inbound ACL that references the server subnet -- the path is filtered too.
CORE_FILTERED = """\
hostname core-rtr-01
!
ip access-list extended PROTECT_SERVERS
 permit tcp any 10.10.30.0 0.0.0.255 eq 80
 deny ip any 10.10.30.0 0.0.0.255
 permit ip any any
!
interface Ethernet0/2
 description Untrusted leg, now filtered
 ip address 172.16.99.2 255.255.255.0
 ip access-group PROTECT_SERVERS in
!
ip route 10.10.30.0 255.255.255.0 10.0.12.1
!
end
"""

# core-rtr-01, gap ABSENT (leg down): no interface on the untrusted net at all.
CORE_LEG_DOWN = """\
hostname core-rtr-01
!
interface Ethernet0/0
 description Core-to-edge transit
 ip address 10.0.12.2 255.255.255.0
!
ip route 10.10.30.0 255.255.255.0 10.0.12.1
!
end
"""


class TestSegmentationGapPresent:
    def test_flags_one_critical_candidate(self):
        states = [_state("edge-rtr-01", EDGE_PROTECTED), _state("core-rtr-01", CORE_EXPOSED)]
        findings = _check_segmentation(states)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.category == "segmentation"
        # HYBRID: a candidate the agent confirms, NOT a deterministic assertion.
        assert f.source == FindingSource.AGENT_REASONING
        # Both devices implicated; edge (protected) first, core (exposed) second.
        assert set(f.devices) == {"edge-rtr-01", "core-rtr-01"}
        # Human-author only -- never auto-bundled across two devices.
        assert f.remediation_kind == ""

    def test_evidence_is_real_config_lines(self):
        states = [_state("edge-rtr-01", EDGE_PROTECTED), _state("core-rtr-01", CORE_EXPOSED)]
        f = _check_segmentation(states)[0]
        joined = "\n".join(f.evidence)

        # Edge: the ACL block (header names the ACL; entries reference the subnet)
        # plus its inbound application on the untrusted leg.
        assert "ip access-group PROTECT_SERVERS in" in joined
        assert "ip access-list extended PROTECT_SERVERS" in joined
        assert any("10.10.30.0" in line and "PROTECT_SERVERS" not in line for line in f.evidence)
        # Core: the untrusted leg + its unfiltered route to the servers.
        assert "ip address 172.16.99.2 255.255.255.0" in joined
        assert "ip route 10.10.30.0 255.255.255.0 10.0.12.1" in joined

    def test_order_independent(self):
        # The core may be gathered before the edge; still one finding.
        states = [_state("core-rtr-01", CORE_EXPOSED), _state("edge-rtr-01", EDGE_PROTECTED)]
        assert len(_check_segmentation(states)) == 1


class TestSegmentationGapAbsent:
    def test_core_leg_filtered_is_clean(self):
        states = [_state("edge-rtr-01", EDGE_PROTECTED), _state("core-rtr-01", CORE_FILTERED)]
        assert _check_segmentation(states) == []

    def test_core_leg_down_is_clean(self):
        states = [_state("edge-rtr-01", EDGE_PROTECTED), _state("core-rtr-01", CORE_LEG_DOWN)]
        assert _check_segmentation(states) == []

    def test_edge_only_is_clean(self):
        # No second device dual-homed into the untrusted net -> no gap.
        assert _check_segmentation([_state("edge-rtr-01", EDGE_PROTECTED)]) == []
