# ============================================================
# Module:       tests/test_audit_checks.py
# Purpose:      Unit tests for the deterministic audit detectors in
#               netagent/audit.py: unauthenticated NTP (MEDIUM) and
#               NetBox intent drift (LOW). Mock-fed, no live devices,
#               no live NetBox -- sample configs in, Findings out.
# Usage:        pytest tests/  (from the network-agent-mcp directory)
# Dependencies: pytest, pydantic>=2 (via netagent.models)
# Author:       G Talks Tech
# Episode:      EP010-L-ai-network-agents
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. All IPs are
#               REAL lab IPs (RFC1918) -- the lab is meant to be replicated.
# ============================================================
"""Tests for the two config-driven detectors.

The honesty rules these tests enforce (same rules cve_source.py lives by):

  * An EMPTY result means "checked and clean" -- so the clean cases assert []
    and the broken-lookup cases assert a RAISE, never a quiet [].
  * Findings only claim what the config proves. The lab's crypto is already
    hardened (no Telnet/SSHv1/type-7), so the NTP check must never smuggle
    weak-crypto language into its output.
"""

from __future__ import annotations

import pytest

from netagent.audit import (
    IntentSourceUnavailable,
    _check_netbox_drift,
    _check_ntp_auth,
    _DeviceState,
    _parse_state,
)
from netagent.models import FindingSource, Severity


def _state(hostname: str, running_config: str) -> _DeviceState:
    """Build a gathered-state snapshot around a sample running-config."""
    return _DeviceState(
        hostname=hostname,
        os_type="ios",
        version="17.16.1a",
        running_config=running_config,
        version_evidence="Version 17.16.1a",
    )


# ----------------------------------------------------------------------------
# Sample configs -- trimmed from the live 2026-06-24 lab capture. The crypto
# posture is deliberately kept in (secret 9, ssh-only vty): the lab IS hardened
# there, and the NTP check must not false-positive on it.
# ----------------------------------------------------------------------------

_HARDENED_BASE = """\
hostname {hostname}
!
service password-encryption
enable secret 9 $9$knmc6E6cIFGqLc$examplehash
username admin privilege 15 secret 9 $9$WdEsdLLZq7uHfz$examplehash
!
ip http server
ip http secure-server
!
line vty 0 4
 login local
 transport input ssh
!
"""

CORE_NTP_MASTER_NO_AUTH = _HARDENED_BASE.format(hostname="core-rtr-01") + """\
ntp master 1
!
end
"""

EDGE_NTP_SERVER_NO_AUTH = _HARDENED_BASE.format(hostname="edge-rtr-01") + """\
ntp server 192.168.1.250
!
end
"""

SW_NTP_AUTHENTICATED = _HARDENED_BASE.format(hostname="access-sw-01") + """\
ntp authenticate
ntp authentication-key 1 md5 141443180F0B7B79 7
ntp trusted-key 1
ntp server 192.168.1.250 key 1
!
end
"""

SW_NTP_PARTIAL_AUTH = _HARDENED_BASE.format(hostname="access-sw-01") + """\
ntp authenticate
ntp authentication-key 1 md5 141443180F0B7B79 7
ntp server 192.168.1.250
!
end
"""

NO_NTP_AT_ALL = _HARDENED_BASE.format(hostname="edge-rtr-01") + """\
end
"""

SWITCH_VLAN20_LIVE = _HARDENED_BASE.format(hostname="access-sw-01") + """\
vlan 20
 name Users
!
interface Ethernet0/1
 switchport access vlan 20
 switchport mode access
!
interface Vlan20
 ip address 10.10.20.1 255.255.255.0
!
ntp server 192.168.1.250
!
end
"""

SWITCH_VLAN20_GONE = _HARDENED_BASE.format(hostname="access-sw-01") + """\
vlan 30
 name Servers
!
interface Vlan30
 ip address 10.10.30.1 255.255.255.0
!
end
"""

# VLAN 200 present, VLAN 20 absent -- guards against substring matching.
SWITCH_VLAN200_ONLY = _HARDENED_BASE.format(hostname="access-sw-01") + """\
vlan 200
 name Lab200
!
interface Ethernet0/1
 switchport access vlan 200
!
interface Vlan200
 ip address 10.10.200.1 255.255.255.0
!
end
"""


# ----------------------------------------------------------------------------
# _parse_state -- OS-family detection against REAL banners.
# ----------------------------------------------------------------------------

# Verbatim first line of `show version` from the live lab (captured
# 2026-07-11 via lab.py). The IOS XE marker on IOL images is the bracketed
# `[IOSXE]` -- NO space, NO hyphen. This caught a real bug live: the pinned
# PSIRT cache (honestly frozen for `iosxe`) refused to answer for a device
# misparsed as `ios`.
_LIVE_IOL_BANNER = (
    "Cisco IOS Software [IOSXE], Linux Software "
    "(X86_64BI_LINUX-ADVENTERPRISEK9-M), Version 17.16.1a, "
    "RELEASE SOFTWARE (fc1)"
)


class TestParseState:
    def test_live_iol_banner_is_ios_xe(self):
        state = _parse_state("core-rtr-01", _LIVE_IOL_BANNER, "")
        assert state.os_type == "ios-xe"
        assert state.version == "17.16.1a"

    def test_spaced_and_hyphenated_banners_are_ios_xe(self):
        for marker in ("Cisco IOS XE Software", "Cisco IOS-XE Software"):
            banner = f"{marker}, Version 17.9.4a, RELEASE SOFTWARE (fc1)"
            assert _parse_state("core-rtr-01", banner, "").os_type == "ios-xe"

    def test_classic_ios_banner_stays_ios(self):
        banner = (
            "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
            "Version 15.2(2)E9, RELEASE SOFTWARE (fc3)"
        )
        assert _parse_state("access-sw-01", banner, "").os_type == "ios"


# ----------------------------------------------------------------------------
# _check_ntp_auth -- MEDIUM 'hardening' finding.
# ----------------------------------------------------------------------------


class TestNtpAuth:
    def test_ntp_master_without_auth_fires_medium(self):
        findings = _check_ntp_auth(_state("core-rtr-01", CORE_NTP_MASTER_NO_AUTH))

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.category == "hardening"
        assert finding.source == FindingSource.DETERMINISTIC_CHECK
        assert finding.devices == ["core-rtr-01"]
        assert "ntp master 1" in finding.evidence

    def test_ntp_server_without_auth_fires_medium(self):
        findings = _check_ntp_auth(_state("edge-rtr-01", EDGE_NTP_SERVER_NO_AUTH))

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert "ntp server 192.168.1.250" in finding.evidence

    def test_authenticated_ntp_is_clean(self):
        # All three auth pieces present -> hardened -> empty means CLEAN.
        assert _check_ntp_auth(_state("access-sw-01", SW_NTP_AUTHENTICATED)) == []

    def test_no_ntp_at_all_is_clean(self):
        # No NTP configured -> nothing to authenticate -> no finding.
        assert _check_ntp_auth(_state("edge-rtr-01", NO_NTP_AT_ALL)) == []

    def test_partial_auth_still_fires(self):
        # authenticate + key exist but no `ntp trusted-key` -> still unauthenticated.
        findings = _check_ntp_auth(_state("access-sw-01", SW_NTP_PARTIAL_AUTH))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_never_claims_weak_crypto(self):
        # The lab's crypto IS hardened; the dropped weak-crypto finding must not
        # leak back in through this check's wording or evidence.
        findings = _check_ntp_auth(_state("core-rtr-01", CORE_NTP_MASTER_NO_AUTH))
        text = " ".join(
            [findings[0].title, findings[0].rationale, *findings[0].evidence]
        ).lower()
        for banned in ("telnet", "sshv1", "ssh version 1", "type 7", "type-7"):
            assert banned not in text

        # And the evidence is ONLY ntp lines -- no unrelated config quoted.
        assert all(line.startswith("ntp ") for line in findings[0].evidence)


# ----------------------------------------------------------------------------
# _check_netbox_drift -- LOW 'drift' finding(s) against a fake NetBox.
# ----------------------------------------------------------------------------


class _FakeVlan:
    """The slice of a pynetbox VLAN record the drift check reads."""

    def __init__(self, vid: int, name: str, url: str = ""):
        self.vid = vid
        self.name = name
        self.url = url


class _FakeNetBox:
    """Duck-typed stand-in for pynetbox.api(): nb.ipam.vlans.filter(...)."""

    class _Vlans:
        def __init__(self, deprecated, exc=None):
            self._deprecated = deprecated
            self._exc = exc

        def filter(self, **kwargs):
            if self._exc is not None:
                raise self._exc
            assert kwargs == {"status": "deprecated"}
            return list(self._deprecated)

    class _Ipam:
        def __init__(self, vlans):
            self.vlans = vlans

    def __init__(self, deprecated_vlans=(), exc=None):
        self.ipam = self._Ipam(self._Vlans(deprecated_vlans, exc))


class TestNetboxDrift:
    def test_deprecated_vlan_still_live_fires_low(self):
        netbox = _FakeNetBox([_FakeVlan(20, "Users")])
        states = [_state("access-sw-01", SWITCH_VLAN20_LIVE)]

        findings = _check_netbox_drift(states, netbox=netbox)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.LOW
        assert finding.category == "drift"
        assert finding.source == FindingSource.DETERMINISTIC_CHECK
        assert finding.devices == ["access-sw-01"]
        assert "20" in finding.title
        # Evidence is the live config lines, attributed to the device.
        assert any("switchport access vlan 20" in line for line in finding.evidence)
        assert any("interface Vlan20" in line for line in finding.evidence)
        assert all("access-sw-01" in line for line in finding.evidence)

    def test_deprecated_vlan_actually_gone_is_clean(self):
        # Intent satisfied: NetBox says deprecated AND the config dropped it.
        netbox = _FakeNetBox([_FakeVlan(20, "Users")])
        states = [_state("access-sw-01", SWITCH_VLAN20_GONE)]
        assert _check_netbox_drift(states, netbox=netbox) == []

    def test_no_deprecated_vlans_is_clean(self):
        # Nothing deprecated in intent -> a live VLAN 20 is not drift.
        netbox = _FakeNetBox([])
        states = [_state("access-sw-01", SWITCH_VLAN20_LIVE)]
        assert _check_netbox_drift(states, netbox=netbox) == []

    def test_vlan_id_is_not_substring_matched(self):
        # VLAN 200 live must NOT satisfy "VLAN 20 is live".
        netbox = _FakeNetBox([_FakeVlan(20, "Users")])
        states = [_state("access-sw-01", SWITCH_VLAN200_ONLY)]
        assert _check_netbox_drift(states, netbox=netbox) == []

    def test_missing_token_raises_instead_of_clean(self, monkeypatch):
        # The honesty rule: "could not look up intent" must NEVER read as
        # "no drift". With no NETBOX_TOKEN the check raises, loudly.
        monkeypatch.delenv("NETBOX_TOKEN", raising=False)
        states = [_state("access-sw-01", SWITCH_VLAN20_LIVE)]

        with pytest.raises(IntentSourceUnavailable) as excinfo:
            _check_netbox_drift(states)
        assert "NETBOX_TOKEN" in str(excinfo.value)

    def test_netbox_query_failure_raises_instead_of_clean(self):
        # Same rule for a NetBox that is configured but unreachable/broken.
        netbox = _FakeNetBox(exc=ConnectionError("connection refused"))
        states = [_state("access-sw-01", SWITCH_VLAN20_LIVE)]

        with pytest.raises(IntentSourceUnavailable):
            _check_netbox_drift(states, netbox=netbox)


# ----------------------------------------------------------------------------
# Ranking -- the sweep must order MEDIUM (NTP) above LOW (drift).
# ----------------------------------------------------------------------------


def test_ntp_medium_ranks_above_drift_low():
    ntp = _check_ntp_auth(_state("core-rtr-01", CORE_NTP_MASTER_NO_AUTH))
    drift = _check_netbox_drift(
        [_state("access-sw-01", SWITCH_VLAN20_LIVE)],
        netbox=_FakeNetBox([_FakeVlan(20, "Users")]),
    )

    combined = sorted(drift + ntp, key=lambda f: f.rank_key())
    assert [f.severity for f in combined] == [Severity.MEDIUM, Severity.LOW]
