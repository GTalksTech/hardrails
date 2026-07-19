# ============================================================
# Module:       audit.py
# Purpose:      The security-posture sweep. Gathers live device state via the
#               read-only path, runs deterministic checks (incl. a version->CVE
#               lookup against a PLUGGABLE CVE source), and returns findings
#               ranked worst-first. The CVE backend is intentionally abstract.
# Dependencies: pydantic>=2 (via models); a CVESource implementation at runtime
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Part of the
#               Hardrails framework reference implementation.
# ============================================================
"""Security-posture audit sweep.

What this produces is a ranked `list[Finding]`. Two honesty rules from models.py
are load-bearing here:

  * The version->CVE finding is tagged DETERMINISTIC_CHECK. It must come from a
    real version-to-advisory LOOKUP, never the model reciting CVE numbers. That
    lookup is delegated to a `CVESource` (below), so the *fact* is reproducible
    regardless of which backend answers.

  * The cross-device segmentation finding is tagged AGENT_REASONING. The code
    cannot cheaply encode "these two configs, joined, leave an unfiltered path" --
    that correlation is the agent's assessment. We present it as such.

The CVE source is deliberately abstract. Two real backends exist (a live Cisco
PSIRT openVuln client and a pinned offline cache -- see cve_source.py), and
audit.py must not care which one answers. It codes against the `CVESource`
interface only.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from netagent.devices import Device, DeviceConnection, load_inventory
from netagent.models import Finding, FindingSource, Severity


# ----------------------------------------------------------------------------
# The CVE source seam (PLUGGABLE -- backend decision still open).
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class CVERecord:
    """One advisory returned by a CVE source. Backend-neutral shape.

    Whatever backend we pick (live Cisco PSIRT openVuln API or a pinned cache)
    must normalize into this. `condition` captures exposure nuance -- e.g.
    CVE-2025-20334 only bites when the HTTP server is enabled.
    """

    cve_id: str
    cvss: float
    title: str
    fixed_version: str
    url: str
    condition: str = ""


@runtime_checkable
class CVESource(Protocol):
    """Interface every CVE backend implements. audit.py depends ONLY on this.

    lookup() takes an OS family + version string and returns the advisories that
    affect it. Keeping this a Protocol means we can swap a live API for an
    offline cache with zero changes to the audit logic -- the boundary between
    "how we look CVEs up" and "how we reason about them" stays clean.
    """

    def lookup(self, os_type: str, version: str) -> list[CVERecord]:
        ...


class NullCVESource:
    """CVE source that returns nothing. Kept as the injection-free default.

    The real backends live in cve_source.py (live Cisco PSIRT openVuln API,
    pinned-cache fallback, and the chained default the server injects). This
    null implementation remains so the sweep can run in isolation -- honest
    (it asserts nothing it cannot look up) rather than fabricated. cve_source.py
    imports CVERecord from here, so this module must not import it back.
    """

    def lookup(self, os_type: str, version: str) -> list[CVERecord]:
        return []


def _severity_from_cvss(cvss: float) -> Severity:
    """Map a CVSS base score to our four-level Severity (worst-first sorting)."""
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# ----------------------------------------------------------------------------
# Gathered device state.
# ----------------------------------------------------------------------------


@dataclass
class _DeviceState:
    """Read-only snapshot of one device, gathered via devices.py."""

    hostname: str
    os_type: str
    version: str
    running_config: str
    version_evidence: str  # the exact line we parsed the version from


_VERSION_RE = re.compile(r"Version\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)", re.IGNORECASE)


def _parse_state(hostname: str, show_version: str, running_config: str) -> _DeviceState:
    """Extract OS family + version from `show version` output.

    Deliberately simple parsing -- enough for the lab's IOS/IOS-XE images.
    """
    # TODO: harden OS-family detection for multi-vendor once the lab grows
    # beyond Cisco IOL. For now: IOS-XE if the banner says so, else IOS.
    # The separator is optional: IOL images mark the family as `[IOSXE]`
    # (no space, no hyphen) -- verified against the live lab 2026-07-11.
    os_type = "ios-xe" if re.search(r"IOS[- ]?XE", show_version, re.IGNORECASE) else "ios"
    match = _VERSION_RE.search(show_version)
    version = match.group(1) if match else "unknown"
    evidence = match.group(0) if match else "(version not parsed from show version)"
    return _DeviceState(
        hostname=hostname,
        os_type=os_type,
        version=version,
        running_config=running_config,
        version_evidence=evidence,
    )


def _gather(devices: list[Device], password: str | None) -> list[_DeviceState]:
    """Connect READ-ONLY to each device and snapshot version + running-config.

    One unreachable device does not abort the sweep -- we skip it. (A real
    deployment might raise a LOW 'device unreachable' finding; TODO if wanted.)
    """
    states: list[_DeviceState] = []
    for device in devices:
        try:
            with DeviceConnection(device, password=password) as conn:
                show_version = conn.get_version()
                running = conn.get_running_config()
        except Exception:  # noqa: BLE001 -- unreachable device, skip cleanly.
            # TODO: optionally emit a LOW severity 'unreachable' finding here.
            continue
        states.append(_parse_state(device.hostname, show_version, running))
    return states


# ----------------------------------------------------------------------------
# Individual checks.
# ----------------------------------------------------------------------------


# ----------------------------------------------------------------------------
# CVE surfacing (BUG 4): consolidate + condition-awareness.
# ----------------------------------------------------------------------------
# The raw version->advisory lookup returns ~24 advisories PER DEVICE. Dumping one
# finding per (advisory x device) buries the one CVE whose exposure condition is
# actually met under ~75 rows sorted by raw CVSS. So we do two things:
#
#   1. Consolidate. Only the two advisories we can CHECK a config condition for
#      surface as distinct findings; every other version-matched advisory folds
#      into ONE "upgrade to fix" summary.
#   2. Condition-awareness. A small map ties an advisory to a checkable config
#      feature. We NEVER invent a condition for an unmapped CVE -- those stay
#      "version-affected, resolved by upgrade," full stop.
#
# The map is deliberately tiny and verified (facts confirmed 2026-07-18 against
# the advisories). Adding an entry is a deliberate, sourced act -- not a guess.

# Advisory whose enabling condition is the HTTP Server feature.
# CVE-2025-20334 (cisco-sa-ios-xe-cmd-inject-rPJM8BGL), CVSS 8.8. Condition = the
# standard HTTP Server feature (no separate IOx/RESTCONF requirement). Verified.
_CVE_HTTP_API = "CVE-2025-20334"

# Advisory gated on Remote Access SSL VPN on IOS XE.
# CVE-2025-20363 (cisco-sa-http-code-exec-WmfP3h3O), CVSS 9.0. The 9.0/unauth
# case is ASA/FTD; on IOS XE it is authenticated AND RA-SSL-VPN-gated. Verified.
_CVE_SSL_VPN = "CVE-2025-20363"


def _find_record(records: list[CVERecord], cve_id: str) -> CVERecord | None:
    """Return the CVERecord for `cve_id` in a device's advisory list, or None."""
    for record in records:
        if record.cve_id.upper() == cve_id.upper():
            return record
    return None


def _http_server_lines(running_config: str) -> list[str]:
    """Verbatim `ip http (secure-)server` lines -- evidence the feature is on."""
    return [
        line.rstrip()
        for line in running_config.splitlines()
        if re.match(r"^\s*ip http (?:secure-)?server\s*$", line)
    ]


def _http_api_exposed(running_config: str) -> bool:
    """Is the HTTP Server feature actually enabled (CVE-2025-20334's condition)?

    Enabled if `ip http server` or `ip http secure-server` is present AND that
    server is not neutered by the matching `... active-session-modules none`.
    Either an enabled plain OR secure server (un-neutered) counts as exposed.
    """
    plain = bool(re.search(r"(?m)^\s*ip http server\s*$", running_config))
    secure = bool(re.search(r"(?m)^\s*ip http secure-server\s*$", running_config))
    if not (plain or secure):
        return False
    plain_neutered = bool(
        re.search(r"(?m)^\s*ip http active-session-modules none\s*$", running_config)
    )
    secure_neutered = bool(
        re.search(
            r"(?m)^\s*ip http secure-active-session-modules none\s*$", running_config
        )
    )
    if plain and not plain_neutered:
        return True
    if secure and not secure_neutered:
        return True
    return False


def _ssl_vpn_configured(running_config: str) -> bool:
    """Is Remote Access SSL VPN configured (CVE-2025-20363's IOS XE condition)?"""
    return bool(
        re.search(r"(?mi)^\s*webvpn\b", running_config)
        or re.search(r"(?mi)^\s*crypto ssl\b", running_config)
        or re.search(r"(?mi)\bssl\s+vpn\b", running_config)
    )


def _check_cve(states: list[_DeviceState], cve_source: CVESource) -> list[Finding]:
    """DETERMINISTIC version->CVE lookup across the fleet, consolidated.

    The agent never asserts a CVE from memory. Each device's (os_type, version)
    is handed to the CVE source and we report exactly what comes back -- but we
    fold it into readable findings instead of ~75 raw rows: the two
    condition-checked advisories surface distinctly (elevated if their config
    condition is met, downgraded if not), and every other version-matched
    advisory collapses into one upgrade summary.

    A failed lookup RAISES (via the source) -- an empty list means "Cisco says
    clean," never "we couldn't check." That honesty rule is unchanged.
    """
    per_host: dict[str, list[CVERecord]] = {}
    for state in states:
        per_host[state.hostname] = cve_source.lookup(state.os_type, state.version)

    findings: list[Finding] = []
    findings += _http_api_cve_finding(states, per_host)
    findings += _ssl_vpn_cve_finding(states, per_host)
    findings += _cve_upgrade_summary(states, per_host)
    return findings


def _http_api_cve_finding(
    states: list[_DeviceState], per_host: dict[str, list[CVERecord]]
) -> list[Finding]:
    """CVE-2025-20334: elevated where the HTTP server is on, downgraded where not."""
    record: CVERecord | None = None
    matched: list[_DeviceState] = []
    exposed: list[_DeviceState] = []
    for state in states:
        found = _find_record(per_host[state.hostname], _CVE_HTTP_API)
        if found is None:
            continue
        record = found
        matched.append(state)
        if _http_api_exposed(state.running_config):
            exposed.append(state)
    if record is None:
        return []

    if exposed:
        target = exposed
        severity = _severity_from_cvss(record.cvss)  # 8.8 -> HIGH
        tag = "condition MET / web server enabled"
        remediation_kind = "disable_http"
        extra_evidence = [
            f"{state.hostname}: {line}"
            for state in exposed
            for line in _http_server_lines(state.running_config)
        ] + ["Exposure condition MET: HTTP Server feature enabled."]
        surface_note = (
            "The web server IS enabled here, so the attack surface is present."
        )
        remediation = (
            "Disable the unused web server ('no ip http server' / 'no ip http "
            "secure-server'), or neuter it surgically with 'ip http "
            "active-session-modules none'. There is no vendor patch below "
            f"{record.fixed_version}; disabling removes the attack surface. "
            "Applying any change goes through a RemediationProposal + approval."
        )
    else:
        target = matched
        severity = Severity.MEDIUM  # downgraded: precondition absent
        tag = "condition NOT met / web server disabled"
        remediation_kind = ""  # upgrade / human-author, no canned config fix
        extra_evidence = [
            "Exposure condition NOT met: HTTP Server feature disabled or neutered "
            "('ip http active-session-modules none')."
        ]
        surface_note = (
            "The web server is not enabled here, so it is not currently exploitable."
        )
        remediation = (
            f"Patch to {record.fixed_version}+ on the normal upgrade cycle; the "
            "exposure precondition (an enabled web server) is absent, so no "
            "immediate config change is required."
        )

    hosts = sorted(state.hostname for state in target)
    evidence = [f"{state.hostname}: {state.version_evidence}" for state in target]
    evidence += extra_evidence
    return [
        Finding(
            id="cve-2025-20334-http-api",
            severity=severity,
            title=f"{_CVE_HTTP_API}: IOS XE HTTP API command injection -- {tag}",
            devices=hosts,
            category="vulnerability",
            remediation_kind=remediation_kind,
            source=FindingSource.DETERMINISTIC_CHECK,
            evidence=evidence,
            rationale=(
                f"{_CVE_HTTP_API} (CVSS {record.cvss}) is a real HTTP API command "
                "injection in IOS XE. Honest scope: exploitation needs an "
                "authenticated admin, or a CSRF against a logged-in admin (UI:R) "
                f"-- not a bare unauthenticated RCE. {surface_note} Cisco lists no "
                f"workaround; fixed in {record.fixed_version}."
            ),
            recommended_remediation=remediation,
            references=[record.url] if record.url else [],
        )
    ]


def _ssl_vpn_cve_finding(
    states: list[_DeviceState], per_host: dict[str, list[CVERecord]]
) -> list[Finding]:
    """CVE-2025-20363: honest debunk when RA SSL VPN is absent (downgraded)."""
    record: CVERecord | None = None
    matched: list[_DeviceState] = []
    configured: list[_DeviceState] = []
    for state in states:
        found = _find_record(per_host[state.hostname], _CVE_SSL_VPN)
        if found is None:
            continue
        record = found
        matched.append(state)
        if _ssl_vpn_configured(state.running_config):
            configured.append(state)
    if record is None:
        return []

    if configured:
        target = configured
        severity = _severity_from_cvss(record.cvss)  # 9.0 -> CRITICAL
        tag = "condition MET / RA SSL VPN configured"
        extra_evidence = ["Exposure condition MET: Remote Access SSL VPN configured."]
        surface_note = (
            "Remote Access SSL VPN IS configured here, so the precondition holds."
        )
    else:
        target = matched
        severity = Severity.MEDIUM  # downgraded: 9.0 raw, precondition absent
        tag = "condition NOT met / not currently exploitable"
        extra_evidence = [
            "Exposure condition NOT met: no Remote Access SSL VPN configuration "
            "found (no webvpn / crypto ssl)."
        ]
        surface_note = (
            "Cisco's 9.0/unauthenticated case is ASA/FTD; on IOS XE it is "
            "authenticated and gated on Remote Access SSL VPN, which is not "
            "configured on these devices -- not currently exploitable here."
        )

    hosts = sorted(state.hostname for state in target)
    evidence = [f"{state.hostname}: {state.version_evidence}" for state in target]
    evidence += extra_evidence
    return [
        Finding(
            id="cve-2025-20363-ssl-vpn",
            severity=severity,
            title=f"{_CVE_SSL_VPN}: web services RCE -- {tag}",
            devices=hosts,
            category="vulnerability",
            remediation_kind="",  # upgrade / human-author
            source=FindingSource.DETERMINISTIC_CHECK,
            evidence=evidence,
            rationale=(
                f"{_CVE_SSL_VPN} (CVSS {record.cvss}). {surface_note} "
                f"Fixed in {record.fixed_version}."
            ),
            recommended_remediation=(
                f"Patch to {record.fixed_version}+ on the normal upgrade cycle. "
                "No config change removes this; if RA SSL VPN is ever enabled, "
                "re-evaluate urgency. Any change goes through a RemediationProposal "
                "+ approval."
            ),
            references=[record.url] if record.url else [],
        )
    ]


def _cve_upgrade_summary(
    states: list[_DeviceState], per_host: dict[str, list[CVERecord]]
) -> list[Finding]:
    """Collapse every non-condition-checked advisory into ONE upgrade finding."""
    special = {_CVE_HTTP_API.upper(), _CVE_SSL_VPN.upper()}
    others: dict[str, CVERecord] = {}  # cve_id -> record (deduped across devices)
    hosts_affected: set[str] = set()
    for state in states:
        for record in per_host[state.hostname]:
            if record.cve_id.upper() in special:
                continue
            others[record.cve_id.upper()] = record
            hosts_affected.add(state.hostname)
    if not others:
        return []

    count = len(others)
    max_cvss = max(record.cvss for record in others.values())
    fixed_versions = sorted(
        {record.fixed_version for record in others.values() if record.fixed_version}
    )
    os_label = f"{states[0].os_type} {states[0].version}" if states else "the image"
    hosts = sorted(hosts_affected)
    evidence = [
        f"{state.hostname}: {state.version_evidence}"
        for state in states
        if state.hostname in hosts_affected
    ]
    references = [record.url for record in others.values() if record.url][:10]
    return [
        Finding(
            id="cve-upgrade-summary",
            severity=Severity.MEDIUM,
            title=(
                f"{count} additional advisories affect {os_label} on these "
                "devices -- resolved by upgrade"
            ),
            devices=hosts,
            category="vulnerability",
            remediation_kind="",  # a scheduled image upgrade, not a config push
            source=FindingSource.DETERMINISTIC_CHECK,
            evidence=evidence,
            rationale=(
                f"{count} further version-matched advisories (highest CVSS "
                f"{max_cvss}) have no separately checkable exposure condition, so "
                "we do not assert one -- the uniform remediation is an image "
                "upgrade, not a per-advisory config change. First-fixed releases "
                f"include: {', '.join(fixed_versions) or 'see advisories'}."
            ),
            recommended_remediation=(
                "Schedule an IOS XE upgrade to a release that clears these "
                "advisories (17.17.1+ per Cisco Software Checker). No individual "
                "config action; any change goes through a RemediationProposal + "
                "approval."
            ),
            references=references,
        )
    ]


# The Option B cross-device topology, hardcoded for the reference lab. These are
# lab facts (see lab-state-snapshot.md), not fabricated: the untrusted net the
# core is wrongly dual-homed into, and the server subnet the edge ACL claims to
# protect. Hardcoding them here is acceptable BECAUSE the evidence below is still
# pulled verbatim from the LIVE config -- the heuristic only knows WHICH subnets
# to look for; it never invents the lines it quotes.
_SEG_UNTRUSTED_PREFIX = "172.16.99."   # shared untrusted net (unmanaged switch)
_SEG_SERVER_SUBNET = "10.10.30.0"      # protected server subnet (10.10.30.0/24)


@dataclass
class _Interface:
    """One parsed interface stanza: verbatim lines + the bits we reason about."""

    name: str
    lines: list[str]              # verbatim, header + body (for evidence)
    ip: str | None = None         # dotted address on the interface, if any
    acl_in: str | None = None     # inbound access-group name, if any


def _parse_interfaces(running_config: str) -> list[_Interface]:
    """Split a running-config into interface stanzas (verbatim-preserving).

    A stanza starts at `interface X` and runs through its indented body until a
    non-indented line (including a bare `!`) ends it. We capture the exact lines
    so the segmentation finding can quote real config, plus the interface IP and
    any inbound access-group -- the two facts the heuristic joins across devices.
    """
    interfaces: list[_Interface] = []
    current: _Interface | None = None
    for raw in running_config.splitlines():
        header = re.match(r"^interface\s+(\S.*)$", raw)
        if header:
            if current is not None:
                interfaces.append(current)
            current = _Interface(name=header.group(1).strip(), lines=[raw.rstrip()])
            continue
        if current is None:
            continue
        if raw[:1].isspace():  # indented -> part of the current stanza body
            current.lines.append(raw.rstrip())
            ip_match = re.match(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+", raw)
            if ip_match:
                current.ip = ip_match.group(1)
            acl_match = re.match(r"^\s*ip access-group\s+(\S+)\s+in\b", raw)
            if acl_match:
                current.acl_in = acl_match.group(1)
        else:  # a non-indented line (or `!`) closes the stanza
            interfaces.append(current)
            current = None
    if current is not None:
        interfaces.append(current)
    return interfaces


def _acl_lines_protecting(running_config: str, acl_name: str, subnet: str) -> list[str]:
    """Return the named-ACL block lines IF any entry references `subnet`, else [].

    Captures `ip access-list ... <name>` and its indented entries verbatim, then
    only returns them when at least one entry mentions the server subnet -- i.e.
    the ACL actually claims to protect the servers. (Named extended ACLs cover
    the lab; numbered ACLs would need a separate parse -- noted, not needed here.)
    """
    block: list[str] = []
    capturing = False
    for raw in running_config.splitlines():
        if re.match(rf"^ip access-list\s+\S+\s+{re.escape(acl_name)}\s*$", raw):
            capturing = True
            block.append(raw.rstrip())
            continue
        if capturing:
            if raw[:1].isspace():
                block.append(raw.rstrip())
            else:
                break
    return block if any(subnet in line for line in block) else []


def _routes_to(running_config: str, subnet: str) -> list[str]:
    """Verbatim static-route lines toward `subnet` (the unfiltered path)."""
    return [
        line.rstrip()
        for line in running_config.splitlines()
        if re.match(rf"^ip route\s+{re.escape(subnet)}\s+", line)
    ]


def _check_segmentation(states: list[_DeviceState]) -> list[Finding]:
    """Cross-device segmentation gap -- the AGENT_REASONING showpiece (HYBRID).

    The flagship CRITICAL finding: an edge ACL appears to protect the
    server subnet, but the core is dual-homed into the SAME untrusted net and
    routes to the servers with no equivalent filter -- an alternate, unfiltered
    path the edge ACL never sees.

    This is a HYBRID: a deterministic heuristic that FLAGS A CANDIDATE, which the
    agent then confirms by reading both configs. That is exactly why the finding
    is tagged AGENT_REASONING, not DETERMINISTIC_CHECK -- the code narrows
    attention to a suspicious structural pattern; it never asserts reachability
    as ground truth (real reachability depends on ACL semantics, VRFs, and
    return paths the grep cannot see). The evidence is pulled verbatim from the
    live configs so the human can verify the candidate on camera.

    Pattern: one device (the "protected" leg) has an inbound ACL referencing the
    server subnet on an interface in the untrusted net; a DIFFERENT device (the
    "exposed" leg) has an interface in the SAME untrusted net, a route to the
    servers, and no filter that references them. Both must exist, on two devices,
    for the gap to be flagged.
    """
    protected: tuple[_DeviceState, _Interface, list[str]] | None = None
    exposed: tuple[_DeviceState, _Interface, list[str]] | None = None

    for state in states:
        untrusted_legs = [
            iface
            for iface in _parse_interfaces(state.running_config)
            if iface.ip and iface.ip.startswith(_SEG_UNTRUSTED_PREFIX)
        ]
        for iface in untrusted_legs:
            acl_block = (
                _acl_lines_protecting(
                    state.running_config, iface.acl_in, _SEG_SERVER_SUBNET
                )
                if iface.acl_in
                else []
            )
            if acl_block:
                # A leg into the untrusted net that DOES filter toward the
                # servers -- this is the "looks protected" side.
                if protected is None:
                    protected = (state, iface, acl_block)
            else:
                # A leg into the untrusted net with NO filter toward the servers.
                # Only a gap if this same device can actually route to them.
                routes = _routes_to(state.running_config, _SEG_SERVER_SUBNET)
                if routes and exposed is None:
                    exposed = (state, iface, routes)

    # Need BOTH sides, on TWO different devices, or there is no cross-device gap.
    if protected is None or exposed is None:
        return []
    if protected[0].hostname == exposed[0].hostname:
        return []

    p_state, p_iface, acl_block = protected
    e_state, e_iface, route_lines = exposed

    evidence = (
        [f"{p_state.hostname}: {line}" for line in p_iface.lines]
        + [f"{p_state.hostname}: {line}" for line in acl_block]
        + [f"{e_state.hostname}: {line}" for line in e_iface.lines]
        + [f"{e_state.hostname}: {line}" for line in route_lines]
    )

    return [
        Finding(
            id="cross-device-segmentation",
            severity=Severity.CRITICAL,
            title=(
                f"Cross-device segmentation gap: {e_state.hostname} routes to "
                f"{_SEG_SERVER_SUBNET}/24 through the untrusted net, unfiltered"
            ),
            # Edge (the leg that LOOKS protected) first, then the exposed core.
            devices=[p_state.hostname, e_state.hostname],
            category="segmentation",
            # Spans the seam between two devices -- never auto-bundled; a human
            # authors the matching filter per device (see remediation _GENERATORS).
            remediation_kind="",
            source=FindingSource.AGENT_REASONING,
            evidence=evidence,
            rationale=(
                f"{p_state.hostname} applies '{p_iface.acl_in}' inbound on "
                f"{p_iface.name} ({p_iface.ip}), which appears to protect "
                f"{_SEG_SERVER_SUBNET}/24. But {e_state.hostname} is dual-homed "
                f"into the SAME untrusted net on {e_iface.name} ({e_iface.ip}) "
                f"and has a route to {_SEG_SERVER_SUBNET}/24 with no equivalent "
                "inbound filter -- an alternate, unfiltered path to the servers "
                "that the edge ACL never sees. This is a CANDIDATE flagged by "
                "correlating both configs; confirm the reachability before acting."
            ),
            recommended_remediation=(
                f"Author a matching inbound filter on {e_state.hostname}'s "
                f"untrusted leg ({e_iface.name}), or remove that leg if the core "
                "should not be dual-homed into the untrusted net. This spans two "
                "devices, so it is authored per-device by a human -- never "
                "auto-bundled. Any change goes through a RemediationProposal + "
                "approval."
            ),
        )
    ]


def _check_mgmt_plane(state: _DeviceState) -> list[Finding]:
    """Legacy/weak management-plane crypto (Telnet, SSHv1, type-7 passwords)."""
    # TODO: parse state.running_config for `transport input telnet`, absence of
    # `ip ssh version 2`, `service password-encryption`/type-7 secrets. Emit a
    # MEDIUM 'crypto' finding, source DETERMINISTIC_CHECK, with the offending
    # config lines as evidence. Config-only -> zero hallucination risk.
    return []


# A device participates in NTP if it syncs to a server or serves time itself.
_NTP_CONFIGURED_RE = re.compile(r"^\s*ntp\s+(?:server|master)\b.*", re.MULTILINE)

# All three must be present for NTP to count as authenticated; any subset
# short of that leaves the time source spoofable.
_NTP_AUTH_LINES = ("ntp authenticate", "ntp authentication-key", "ntp trusted-key")


def _check_ntp_auth(state: _DeviceState) -> list[Finding]:
    """Unauthenticated NTP on the management plane (MEDIUM, config grep).

    Fires when the device takes or serves time (`ntp server ...` / `ntp
    master`) without the full authentication triple. No NTP at all is clean,
    authenticated NTP is clean -- an empty result always means "checked, and
    hardened or not applicable," never "could not check."
    """
    ntp_lines = [
        match.group(0).strip()
        for match in _NTP_CONFIGURED_RE.finditer(state.running_config)
    ]
    if not ntp_lines:
        return []

    missing = [
        line
        for line in _NTP_AUTH_LINES
        if not re.search(
            rf"^\s*{re.escape(line)}\b", state.running_config, re.MULTILINE
        )
    ]
    if not missing:
        return []

    return [
        Finding(
            id=f"unauth-ntp-{state.hostname}",
            severity=Severity.MEDIUM,
            title="Unauthenticated NTP: time source is spoofable",
            devices=[state.hostname],
            category="hardening",
            # Human-author only: an NTP auth fix needs a human-chosen key, so we
            # never hand it a canned generator (Option B, locked). See _GENERATORS.
            remediation_kind="ntp_auth",
            source=FindingSource.DETERMINISTIC_CHECK,
            evidence=ntp_lines,
            rationale=(
                f"{state.hostname} takes or serves time without NTP "
                f"authentication (missing: {', '.join(missing)}). An attacker "
                "who can answer as the time source can skew the clock, which "
                "undermines certificate validation, log correlation, and "
                "time-based authentication."
            ),
            recommended_remediation=(
                "Configure the NTP authentication triple -- 'ntp authenticate', "
                "'ntp authentication-key <id> md5 <key>', 'ntp trusted-key <id>' "
                "-- and key the server association ('ntp server <ip> key <id>'). "
                "Applying any change goes through a RemediationProposal + approval."
            ),
        )
    ]


class IntentSourceUnavailable(RuntimeError):
    """NetBox (the intent source of truth) could not be queried.

    Same honesty rule as cve_source.py: an empty findings list means "checked
    and clean." A lookup that cannot happen must raise, loudly -- it never
    masquerades as "no drift."
    """


_NETBOX_URL_ENV = "NETBOX_URL"
_NETBOX_TOKEN_ENV = "NETBOX_TOKEN"


def _netbox_api():
    """Build a pynetbox client from the environment -- URL + token only.

    Same credential rule as NETAGENT_PASSWORD and the PSIRT creds: env vars,
    never a file, never a CLI flag. Use a READ-ONLY NetBox token here -- the
    drift check only reads intent, so its credential should not be able to
    write. (NetBox 4.6 issues v2 tokens as `nbt_<key>.<secret>`; export the
    FULL value.)
    """
    try:
        import pynetbox  # deferred so the other checks run without it installed
    except ImportError as exc:
        raise IntentSourceUnavailable(
            "pynetbox is not installed, so the NetBox drift check cannot run. "
            "In your venv: pip install pynetbox"
        ) from exc

    url = os.environ.get(_NETBOX_URL_ENV, "http://localhost:8000")
    token = os.environ.get(_NETBOX_TOKEN_ENV, "")
    if not token:
        raise IntentSourceUnavailable(
            "NETBOX_TOKEN is not set. Export a READ-ONLY NetBox API token "
            f"(and optionally {_NETBOX_URL_ENV}; default http://localhost:8000) "
            "in the shell."
        )
    return pynetbox.api(url, token=token)


def _vlan_live_evidence(vid: int, running_config: str) -> list[str]:
    """Verbatim config lines proving VLAN `vid` is still configured.

    Three unambiguous anchors: the VLAN definition, an SVI, and an access-port
    assignment. Trunk allowed-lists are deliberately NOT parsed -- their range
    syntax ('1-4094') invites false positives, and the three anchors are
    already conclusive.
    """
    patterns = (
        rf"^\s*vlan\s+{vid}\s*$",                        # vlan definition
        rf"^\s*interface\s+Vlan\s*{vid}\s*$",            # SVI
        rf"^\s*switchport\s+access\s+vlan\s+{vid}\s*$",  # access port
    )
    lines: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, running_config, re.MULTILINE | re.IGNORECASE):
            lines.append(match.group(0).strip())
    return lines


def _check_netbox_drift(states: list[_DeviceState], netbox=None) -> list[Finding]:
    """Intent drift: live state vs. the NetBox source of truth (LOW).

    The deterministic slice of the intent diff: a VLAN NetBox records as
    `deprecated` -- intent says decommissioned -- that is still configured on
    a live device. `netbox` is injectable (any object shaped like
    `pynetbox.api()`), same seam pattern as `cve_source`; by default it is
    built from the environment. If NetBox cannot be queried this RAISES
    IntentSourceUnavailable -- the sweep fails loud rather than reporting a
    clean bill of intent it never checked.
    """
    nb = netbox if netbox is not None else _netbox_api()
    try:
        deprecated_vlans = list(nb.ipam.vlans.filter(status="deprecated"))
    except Exception as exc:  # noqa: BLE001 -- any API failure means "no answer"
        raise IntentSourceUnavailable(
            f"Could not query NetBox for VLAN intent: {exc}"
        ) from exc

    findings: list[Finding] = []
    for vlan in deprecated_vlans:
        vid = int(vlan.vid)
        per_device: dict[str, list[str]] = {}
        for state in states:
            evidence = _vlan_live_evidence(vid, state.running_config)
            if evidence:
                per_device[state.hostname] = evidence
        if not per_device:
            continue  # intent satisfied: deprecated AND actually gone

        name = str(getattr(vlan, "name", "") or "")
        label = f"VLAN {vid} ({name})" if name else f"VLAN {vid}"
        url = str(getattr(vlan, "url", "") or "")
        findings.append(
            Finding(
                id=f"netbox-drift-vlan{vid}",
                severity=Severity.LOW,
                title=f"{label} is deprecated in NetBox but still live",
                devices=sorted(per_device),
                category="drift",
                source=FindingSource.DETERMINISTIC_CHECK,
                evidence=[
                    f"{hostname}: {line}"
                    for hostname in sorted(per_device)
                    for line in per_device[hostname]
                ],
                rationale=(
                    f"NetBox records {label} as deprecated -- intent says it "
                    f"was decommissioned -- but it is still configured on "
                    f"{', '.join(sorted(per_device))}. Either the decommission "
                    "never finished or the documentation is wrong; both are "
                    "drift between intent and reality."
                ),
                recommended_remediation=(
                    "Either complete the decommission (remove the VLAN, its "
                    "SVI, and port assignments) or correct the NetBox record "
                    "if the VLAN is still legitimately in service. Any device "
                    "change goes through a RemediationProposal + approval."
                ),
                references=[url] if url else [],
            )
        )
    return findings


# ----------------------------------------------------------------------------
# The sweep.
# ----------------------------------------------------------------------------


def audit_security_posture(
    devices: list[Device] | None = None,
    cve_source: CVESource | None = None,
    password: str | None = None,
) -> list[Finding]:
    """Run the full posture sweep and return findings ranked worst-first.

    Read-only end to end: it gathers state through devices.py and produces
    Finding objects. It changes nothing. Remediation of any finding is a
    separate, human-gated path (remediation.py + approval.py).

    `cve_source` is injected so the CVE backend stays pluggable; defaults to the
    NullCVESource stub so the sweep runs before the real backend is chosen.
    """
    devices = devices if devices is not None else load_inventory()
    cve_source = cve_source if cve_source is not None else NullCVESource()

    states = _gather(devices, password)

    findings: list[Finding] = []

    # Per-device deterministic checks.
    for state in states:
        findings.extend(_check_mgmt_plane(state))
        findings.extend(_check_ntp_auth(state))

    # Fleet-wide checks (need the whole fleet's state). The CVE check consolidates
    # across devices, so it runs once over all states, not per device (BUG 4).
    findings.extend(_check_cve(states, cve_source))
    findings.extend(_check_segmentation(states))
    findings.extend(_check_netbox_drift(states))

    # Worst-first ordering, stable within a severity (rank_key from models.py).
    findings.sort(key=lambda f: f.rank_key())
    return findings
