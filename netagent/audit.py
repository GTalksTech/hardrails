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


def _check_cve(state: _DeviceState, cve_source: CVESource) -> list[Finding]:
    """DETERMINISTIC version->CVE lookup for one device.

    The agent never asserts a CVE from memory. It hands (os_type, version) to
    the CVE source and reports exactly what comes back -- reproducible, and safe
    to state on camera.
    """
    findings: list[Finding] = []
    for record in cve_source.lookup(state.os_type, state.version):
        findings.append(
            Finding(
                id=f"{record.cve_id.lower()}-{state.hostname}",
                severity=_severity_from_cvss(record.cvss),
                title=f"{record.cve_id}: {record.title}",
                devices=[state.hostname],
                category="vulnerability",
                source=FindingSource.DETERMINISTIC_CHECK,
                evidence=[state.version_evidence]
                + ([f"Exposure condition: {record.condition}"] if record.condition else []),
                rationale=(
                    f"{state.hostname} runs {state.os_type} {state.version}, which the "
                    f"CVE source flags as affected by {record.cve_id} "
                    f"(CVSS {record.cvss}). Fixed in {record.fixed_version}."
                ),
                recommended_remediation=(
                    "If no upgrade is available, reduce attack surface per the "
                    "advisory (e.g. disable the affected service). Applying any "
                    "change goes through a RemediationProposal + approval."
                ),
                references=[record.url],
            )
        )
    return findings


def _check_segmentation(states: list[_DeviceState]) -> list[Finding]:
    """Cross-device segmentation gap -- the AGENT_REASONING showpiece.

    The CRITICAL finding of the episode: an edge ACL appears to protect the
    server subnet, but the core offers an unfiltered alternate path. Proving that
    means JOINING two devices' configs and reasoning about the topology -- which
    the agent does, not a coded grep. This function is scaffolding for that
    reasoning, not a substitute for it.
    """
    # TODO: this finding is produced by the AGENT correlating the gathered
    # configs (which is why its source is AGENT_REASONING, not DETERMINISTIC).
    # The agent receives each device's running-config via the read tools and
    # asserts the gap; the server records it as a Finding. A future deterministic
    # heuristic (reachability graph across ACLs + routing) could pre-flag
    # candidates, but must NOT be presented as ground truth. Returns [] for now.
    return []


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
        findings.extend(_check_cve(state, cve_source))
        findings.extend(_check_mgmt_plane(state))
        findings.extend(_check_ntp_auth(state))

    # Cross-device checks (need the whole fleet's state).
    findings.extend(_check_segmentation(states))
    findings.extend(_check_netbox_drift(states))

    # Worst-first ordering, stable within a severity (rank_key from models.py).
    findings.sort(key=lambda f: f.rank_key())
    return findings
