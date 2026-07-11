# ============================================================
# Module:       remediation.py
# Purpose:      Build DRY-RUN remediation proposals from findings, and provide
#               the ONE gated path that actually applies an approved change to a
#               single device. Proposal-building never touches the wire.
# Dependencies: netmiko (apply path only), pydantic>=2 (via models)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Part of the
#               Hardrails framework reference implementation.
# ============================================================
"""Remediation: propose in dry-run, apply only under approval.

The split in this file mirrors the boundary itself:

    build_proposal()  -- pure, read-only, produces a RemediationProposal (the
                         exact CLI + a rendered diff). It CANNOT change a device;
                         it does not even import a live connection.

    apply_approved()  -- the single, narrow doorway that enters config mode. It
                         refuses to run unless handed an APPROVED, single-device
                         ApprovalRequest whose device matches the proposal. This
                         is the only function in the whole package that writes.

Keeping these apart is what lets us say, truthfully, that a proposal is not a
change. The type you get back from build_proposal() has no method that reaches a
device -- applying it requires a separate, human-gated call.
"""

from __future__ import annotations

import difflib

from netmiko import ConnectHandler

from netagent.devices import (
    _CONNECT_TIMEOUT,
    _READ_TIMEOUT,
    _resolve_password,
    get_device,
)
from netagent.models import (
    ApprovalRequest,
    ApprovalState,
    Finding,
    RemediationProposal,
)


class RemediationError(RuntimeError):
    """Raised when a proposal can't be built or an apply is illegal."""


# ----------------------------------------------------------------------------
# Command generation.
# ----------------------------------------------------------------------------
# Each generator returns the exact CLI a human would review for one finding
# CATEGORY, targeting ONE device. These are intentionally small and legible --
# the point of the demo is that the human reads the commands before approving,
# so they must be readable. Categories with no safe canned fix return an empty
# list and force a human to author the change (we never invent config we are
# unsure of -- that would defeat the honesty thesis).


def _remediate_hardening(finding: Finding, device: str) -> list[str]:
    """Mitigations for the hardening / CVE-exposure findings.

    For CVE-2025-20334 (IOS XE HTTP API command injection) there is no vendor
    patch below 17.17.1, but the attack surface is the web server -- which is
    unused in this lab. Disabling it REMOVES the exposure without a code upgrade.
    We are careful on camera to call this a mitigation, not a patch.
    """
    return [
        "no ip http server",
        "no ip http secure-server",
    ]


def _remediate_crypto(finding: Finding, device: str) -> list[str]:
    """Kill legacy management-plane crypto (Telnet / SSHv1 / weak transports).

    Pure config, zero device-state guesswork -- the safest class of change and a
    good one to show the approval flow on.
    """
    return [
        "ip ssh version 2",
        "line vty 0 15",
        " transport input ssh",
    ]


# Deterministic dispatch by finding category. Unknown categories -> no canned
# fix (empty list), which surfaces as "human must author this" rather than a
# fabricated command set.
_GENERATORS = {
    "hardening": _remediate_hardening,
    "vulnerability": _remediate_hardening,
    "crypto": _remediate_crypto,
    # TODO: 'segmentation' (the cross-device CRITICAL) is deliberately NOT auto-
    # generated. That fix spans the seam between two devices and must be authored
    # per-device by a human -- exactly the kind of change we refuse to bundle.
    # TODO: 'drift' remediation depends on NetBox intent; wire it once the NetBox
    # source-of-truth diff (audit.py) is live.
}


def build_proposal(
    finding: Finding,
    device: str,
    running_config: str,
) -> RemediationProposal:
    """Build a DRY-RUN RemediationProposal for ONE device from a finding.

    Read-only and side-effect-free. Raises if `device` is not one this finding
    implicates (you cannot remediate a device the finding does not name), or if
    the category has no canned generator (a human must author the change).

    `running_config` is passed in by the caller (fetched via the read path) so
    this function never opens its own connection -- it only renders a diff.
    """
    if device not in finding.devices:
        raise RemediationError(
            f"Finding {finding.id} does not implicate '{device}'. "
            f"Implicated devices: {', '.join(finding.devices)}."
        )

    generator = _GENERATORS.get(finding.category)
    if generator is None:
        raise RemediationError(
            f"No automated remediation for category '{finding.category}'. "
            "This change must be authored and reviewed by a human."
        )

    commands = generator(finding, device)
    if not commands:
        raise RemediationError(
            f"Category '{finding.category}' produced no commands for {device}. "
            "Human authoring required."
        )

    diff = _render_dry_run_diff(running_config, commands)

    return RemediationProposal(
        finding_id=finding.id,
        device=device,
        config_commands=commands,
        dry_run_diff=diff,
        notes=(
            "DRY RUN. These commands have NOT been applied. Review them, then "
            "approve to apply to this one device only. Rollback: re-enable any "
            "line this removes, or restore from the pre-change running-config."
        ),
    )


def _render_dry_run_diff(running_config: str, commands: list[str]) -> str:
    """Render an intended-vs-running preview for human review.

    This is a PREVIEW, not a simulation of IOS parser behavior. For each
    proposed command we show it as an addition; where a command negates an
    existing line (`no ...`), we surface the matching running-config line as the
    thing being removed. Honest about its own limits -- the human still reads the
    device, not just this diff.
    """
    running_lines = running_config.splitlines()
    intended = list(running_lines)

    for cmd in commands:
        stripped = cmd.strip()
        if stripped.startswith("no "):
            target = stripped[3:].strip()
            intended = [ln for ln in intended if ln.strip() != target]
        elif stripped and stripped not in (ln.strip() for ln in intended):
            intended.append(stripped)

    diff = difflib.unified_diff(
        running_lines,
        intended,
        fromfile="running-config (live)",
        tofile="intended (after proposed change)",
        lineterm="",
        n=2,
    )
    rendered = "\n".join(diff)
    return rendered or "(no textual difference detected -- review commands directly)"


def apply_approved(
    proposal: RemediationProposal,
    approval: ApprovalRequest,
    password: str | None = None,
) -> str:
    """Apply an approved proposal to ONE device. The only write path in the app.

    Every guard here is a hard assertion, not a warning -- if any fails we raise
    before a single command is sent:

      * the approval must be APPROVED (not pending/rejected),
      * the approval must be FOR this exact proposal,
      * proposal + approval must name the SAME single device.

    Only then do we open a config-mode session (the one place we bypass the
    read-only DeviceConnection) and push the reviewed commands. The boundary
    should already have blocked an unapproved call upstream; these asserts are
    the last line of defense so this function is safe even if called directly.
    """
    if approval.state is not ApprovalState.APPROVED:
        raise RemediationError(
            f"Refusing to apply: approval is '{approval.state.value}', not "
            "'approved'. A human must approve first."
        )
    if approval.proposal is not proposal and approval.proposal != proposal:
        raise RemediationError(
            "Refusing to apply: this approval was not issued for this proposal."
        )
    if approval.proposal.device != proposal.device:
        raise RemediationError(
            "Refusing to apply: approval/proposal device mismatch. "
            "One device per approval -- no substitution."
        )

    device = get_device(proposal.device)
    params = {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": device["username"],
        "password": password or _resolve_password(),
        "conn_timeout": _CONNECT_TIMEOUT,
        "read_timeout_override": _READ_TIMEOUT,
    }

    conn = ConnectHandler(**params)
    try:
        output = conn.send_config_set(proposal.config_commands)
    finally:
        conn.disconnect()
    return output
