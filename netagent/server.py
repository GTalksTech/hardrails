# ============================================================
# Module:       server.py
# Purpose:      FastMCP (stdio) server exposing the bounded network-agent tools.
#               EVERY tool routes through the server-side Boundary: read tools
#               run free, the apply tool is gated behind a human approval.
# Dependencies: fastmcp, pydantic>=2 (+ netmiko/pyyaml via the netagent modules)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Credentials are
#               read from the NETAGENT_PASSWORD env var at runtime. Part of
#               the Hardrails framework reference implementation.
# ============================================================
"""The MCP host surface for Hardrails.

This file is thin on purpose. It does not re-implement any policy -- it wires
the agent's tools to the Boundary and the domain modules. The rule the whole
framework rests on is visible in one place here: read tools are declared READ and
run autonomously; `apply_remediation` is declared MUTATE and cannot run without
an APPROVED, single-device ApprovalRequest. The boundary enforces that; the
server just routes calls through it and hands blocks back to the agent as text.

State (proposals, approvals, cached findings) lives in module-level dicts. One
server process = one session; that is intentional for a lab demo. A production
deployment would persist these, but the boundary logic would not change.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

import netagent
from netagent import approval as approval_mod
from netagent import artifacts as artifacts_mod
from netagent import remediation as remediation_mod
from netagent import trusted_path as trusted_path_mod
from netagent.audit import audit_security_posture as run_posture_sweep
from netagent.boundary import Boundary, BoundaryViolation, ToolKind
from netagent.cve_source import ChainedCVESource
from netagent.devices import DeviceConnection, get_device, load_inventory
from netagent.models import (
    ApprovalRequest,
    Finding,
    RemediationProposal,
    ToolDecision,
)

mcp = FastMCP("netagent")
boundary = Boundary()

# The default CVE backend: live PSIRT openVuln API, pinned-cache fallback.
# One instance for the server's lifetime so the OAuth token cache survives
# across sweeps. Construction touches nothing; creds are read at lookup time.
_cve_source = ChainedCVESource()

# -- in-memory session state -------------------------------------------------
# Findings are cached by id so a remediation can be proposed against the exact
# finding the audit produced (never a finding the model invents).
_findings: dict[str, Finding] = {}
_proposals: dict[str, RemediationProposal] = {}
_approvals: dict[str, ApprovalRequest] = {}
_approval_counter = 0

# The live approval surface (mode `trusted` only; started in main()). Kept as
# module state so request_approval can hand out per-approval URLs.
_approval_surface: trusted_path_mod.ApprovalSurface | None = None

# How the human's decision is allowed to enter (issue #9).
_APPROVAL_MODE_ENV = "NETAGENT_APPROVAL_MODE"
_SECRET_FILE_ENV = "NETAGENT_APPROVAL_SECRET_FILE"


def _approval_mode() -> str:
    """'trusted' (default) or 'tool' (testing purposes only).

    Anything unrecognized resolves to 'trusted' -- a typo in an env var must
    fail closed, never quietly open the relayed path.
    """
    mode = os.environ.get(_APPROVAL_MODE_ENV, "trusted").strip().lower()
    return mode if mode == "tool" else "trusted"


def _surface_url(approval_id: str) -> str | None:
    """The approval page URL for one approval, or None if no live surface."""
    if _approval_surface is None:
        return None
    return _approval_surface.url_for(approval_id)


# -- argument schemas (the boundary validates these before a tool runs) ------


class RunShowArgs(BaseModel):
    device: str = Field(..., description="Inventory hostname, e.g. 'core-rtr-01'.")
    command: str = Field(..., description="A show/ping/traceroute command only.")


class FindingRef(BaseModel):
    finding_id: str
    device: str


class ResolveArgs(BaseModel):
    approval_id: str
    decision: str = Field(..., description="'approve' or 'reject'.")
    approver: str
    reason: str = Field(
        "",
        description="REQUIRED non-empty: the human's explicit decision, e.g. "
        "'Reviewed the diff on screen; approved for core-rtr-01 only'. An "
        "empty reason is refused.",
    )


class ApplyArgs(BaseModel):
    approval_id: str
    device: str = Field(..., description="Must match the approval's device.")


# -- boundary registration (one line per tool = the whole policy at a glance) -
boundary.register("list_devices", ToolKind.READ)
boundary.register("run_show", ToolKind.READ, RunShowArgs)
boundary.register("audit_security_posture", ToolKind.READ)
boundary.register("propose_remediation", ToolKind.READ, FindingRef)
boundary.register("request_approval", ToolKind.READ, FindingRef)
boundary.register("resolve_approval", ToolKind.READ, ResolveArgs)
boundary.register("get_audit_log", ToolKind.READ)
boundary.register("apply_remediation", ToolKind.MUTATE, ApplyArgs)


def _blocked(exc: BoundaryViolation) -> dict[str, Any]:
    """Turn a boundary BLOCK into a clear payload for the agent.

    The block is already recorded in the audit log; here we just make the reason
    legible so the model understands why it was stopped and does not retry blind.
    """
    return {"blocked": True, "reason": exc.record.reason, "tool": exc.record.tool_name}


# ============================================================================
# READ TOOLS -- run autonomously (still audited).
# ============================================================================


@mcp.tool()
def list_devices() -> Any:
    """List the devices the agent may operate on (from inventory.yaml)."""
    def _run() -> list[dict]:
        return [
            {"hostname": d.hostname, "host": d["host"], "role": d.role}
            for d in load_inventory()
        ]

    try:
        return boundary.guard("list_devices", {}, _run)
    except BoundaryViolation as exc:
        return _blocked(exc)


@mcp.tool()
def run_show(device: str, command: str) -> Any:
    """Run ONE read-only show/ping/traceroute command against a device.

    The read path physically refuses config/write commands; the boundary also
    schema-validates the arguments first.
    """
    args = {"device": device, "command": command}

    def _run() -> str:
        with DeviceConnection(get_device(device)) as conn:
            return conn.run_show(command)

    try:
        return boundary.guard("run_show", args, _run)
    except BoundaryViolation as exc:
        return _blocked(exc)


@mcp.tool()
def audit_security_posture() -> Any:
    """Run the full posture sweep; return findings ranked worst-first.

    Read-only end to end. Results are cached so a remediation can later be
    proposed against the exact finding id produced here. The payload names
    which CVE backend answered (live PSIRT API vs. dated pinned cache) --
    both are honest, but they are different claims, and the difference
    should never be invisible.
    """
    def _run() -> dict:
        findings = run_posture_sweep(cve_source=_cve_source)
        _findings.clear()
        for f in findings:
            _findings[f.id] = f
        return {
            "cve_source": _cve_source.answered_by,
            "cve_source_fallback_reason": _cve_source.fallback_reason,
            "findings": [f.model_dump(mode="json") for f in findings],
        }

    try:
        return boundary.guard("audit_security_posture", {}, _run)
    except BoundaryViolation as exc:
        return _blocked(exc)


@mcp.tool()
def propose_remediation(finding_id: str, device: str) -> Any:
    """Build a DRY-RUN remediation proposal for one finding on one device.

    Read-only: it fetches the running-config, renders a diff, and returns the
    exact CLI for human review. It applies NOTHING. Returns a proposal_id to
    reference in request_approval.

    A finding with no canned generator (NTP auth, non-HTTP CVEs, the
    cross-device gap, drift) comes back as a STRUCTURED refusal --
    `human_author_required: true` plus the reason -- not an exception. The
    refusal is the honesty model working as designed, so it must read as a
    normal result, never as a tool failure.
    """
    args = {"finding_id": finding_id, "device": device}

    def _run() -> dict:
        finding = _findings.get(finding_id)
        if finding is None:
            return {
                "error": f"Unknown finding '{finding_id}'. Run "
                "audit_security_posture first and use an id from its output."
            }
        with DeviceConnection(get_device(device)) as conn:
            running = conn.get_running_config()
        try:
            proposal = remediation_mod.build_proposal(finding, device, running)
        except remediation_mod.RemediationError as err:
            return {
                "human_author_required": True,
                "finding_id": finding_id,
                "device": device,
                "reason": str(err),
                "message": "No automated remediation exists for this finding. "
                "A human must author and review the change; nothing was "
                "proposed and nothing will be applied.",
            }
        proposal_id = f"{finding_id}:{device}"
        _proposals[proposal_id] = proposal
        payload = proposal.model_dump(mode="json")
        payload["proposal_id"] = proposal_id
        # The server teaches its own flow at every seam (issue #4): blocked
        # mutations prescribe the sequence and request_approval instructs the
        # resolve step, but this success payload relied on the tool
        # description alone -- and field testing showed agents presenting the
        # diff and stopping, leaving no approval id or artifact at the moment
        # the human was actually reviewing.
        payload["message"] = (
            "Dry-run only -- nothing was applied. Next step, in this same "
            f"turn: call request_approval(finding_id='{finding_id}', "
            f"device='{device}') so the approval ID, the on-disk artifact, "
            "and the approval_url exist while the human reviews this diff. "
            "Then present the diff and the approval_url together."
        )
        return payload

    try:
        return boundary.guard("propose_remediation", args, _run)
    except BoundaryViolation as exc:
        return _blocked(exc)


@mcp.tool()
def request_approval(finding_id: str, device: str) -> Any:
    """Open a PENDING human-approval gate for a previously built proposal.

    Bookkeeping only -- touches no device. Returns an approval_id AND writes the
    on-disk approval artifact (approvals/<approval-id>.md: the commands, the
    dry-run diff, the state) so the human has a reviewable file, not just chat
    scrollback. Nothing can be applied until a human resolves this via
    resolve_approval.
    """
    args = {"finding_id": finding_id, "device": device}

    def _run() -> dict:
        proposal_id = f"{finding_id}:{device}"
        proposal = _proposals.get(proposal_id)
        if proposal is None:
            return {
                "error": f"No proposal for '{proposal_id}'. Call "
                "propose_remediation first."
            }
        global _approval_counter
        _approval_counter += 1
        approval_id = f"appr-{_approval_counter}"
        request = approval_mod.create_approval_request(proposal)
        _approvals[approval_id] = request
        artifact = artifacts_mod.update_artifact(
            approval_id, request, boundary.audit_log_path, "requested (pending)"
        )
        approval_url = _surface_url(approval_id)
        if approval_url:
            message = (
                "Awaiting human approval. Give the human the approval_url -- "
                "they open it on a device that is NOT this machine, review "
                "the dry-run diff, and decide there. This server refuses "
                "approvals relayed through resolve_approval."
            )
        else:
            message = (
                "Awaiting human approval. Show the human the dry-run diff "
                "and this approval_id (the artifact file holds both); a "
                "person must decide. (No live approval surface: in trusted "
                "mode approvals are impossible until it is up; in the "
                "testing-only tool mode resolve_approval relays the "
                "decision.)"
            )
        return {
            "approval_id": approval_id,
            "state": "pending",
            "device": proposal.device,
            "config_commands": proposal.config_commands,
            "approval_artifact": str(artifact) if artifact else None,
            "approval_url": approval_url,
            "message": message,
        }

    try:
        return boundary.guard("request_approval", args, _run)
    except BoundaryViolation as exc:
        return _blocked(exc)


@mcp.tool()
def resolve_approval(
    approval_id: str, decision: str, approver: str, reason: str = ""
) -> Any:
    """Approve or reject a pending request (the human-in-the-loop decision).

    `decision` is 'approve' or 'reject'. Requires a named approver AND a
    non-empty reason describing the human's explicit decision -- an anonymous
    or unexplained approval is refused. This is the moment a person takes
    ownership, and the approval artifact is updated to record it.
    """
    args = {
        "approval_id": approval_id,
        "decision": decision,
        "approver": approver,
        "reason": reason,
    }

    def _run() -> dict:
        request = _approvals.get(approval_id)
        if request is None:
            return {"error": f"Unknown approval '{approval_id}'."}
        # Demotion (issue #9): in trusted mode this tool cannot approve --
        # approving is the one act that must not be relayable by the model.
        # Rejecting stays tool-callable because a forged rejection fails safe:
        # nothing gets applied.
        if decision.lower() == "approve" and _approval_mode() == "trusted":
            return {
                "error": "Refused: this server accepts approvals only via "
                "the approval page (the approval_url returned by "
                "request_approval), opened on a device that is not this "
                "machine. resolve_approval can only reject. "
                "(NETAGENT_APPROVAL_MODE=tool enables the relayed mode, "
                "for testing purposes only.)"
            }
        try:
            if decision.lower() == "approve":
                approval_mod.approve(request, approver, reason)
            elif decision.lower() == "reject":
                approval_mod.reject(request, approver, reason)
            else:
                return {"error": "decision must be 'approve' or 'reject'."}
        except approval_mod.ApprovalError as err:
            return {"error": str(err)}
        artifact = artifacts_mod.update_artifact(
            approval_id,
            request,
            boundary.audit_log_path,
            f"{request.state.value} by {request.approver}: {request.reason}",
        )
        return {
            "approval_id": approval_id,
            "state": request.state.value,
            "approver": request.approver,
            "approval_artifact": str(artifact) if artifact else None,
            "resolved_at": request.resolved_at.isoformat() if request.resolved_at else None,
        }

    try:
        return boundary.guard("resolve_approval", args, _run)
    except BoundaryViolation as exc:
        return _blocked(exc)


@mcp.tool()
def get_audit_log() -> Any:
    """Return the append-only audit log: every tool call, allowed or blocked.

    This is the receipt. On camera it proves exactly what the agent attempted
    and what the boundary permitted. `audit_log_path` is the durable JSONL copy
    on disk -- the log survives a server restart, and you can point at the file.
    """
    def _run() -> dict:
        return {
            "audit_log_path": str(boundary.audit_log_path),
            "records": [r.model_dump(mode="json") for r in boundary.audit_log()],
        }

    # Note: this call itself is recorded, so its own entry appears on the NEXT read.
    try:
        return boundary.guard("get_audit_log", {}, _run)
    except BoundaryViolation as exc:
        return _blocked(exc)


# ============================================================================
# MUTATE TOOL -- gated behind an approved, single-device ApprovalRequest.
# ============================================================================


@mcp.tool()
def apply_remediation(approval_id: str, device: str) -> Any:
    """Apply an APPROVED proposal to ONE device. The only write tool.

    The boundary blocks this unless `approval_id` refers to an APPROVED request
    whose device matches `device`. Even if it somehow slips through, the
    apply_approved() function re-asserts approval + single-device before entering
    config mode. Two gates, both server-side.

    An UNKNOWN approval_id is routed through the boundary too (approval=None ->
    audited BLOCK), never short-circuited into a bare error -- every call gets
    its ToolCallRecord, and the block reason teaches the required flow.
    """
    args = {"approval_id": approval_id, "device": device}

    # May be None (unknown id). Deliberately NOT returned early: the boundary
    # must see and record the call either way.
    request = _approvals.get(approval_id)

    def _run() -> dict:
        output = remediation_mod.apply_approved(request.proposal, request)
        artifact = artifacts_mod.update_artifact(
            approval_id,
            request,
            boundary.audit_log_path,
            # A short receipt of the outcome -- NEVER the device payload.
            f"applied to {request.proposal.device}: "
            f"{len(output)} chars of device output",
        )
        return {
            "applied": True,
            "device": request.proposal.device,
            "commands": request.proposal.config_commands,
            "approval_artifact": str(artifact) if artifact else None,
            "device_output": output,
        }

    try:
        # The approval is handed to the boundary so it can verify state + device.
        return boundary.guard("apply_remediation", args, _run, approval=request)
    except BoundaryViolation as exc:
        return _blocked(exc)


# ============================================================================
# TRUSTED PATH -- the approval surface's bridge into session state.
# ============================================================================

# Enrollment record loaded once at startup (trusted mode, secret identity).
# Module state so the surface's resolve callback can verify without
# re-reading the file on every submission.
_enrollment_record: dict | None = None

# The identity seam (design doc §5): who stands behind a submission. Built
# in main() from NETAGENT_APPROVAL_IDENTITY; when unset (tests, legacy
# wiring), _current_identity() falls back to secret identity over the
# loaded enrollment.
_identity: object | None = None
_IDENTITY_ENV = "NETAGENT_APPROVAL_IDENTITY"
_TAILNET_APPROVERS_ENV = "NETAGENT_TAILNET_APPROVERS"


def _current_identity():
    if _identity is not None:
        return _identity
    if _enrollment_record is not None:
        return trusted_path_mod.SecretIdentity(enrollment=_enrollment_record)
    return None


def _build_identity() -> object:
    """Construct the identity seam from the environment. Fail-deny on gaps.

    'secret' (default): requires an enrollment (netagent-enroll).
    'tailscale': requires a non-empty NETAGENT_TAILNET_APPROVERS allowlist;
    whois does the attesting, so no enrollment is needed or loaded.
    """
    global _enrollment_record
    identity_mode = (
        os.environ.get(_IDENTITY_ENV, "secret").strip().lower() or "secret"
    )
    if identity_mode == "tailscale":
        approvers = frozenset(
            name.strip()
            for name in os.environ.get(_TAILNET_APPROVERS_ENV, "").split(",")
            if name.strip()
        )
        if not approvers:
            raise trusted_path_mod.TrustedPathError(
                "NETAGENT_APPROVAL_IDENTITY=tailscale requires a non-empty "
                "NETAGENT_TAILNET_APPROVERS allowlist (comma-separated "
                "tailnet logins or device names). An empty allowlist means "
                "nobody can approve, so the server refuses to start "
                "(fail-deny)."
            )
        if shutil.which("tailscale") is None:
            raise trusted_path_mod.TrustedPathError(
                "NETAGENT_APPROVAL_IDENTITY=tailscale, but no `tailscale` "
                "CLI is on PATH -- whois attestation is impossible, so the "
                "server refuses to start (fail-deny)."
            )
        return trusted_path_mod.TailscaleIdentity(approvers=approvers)
    _enrollment_record = trusted_path_mod.load_enrollment(_secret_file_path())
    return trusted_path_mod.SecretIdentity(enrollment=_enrollment_record)


def _secret_file_path() -> Path:
    """Env override, else next to the audit log (same discipline as the rest)."""
    override = os.environ.get(_SECRET_FILE_ENV)
    if override:
        return Path(override)
    return boundary.audit_log_path.parent / "approval-secret.json"


def _trusted_resolve(
    approval_id: str,
    *,
    decision: str,
    approver: str,
    reason: str,
    submitted_secret: str,
    source_ip: str,
) -> dict:
    """Resolve one approval from the surface, with full receipts.

    Every outcome -- including refusals (local-source hits, bad secrets) --
    lands one record on the same append-only log as the tool calls. The
    arguments recorded NEVER include the submitted secret: the audit log
    must not hold credential material, right or wrong.
    """
    args = {
        "approval_id": approval_id,
        "decision": decision,
        "approver": approver,
        "source_ip": source_ip,
    }
    request = _approvals.get(approval_id)
    if request is None:
        boundary.record_event(
            "trusted_path.resolve", args, ToolDecision.BLOCKED,
            f"Unknown approval '{approval_id}'.",
        )
        return {"error": f"Unknown approval '{approval_id}'."}
    identity = _current_identity()
    if identity is None:
        boundary.record_event(
            "trusted_path.resolve", args, ToolDecision.BLOCKED,
            "No identity configured; approvals are impossible (fail-deny).",
        )
        return {"error": "No identity configured; approvals are impossible."}
    try:
        trusted_path_mod.resolve_trusted(
            request,
            decision=decision,
            approver=approver,
            reason=reason,
            submitted_secret=submitted_secret,
            identity=identity,
            source_ip=source_ip,
        )
    except (trusted_path_mod.TrustedPathError, approval_mod.ApprovalError) as err:
        boundary.record_event(
            "trusted_path.resolve", args, ToolDecision.BLOCKED, str(err)
        )
        return {"error": str(err)}
    boundary.record_event(
        "trusted_path.resolve", args, ToolDecision.ALLOWED,
        # request.approver is what the identity seam attested -- in tailnet
        # mode that is the whois login, not the name typed on the page.
        f"{request.state.value} by {request.approver} via trusted path "
        f"from {source_ip}.",
    )
    artifacts_mod.update_artifact(
        approval_id, request, boundary.audit_log_path,
        f"{request.state.value} by {request.approver} via trusted path: "
        f"{request.reason}",
    )
    return {
        "approval_id": approval_id,
        "state": request.state.value,
        "approver": request.approver,
    }


def main() -> None:
    """Start the server: record the mode, wire the surface, then serve stdio.

    Fail-deny is enforced HERE, at the door: in trusted mode a missing
    enrollment or no non-loopback address is a refusal to start, never a
    silent downgrade to relayed approvals.
    """
    global _approval_surface, _identity
    mode = _approval_mode()
    identity_mode = (
        os.environ.get(_IDENTITY_ENV, "secret").strip().lower() or "secret"
    )
    boundary.require_trusted_channel = mode == "trusted"
    boundary.record_event(
        "server.startup",
        {
            "approval_mode": mode,
            "approval_identity": identity_mode,
            "version": netagent.__version__,
        },
        ToolDecision.ALLOWED,
        f"netagent {netagent.__version__} starting; approval mode: {mode}; "
        f"identity: {identity_mode}.",
    )
    if mode == "tool":
        print(
            "netagent: NETAGENT_APPROVAL_MODE=tool -- approvals are relayed "
            "strings, UNATTESTED. For testing purposes only; never operate "
            "this mode against a device you care about.",
            file=sys.stderr,
        )
    else:
        try:
            _identity = _build_identity()
            bind = os.environ.get("NETAGENT_APPROVAL_BIND")
            if bind:
                bind = trusted_path_mod.resolve_bind(bind)
            else:
                # Tailnet identity: the approving peer arrives over the
                # tailnet, so the surface prefers the Tailscale address.
                bind = trusted_path_mod.select_bind_address(
                    prefer_cgnat=identity_mode == "tailscale"
                )
            tls_context = trusted_path_mod.tls_from_env(
                os.environ.get("NETAGENT_APPROVAL_TLS_CERT"),
                os.environ.get("NETAGENT_APPROVAL_TLS_KEY"),
            )
        except trusted_path_mod.TrustedPathError as err:
            print(f"netagent: refusing to start: {err}", file=sys.stderr)
            raise SystemExit(2)
        port = int(os.environ.get("NETAGENT_APPROVAL_PORT", "8484"))
        _approval_surface = trusted_path_mod.ApprovalSurface(
            bind_address=bind,
            get_request=_approvals.get,
            resolve=_trusted_resolve,
            port=port,
            tls_context=tls_context,
            display_host=os.environ.get("NETAGENT_APPROVAL_HOSTNAME"),
        )
        _approval_surface.start()
        print(
            f"netagent: approval surface at {_approval_surface.base_url} -- "
            "open approval URLs on a device that is NOT this machine.",
            file=sys.stderr,
        )
    # stdio transport is the default -- Claude Code launches this over stdio
    # via the .mcp.json entry. The MCP side opens no network listener; the
    # approval surface above is the only port, and it is not the agent's.
    mcp.run()


if __name__ == "__main__":
    main()
