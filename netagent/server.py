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
episode rests on is visible in one place here: read tools are declared READ and
run autonomously; `apply_remediation` is declared MUTATE and cannot run without
an APPROVED, single-device ApprovalRequest. The boundary enforces that; the
server just routes calls through it and hands blocks back to the agent as text.

State (proposals, approvals, cached findings) lives in module-level dicts. One
server process = one session; that is intentional for a lab demo. A production
deployment would persist these, but the boundary logic would not change.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from netagent import approval as approval_mod
from netagent import remediation as remediation_mod
from netagent.audit import audit_security_posture as run_posture_sweep
from netagent.boundary import Boundary, BoundaryViolation, ToolKind
from netagent.cve_source import ChainedCVESource
from netagent.devices import DeviceConnection, get_device, load_inventory
from netagent.models import ApprovalRequest, Finding, RemediationProposal

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
    reason: str = ""


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
        proposal = remediation_mod.build_proposal(finding, device, running)
        proposal_id = f"{finding_id}:{device}"
        _proposals[proposal_id] = proposal
        payload = proposal.model_dump(mode="json")
        payload["proposal_id"] = proposal_id
        return payload

    try:
        return boundary.guard("propose_remediation", args, _run)
    except BoundaryViolation as exc:
        return _blocked(exc)


@mcp.tool()
def request_approval(finding_id: str, device: str) -> Any:
    """Open a PENDING human-approval gate for a previously built proposal.

    Bookkeeping only -- touches no device. Returns an approval_id. Nothing can
    be applied until a human resolves this via resolve_approval.
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
        _approvals[approval_id] = approval_mod.create_approval_request(proposal)
        return {
            "approval_id": approval_id,
            "state": "pending",
            "device": proposal.device,
            "config_commands": proposal.config_commands,
            "message": "Awaiting human approval. A person must call "
            "resolve_approval to approve or reject.",
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

    `decision` is 'approve' or 'reject'. Requires a named approver -- an
    anonymous approval is refused. This is the moment a person takes ownership.
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
        try:
            if decision.lower() == "approve":
                approval_mod.approve(request, approver, reason)
            elif decision.lower() == "reject":
                approval_mod.reject(request, approver, reason)
            else:
                return {"error": "decision must be 'approve' or 'reject'."}
        except approval_mod.ApprovalError as err:
            return {"error": str(err)}
        return {
            "approval_id": approval_id,
            "state": request.state.value,
            "approver": request.approver,
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
    and what the boundary permitted.
    """
    def _run() -> list[dict]:
        return [r.model_dump(mode="json") for r in boundary.audit_log()]

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
    """
    args = {"approval_id": approval_id, "device": device}

    request = _approvals.get(approval_id)
    if request is None:
        return {"error": f"Unknown approval '{approval_id}'."}

    def _run() -> dict:
        output = remediation_mod.apply_approved(request.proposal, request)
        return {
            "applied": True,
            "device": request.proposal.device,
            "commands": request.proposal.config_commands,
            "device_output": output,
        }

    try:
        # The approval is handed to the boundary so it can verify state + device.
        return boundary.guard("apply_remediation", args, _run, approval=request)
    except BoundaryViolation as exc:
        return _blocked(exc)


if __name__ == "__main__":
    # stdio transport is the default -- Claude Code launches this over stdio via
    # the .mcp.json entry. No network listener, no open port.
    mcp.run()
