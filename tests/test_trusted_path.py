# ============================================================
# Module:       tests/test_trusted_path.py
# Purpose:      Tests for the trusted-path approval surface (issue #9): the
#               approval decision enters through a channel the agent cannot
#               write. Local-source rejection, hash-only secret enrollment,
#               provenance enforcement at the boundary, resolve_approval
#               demotion, fail-deny bind selection, and unattested stamps in
#               tool mode.
# Usage:        pytest tests/  (from the repository root)
# Dependencies: pytest, pydantic>=2 (fastmcp via netagent.server for the
#               server-level tests)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Tests use a
#               DISPOSABLE secret enrolled into tmp_path; nothing here is a
#               real credential.
# ============================================================
"""Trusted path: no agent-producible input reaches APPROVED.

The design under test (docs/specs/2026-08-05-trusted-path-approval.md) makes
two deterministic checks on every approval submission, in order:

    1. local-source rejection -- a connection from any address the server's
       own machine holds is refused, regardless of credentials;
    2. secret verification -- the submitted secret must match the enrolled
       scrypt hash.

Only a submission passing both resolves the request, and it does so carrying
TRUSTED_PATH provenance, which the boundary requires before any mutation.
Verification logic takes the source address and enrollment as explicit
arguments, so every test here runs offline with no sockets.
"""

from __future__ import annotations

import json

import pytest

import netagent.server as server
from netagent import approval as approval_mod
from netagent import artifacts as artifacts_mod
from netagent import trusted_path
from netagent.boundary import Boundary, ToolKind
from netagent.models import (
    ApprovalChannel,
    ApprovalRequest,
    ApprovalState,
    Finding,
    FindingSource,
    RemediationProposal,
    Severity,
    ToolDecision,
)

# A fake machine: loopbacks plus one LAN address the host itself holds.
_LOCAL_ADDRS = frozenset({"127.0.0.1", "::1", "192.168.1.20"})
_PHONE = "192.168.1.77"  # a foreign address on the same LAN (the second device)


def _proposal() -> RemediationProposal:
    return RemediationProposal(
        finding_id="cve-2025-20334-http-api",
        device="core-rtr-01",
        config_commands=["no ip http server", "no ip http secure-server"],
        dry_run_diff="- ip http server\n- ip http secure-server",
    )


def _pending() -> ApprovalRequest:
    return ApprovalRequest(proposal=_proposal())


@pytest.fixture()
def enrollment(tmp_path):
    """A disposable enrolled secret; returns (plaintext, loaded enrollment)."""
    secret_file = tmp_path / "approval-secret.json"
    secret = trusted_path.enroll(secret_file)
    return secret, trusted_path.load_enrollment(secret_file)


def _resolve(request, *, secret, enrollment, source, decision="approve"):
    return trusted_path.resolve_trusted(
        request,
        decision=decision,
        approver="Garrett",
        reason="Reviewed the diff on the approval page.",
        submitted_secret=secret,
        enrollment=enrollment,
        source_ip=source,
        local_addrs=_LOCAL_ADDRS,
    )


# ----------------------------------------------------------------------------
# 1. Local-source rejection: the agent's own machine can never approve.
# ----------------------------------------------------------------------------


class TestLocalSourceRejection:
    @pytest.mark.parametrize("source", ["127.0.0.1", "::1", "192.168.1.20"])
    def test_machine_held_addresses_are_refused(self, enrollment, source):
        secret, stored = enrollment
        request = _pending()
        with pytest.raises(trusted_path.TrustedPathError) as err:
            _resolve(request, secret=secret, enrollment=stored, source=source)
        assert "local" in str(err.value).lower()
        assert request.state is ApprovalState.PENDING

    def test_local_source_refused_even_with_correct_secret(self, enrollment):
        """Ordering: the source check fires before the secret is examined.

        A correct secret submitted from the server's own machine must be
        refused with the local-source reason -- proving credentials cannot
        buy the agent's box back in.
        """
        secret, stored = enrollment
        request = _pending()
        with pytest.raises(trusted_path.TrustedPathError) as err:
            _resolve(request, secret=secret, enrollment=stored, source="127.0.0.1")
        assert "local" in str(err.value).lower()
        assert "secret" not in str(err.value).lower()

    def test_foreign_source_with_correct_secret_approves(self, enrollment):
        secret, stored = enrollment
        request = _pending()
        resolved = _resolve(request, secret=secret, enrollment=stored, source=_PHONE)
        assert resolved.state is ApprovalState.APPROVED

    def test_real_local_addresses_include_loopback(self):
        addrs = trusted_path.local_addresses()
        assert "127.0.0.1" in addrs


# ----------------------------------------------------------------------------
# 2. Enrollment: hash on disk, never plaintext.
# ----------------------------------------------------------------------------


class TestSecretEnrollment:
    def test_secret_file_contains_no_plaintext(self, tmp_path):
        secret_file = tmp_path / "approval-secret.json"
        secret = trusted_path.enroll(secret_file)
        raw = secret_file.read_text(encoding="utf-8")
        assert secret not in raw
        stored = json.loads(raw)
        assert "salt" in stored and "hash" in stored

    def test_correct_secret_verifies(self, enrollment):
        secret, stored = enrollment
        assert trusted_path.verify_secret(secret, stored) is True

    def test_wrong_secret_fails(self, enrollment):
        _, stored = enrollment
        assert trusted_path.verify_secret("not-the-secret", stored) is False

    def test_reenroll_rotates_the_secret(self, tmp_path):
        secret_file = tmp_path / "approval-secret.json"
        old = trusted_path.enroll(secret_file)
        trusted_path.enroll(secret_file)  # rotate
        stored = trusted_path.load_enrollment(secret_file)
        assert trusted_path.verify_secret(old, stored) is False


# ----------------------------------------------------------------------------
# 3. Trusted resolution carries provenance; refusals change nothing.
# ----------------------------------------------------------------------------


class TestTrustedResolution:
    def test_approval_carries_trusted_channel(self, enrollment):
        secret, stored = enrollment
        resolved = _resolve(_pending(), secret=secret, enrollment=stored, source=_PHONE)
        assert resolved.channel is ApprovalChannel.TRUSTED_PATH

    def test_rejection_via_trusted_path(self, enrollment):
        secret, stored = enrollment
        resolved = _resolve(
            _pending(), secret=secret, enrollment=stored, source=_PHONE,
            decision="reject",
        )
        assert resolved.state is ApprovalState.REJECTED
        assert resolved.channel is ApprovalChannel.TRUSTED_PATH

    def test_wrong_secret_refused_and_state_unchanged(self, enrollment):
        _, stored = enrollment
        request = _pending()
        with pytest.raises(trusted_path.TrustedPathError) as err:
            _resolve(request, secret="wrong", enrollment=stored, source=_PHONE)
        assert "secret" in str(err.value).lower()
        assert request.state is ApprovalState.PENDING
        assert request.channel is ApprovalChannel.TOOL

    def test_default_channel_is_tool(self):
        assert _pending().channel is ApprovalChannel.TOOL


# ----------------------------------------------------------------------------
# 4. The boundary requires trusted provenance before any mutation.
# ----------------------------------------------------------------------------


def _tool_approved() -> ApprovalRequest:
    """An approval resolved the legacy way: channel stays TOOL."""
    request = _pending()
    approval_mod.approve(request, "Garrett", "Relayed by the model.")
    return request


def _trusted_approved(enrollment) -> ApprovalRequest:
    secret, stored = enrollment
    return _resolve(_pending(), secret=secret, enrollment=stored, source=_PHONE)


class TestBoundaryProvenance:
    def _boundary(self, tmp_path, require_trusted: bool) -> Boundary:
        b = Boundary(audit_log_path=tmp_path / "audit.jsonl")
        b.require_trusted_channel = require_trusted
        b.register("apply_remediation", ToolKind.MUTATE)
        return b

    def test_tool_channel_approval_is_blocked_when_trusted_required(self, tmp_path):
        boundary = self._boundary(tmp_path, require_trusted=True)
        decision = boundary.check(
            "apply_remediation",
            {"approval_id": "appr-1", "device": "core-rtr-01"},
            approval=_tool_approved(),
        )
        assert decision is ToolDecision.BLOCKED
        assert "approval page" in boundary.last_record.reason.lower()

    def test_trusted_channel_approval_is_allowed(self, tmp_path, enrollment):
        boundary = self._boundary(tmp_path, require_trusted=True)
        decision = boundary.check(
            "apply_remediation",
            {"approval_id": "appr-1", "device": "core-rtr-01"},
            approval=_trusted_approved(enrollment),
        )
        assert decision is ToolDecision.ALLOWED

    def test_tool_mode_allow_is_stamped_unattested(self, tmp_path):
        """Legacy mode still allows -- but the receipt says what it is."""
        boundary = self._boundary(tmp_path, require_trusted=False)
        decision = boundary.check(
            "apply_remediation",
            {"approval_id": "appr-1", "device": "core-rtr-01"},
            approval=_tool_approved(),
        )
        assert decision is ToolDecision.ALLOWED
        assert "unattested" in boundary.last_record.reason.lower()

    def test_trusted_mode_is_the_boundary_default(self, tmp_path):
        assert Boundary(audit_log_path=tmp_path / "a.jsonl").require_trusted_channel


# ----------------------------------------------------------------------------
# 5. resolve_approval is demoted: reject-only in trusted mode.
# ----------------------------------------------------------------------------


@pytest.fixture()
def wired(monkeypatch, tmp_path):
    """Sandbox the server module for demotion tests (no devices touched)."""
    monkeypatch.setattr(server.boundary, "audit_log_path", tmp_path / "audit.jsonl")
    monkeypatch.delenv("NETAGENT_APPROVAL_SECRET_FILE", raising=False)
    monkeypatch.delenv("NETAGENT_APPROVALS_DIR", raising=False)
    server._findings.clear()
    server._proposals.clear()
    server._approvals.clear()
    yield tmp_path
    server._findings.clear()
    server._proposals.clear()
    server._approvals.clear()


def _seed_pending_approval() -> str:
    """Plant a PENDING approval in the server's session state directly."""
    server._approvals["appr-t1"] = _pending()
    return "appr-t1"


class TestResolveApprovalDemotion:
    def test_approve_is_refused_in_trusted_mode(self, wired, monkeypatch):
        monkeypatch.setenv("NETAGENT_APPROVAL_MODE", "trusted")
        approval_id = _seed_pending_approval()
        result = server.resolve_approval(
            approval_id, "approve", "Garrett", "Looks good."
        )
        assert "error" in result
        assert "approval page" in result["error"].lower()
        assert server._approvals[approval_id].state is ApprovalState.PENDING

    def test_reject_still_works_in_trusted_mode(self, wired, monkeypatch):
        monkeypatch.setenv("NETAGENT_APPROVAL_MODE", "trusted")
        approval_id = _seed_pending_approval()
        result = server.resolve_approval(
            approval_id, "reject", "Garrett", "Wrong window; not tonight."
        )
        assert result["state"] == "rejected"

    def test_approve_works_in_tool_mode(self, wired, monkeypatch):
        monkeypatch.setenv("NETAGENT_APPROVAL_MODE", "tool")
        approval_id = _seed_pending_approval()
        result = server.resolve_approval(
            approval_id, "approve", "Garrett", "Reviewed the diff on screen."
        )
        assert result["state"] == "approved"

    def test_request_approval_payload_names_the_approval_url(self, wired, monkeypatch):
        """The payload carries the key even with no live surface (None)."""
        monkeypatch.setenv("NETAGENT_APPROVAL_MODE", "trusted")
        finding = Finding(
            id="cve-2025-20334-http-api",
            severity=Severity.HIGH,
            title="CVE-2025-20334",
            devices=["core-rtr-01"],
            category="vulnerability",
            remediation_kind="disable_http",
            source=FindingSource.DETERMINISTIC_CHECK,
            rationale="test",
        )
        server._findings[finding.id] = finding
        server._proposals[f"{finding.id}:core-rtr-01"] = _proposal()
        payload = server.request_approval(finding.id, "core-rtr-01")
        assert "approval_url" in payload


# ----------------------------------------------------------------------------
# 6. Fail-deny: no non-loopback address, no server.
# ----------------------------------------------------------------------------


class TestFailDenyBindSelection:
    def test_loopback_only_refuses(self):
        with pytest.raises(trusted_path.TrustedPathError):
            trusted_path.select_bind_address(["127.0.0.1", "::1"])

    def test_nonloopback_is_selected(self):
        assert (
            trusted_path.select_bind_address(["127.0.0.1", "192.168.1.20"])
            == "192.168.1.20"
        )

    def test_empty_candidates_refuse(self):
        with pytest.raises(trusted_path.TrustedPathError):
            trusted_path.select_bind_address([])


# ----------------------------------------------------------------------------
# 7. Artifacts stamp the channel; tool mode reads as unattested.
# ----------------------------------------------------------------------------


class TestArtifactChannelStamp:
    def test_tool_channel_artifact_is_stamped_unattested(self, tmp_path):
        request = _tool_approved()
        path = artifacts_mod.update_artifact(
            "appr-a1", request, tmp_path / "audit.jsonl", "approved by Garrett"
        )
        text = path.read_text(encoding="utf-8")
        assert "unattested" in text.lower()

    def test_trusted_channel_artifact_names_the_channel(self, tmp_path, enrollment):
        request = _trusted_approved(enrollment)
        path = artifacts_mod.update_artifact(
            "appr-a2", request, tmp_path / "audit.jsonl", "approved via trusted path"
        )
        text = path.read_text(encoding="utf-8")
        assert "trusted_path" in text
        assert "unattested" not in text.lower()


# ----------------------------------------------------------------------------
# 8. The approval page renders the review content (no secrets in it).
# ----------------------------------------------------------------------------


class TestApprovalPage:
    def test_page_shows_commands_diff_and_device(self):
        html = trusted_path.render_approval_page("appr-p1", _pending())
        assert "core-rtr-01" in html
        assert "no ip http server" in html
        assert "appr-p1" in html

    def test_page_never_embeds_the_enrolled_hash(self, enrollment):
        _, stored = enrollment
        html = trusted_path.render_approval_page("appr-p1", _pending())
        assert stored["hash"] not in html


# ----------------------------------------------------------------------------
# 9. Full-stack over the wire: real socket -> surface -> resolver -> boundary.
# ----------------------------------------------------------------------------


class TestSurfaceOverTheWire:
    """Integration: the whole chain over a real HTTP socket.

    A test cannot forge its TCP source address, so the client here is
    loopback and the FOREIGN case injects a refusal set that excludes it --
    a seam in the environment, never in the checks (resolve_trusted still
    runs both, in order). The genuine local-source refusal over the wire is
    also pinned below, with the real refusal set.
    """

    @pytest.fixture()
    def surface(self, monkeypatch, tmp_path, enrollment):
        import urllib.error
        import urllib.parse
        import urllib.request

        secret, stored = enrollment
        monkeypatch.setattr(server.boundary, "audit_log_path", tmp_path / "audit.jsonl")
        monkeypatch.setattr(server.boundary, "require_trusted_channel", True)
        monkeypatch.setattr(server, "_enrollment_record", stored)
        monkeypatch.delenv("NETAGENT_APPROVALS_DIR", raising=False)
        server._approvals.clear()
        server._approvals["appr-w1"] = _pending()
        live = trusted_path.ApprovalSurface(
            bind_address="127.0.0.1",  # bind loopback IN TESTS ONLY
            get_request=server._approvals.get,
            resolve=server._trusted_resolve,
            port=0,  # let the OS pick a free port
        )
        live.start()
        port = live._httpd.server_address[1]

        def post(fields: dict) -> tuple[int, str]:
            data = urllib.parse.urlencode(fields).encode()
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/a/appr-w1", data=data, timeout=5
                ) as resp:
                    return resp.status, resp.read().decode()
            except urllib.error.HTTPError as err:
                return err.code, err.read().decode()

        yield post, secret
        live.stop()
        server._approvals.clear()

    def test_wire_approve_with_foreign_source_allows_apply(
        self, surface, monkeypatch
    ):
        post, secret = surface
        # The seam: loopback is not in the refusal set for this test.
        monkeypatch.setattr(
            trusted_path, "local_addresses", lambda: frozenset({"192.0.2.99"})
        )
        status, _ = post(
            {
                "decision": "approve",
                "approver": "Garrett",
                "reason": "Reviewed the diff on the approval page.",
                "secret": secret,
            }
        )
        assert status == 200
        request = server._approvals["appr-w1"]
        assert request.state is ApprovalState.APPROVED
        assert request.channel is ApprovalChannel.TRUSTED_PATH
        decision = server.boundary.check(
            "apply_remediation",
            {"approval_id": "appr-w1", "device": "core-rtr-01"},
            approval=request,
        )
        assert decision is ToolDecision.ALLOWED

    def test_wire_local_source_is_refused_with_correct_secret(self, surface):
        post, secret = surface
        status, body = post(
            {
                "decision": "approve",
                "approver": "the-agent",
                "reason": "self-approval attempt",
                "secret": secret,
            }
        )
        assert status == 403
        assert "local address" in body
        assert server._approvals["appr-w1"].state is ApprovalState.PENDING
        # The refusal is on the audit log, like every guarded call.
        record = server.boundary.last_record
        assert record.tool_name == "trusted_path.resolve"
        assert record.decision is ToolDecision.BLOCKED
