# ============================================================
# Module:       tests/test_tailscale_identity.py
# Purpose:      Tests for approval identity mode B (spec design doc §6):
#               tailnet whois replaces the enrolled secret, the recorded
#               approver is the ATTESTED tailnet identity (never the typed
#               name), unreachable tailscaled fails deny, and the surface
#               bind prefers the Tailscale (CGNAT) interface in this mode.
# Usage:        pytest tests/  (from the repository root)
# Dependencies: pytest, pydantic>=2
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. The whois
#               backend is injected in every test -- no tailnet, no network.
# ============================================================
"""Identity mode B: the tailnet attests the approver.

Mode A's honest limit is that it attests possession ("someone holding the
enrolled secret"), with the approver name still typed. Mode B upgrades
check 2: the server asks the local tailscaled who the connecting peer IS,
and requires that identity to be on an explicit approver allowlist. The
recorded approver becomes the tailnet login -- attested, not claimed.
Check 1 (local-source rejection) is untouched and still fires first, and
an unreachable tailscaled refuses approvals rather than degrading
(fail-deny; never silently back to secret-only)."""

from __future__ import annotations

import pytest

from netagent import trusted_path
from netagent.models import (
    ApprovalChannel,
    ApprovalRequest,
    ApprovalState,
    RemediationProposal,
)

_LOCAL_ADDRS = frozenset({"127.0.0.1", "::1", "192.168.1.20", "100.97.1.36"})
_PEER = "100.94.194.78"  # a tailnet peer (not held by this machine)


def _pending() -> ApprovalRequest:
    return ApprovalRequest(
        proposal=RemediationProposal(
            finding_id="cve-2025-20334-http-api",
            device="core-rtr-01",
            config_commands=["no ip http server"],
            dry_run_diff="-ip http server",
        )
    )


def _whois_garrett(ip: str) -> dict:
    assert ip == _PEER
    return {
        "Node": {"ComputedName": "garretts-s24-ultra"},
        "UserProfile": {"LoginName": "gmasters428@github"},
    }


def _identity(approvers=("gmasters428@github",), whois=_whois_garrett):
    return trusted_path.TailscaleIdentity(
        approvers=frozenset(approvers), whois=whois
    )


def _resolve(request, identity, *, source=_PEER, decision="approve"):
    return trusted_path.resolve_trusted(
        request,
        decision=decision,
        approver="whatever-was-typed",
        reason="Reviewed on the approval page over the tailnet.",
        submitted_secret="",  # no secret exists in this mode
        identity=identity,
        source_ip=source,
        local_addrs=_LOCAL_ADDRS,
    )


class TestTailscaleIdentity:
    def test_allowed_login_approves_with_attested_approver(self):
        request = _pending()
        resolved = _resolve(request, _identity())
        assert resolved.state is ApprovalState.APPROVED
        assert resolved.channel is ApprovalChannel.TRUSTED_PATH
        # The typed name is discarded; the tailnet identity is recorded.
        assert resolved.approver == "gmasters428@github"

    def test_device_name_match_is_also_allowed(self):
        resolved = _resolve(_pending(), _identity(approvers=("garretts-s24-ultra",)))
        assert resolved.state is ApprovalState.APPROVED

    def test_unlisted_peer_is_refused(self):
        request = _pending()
        with pytest.raises(trusted_path.TrustedPathError) as err:
            _resolve(request, _identity(approvers=("someone-else@github",)))
        assert "approver" in str(err.value).lower()
        assert request.state is ApprovalState.PENDING

    def test_unreachable_tailscaled_fails_deny(self):
        def broken(ip: str) -> dict:
            raise OSError("tailscaled not running")

        request = _pending()
        with pytest.raises(trusted_path.TrustedPathError) as err:
            _resolve(request, _identity(whois=broken))
        assert "tailscale" in str(err.value).lower()
        assert request.state is ApprovalState.PENDING

    def test_no_secret_is_needed_in_this_mode(self):
        # submitted_secret is empty in _resolve; approval still lands.
        assert _resolve(_pending(), _identity()).state is ApprovalState.APPROVED

    def test_local_source_still_refused_first(self):
        """Check 1 outranks the tailnet: the machine's own Tailscale address
        cannot approve even if whois would vouch for it."""
        request = _pending()
        with pytest.raises(trusted_path.TrustedPathError) as err:
            _resolve(request, _identity(), source="100.97.1.36")
        assert "local" in str(err.value).lower()


class TestSecretIdentityStillWorks:
    """Mode A expressed through the same identity seam."""

    def test_secret_identity_records_the_typed_name(self, tmp_path):
        secret_file = tmp_path / "approval-secret.json"
        secret = trusted_path.enroll(secret_file)
        identity = trusted_path.SecretIdentity(
            enrollment=trusted_path.load_enrollment(secret_file)
        )
        request = _pending()
        resolved = trusted_path.resolve_trusted(
            request,
            decision="approve",
            approver="Garrett",
            reason="Reviewed.",
            submitted_secret=secret,
            identity=identity,
            source_ip="192.168.1.77",
            local_addrs=_LOCAL_ADDRS,
        )
        assert resolved.state is ApprovalState.APPROVED
        assert resolved.approver == "Garrett"


class TestCgnatBindPreference:
    def test_prefers_tailscale_address_when_asked(self):
        assert (
            trusted_path.select_bind_address(
                ["192.168.1.30", "100.97.1.36"], prefer_cgnat=True
            )
            == "100.97.1.36"
        )

    def test_falls_back_when_no_cgnat_address(self):
        assert (
            trusted_path.select_bind_address(
                ["127.0.0.1", "192.168.1.30"], prefer_cgnat=True
            )
            == "192.168.1.30"
        )

    def test_default_behavior_unchanged(self):
        assert (
            trusted_path.select_bind_address(["192.168.1.30", "100.97.1.36"])
            == "192.168.1.30"
        )


class TestServerIdentityWiring:
    """server._build_identity: env -> identity seam, fail-deny on gaps."""

    def test_empty_allowlist_refuses(self, monkeypatch):
        import netagent.server as server

        monkeypatch.setenv("NETAGENT_APPROVAL_IDENTITY", "tailscale")
        monkeypatch.setenv("NETAGENT_TAILNET_APPROVERS", "  , ")
        with pytest.raises(trusted_path.TrustedPathError) as err:
            server._build_identity()
        assert "allowlist" in str(err.value).lower()

    def test_missing_tailscale_cli_refuses(self, monkeypatch):
        import netagent.server as server

        monkeypatch.setenv("NETAGENT_APPROVAL_IDENTITY", "tailscale")
        monkeypatch.setenv("NETAGENT_TAILNET_APPROVERS", "gmasters428@github")
        monkeypatch.setattr(server.shutil, "which", lambda _: None)
        with pytest.raises(trusted_path.TrustedPathError) as err:
            server._build_identity()
        assert "tailscale" in str(err.value).lower()

    def test_tailscale_identity_built_from_env(self, monkeypatch):
        import netagent.server as server

        monkeypatch.setenv("NETAGENT_APPROVAL_IDENTITY", "tailscale")
        monkeypatch.setenv(
            "NETAGENT_TAILNET_APPROVERS", "gmasters428@github, pi5"
        )
        monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/tailscale")
        monkeypatch.setattr(
            server.trusted_path_mod, "tailscale_self_name", lambda binary: "agent-host"
        )
        identity = server._build_identity()
        assert isinstance(identity, trusted_path.TailscaleIdentity)
        assert identity.approvers == frozenset({"gmasters428@github", "pi5"})
        # The agent's own node name is captured so it can be excluded (issue #22).
        assert identity.self_name == "agent-host"


class TestWhoisParsing:
    def test_names_extracted_from_whois_payload(self):
        login, device = trusted_path.tailnet_names(
            {
                "Node": {"ComputedName": "pi5.tail1234.ts.net"},
                "UserProfile": {"LoginName": "gmasters428@github"},
            }
        )
        assert login == "gmasters428@github"
        assert device == "pi5"

    def test_missing_fields_yield_empty_strings(self):
        assert trusted_path.tailnet_names({}) == ("", "")


# ----------------------------------------------------------------------------
# Mode-B hardening (issue #22): self-node refusal, IP normalization, binary pin.
# ----------------------------------------------------------------------------


class TestSelfNodeRefusal:
    """The agent's own host must never approve, even when its login is on the
    allowlist (every device on an account shares one tailnet login)."""

    @staticmethod
    def _whois_self(ip: str) -> dict:
        # whois resolves the connecting peer to THIS machine's own node.
        return {
            "Node": {"ComputedName": "agent-host.tail1234.ts.net"},
            "UserProfile": {"LoginName": "gmasters428@github"},
        }

    def test_peer_resolving_to_self_node_is_refused(self):
        identity = trusted_path.TailscaleIdentity(
            approvers=frozenset({"gmasters428@github"}),  # the login IS allowlisted
            whois=self._whois_self,
            self_name="agent-host",
        )
        request = _pending()
        with pytest.raises(trusted_path.TrustedPathError) as err:
            trusted_path.resolve_trusted(
                request, decision="approve", approver="x", reason="r",
                submitted_secret="", identity=identity,
                source_ip="100.99.99.99",  # NOT in the local-addr refusal set
                local_addrs=_LOCAL_ADDRS,
            )
        msg = str(err.value).lower()
        assert "own tailnet node" in msg or "agent's host" in msg
        assert request.state is ApprovalState.PENDING

    def test_a_different_node_on_the_same_login_still_approves(self):
        # The operator's phone shares the login but is a DIFFERENT node -> ok.
        identity = trusted_path.TailscaleIdentity(
            approvers=frozenset({"gmasters428@github"}),
            whois=_whois_garrett,  # device 'garretts-s24-ultra' != self_name
            self_name="agent-host",
        )
        resolved = trusted_path.resolve_trusted(
            _pending(), decision="approve", approver="x", reason="r",
            submitted_secret="", identity=identity, source_ip=_PEER,
            local_addrs=_LOCAL_ADDRS,
        )
        assert resolved.state is ApprovalState.APPROVED
        assert resolved.approver == "gmasters428@github"


class TestLocalSourceNormalization:
    def test_ipv4_mapped_ipv6_of_a_local_address_is_refused(self):
        # ::ffff:192.168.1.20 IS 192.168.1.20, a local address (issue #22).
        request = _pending()
        with pytest.raises(trusted_path.TrustedPathError) as err:
            _resolve(request, _identity(), source="::ffff:192.168.1.20")
        assert "local" in str(err.value).lower()

    def test_a_genuine_remote_peer_is_unaffected(self):
        assert _resolve(_pending(), _identity()).state is ApprovalState.APPROVED


class TestBinaryPinning:
    def test_whois_invokes_the_given_absolute_binary(self, monkeypatch):
        seen: dict = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd

            class _R:
                stdout = '{"Node":{"ComputedName":"x"},"UserProfile":{"LoginName":"y"}}'

            return _R()

        monkeypatch.setattr(trusted_path.subprocess, "run", fake_run)
        trusted_path.tailscale_whois("100.1.2.3", binary="/opt/bin/tailscale")
        assert seen["cmd"][0] == "/opt/bin/tailscale"  # absolute path, not bare name
        assert "whois" in seen["cmd"]

    def test_self_name_parses_self_computed_name(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            assert cmd[0] == "/opt/bin/tailscale" and "status" in cmd

            class _R:
                stdout = '{"Self":{"ComputedName":"agent-host.tailnet.ts.net"}}'

            return _R()

        monkeypatch.setattr(trusted_path.subprocess, "run", fake_run)
        assert trusted_path.tailscale_self_name("/opt/bin/tailscale") == "agent-host"
