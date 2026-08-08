# ============================================================
# Module:       tests/test_surface_tls.py
# Purpose:      Tests for TLS on the approval surface (first slice toward
#               issue #11): operator-supplied cert/key, fail-deny on
#               half-configuration or unloadable material, https URLs with
#               a display hostname, and a full approve over a real TLS
#               socket using an ephemeral self-signed certificate.
# Usage:        pytest tests/  (from the repository root)
# Dependencies: pytest, pydantic>=2, cryptography (via the lab extra's
#               netmiko -> paramiko chain) for the ephemeral test cert
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. The test
#               certificate is generated fresh per run and never committed.
# ============================================================
"""TLS on the approval surface: encrypt the wire, keep every gate.

The design doc (2026-08-08-approval-surface-tls.md) is explicit about
what TLS is here: wire defense and browser secure-context, NOT a secret
kept from the agent -- the key lives on the machine the attacker reads.
So these tests pin configuration honesty (both-or-neither, fail-deny on
bad material), URL shape, and that the two real gates keep working
unchanged over an encrypted socket.
"""

from __future__ import annotations

import datetime
import ssl

import pytest

from netagent import trusted_path
from netagent.models import ApprovalRequest, ApprovalState, RemediationProposal

cryptography = pytest.importorskip("cryptography")


@pytest.fixture()
def cert_pair(tmp_path):
    """An ephemeral self-signed cert/key for localhost, minted per test run."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "netagent-test.invalid")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


class TestTlsFromEnv:
    def test_neither_set_means_plain_http(self):
        assert trusted_path.tls_from_env(None, None) is None

    @pytest.mark.parametrize("cert,key", [("cert.pem", None), (None, "key.pem")])
    def test_half_configuration_refuses(self, cert, key):
        with pytest.raises(trusted_path.TrustedPathError) as err:
            trusted_path.tls_from_env(cert, key)
        assert "both" in str(err.value).lower()

    def test_unloadable_material_refuses(self, tmp_path):
        missing = tmp_path / "nope.pem"
        with pytest.raises(trusted_path.TrustedPathError):
            trusted_path.tls_from_env(str(missing), str(missing))

    def test_valid_pair_builds_a_context(self, cert_pair):
        cert_file, key_file = cert_pair
        ctx = trusted_path.tls_from_env(str(cert_file), str(key_file))
        assert isinstance(ctx, ssl.SSLContext)


class TestHttpsUrls:
    def test_url_uses_https_and_display_hostname(self, cert_pair):
        cert_file, key_file = cert_pair
        ctx = trusted_path.tls_from_env(str(cert_file), str(key_file))
        surface = trusted_path.ApprovalSurface(
            bind_address="127.0.0.1",
            get_request=lambda _id: None,
            resolve=lambda *a, **k: {},
            port=8484,
            tls_context=ctx,
            display_host="gm.tail1234.ts.net",
        )
        assert surface.url_for("appr-x") == "https://gm.tail1234.ts.net:8484/a/appr-x"

    def test_plain_surface_keeps_http_and_bind_address(self):
        surface = trusted_path.ApprovalSurface(
            bind_address="192.168.1.20",
            get_request=lambda _id: None,
            resolve=lambda *a, **k: {},
        )
        assert surface.url_for("appr-x") == "http://192.168.1.20:8484/a/appr-x"


class TestApproveOverTls:
    def test_full_approve_over_a_real_tls_socket(
        self, cert_pair, monkeypatch, tmp_path
    ):
        import urllib.error
        import urllib.parse
        import urllib.request

        import netagent.server as server

        cert_file, key_file = cert_pair
        secret_file = tmp_path / "approval-secret.json"
        secret = trusted_path.enroll(secret_file)
        monkeypatch.setattr(server.boundary, "audit_log_path", tmp_path / "a.jsonl")
        monkeypatch.setattr(
            server, "_enrollment_record", trusted_path.load_enrollment(secret_file)
        )
        monkeypatch.delenv("NETAGENT_APPROVALS_DIR", raising=False)
        # The foreign-source seam, as in the plain-HTTP wire test: a test
        # cannot forge its TCP source, so the refusal set excludes loopback.
        monkeypatch.setattr(
            trusted_path, "local_addresses", lambda: frozenset({"192.0.2.99"})
        )
        server._approvals.clear()
        server._approvals["appr-tls1"] = ApprovalRequest(
            proposal=RemediationProposal(
                finding_id="cve-2025-20334-http-api",
                device="core-rtr-01",
                config_commands=["no ip http server"],
                dry_run_diff="-ip http server",
            )
        )
        surface = trusted_path.ApprovalSurface(
            bind_address="127.0.0.1",  # TESTS ONLY
            get_request=server._approvals.get,
            resolve=server._trusted_resolve,
            port=0,
            tls_context=trusted_path.tls_from_env(str(cert_file), str(key_file)),
        )
        surface.start()
        try:
            port = surface._httpd.server_address[1]
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE  # trust is not under test
            data = urllib.parse.urlencode(
                {
                    "decision": "approve",
                    "approver": "Garrett",
                    "reason": "Reviewed over TLS.",
                    "secret": secret,
                }
            ).encode()
            with urllib.request.urlopen(
                f"https://127.0.0.1:{port}/a/appr-tls1",
                data=data,
                timeout=30,
                context=client_ctx,
            ) as resp:
                assert resp.status == 200
            assert (
                server._approvals["appr-tls1"].state is ApprovalState.APPROVED
            )
        finally:
            surface.stop()
            server._approvals.clear()
