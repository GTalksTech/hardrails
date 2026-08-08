# ============================================================
# Module:       trusted_path.py
# Purpose:      The trusted-path approval surface: the channel a human
#               approval enters through that the agent cannot write. Local
#               sources are refused before anything else; the decision must
#               carry the enrolled secret (stored hash-only); a passing
#               submission resolves the ApprovalRequest with TRUSTED_PATH
#               provenance, which the boundary requires before any mutation.
# Dependencies: pydantic>=2 (via models); stdlib only otherwise
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. The enrollment
#               file holds a scrypt hash + salt, never plaintext; the
#               plaintext secret exists only on the human's second device.
#               Design: docs/specs/2026-08-05-trusted-path-approval.md.
# ============================================================
"""The approval channel the agent cannot write.

`resolve_approval` records who approved and why -- but those are strings
supplied by whoever calls the tool, which is the model. This module is the
fix (issue #9): approvals enter through an HTTP surface bound to a
non-loopback address, and every submission passes two deterministic checks,
in order:

    1. Local-source rejection. A connection from any address this machine
       holds is refused regardless of credentials. The agent's most direct
       move -- curl from its own shell -- dies here.
    2. Secret verification. The submitted secret must match the enrolled
       scrypt hash. Anyone else on the network dies here.

The ordering is deliberate: the source check is cheap, has no false
negatives for the attack it targets, and keeps credential-guessing traffic
from the agent's own box out of the verifier entirely.

Threat-model honesty (the spec states this in full): the attacker is a
same-user shell on this machine. It reads the enrollment file -- which is
why the file holds only a hash. It speaks to every address the machine
holds -- which is why those sources are refused outright. What it cannot do
is present a secret that exists only on the human's second device, from an
address the machine does not own.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import secrets as _secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlparse

from netagent import approval as approval_mod
from netagent.models import ApprovalChannel, ApprovalRequest, _utcnow

_LOOPBACKS = frozenset({"127.0.0.1", "::1"})

# scrypt parameters: interactive-strength (the secret is 128-bit random, so
# the hash is belt-and-braces against weak-secret reuse, not the main event).
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


class TrustedPathError(RuntimeError):
    """A refused submission or an unusable surface. Always fail-deny."""


# -- machine identity --------------------------------------------------------


def local_addresses() -> frozenset[str]:
    """Every address this machine holds -- the refusal set for check 1.

    Best-effort by design: loopbacks always, plus everything the hostname
    resolves to, plus the primary outbound interface (UDP-connect trick; no
    packet is sent). A miss here is defense-in-depth lost, not the gate
    lost -- check 2 still requires the enrolled secret.
    """
    addrs = set(_LOOPBACKS)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addrs.add(str(info[4][0]))
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))  # TEST-NET-1; nothing transmitted
            addrs.add(probe.getsockname()[0])
    except OSError:
        pass
    return frozenset(addrs)


def select_bind_address(candidates: list[str] | None = None) -> str:
    """Pick the non-loopback address the surface binds. Fail-deny otherwise.

    The surface must never listen on loopback -- a loopback listener would
    be a same-machine approval endpoint, which is the exact thing this
    module exists to prevent.
    """
    if candidates is None:
        candidates = sorted(local_addresses())
    for addr in candidates:
        if addr not in _LOOPBACKS and not addr.startswith("fe80:"):
            return addr
    raise TrustedPathError(
        "No non-loopback address available: the approval surface cannot "
        "start, so approvals are impossible (fail-deny). Connect the "
        "machine to a network, or start the server in the testing-only "
        "tool mode (NETAGENT_APPROVAL_MODE=tool) if no device will be "
        "touched."
    )


# -- enrollment: hash on disk, plaintext only on the second device -----------


def enroll(secret_file: Path) -> str:
    """Generate the approval secret; store its hash; return plaintext ONCE.

    Re-running rotates: the old secret stops verifying the moment the new
    hash lands. The caller (the enrollment CLI, run by the human) is
    responsible for displaying the plaintext and the handling rule: it is
    only ever typed on a device that is not the agent's machine.
    """
    secret = _secrets.token_urlsafe(16)  # 128 bits
    salt = _secrets.token_bytes(16)
    record = {
        "salt": salt.hex(),
        "hash": _scrypt(secret, salt).hex(),
        "scrypt": {"n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P},
        "created_at": _utcnow().isoformat(),
    }
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    secret_file.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return secret


def load_enrollment(secret_file: Path) -> dict:
    """Load the stored hash record. Raises TrustedPathError if unusable."""
    try:
        record = json.loads(secret_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TrustedPathError(
            f"No usable enrollment at {secret_file}: {exc}. Run the "
            "enrollment step (netagent-enroll) from your own terminal first."
        ) from exc
    if "salt" not in record or "hash" not in record:
        raise TrustedPathError(
            f"Enrollment file {secret_file} is missing its hash material. "
            "Re-run netagent-enroll."
        )
    return record


def verify_secret(candidate: str, enrollment: dict) -> bool:
    """Constant-time check of a submitted secret against the stored hash."""
    params = enrollment.get("scrypt", {})
    digest = _scrypt(
        candidate,
        bytes.fromhex(enrollment["salt"]),
        n=params.get("n", _SCRYPT_N),
        r=params.get("r", _SCRYPT_R),
        p=params.get("p", _SCRYPT_P),
    )
    return hmac.compare_digest(digest.hex(), enrollment["hash"])


def _scrypt(
    secret: str, salt: bytes, n: int = _SCRYPT_N, r: int = _SCRYPT_R, p: int = _SCRYPT_P
) -> bytes:
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=n, r=r, p=p)


# -- the resolver: both checks, then provenance ------------------------------


def resolve_trusted(
    request: ApprovalRequest,
    *,
    decision: str,
    approver: str,
    reason: str,
    submitted_secret: str,
    enrollment: dict,
    source_ip: str,
    local_addrs: frozenset[str] | None = None,
) -> ApprovalRequest:
    """Resolve an approval through the trusted path. The only code path that
    sets TRUSTED_PATH provenance.

    Checks in order (see module docstring for why): local source refused
    first -- before the credential is even examined -- then the enrolled
    hash, then the ordinary approval state machine. Any refusal raises
    TrustedPathError and leaves the request untouched.
    """
    if local_addrs is None:
        local_addrs = local_addresses()
    if source_ip in local_addrs:
        raise TrustedPathError(
            f"Refused: connection from a local address ({source_ip}). The "
            "approval surface only accepts decisions from a device that is "
            "not this machine."
        )
    if not verify_secret(submitted_secret, enrollment):
        raise TrustedPathError(
            "Refused: the submitted secret does not match the enrolled "
            "approval secret."
        )
    if decision == "approve":
        approval_mod.approve(request, approver, reason)
    elif decision == "reject":
        approval_mod.reject(request, approver, reason)
    else:
        raise TrustedPathError("decision must be 'approve' or 'reject'.")
    request.channel = ApprovalChannel.TRUSTED_PATH
    return request


# -- the page ----------------------------------------------------------------


def render_approval_page(approval_id: str, request: ApprovalRequest) -> str:
    """The review page the human opens on the second device.

    Same content discipline as the on-disk artifact: the finding, device,
    exact commands, and full dry-run diff -- never credential material.
    """
    proposal = request.proposal
    commands = html.escape("\n".join(proposal.config_commands))
    diff = html.escape(proposal.dry_run_diff)
    device = html.escape(proposal.device)
    finding = html.escape(proposal.finding_id)
    safe_id = html.escape(approval_id)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approval {safe_id} — netagent</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 1.5rem; max-width: 40rem; }}
  pre {{ background: #f4f4f4; padding: .75rem; overflow-x: auto; border-radius: 6px; }}
  .state {{ font-weight: 600; }}
  form {{ margin-top: 1.5rem; display: grid; gap: .6rem; }}
  input, textarea {{ font: inherit; padding: .45rem; }}
  button {{ font: inherit; padding: .55rem 1.2rem; cursor: pointer; }}
  .approve {{ background: #146c2e; color: #fff; border: 0; border-radius: 6px; }}
  .reject  {{ background: #8b1a1a; color: #fff; border: 0; border-radius: 6px; }}
  .rule {{ color: #555; font-size: .85rem; }}
</style>
</head>
<body>
<h1>Approval {safe_id}</h1>
<p class="state">State: {html.escape(request.state.value)}</p>
<p>Finding <strong>{finding}</strong> on device <strong>{device}</strong>.</p>
<h2>Proposed commands</h2>
<pre>{commands}</pre>
<h2>Dry-run diff</h2>
<pre>{diff}</pre>
<form method="post">
  <input name="approver" placeholder="Your name" required>
  <input name="reason" placeholder="Why (recorded in the audit log)" required>
  <input name="secret" type="password" placeholder="Approval secret" required
         autocomplete="current-password">
  <button class="approve" name="decision" value="approve">Approve</button>
  <button class="reject" name="decision" value="reject">Reject</button>
  <p class="rule">Only submit from a device that is not the agent's
  machine. Submissions from the server's own addresses are refused.</p>
</form>
</body>
</html>
"""


# -- the listener ------------------------------------------------------------


class ApprovalSurface:
    """The HTTP listener serving approval pages on a non-loopback bind.

    Thin transport around the pure pieces: GET renders the review page for a
    known approval; POST hands the form to the server-supplied `resolve`
    callback, which applies the two checks and owns the audit and artifact
    writes. This class holds no secrets and makes no decisions -- if the
    transport is torn out and replaced, the checks travel with the resolver,
    not with it.
    """

    def __init__(
        self,
        bind_address: str,
        get_request: Callable[[str], ApprovalRequest | None],
        resolve: Callable[..., dict],
        port: int = 8484,
    ) -> None:
        self._bind = bind_address
        self._get_request = get_request
        self._resolve = resolve
        self._port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self._bind}:{self._port}"

    def url_for(self, approval_id: str) -> str:
        return f"{self.base_url}/a/{approval_id}"

    def start(self) -> None:
        surface = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                # stdio belongs to the MCP transport; the audit log is the
                # record of note, so the default stderr chatter is silenced.
                pass

            def do_GET(self) -> None:  # noqa: N802 -- http.server API
                surface._handle_get(self)

            def do_POST(self) -> None:  # noqa: N802 -- http.server API
                surface._handle_post(self)

        self._httpd = ThreadingHTTPServer((self._bind, self._port), _Handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True, name="approval-surface"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()

    # -- request handling ----------------------------------------------------

    @staticmethod
    def _approval_id(path: str) -> str | None:
        parts = urlparse(path).path.strip("/").split("/")
        return parts[1] if len(parts) == 2 and parts[0] == "a" else None

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        approval_id = self._approval_id(handler.path)
        request = self._get_request(approval_id) if approval_id else None
        if request is None:
            _respond(handler, 404, "<h1>Unknown approval</h1>")
            return
        _respond(handler, 200, render_approval_page(approval_id, request))

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        approval_id = self._approval_id(handler.path)
        if approval_id is None:
            _respond(handler, 404, "<h1>Unknown approval</h1>")
            return
        length = int(handler.headers.get("Content-Length") or 0)
        form = parse_qs(handler.rfile.read(length).decode("utf-8"))

        def _field(name: str) -> str:
            return (form.get(name) or [""])[0]

        result = self._resolve(
            approval_id,
            decision=_field("decision"),
            approver=_field("approver"),
            reason=_field("reason"),
            submitted_secret=_field("secret"),
            source_ip=handler.client_address[0],
        )
        if "error" in result:
            _respond(
                handler, 403,
                f"<h1>Refused</h1><p>{html.escape(result['error'])}</p>",
            )
        else:
            _respond(
                handler, 200,
                f"<h1>{html.escape(result['state'])}</h1>"
                f"<p>Approval {html.escape(approval_id)} recorded. This "
                "decision is single-use and on the audit log.</p>",
            )


def _respond(handler: BaseHTTPRequestHandler, status: int, body: str) -> None:
    data = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
