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

import functools
import hashlib
import hmac
import html
import ipaddress
import json
import re
import secrets as _secrets
import socket
import ssl
import subprocess
import threading
from dataclasses import dataclass
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


@functools.lru_cache(maxsize=1)
def local_addresses() -> frozenset[str]:
    """Every address this machine holds -- the refusal set for check 1.

    Best-effort by design: loopbacks always, plus everything the hostname
    resolves to, plus the primary outbound interface (UDP-connect trick; no
    packet is sent). A miss here is defense-in-depth lost, not the gate
    lost -- check 2 still requires the enrolled secret.

    Computed once per process (hostname resolution can take seconds on some
    platforms, and this runs inside the request handler). An address the
    machine acquires later is therefore not in the refusal set until
    restart -- acceptable, because the secret check still gates, and the
    set is a refusal list, not a trust list.
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


def _is_cgnat(addr: str) -> bool:
    """True for Tailscale-style CGNAT addresses (100.64.0.0/10)."""
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


def _normalize_addr(addr: str):
    """Canonical IP for comparison, or None if unparseable.

    Strips an IPv6 zone id (`%eth0`) and collapses an IPv4-mapped IPv6 address
    (`::ffff:192.168.1.20`) to its IPv4 form, so divergent spellings of the same
    address compare equal (issue #22).
    """
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _source_is_local(source_ip: str, local_addrs: frozenset[str]) -> bool:
    """True if source_ip is one of this machine's addresses.

    Compared on NORMALIZED IP values, not raw strings: exact-string membership
    missed IPv4-mapped IPv6, zone-scoped, and format-skewed forms of a local
    address (issue #22). An unparseable source is treated as non-local -- the
    identity seam (check 2) still has to attest it.
    """
    src = _normalize_addr(source_ip)
    if src is None:
        return False
    normalized = {n for n in (_normalize_addr(a) for a in local_addrs) if n is not None}
    return src in normalized


def select_bind_address(
    candidates: list[str] | None = None, prefer_cgnat: bool = False
) -> str:
    """Pick the non-loopback address the surface binds. Fail-deny otherwise.

    The surface must never listen on loopback -- a loopback listener would
    be a same-machine approval endpoint, which is the exact thing this
    module exists to prevent. With prefer_cgnat (tailnet identity mode),
    the Tailscale interface address wins when present, since that is the
    network the approving peer will arrive on.
    """
    if candidates is None:
        candidates = sorted(local_addresses())
    usable = [
        a for a in candidates
        if a not in _LOOPBACKS and not a.startswith("fe80:")
    ]
    if prefer_cgnat:
        for addr in usable:
            if _is_cgnat(addr):
                return addr
    if usable:
        return usable[0]
    raise TrustedPathError(
        "No non-loopback address available: the approval surface cannot "
        "start, so approvals are impossible (fail-deny). Connect the "
        "machine to a network, or start the server in the testing-only "
        "tool mode (NETAGENT_APPROVAL_MODE=tool) if no device will be "
        "touched."
    )


def resolve_bind(
    override: str | None, candidates: list[str] | None = None
) -> str:
    """The surface's bind address: operator override, else auto-selection.

    A machine can hold several non-loopback addresses (LAN, mesh, virtual
    adapters) and only the operator knows which one their second device can
    reach -- NETAGENT_APPROVAL_BIND pins it. The override is a knob, not an
    escape hatch: loopback is refused here exactly as in auto-selection.
    """
    if override is not None:
        addr = override.strip()
        if not addr or addr in _LOOPBACKS or addr.startswith("127."):
            raise TrustedPathError(
                f"NETAGENT_APPROVAL_BIND={override!r} is not usable: the "
                "approval surface never listens on loopback (a same-machine "
                "approval endpoint is the exact thing the trusted path "
                "exists to prevent). Set it to an address your second "
                "device can reach."
            )
        return addr
    return select_bind_address(candidates)


def tls_from_env(cert_path: str | None, key_path: str | None) -> ssl.SSLContext | None:
    """Build the surface's TLS context from operator configuration.

    Both-or-neither: a certificate without its key (or vice versa) is a
    misconfiguration, and a pair that will not load is a misconfiguration.
    Either refuses (fail-deny) rather than starting a surface that is not
    what the operator believes it is. Returning None -- both unset -- means
    plain HTTP, mode A's documented wire limitation.

    What TLS is here, stated honestly: the private key lives on the agent's
    machine and is readable by the threat model's same-user attacker. It
    defends the WIRE (the LAN-sniffing gap) and satisfies the browser
    secure-context requirement WebAuthn needs (issue #11); the gate remains
    the local-source check and the identity seam, which never depended on
    transport secrecy.
    """
    if cert_path is None and key_path is None:
        return None
    if cert_path is None or key_path is None:
        raise TrustedPathError(
            "TLS misconfiguration: NETAGENT_APPROVAL_TLS_CERT and "
            "NETAGENT_APPROVAL_TLS_KEY must BOTH be set (or neither). "
            "Refusing to start rather than serving something other than "
            "what was configured."
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Pin the floor explicitly: modern interpreters default to 1.2+, but the
    # default is inherited from the OpenSSL build -- on an old stack it can
    # be 1.0. A security surface does not inherit its protocol floor.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    except (OSError, ssl.SSLError) as exc:
        raise TrustedPathError(
            f"TLS material at cert={cert_path!r} key={key_path!r} did not "
            f"load ({exc}). Refusing to start (fail-deny)."
        ) from exc
    return context


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


# -- identity: WHO stands behind a submission (check 2, pluggable) -----------
#
# The identity ladder (design doc §5): each mode swaps only this seam. The
# surface, the local-source check, provenance, and fail-deny never change.


@dataclass(frozen=True)
class SecretIdentity:
    """Mode A: possession of the enrolled secret.

    Attests "an off-machine holder of the secret decided." The approver
    name is the one the human typed -- self-reported, but self-reported by
    the secret-holder through a channel the agent cannot write.
    """

    enrollment: dict

    def verify(
        self, source_ip: str, submitted_secret: str, claimed_approver: str
    ) -> str:
        if not verify_secret(submitted_secret, self.enrollment):
            raise TrustedPathError(
                "Refused: the submitted secret does not match the enrolled "
                "approval secret."
            )
        return claimed_approver


def tailnet_names(whois_payload: dict) -> tuple[str, str]:
    """Extract (login, short device name) from a tailscale whois payload."""
    login = (whois_payload.get("UserProfile") or {}).get("LoginName") or ""
    device = (whois_payload.get("Node") or {}).get("ComputedName") or ""
    return login, device.split(".")[0]


def tailscale_whois(source_ip: str, binary: str = "tailscale") -> dict:
    """Ask the local tailscaled who a peer address belongs to (via the CLI).

    `binary` should be an ABSOLUTE path resolved at startup (see
    server._build_identity, which binds it): invoking a bare name at request
    time would let a same-user attacker win the executable search with a planted
    `tailscale` and forge the attestation (issue #22).
    """
    proc = subprocess.run(
        [binary, "whois", "--json", source_ip],
        capture_output=True, text=True, timeout=10, check=True,
    )
    return json.loads(proc.stdout)


def tailscale_self_name(binary: str = "tailscale") -> str:
    """This machine's own short tailnet name (`Self.ComputedName`).

    Captured once at startup so the resolver can refuse a peer that resolves to
    THIS node -- the agent's host must never be an approver, even when its login
    is on the allowlist (every device on an account shares one login). Same
    absolute-binary discipline as tailscale_whois (issue #22).
    """
    proc = subprocess.run(
        [binary, "status", "--json"],
        capture_output=True, text=True, timeout=10, check=True,
    )
    payload = json.loads(proc.stdout)
    name = (payload.get("Self") or {}).get("ComputedName") or ""
    return name.split(".")[0]


@dataclass(frozen=True)
class TailscaleIdentity:
    """Mode B: the tailnet attests the approver.

    whois resolves the connecting peer to a tailnet login and device name;
    one of them must be on the explicit approver allowlist. The recorded
    approver is the ATTESTED login (falling back to the device name for
    tagged devices) -- never the typed name. An unreachable tailscaled is
    a refusal, not a downgrade: there is no silent fall back to
    secret-only (fail-deny, design doc §6).
    """

    approvers: frozenset[str]
    whois: Callable[[str], dict] = tailscale_whois
    # This machine's own short tailnet name. The agent's host must never be an
    # approver -- every device on an account shares one tailnet login, so a login
    # allowlist would otherwise vouch for the agent's own machine -- so a peer
    # that resolves to this name is refused regardless of the allowlist. Empty
    # disables the check; the server always supplies it (issue #22).
    self_name: str = ""

    def verify(
        self, source_ip: str, submitted_secret: str, claimed_approver: str
    ) -> str:
        try:
            payload = self.whois(source_ip)
        except Exception as exc:  # noqa: BLE001 -- every failure is a refusal
            raise TrustedPathError(
                f"Refused: tailscale whois for {source_ip} failed "
                f"({type(exc).__name__}: {exc}). Approvals are impossible "
                "until tailscaled answers (fail-deny; no fallback)."
            ) from exc
        login, device = tailnet_names(payload)
        # Self-node refusal: the approving peer must be a DIFFERENT node than the
        # one the agent runs on. This holds even when the enumeration-based
        # local-source check missed the machine's own tailnet address, and even
        # when the allowlist lists the operator's login (issue #22).
        if self.self_name and device and device.lower() == self.self_name.lower():
            raise TrustedPathError(
                f"Refused: the connecting peer is this machine's own tailnet "
                f"node ('{device}'). The approving device must not be the "
                "agent's host -- approve from a different device."
            )
        allowed = {a.strip().lower() for a in self.approvers if a.strip()}
        if login.lower() not in allowed and device.lower() not in allowed:
            raise TrustedPathError(
                f"Refused: tailnet peer '{login or device or source_ip}' is "
                "not on the approver allowlist (NETAGENT_TAILNET_APPROVERS)."
            )
        return login or device


# -- the resolver: both checks, then provenance ------------------------------


def resolve_trusted(
    request: ApprovalRequest,
    *,
    decision: str,
    approver: str,
    reason: str,
    submitted_secret: str,
    identity: SecretIdentity | TailscaleIdentity,
    source_ip: str,
    local_addrs: frozenset[str] | None = None,
) -> ApprovalRequest:
    """Resolve an approval through the trusted path. The only code path that
    sets TRUSTED_PATH provenance.

    Checks in order (see module docstring for why): local source refused
    first -- before any credential or identity is even examined -- then the
    identity seam (enrolled hash in mode A, tailnet whois in mode B), then
    the ordinary approval state machine. Any refusal raises
    TrustedPathError and leaves the request untouched. The approver put on
    the record is whatever the identity seam returns -- the typed name in
    mode A, the attested tailnet identity in mode B.
    """
    if local_addrs is None:
        local_addrs = local_addresses()
    if _source_is_local(source_ip, local_addrs):
        raise TrustedPathError(
            f"Refused: connection from a local address ({source_ip}). The "
            "approval surface only accepts decisions from a device that is "
            "not this machine."
        )
    attested = identity.verify(source_ip, submitted_secret, approver)
    if decision == "approve":
        approval_mod.approve(request, attested, reason)
    elif decision == "reject":
        approval_mod.reject(request, attested, reason)
    else:
        raise TrustedPathError("decision must be 'approve' or 'reject'.")
    request.channel = ApprovalChannel.TRUSTED_PATH
    return request


# -- the page ----------------------------------------------------------------


_PAGE_CSS = """\
  body { font-family: system-ui, sans-serif; margin: 1.5rem; max-width: 40rem; }
  pre { background: #f4f4f4; padding: .75rem; overflow-x: auto; border-radius: 6px; }
  .state { font-weight: 600; }
  form { margin-top: 1.5rem; display: grid; gap: .6rem; }
  input, textarea { font: inherit; padding: .45rem; }
  button { font: inherit; padding: .55rem 1.2rem; cursor: pointer; }
  .approve { background: #146c2e; color: #fff; border: 0; border-radius: 6px; }
  .reject  { background: #8b1a1a; color: #fff; border: 0; border-radius: 6px; }
  .rule { color: #555; font-size: .85rem; }
  .verdict-ok { color: #146c2e; }
  .verdict-no { color: #8b1a1a; }"""


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
{_PAGE_CSS}
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


def render_result_page(title: str, detail: str, ok: bool) -> str:
    """The post-decision page: same styling as the review page, one verdict."""
    css_class = "verdict-ok" if ok else "verdict-no"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} — netagent</title>
<style>
{_PAGE_CSS}
</style>
</head>
<body>
<h1 class="{css_class}">{html.escape(title)}</h1>
<p>{html.escape(detail)}</p>
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
        tls_context: ssl.SSLContext | None = None,
        display_host: str | None = None,
    ) -> None:
        self._bind = bind_address
        self._get_request = get_request
        self._resolve = resolve
        self._port = port
        self._tls_context = tls_context
        # display_host is what goes in the URLs the human taps -- a DNS name
        # matching the certificate (e.g. a ts.net MagicDNS name). Binding is
        # still by address; this is presentation, not policy.
        self._display_host = display_host
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        scheme = "https" if self._tls_context is not None else "http"
        host = self._display_host or self._bind
        return f"{scheme}://{host}:{self._port}"

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
        if self._tls_context is not None:
            self._httpd.socket = self._tls_context.wrap_socket(
                self._httpd.socket, server_side=True
            )
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True, name="approval-surface"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()

    # -- request handling ----------------------------------------------------

    # Server-issued ids look like 'appr-3'. Anything outside this shape --
    # separators, blanks, leading dots -- is hostile-or-broken and dies at
    # the door, BEFORE it can reach a dict lookup or a filesystem path.
    _SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

    @classmethod
    def _approval_id(cls, path: str) -> str | None:
        parts = urlparse(path).path.strip("/").split("/")
        if len(parts) != 2 or parts[0] != "a":
            return None
        return parts[1] if cls._SAFE_ID.fullmatch(parts[1]) else None

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
                render_result_page(
                    "Refused", result["error"], ok=False
                ),
            )
        else:
            _respond(
                handler, 200,
                render_result_page(
                    result["state"].capitalize(),
                    f"Approval {approval_id} recorded"
                    + (
                        f" for {result['approver']}"
                        if result.get("approver")
                        else ""
                    )
                    + ". This decision is single-use and on the audit log.",
                    ok=True,
                ),
            )


def _respond(handler: BaseHTTPRequestHandler, status: int, body: str) -> None:
    data = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
