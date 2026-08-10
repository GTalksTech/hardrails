# ============================================================
# Module:       devices.py
# Purpose:      Thin, READ-ONLY Netmiko wrapper + inventory loader. This is the
#               only place the agent talks to a device on the read path -- and it
#               structurally refuses to send configuration commands.
# Dependencies: netmiko, pyyaml
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Part of the
#               Hardrails framework reference implementation.
# ============================================================
"""Device access layer for the bounded network-agent.

Boundary rationale (this file is read on camera):

    "Read-only by default" is not a comment we hope the agent honors -- it is
    enforced by the shape of this module. `DeviceConnection` exposes ONLY show
    helpers, and `run_show()` validates every command against a positive
    read-only allowlist -- one show/ping/traceroute, no second command, no
    redirect -- and refuses anything else. There is no method here that enters
    config mode. The single path that mutates a device lives in remediation.py, behind
    an approved ApprovalRequest. That separation is the whole point: even a
    confused or adversarial agent cannot turn a "read" into a "write" through
    this object, because the capability simply is not present.
"""

from __future__ import annotations

import os
from getpass import getpass
from pathlib import Path

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

# Where the inventory lives, relative to this file.
_INVENTORY_PATH = Path(__file__).with_name("inventory.yaml")

# Environment variable the runtime reads the password from. We NEVER accept a
# password as a function argument or CLI flag -- that keeps it out of process
# listings, shell history, and this public repo.
_PASSWORD_ENV = "NETAGENT_PASSWORD"

# Netmiko timeouts (seconds). Kept conservative so a wedged device fails fast
# and loudly instead of hanging the agent mid-audit.
_CONNECT_TIMEOUT = 15
_READ_TIMEOUT = 30

# ----------------------------------------------------------------------------
# Read-path command policy: a positive allowlist.
# ----------------------------------------------------------------------------
# `run_show` is a READ tool -- the boundary lets it run without an approval, so
# THIS policy is the per-command enforcement of "read-only by default" (boundary
# principle 1). It is a positive allowlist, not a blocklist: the tool contract
# is exactly ONE read command, so a command is permitted only if it is one show/
# ping/traceroute with no second command smuggled in and no output redirect.
# Anything we do not positively recognise is refused -- an unforeseen verb fails
# closed instead of sailing through, which is the whole point of an allowlist.
#
# Why not a blocklist of mutating verbs (the old design): it was bypassable. The
# old patterns were anchored to the START of the string and matched without
# re.MULTILINE, so a newline or ';' hid a second command from them
# ("show version\nconfigure terminal"), and abbreviations (`wr`, `rel`) and
# unlisted EXEC verbs (`debug`, `tclsh`) were never covered. netmiko.send_command
# writes the raw string -- interior newlines and all -- so any smuggled line
# reaches the wire. See docs/specs/2026-08-08-read-path-command-allowlist.md.

# The only verbs allowed to reach the wire on the read path. Full verbs only --
# the agent surface emits them in full, and refusing abbreviations keeps the
# allowlist unambiguous.
_READ_VERBS = frozenset({"show", "ping", "traceroute"})

# A read may be piped to a FILTER, and the filter is itself a POSITIVE allowlist:
# after a `|`, only these display-only modifiers are permitted, full word. This
# is the same allowlist discipline as the leading verb, and for the same reason
# -- a write-target *blocklist* (redirect/tee/append) missed IOS abbreviations
# (`red`/`te`/`a`) and modifiers hidden behind a legal filter in a chained pipe,
# turning the read path into an unapproved (and remotely-exfiltrating) write path
# (issue #35). Anything after `|` that is not on this list fails closed --
# including `redirect`/`tee`/`append`, their abbreviations, and unknown modifiers.
_READ_PIPE_FILTERS = frozenset({"include", "exclude", "begin", "section", "count"})


class WriteAttemptOnReadPath(RuntimeError):
    """Raised when a non-read command is sent through the read-only path.

    Surfacing this as a distinct exception lets the boundary log it as an
    attempted mutation rather than a generic error -- that distinction matters
    for the audit trail on camera.
    """


def _read_command_rejection(command: str) -> str | None:
    """Why `command` is not a single permitted read command, or None if it is.

    The allowlist, in order: reject anything that packs in more than one command
    (embedded newline, carriage return, ';', or any other control character);
    require the first token to be a known read verb; and refuse an output
    redirect. Returning a reason (not a bool) lets the caller tell the agent
    exactly which rule it hit.
    """
    if not command or not command.strip():
        return "empty command: send one show/ping/traceroute command."
    # One command only. A newline / CR / ';' means a second command is riding
    # along, and netmiko would deliver every line to the device -- this is
    # exactly where a "read" turns into a write. Refuse the whole string.
    if any(sep in command for sep in ("\n", "\r", ";")):
        return (
            "more than one command on the read path (found a newline, carriage "
            "return, or ';'). Send exactly one show/ping/traceroute command; "
            "changes go through a RemediationProposal and an approved "
            "ApprovalRequest."
        )
    if any(ord(ch) < 0x20 for ch in command):
        return "control characters are not allowed in a read command."
    first = command.split()[0].lower()
    if first not in _READ_VERBS:
        return (
            f"'{first}' is not a permitted read verb. The read path allows only "
            f"{', '.join(sorted(_READ_VERBS))} (full verb, no abbreviations). "
            "A change must go through a RemediationProposal and an approved "
            "ApprovalRequest."
        )
    # Pipe filters are a positive allowlist, checked on EVERY segment (not just
    # the first) so a redirect cannot hide behind a legal filter in a chained
    # pipe. The first token of each `| ...` segment must be a known read filter,
    # full word -- redirect/tee/append and their abbreviations are not on the
    # list and fail closed. See docs/specs/2026-08-10-read-path-pipe-filter-allowlist.md.
    if "|" in command:
        for segment in command.split("|")[1:]:
            tokens = segment.split()
            if not tokens:
                return (
                    "empty pipe segment ('|' with nothing after it). Pipe a read "
                    "to exactly one filter: "
                    f"| {', '.join(sorted(_READ_PIPE_FILTERS))}."
                )
            modifier = tokens[0].lower()
            if modifier not in _READ_PIPE_FILTERS:
                return (
                    f"'| {tokens[0]}' is not a permitted read filter. After a "
                    f"pipe the read path allows only "
                    f"{', '.join(sorted(_READ_PIPE_FILTERS))} (full word, no "
                    "abbreviations); output redirects (redirect/tee/append) write "
                    "to the device -- including to remote destinations -- and are "
                    "refused. A change must go through a RemediationProposal and "
                    "an approved ApprovalRequest."
                )
    return None


class Device(dict):
    """A single inventory entry (hostname, host, role, device_type, username).

    Kept as a plain dict subclass so it drops straight into Netmiko's
    ConnectHandler(**params) without ceremony.
    """

    @property
    def hostname(self) -> str:
        return self["hostname"]

    @property
    def role(self) -> str:
        return self.get("role", "unknown")


def load_inventory(path: Path | str = _INVENTORY_PATH) -> list[Device]:
    """Load and normalize inventory.yaml into a list of Device entries.

    `defaults` are merged into every device so each entry is self-contained.
    No password is read here -- inventory carries no secrets.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    defaults = data.get("defaults", {}) or {}
    devices: list[Device] = []
    for entry in data.get("devices", []) or []:
        merged = {**defaults, **entry}
        devices.append(Device(merged))
    return devices


def get_device(hostname: str, path: Path | str = _INVENTORY_PATH) -> Device:
    """Look up one device by hostname. Raises KeyError if it is not in inventory.

    The agent can only act on devices the operator has declared -- an unknown
    hostname is a hard stop, not a silent connect attempt to an arbitrary IP.
    """
    for device in load_inventory(path):
        if device.hostname == hostname:
            return device
    known = ", ".join(d.hostname for d in load_inventory(path))
    raise KeyError(f"Unknown device '{hostname}'. Known devices: {known}")


def _resolve_password() -> str:
    """Get the device password from the environment, or prompt for it once.

    Order: NETAGENT_PASSWORD env var first (for non-interactive / MCP use),
    getpass fallback for a human at a terminal. The password is never written
    to disk, never logged, and never accepted as an argument.
    """
    password = os.environ.get(_PASSWORD_ENV)
    if password:
        return password
    return getpass("Device password (input hidden): ")


class DeviceConnection:
    """A READ-ONLY Netmiko session to a single device.

    Use as a context manager:

        with DeviceConnection(get_device("core-rtr-01")) as conn:
            output = conn.run_show("show ip interface brief")

    The object deliberately exposes no way to enter configuration mode. Every
    convenience method funnels through `run_show`, which refuses writes. This is
    the read half of the boundary; the write half lives in remediation.py.
    """

    def __init__(self, device: Device, password: str | None = None) -> None:
        self.device = device
        # Password is resolved lazily at connect time if not supplied. We accept
        # it as an OPTIONAL constructor arg only so the server can resolve it
        # once and reuse it -- it is never persisted on the instance beyond the
        # live session and never comes from a file or CLI flag.
        self._password = password
        self._conn: ConnectHandler | None = None

    # -- lifecycle -----------------------------------------------------------

    def connect(self) -> "DeviceConnection":
        password = self._password or _resolve_password()
        params = {
            "device_type": self.device["device_type"],
            "host": self.device["host"],
            "username": self.device["username"],
            "password": password,
            "conn_timeout": _CONNECT_TIMEOUT,
            "read_timeout_override": _READ_TIMEOUT,
        }
        try:
            self._conn = ConnectHandler(**params)
        except NetmikoAuthenticationException as exc:
            raise RuntimeError(
                f"Authentication failed for {self.device.hostname} "
                f"({self.device['host']}). Check NETAGENT_PASSWORD."
            ) from exc
        except NetmikoTimeoutException as exc:
            raise RuntimeError(
                f"Timed out connecting to {self.device.hostname} "
                f"({self.device['host']}) after {_CONNECT_TIMEOUT}s."
            ) from exc
        return self

    def disconnect(self) -> None:
        if self._conn is not None:
            self._conn.disconnect()
            self._conn = None

    def __enter__(self) -> "DeviceConnection":
        return self.connect()

    def __exit__(self, *exc_info: object) -> None:
        self.disconnect()

    # -- read helpers --------------------------------------------------------

    def run_show(self, command: str) -> str:
        """Run a single READ command and return its text output.

        Raises WriteAttemptOnReadPath if `command` is not a single permitted
        read command (see the read-path allowlist above). This is the choke
        point: nothing reaches the wire from this object without passing it.
        """
        if self._conn is None:
            raise RuntimeError("Not connected. Use DeviceConnection as a context manager.")
        rejection = _read_command_rejection(command)
        if rejection is not None:
            raise WriteAttemptOnReadPath(f"Refused: {rejection}")
        return self._conn.send_command(command, read_timeout=_READ_TIMEOUT)

    def get_version(self) -> str:
        """`show version` -- feeds the deterministic version->CVE check."""
        return self.run_show("show version")

    def get_running_config(self) -> str:
        """`show running-config` -- feeds config-based hardening/drift checks."""
        return self.run_show("show running-config")
