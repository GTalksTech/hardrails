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
    helpers, and `run_show()` inspects every command and raises if it smells
    like configuration or a write. There is no method here that enters config
    mode. The single path that mutates a device lives in remediation.py, behind
    an approved ApprovalRequest. That separation is the whole point: even a
    confused or adversarial agent cannot turn a "read" into a "write" through
    this object, because the capability simply is not present.
"""

from __future__ import annotations

import os
import re
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
# Write-command guard rail.
# ----------------------------------------------------------------------------
# Any command matching one of these is refused on the READ path. This is a
# belt-and-suspenders check: the read object has no config-mode method at all,
# but if someone routes a hostile string through run_show() we still block it
# with a clear reason rather than silently shipping it to the device.
_WRITE_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*conf(igure)?\b", re.IGNORECASE),        # configure terminal
    re.compile(r"^\s*(no|default)\s+", re.IGNORECASE),        # negate / default a line
    re.compile(r"^\s*write\b", re.IGNORECASE),                # write memory
    re.compile(r"^\s*copy\b", re.IGNORECASE),                 # copy run start, tftp, etc.
    re.compile(r"^\s*(reload|erase|delete|format)\b", re.IGNORECASE),
    re.compile(r"^\s*clear\b", re.IGNORECASE),                # clears mutate state (counters/BGP)
    re.compile(r"^\s*(interface|router|line|vlan|ip\s+route)\b", re.IGNORECASE),  # config-mode entry
)


class WriteAttemptOnReadPath(RuntimeError):
    """Raised when a config/write command is sent through the read-only path.

    Surfacing this as a distinct exception lets the boundary log it as an
    attempted mutation rather than a generic error -- that distinction matters
    for the audit trail on camera.
    """


def _looks_like_write(command: str) -> bool:
    """Return True if `command` would change device state.

    We default to caution: 'show', 'ping', and 'traceroute' are the only verbs
    we actually expect on this path, but rather than allow-list every safe show
    variant we block the known mutating verbs explicitly and let genuine reads
    through. If in doubt, prefer a false positive (block) over a false negative.
    """
    return any(pattern.search(command) for pattern in _WRITE_COMMAND_PATTERNS)


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

        Raises WriteAttemptOnReadPath if `command` would mutate the device.
        This is the choke point: nothing reaches the wire from this object
        without passing the write guard first.
        """
        if self._conn is None:
            raise RuntimeError("Not connected. Use DeviceConnection as a context manager.")
        if _looks_like_write(command):
            raise WriteAttemptOnReadPath(
                f"Refused: '{command}' looks like a configuration/write command. "
                "The read path is read-only; changes must go through a "
                "RemediationProposal and an approved ApprovalRequest."
            )
        return self._conn.send_command(command, read_timeout=_READ_TIMEOUT)

    def get_version(self) -> str:
        """`show version` -- feeds the deterministic version->CVE check."""
        return self.run_show("show version")

    def get_running_config(self) -> str:
        """`show running-config` -- feeds config-based hardening/drift checks."""
        return self.run_show("show running-config")
