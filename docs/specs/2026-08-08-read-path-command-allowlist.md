# Read-path command policy: allowlist, not blocklist (close the write-guard bypass)

**Status:** implemented in the same PR (fix for issue #16)
**Date:** 2026-08-08

## Problem

`run_show` is registered as a READ tool (`server.py`), so the boundary allows
it to run freely — no approval, no dry-run. The *only* thing standing between
the agent and the wire on that path is `devices._looks_like_write()`, a
**blocklist** of mutating verbs (`_WRITE_COMMAND_PATTERNS`). It is bypassable
several ways, and the bypass turns the read path into an unapproved write path
— defeating boundary principle 1 (invariant 1), and with it 2 and 3:

1. **Newline / carriage-return smuggling.** Every pattern is anchored `^\s*…`
   and matched with `re.search` *without* `re.MULTILINE`, so `^` matches only
   position 0 of the whole string. Only the first line is inspected.
   `run_show` then hands the raw string to `netmiko.send_command`, which writes
   it — interior newlines intact — to the channel, so each embedded line is a
   separate CLI command. `show version\nconfigure terminal\nno ip http server`
   passes the guard, enters config mode on the device, and applies the change.
2. **Separator chaining.** `show run ; conf t` (a separator on some platforms)
   is inspected only up to the first token.
3. **Output redirect.** `show running-config | redirect flash:x` (also `| tee`,
   `| append`) writes to the device filesystem with no config mode at all.
4. **Verbs absent from the blocklist.** `debug …` (an availability hazard), and
   abbreviations of blocked verbs the `\b`-anchored patterns miss: `wr`,
   `wr mem`, `rel`, `cop`.

This is the exact failure the spec warns about in principle 1: "a 'show
command' tool that passes arbitrary strings to a device is a config tool with a
friendly name. Validate or **allowlist** what actually reaches the wire." A
blocklist enumerates what to forbid and is beaten by anything unforeseen; the
tool's contract ("ONE read command") is a positive shape, so the policy should
be positive too.

The guard had **zero test coverage** — nothing exercised `_looks_like_write` or
`WriteAttemptOnReadPath` — which is why this went unnoticed.

## Fix

Replace the blocklist with a positive **allowlist**, enforced at `run_show`
(the sole choke point to `send_command`), refusing before anything reaches the
wire. A command is permitted only if all hold:

1. **One command only.** No embedded command separators — reject any `\n`,
   `\r`, or `;`, and any other ASCII control character. The tool contract is
   exactly one read command; a string carrying a second one is refused
   outright. This alone closes bypasses 1 and 2.
2. **First token is a known read verb.** The first whitespace-delimited token
   (lower-cased) must be in a small allowlist: `show`, `ping`, `traceroute`.
   An unrecognised verb is refused — so `configure`/`conf`, `write`/`wr`,
   `reload`/`rel`, `copy`/`cop`, `clear`, `debug`, `tclsh`, `interface`, … are
   all refused because they are *not on the list*, not because we remembered to
   forbid each one. Abbreviations of read verbs (`sh`, `sho`) are also refused;
   the agent surface sends the full verb (the internal callers already do), and
   "prefer a false positive (block) over a false negative" is the module's
   stated bias.
3. **No output redirect.** A read may be piped to a *filter*
   (`| include`, `| exclude`, `| begin`, `| section`, `| count`), but never to
   a device-side write target — reject `| redirect`, `| tee`, `| append`.

The refusal is a `WriteAttemptOnReadPath` with a reason that names the rule, so
the block is legible to the agent and lands in the audit trail rather than
silently reaching the device.

## Non-goals

- **Full IOS command parsing.** The allowlist is deliberately small and literal.
  It does not model every safe `show` variant or every platform's separator
  grammar; it refuses anything it does not positively recognise as one read
  command. Breadth is a false-negative risk; this errs to refusal.
- **Changing the boundary's tool-kind model.** `run_show` stays a READ tool;
  this hardens what "read" is allowed to mean at the command level. The MUTATE
  path (dry-run + approval) is unchanged.
- **Rejecting filter pipes.** `| include`/`| section` etc. remain allowed — they
  shape output, they do not write.

## Tests

New `tests/test_read_path_guard.py` (the coverage that was missing) drives
`DeviceConnection.run_show` with a fake `_conn` and asserts:

- Legitimate reads pass and reach `send_command`: `show version`,
  `show running-config`, `show ip interface brief`, `ping 10.0.0.1`,
  `traceroute 10.0.0.1`, `show run | include secret`.
- Every write/EXEC verb is refused and **nothing reaches `send_command`**:
  `configure terminal`, `conf t`, `no ip http server`, `write memory`, `wr`,
  `copy running-config startup-config`, `reload`, `clear ip bgp *`,
  `interface Gi0/0`, `debug ip packet`, `debug all`, `tclsh`.
- The smuggling matrix is refused with nothing on the wire:
  `show version\nconfigure terminal`, `show run\nconf t\ninterface Gi0/0`,
  `show version ; conf t`, `show ip int brief\rno ip http server`,
  `show running-config | redirect flash:pwn.txt`, `show run | tee flash:x`.
- A refusal raises `WriteAttemptOnReadPath`; a permitted command does not.
