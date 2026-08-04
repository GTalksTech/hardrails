# Security Policy

Hardrails is a framework about enforcing boundaries on AI agents, so security
reports get taken seriously here even though the reference implementation is a
home-lab tool, not a production platform.

## Reporting a vulnerability

**Please do not open a public issue for an undisclosed vulnerability.**

Use GitHub's private vulnerability reporting instead:
[Report a vulnerability](https://github.com/GTalksTech/hardrails/security/advisories/new).
That opens a private thread with the maintainer where the report can be
confirmed, fixed, and credited before anything is public.

If you cannot use the form, email garrett@gtalkstech.com with "SECURITY" in
the subject line.

## What to expect

This is a solo-maintained project. Reports get acknowledged within a few days,
usually faster. You will get an honest read on severity and a fix timeline,
and credit in the advisory unless you prefer otherwise.

## Already-public limitations

Limitations that are already publicly documented (in the spec, in code
comments, or on the issue tracker) are tracked as regular GitHub issues, in
the open. Private reporting is for things not yet public.

## Supported versions

Pre-1.0: only the latest release and `main` are supported. There are no
security backports to older 0.x versions.

## Scope worth knowing

The reference implementation (`netagent/`) is designed for an isolated lab
network with documented placeholder credentials. It is not hardened for
production use, and the spec says so. Reports that find holes in the boundary
mechanisms themselves (the read-only enforcement, the approval gate, the audit
log) are the most valuable kind and are very welcome.
