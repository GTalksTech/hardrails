#!/usr/bin/env python3
# ============================================================
# Script:       provision_netbox_ro_token.py
# Purpose:      Mint a READ-ONLY NetBox API token (least privilege) for the
#               intent-drift check, verify it authenticates, PROVE it cannot
#               write, then print it once -- like the NetBox UI does.
# Usage:        python scripts/provision_netbox_ro_token.py [--url URL]
#                   [--username NAME] [--description TEXT]
# Dependencies: httpx (installed with `pip install hardrails[lab]`)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. The password is read via getpass only --
#               never an argument, never an env var, never stored.
# ============================================================
"""Provision a least-privilege NetBox token for the drift check.

Why this exists: the posture sweep only READS intent from NetBox, so its
credential should not be able to write -- the Hardrails least-privilege
principle applied to the agent's own supply chain. NetBox 4.6+ v2 token
mechanics this script handles for you:

  * The provision endpoint mints a token from username + password, so you
    never need an existing token to get started.
  * The API returns the credential in PARTS: `key` (a public identifier)
    and `token` (the secret half, shown exactly once -- NetBox stores only
    an HMAC digest). The usable value is `nbt_<key>.<secret>`, assembled
    here so you don't learn that the hard way.
  * A 403 alone proves nothing about permissions -- invalid tokens also get
    403 -- so the write-denial proof only counts AFTER a positive read
    check passes.

Exit codes: 0 = token minted and least privilege proven; 1 = the proof
failed (do not use the token); 2 = could not provision.
"""

from __future__ import annotations

import argparse
import os
import sys
from getpass import getpass

try:
    import httpx
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("httpx is not installed. In your venv: pip install hardrails[lab]")

_PROBE_TAG = {"name": "hardrails-rw-probe", "slug": "hardrails-rw-probe"}


def _fail(code: int, msg: str) -> "NoReturn":  # noqa: F821 - py3.10 friendly
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def provision(client: httpx.Client, api: str, username: str, password: str,
              description: str) -> dict:
    """Mint the read-only token; return the API's response object."""
    resp = client.post(
        f"{api}/users/tokens/provision/",
        json={
            "username": username,
            "password": password,
            "write_enabled": False,
            "description": description,
        },
    )
    if resp.status_code in (401, 403):
        _fail(2, "NetBox refused the credentials (invalid username/password, "
                 "or the account lacks API access).")
    if resp.status_code not in (200, 201):
        _fail(2, f"Provision endpoint returned HTTP {resp.status_code}: "
                 f"{resp.text[:200]}")
    return resp.json()


def assemble_token(payload: dict) -> str:
    """Build the usable credential from the response's key + secret parts."""
    secret = str(payload.get("token") or "").strip()
    if not secret:
        _fail(2, "No plaintext token in the provision response (fields: "
                 f"{', '.join(sorted(payload))}).")
    if secret.startswith("nbt_"):  # future-proof: already composite
        return secret
    key = str(payload.get("key") or "").strip()
    if not key:
        _fail(2, "Provision response had a token secret but no key part.")
    return f"nbt_{key}.{secret}"


def prove_least_privilege(client: httpx.Client, api: str, token: str) -> None:
    """Positive read first, then the write must be denied."""
    headers = {"Authorization": f"Token {token}"}

    read = client.get(f"{api}/", headers=headers)
    if read.status_code != 200:
        _fail(1, f"Positive read check failed (HTTP {read.status_code}) -- "
                 "the fresh token does not authenticate; a write probe would "
                 "prove nothing.")
    print("Positive read check: OK (the token authenticates).")

    write = client.post(f"{api}/extras/tags/", headers=headers, json=_PROBE_TAG)
    if write.status_code == 403:
        detail = ""
        try:
            detail = write.json().get("detail", "")
        except ValueError:
            pass
        print(f"Least-privilege proof: write DENIED (HTTP 403 {detail}). Good.")
        return

    # The write went through (or something unexpected). Clean up and refuse.
    if write.status_code in (200, 201):
        probe = client.get(
            f"{api}/extras/tags/?slug={_PROBE_TAG['slug']}", headers=headers
        )
        for tag in probe.json().get("results", []):
            client.delete(f"{api}/extras/tags/{tag['id']}/", headers=headers)
    _fail(1, f"Write probe was NOT denied (HTTP {write.status_code}). "
             "The token is not read-only -- do not use it.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mint a read-only NetBox token and prove it cannot write."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("NETBOX_URL", "http://localhost:8000"),
        help="NetBox base URL (default: $NETBOX_URL or http://localhost:8000)",
    )
    parser.add_argument("--username", help="NetBox username (prompted if omitted)")
    parser.add_argument(
        "--description",
        default="hardrails drift-check read-only token",
        help="Description stored on the token in NetBox",
    )
    args = parser.parse_args()

    username = args.username or input("NetBox username: ")
    password = getpass("NetBox password (input hidden): ")
    api = args.url.rstrip("/") + "/api"

    with httpx.Client(timeout=15.0) as client:
        try:
            payload = provision(client, api, username, password, args.description)
        except httpx.HTTPError as exc:
            _fail(2, f"Could not reach NetBox at {args.url}: {exc}")
        token = assemble_token(payload)
        print(f"Token minted: id {payload.get('id')}, "
              f"write_enabled={payload.get('write_enabled')}")
        prove_least_privilege(client, api, token)

    print()
    print("Your READ-ONLY NetBox token (shown once, like the NetBox UI -- "
          "save it in your secret manager now):")
    print()
    print(f"  {token}")
    print()
    print("Use it via the environment only (never a file, never a CLI flag):")
    print('  PowerShell:  $env:NETBOX_TOKEN = "<paste>"')
    print('  bash/zsh:    export NETBOX_TOKEN="<paste>"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
