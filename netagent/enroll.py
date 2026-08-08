# ============================================================
# Module:       enroll.py
# Purpose:      One-time approval-secret enrollment, run by the HUMAN in
#               their own terminal (never by the agent). Generates the
#               secret, stores only its scrypt hash, and prints the
#               plaintext once with the handling rule.
# Dependencies: stdlib (qrcode optional, for a scannable code)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets committed --
#               the enrollment FILE holds a hash; the plaintext exists only
#               on the human's second device after this prints it.
# ============================================================
"""Enrollment CLI for the trusted-path approval surface.

    netagent-enroll [--file PATH]

Run this yourself, in your own terminal, once. It prints the approval
secret a single time; store it on the device you will approve from (a
phone's password manager is ideal) and never type it on the machine the
agent runs on. Re-running rotates the secret: the old one stops working
the moment the new hash is written.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from netagent.boundary import _resolve_audit_log_path
from netagent.trusted_path import enroll

_SECRET_FILE_ENV = "NETAGENT_APPROVAL_SECRET_FILE"


def _default_secret_file() -> Path:
    override = os.environ.get(_SECRET_FILE_ENV)
    if override:
        return Path(override)
    return _resolve_audit_log_path().parent / "approval-secret.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netagent-enroll",
        description="Enroll (or rotate) the trusted-path approval secret.",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Where the hash record is written (default: next to the audit "
        "log, or NETAGENT_APPROVAL_SECRET_FILE).",
    )
    args = parser.parse_args(argv)
    secret_file = args.file or _default_secret_file()

    rotating = secret_file.exists()
    secret = enroll(secret_file)

    print()
    print("Approval secret enrolled." if not rotating else
          "Approval secret ROTATED -- the previous secret no longer works.")
    print(f"Hash record: {secret_file}  (hash + salt only; safe on this disk)")
    print()
    print("Your approval secret -- shown ONCE, store it now:")
    print()
    print(f"    {secret}")
    print()
    print("Handling rule: this secret is only ever typed on a device that is")
    print("NOT the agent's machine (your phone, another laptop). If it ever")
    print("touches this machine again, re-run netagent-enroll to rotate it.")
    try:  # optional nicety: a scannable code if the qrcode package is present
        import qrcode  # type: ignore[import-not-found]

        qr = qrcode.QRCode(border=1)
        qr.add_data(secret)
        qr.print_ascii(out=sys.stdout)
    except ImportError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
