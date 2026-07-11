# ============================================================
# Script:       generate_psirt_cache.py
# Purpose:      Freeze a REAL Cisco PSIRT openVuln API response into
#               netagent/data/psirt_cache.json, with a provenance envelope
#               (when, from which endpoint, for which version). This is the
#               ONLY sanctioned way that file comes into existence.
# Usage:        set PSIRT_CLIENT_ID / PSIRT_CLIENT_SECRET in the shell, then
#               python scripts/generate_psirt_cache.py --os-type iosxe --version 17.16.1a
# Dependencies: httpx (via netagent.cve_source)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Credentials are
#               read from environment variables only. Part of the Hardrails
#               framework reference implementation.
# ============================================================
"""Generate the pinned PSIRT cache from a live API call.

The offline CVE fallback (`CachedCVESource`) refuses to load a file without a
provenance envelope, and this script is what writes that envelope. Run it once
against the live API and the lab can then run credential-free, replaying the
frozen answer -- honestly labeled as the API's response, dated, never hand-typed.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running straight from the repo (python scripts/generate_psirt_cache.py)
# even without `pip install -e .` -- the package sits one level up.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netagent.cve_source import (  # noqa: E402 -- after the path shim, deliberately
    DEFAULT_CACHE_PATH,
    CVESourceError,
    PsirtCVESource,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze a live Cisco PSIRT openVuln API response to disk."
    )
    parser.add_argument(
        "--os-type",
        default="iosxe",
        help="API OSType to query (e.g. iosxe, ios). Default: iosxe.",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Software version to query, e.g. 17.16.1a.",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_CACHE_PATH),
        help=f"Output path. Default: {DEFAULT_CACHE_PATH}",
    )
    args = parser.parse_args()

    source = PsirtCVESource()
    try:
        request_url, advisories = source.fetch_raw(args.os_type, args.version)
    except CVESourceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    payload = {
        "snapshot": {
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "endpoint": request_url,
            "os_type": args.os_type,
            "version": args.version,
            "advisory_count": len(advisories),
            "generated_by": "scripts/generate_psirt_cache.py",
        },
        # The raw advisory objects, exactly as the API returned them. The cache
        # and the live path normalize through the same function, so replaying
        # this file reproduces the live answer.
        "advisories": advisories,
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"Froze {len(advisories)} advisory object(s) for {args.os_type} "
          f"{args.version} -> {out}")
    print(f"Source: {request_url}")
    print("This file is now evidence. Do not hand-edit it; regenerate instead.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
