#!/usr/bin/env python3
# ============================================================
# Script:       seed_netbox.py
# Purpose:      Populate a local NetBox with the demo lab's INTENT (the
#               "source of truth" the bounded agent audits live state against).
# Usage:        python seed_netbox.py            (reads NETBOX_URL / NETBOX_TOKEN)
#               python seed_netbox.py --dry-run  (print actions, change nothing)
# Dependencies: pynetbox>=7
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. The NetBox URL and
#               API token come from the NETBOX_URL / NETBOX_TOKEN env vars only,
#               never a file or a CLI flag. All addresses are REAL home-lab
#               RFC1918 values (the lab exists to be replicated).
# ============================================================
"""Seed a local NetBox instance with the demo lab intent.

This is the "what the network is SUPPOSED to be." The agent pulls live state
with Netmiko and diffs it against what this script writes. Two records here are
deliberately load-bearing for the demo's findings; they are called out inline:

1. SECURITY INTENT (CRITICAL finding anchor). The Servers prefix 10.10.30.0/24
   is tagged as a restricted, internal-only zone. NetBox natively models
   structure (interfaces, IPs, VLANs), not security posture, so the one piece of
   security intent the showpiece needs is encoded as tags. The agent then judges
   whether the multi-device config actually honors that documented intent. NetBox
   is the anchor; the agent's reasoning does the security work.

2. INTENT DRIFT (LOW finding anchor). VLAN 20 (Users) is recorded here as
   `deprecated` -- intent says it was decommissioned -- while it is still live on
   an access port in the lab. That gap is the drift the agent reports. This is
   the single cleanest mismatch; swap it for another if you prefer (see the
   VLAN block below).

Idempotent: safe to run repeatedly. Every object is fetched-or-created by a
natural key, so a second run reconciles instead of duplicating.

Written against NetBox 4.x + pynetbox 7.x. It has NOT been run against a live
NetBox yet (stand up netbox-docker first). If a field name differs on your
version, the failure will name the endpoint and payload so you can adjust.
"""

from __future__ import annotations

import argparse
import os
import sys

try:
    import pynetbox
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("pynetbox is not installed. In your venv: pip install pynetbox")


# --- Lab intent data (real RFC1918 values, per lab-state-snapshot.md) ----------

SITE = {"name": "GTT Home Lab", "slug": "gtt-home-lab"}
MANUFACTURER = {"name": "Cisco", "slug": "cisco"}

DEVICE_TYPES = [
    {"model": "Cisco IOL", "slug": "cisco-iol"},        # routers
    {"model": "Cisco IOL-L2", "slug": "cisco-iol-l2"},  # switch
]

DEVICE_ROLES = [
    {"name": "Router", "slug": "router", "color": "2196f3"},
    {"name": "Switch", "slug": "switch", "color": "4caf50"},
]

# Tags used to carry security intent NetBox does not model natively.
TAGS = [
    {"name": "security-zone-restricted", "slug": "security-zone-restricted",
     "color": "f44336"},
    {"name": "exposure-internal-only", "slug": "exposure-internal-only",
     "color": "ff9800"},
]

# device -> (device_type slug, role slug, primary mgmt address w/o mask)
DEVICES = [
    {"name": "core-rtr-01", "type": "cisco-iol", "role": "router",
     "primary_ip": "192.168.1.250/24"},
    {"name": "edge-rtr-01", "type": "cisco-iol", "role": "router",
     "primary_ip": "10.0.0.2/32"},
    {"name": "access-sw-01", "type": "cisco-iol-l2", "role": "switch",
     "primary_ip": "192.168.1.251/24"},
]

# VLANs. NOTE the deliberate drift on VLAN 20 (see module docstring #2).
VLANS = [
    {"vid": 1, "name": "default", "status": "active"},
    {"vid": 10, "name": "Management", "status": "active"},
    {"vid": 20, "name": "Users", "status": "deprecated"},   # <-- intent drift (LOW)
    {"vid": 30, "name": "Servers", "status": "active"},
]

# Prefixes. The Servers prefix carries the security-intent tags (CRITICAL anchor).
PREFIXES = [
    {"prefix": "192.168.1.0/24", "description": "LAN / management segment"},
    {"prefix": "10.0.12.0/30", "description": "core<->edge WAN point-to-point"},
    {"prefix": "10.10.10.0/24", "vlan": 10, "description": "Management VLAN"},
    {"prefix": "10.10.20.0/24", "vlan": 20, "description": "Users VLAN (intended decommissioned)"},
    {"prefix": "10.10.30.0/24", "vlan": 30,
     "description": "Servers VLAN -- restricted, internal-only",
     "tags": ["security-zone-restricted", "exposure-internal-only"]},
]

# Interfaces + IPs the agent actually reasons about (mgmt, links, SVIs, loopbacks).
# device -> list of (interface, type, address-or-None)
INTERFACES = {
    "core-rtr-01": [
        ("Loopback0", "virtual", "10.0.0.1/32"),
        ("Ethernet0/0", "1000base-t", "192.168.1.250/24"),
        ("Ethernet0/1", "1000base-t", "10.0.12.2/30"),
    ],
    "edge-rtr-01": [
        ("Loopback0", "virtual", "10.0.0.2/32"),
        ("Ethernet0/0", "1000base-t", "10.0.12.1/30"),
    ],
    "access-sw-01": [
        ("Vlan1", "virtual", "192.168.1.251/24"),
        ("Vlan10", "virtual", "10.10.10.1/24"),
        ("Vlan20", "virtual", "10.10.20.1/24"),
        ("Vlan30", "virtual", "10.10.30.1/24"),
        ("Ethernet0/0", "1000base-t", None),  # trunk to core
    ],
}


# --- Helpers -------------------------------------------------------------------

class Seeder:
    def __init__(self, nb, dry_run: bool):
        self.nb = nb
        self.dry_run = dry_run

    def ensure(self, endpoint, lookup: dict, create: dict):
        """Fetch by natural key, or create. Returns the record (None in dry-run
        when it would be newly created)."""
        existing = endpoint.get(**lookup)
        if existing:
            return existing
        label = create.get("name") or create.get("model") or create.get(
            "prefix") or create.get("address") or str(lookup)
        if self.dry_run:
            print(f"  WOULD CREATE {endpoint.name}: {label}")
            return None
        print(f"  create {endpoint.name}: {label}")
        return endpoint.create(**create)


def build_api(url: str, token: str):
    nb = pynetbox.api(url, token=token)
    # Surface a clear error early if the token/URL is wrong.
    try:
        nb.status()
    except Exception as exc:  # pragma: no cover - network dependent
        sys.exit(f"Could not reach NetBox at {url}: {exc}")
    return nb


def seed(nb, dry_run: bool) -> None:
    s = Seeder(nb, dry_run)

    print("Tags (security intent carriers):")
    for t in TAGS:
        s.ensure(nb.extras.tags, {"slug": t["slug"]}, t)

    print("Site / manufacturer:")
    site = s.ensure(nb.dcim.sites, {"slug": SITE["slug"]},
                    {**SITE, "status": "active"})
    manu = s.ensure(nb.dcim.manufacturers, {"slug": MANUFACTURER["slug"]},
                    MANUFACTURER)

    print("Device types:")
    dtypes = {}
    for dt in DEVICE_TYPES:
        rec = s.ensure(nb.dcim.device_types, {"slug": dt["slug"]},
                       {**dt, "manufacturer": _id(manu)})
        dtypes[dt["slug"]] = rec

    print("Device roles:")
    roles = {}
    for r in DEVICE_ROLES:
        rec = s.ensure(nb.dcim.device_roles, {"slug": r["slug"]}, r)
        roles[r["slug"]] = rec

    print("VLANs:")
    vlans = {}
    for v in VLANS:
        rec = s.ensure(nb.ipam.vlans, {"vid": v["vid"]},
                       {**v, "site": _id(site)})
        vlans[v["vid"]] = rec

    print("Prefixes:")
    for p in PREFIXES:
        create = {"prefix": p["prefix"], "status": "active",
                  "description": p.get("description", "")}
        if "vlan" in p:
            create["vlan"] = _id(vlans.get(p["vlan"]))
        if "tags" in p:
            create["tags"] = [{"slug": slug} for slug in p["tags"]]
        s.ensure(nb.ipam.prefixes, {"prefix": p["prefix"]}, create)

    print("Devices, interfaces, IPs:")
    for d in DEVICES:
        dev = s.ensure(
            nb.dcim.devices, {"name": d["name"]},
            {"name": d["name"], "device_type": _id(dtypes[d["type"]]),
             "role": _id(roles[d["role"]]), "site": _id(site),
             "status": "active"},
        )
        for (ifname, iftype, addr) in INTERFACES.get(d["name"], []):
            iface = s.ensure(
                nb.dcim.interfaces,
                {"device_id": _id(dev), "name": ifname} if dev else {"name": ifname},
                {"device": _id(dev), "name": ifname, "type": iftype},
            )
            if addr:
                ip = s.ensure(
                    nb.ipam.ip_addresses, {"address": addr},
                    {"address": addr, "status": "active",
                     "assigned_object_type": "dcim.interface",
                     "assigned_object_id": _id(iface)},
                )
                # Set the device's primary IPv4 to its management address.
                if dev and not dry_run and addr == d["primary_ip"] and ip:
                    dev.primary_ip4 = _id(ip)
                    dev.save()
                    print(f"    set {d['name']} primary_ip4 = {addr}")


def _id(rec):
    """pynetbox record -> id, tolerant of dry-run None."""
    return rec.id if rec is not None else None


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed NetBox with demo lab intent.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print what would change; write nothing.")
    args = ap.parse_args()

    url = os.environ.get("NETBOX_URL", "http://localhost:8000")
    token = os.environ.get("NETBOX_TOKEN")
    if not token:
        sys.exit("Set NETBOX_TOKEN in your environment (never in a file). "
                 "Optionally set NETBOX_URL (default http://localhost:8000).")

    print(f"NetBox: {url}  (dry-run={args.dry_run})")
    nb = build_api(url, token)
    seed(nb, args.dry_run)
    print("Done." if not args.dry_run else "Dry run complete (no changes made).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
