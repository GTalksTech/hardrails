# netagent/data

`psirt_cache.json` is a frozen copy of a real Cisco PSIRT openVuln API response,
written by `scripts/generate_psirt_cache.py` -- never by hand. The `snapshot`
block records when it was retrieved, from which endpoint, and for which version;
that provenance is what makes the offline fallback honest. If you edit this file
manually it stops being evidence and becomes a hand-typed CVE list, which is
exactly what this project refuses to ship. `psirt_cache.json.example` shows the
structure only (empty advisories, placeholder metadata).
