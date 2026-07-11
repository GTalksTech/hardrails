# ============================================================
# Module:       cve_source.py
# Purpose:      The real CVE backends behind audit.py's CVESource seam: a live
#               Cisco PSIRT openVuln API client, a pinned offline cache that is
#               a frozen copy of a real API response, and the chained default
#               that prefers live and falls back honestly.
# Dependencies: httpx (live client); stdlib json/pathlib for the cache
# Author:       G Talks Tech
# Episode:      EP010-L-ai-network-agents
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Part of the
#               Hardrails framework reference implementation.
# ============================================================
"""CVE backends: live PSIRT, pinned cache, and the chain that prefers live.

The audit sweep's CVE finding is tagged DETERMINISTIC_CHECK, which is a promise:
the CVE came from a real version-to-advisory lookup, never the model reciting
CVE numbers from memory. This module is where that promise is kept. Three
implementations of the `CVESource` Protocol from audit.py:

    PsirtCVESource   -- asks Cisco's PSIRT openVuln API live. The authoritative
                        answer, same data Cisco Software Checker uses.
    CachedCVESource  -- replays a FROZEN copy of a real API response from disk,
                        for anyone running the lab without Cisco API creds. The
                        file carries provenance (when it was retrieved, from
                        which endpoint, for which version) so you can show the
                        cache IS the API's answer, not a hand-typed list.
    ChainedCVESource -- tries live, falls back to the cache, and records which
                        one answered. This is the default the server uses.

One honesty rule holds across all three, and it is the reason the failure modes
below are loud instead of quiet: an EMPTY list means "Cisco says no advisories
affect this version." It never means "the lookup failed." A failed lookup
raises `CVESourceUnavailable`, so a broken network or missing credentials can
never masquerade as a clean bill of health.

Every API detail below (endpoints, field names, limits) was verified against
Cisco's live documentation before it was written down -- the doc URLs sit next
to the constants they justify. Nothing in this file is guessed.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from netagent.audit import CVERecord

# ----------------------------------------------------------------------------
# Verified Cisco PSIRT openVuln API facts (with sources).
# ----------------------------------------------------------------------------

# OAuth2 token endpoint (client-credentials grant, form-encoded POST).
# Verified: https://developer.cisco.com/docs/psirt/authentication/
#   "curl ... -d 'grant_type=client_credentials' https://id.cisco.com/oauth2/default/v1/token"
# Also confirmed by Cisco's own client, CiscoPSIRT/openVulnQuery
# (openVulnQuery/_library/config.py: REQUEST_TOKEN_URL). The old
# cloudsso.cisco.com endpoint is retired.
TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"

# Token lifetime: the docs' example token response shows "expires_in": 3600
# (one hour). Verified: https://developer.cisco.com/docs/psirt/authentication/
# We trust the expires_in the server actually returns, minus a safety margin.
_TOKEN_SAFETY_MARGIN_S = 60

# API base. Verified: https://developer.cisco.com/docs/psirt/ostypeostype/
# (example request https://apix.cisco.com/security/advisories/v2/OSType/ios?...)
# and CiscoPSIRT/openVulnQuery config.py (API_URL). The pre-2023 api.cisco.com
# host is retired.
API_BASE = "https://apix.cisco.com/security/advisories/v2"

# The version query: GET /OSType/{OSType}?version=<ver>. This is the same
# lookup Cisco Software Checker performs. Verified:
# https://developer.cisco.com/docs/psirt/ostypeostype/ (path, params, and the
# supported OSType values: aci, ios, iosxe, nxos, asa, ftd, fmc, fxos) and
# https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/
# (example: .../OSType/iosxe?version=17.2.1, and the note that version queries
# include firstFixed data).
#
# audit.py's parser emits "ios-xe" / "ios"; the API spells it "iosxe" / "ios".
# This map is the translation. An OS family we cannot map raises rather than
# guessing an endpoint.
_OS_TYPE_ALIASES = {
    "ios": "ios",
    "ios-xe": "iosxe",
    "iosxe": "iosxe",
}

# Response shape. The body is {"advisories": [...]} -- envelope confirmed by
# Cisco's own reference client (CiscoPSIRT/openVulnQuery
# openVulnQuery/_library/query_client.py reads advisories['advisories']).
# Advisory field names, verified at
# https://developer.cisco.com/docs/psirt/ostypeostype/ :
#   advisoryId, advisoryTitle, cves, cvssBaseScore, firstPublished,
#   lastUpdated, publicationUrl, sir, bugIDs, summary
# plus firstFixed (array of first-fixed releases), which version queries
# include per https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/

# "No advisories affect this version" is NOT an empty 200. Verified:
# https://developer.cisco.com/docs/psirt/errors-and-troubleshooting/ -- the API
# answers 404 with {"errorCode": "NO_DATA_FOUND", "errorMessage": "No data
# found" / "No advisories found"}. That exact case is the ONLY one we translate
# to an empty list, because it is Cisco affirmatively saying "nothing matches."
# Any other 404 (or any other error) raises.
_NO_DATA_ERROR_CODE = "NO_DATA_FOUND"

# Rate limits: "a combination of 5 calls per second, 30 calls per minute, and
# 5000 calls per day." Verified:
# https://sec.cloudapps.cisco.com/security/center/resources/openvulnapi
# Our sweep makes one query per device (three in the lab), so we implement
# modest courtesy -- a minimum spacing between calls -- not elaborate throttling.
_MIN_SECONDS_BETWEEN_CALLS = 0.25


# ----------------------------------------------------------------------------
# Failure modes (typed, so the chain can catch them).
# ----------------------------------------------------------------------------


class CVESourceError(RuntimeError):
    """Base error for CVE backends. Anything raised here means NO answer.

    Deliberately never swallowed into an empty list -- see the module
    docstring. Empty list = "Cisco says clean." Exception = "we don't know."
    """


class CVESourceUnavailable(CVESourceError):
    """The source could not answer (missing creds, network, auth, bad response).

    This is the exception `ChainedCVESource` catches to fall back from the live
    API to the pinned cache. It means "try another source," never "assume
    clean."
    """


# ----------------------------------------------------------------------------
# Shared normalization (live and cache MUST go through the same code path).
# ----------------------------------------------------------------------------


def _normalize_os_type(os_type: str) -> str:
    """Translate audit.py's OS family spelling into the API's OSType value."""
    normalized = _OS_TYPE_ALIASES.get(os_type.strip().lower())
    if normalized is None:
        raise CVESourceError(
            f"Unsupported OS family '{os_type}'. This backend knows how to ask "
            f"the PSIRT API about: {', '.join(sorted(set(_OS_TYPE_ALIASES)))}. "
            "Refusing to guess an endpoint."
        )
    return normalized


def records_from_advisories(advisories: list[dict]) -> list[CVERecord]:
    """Normalize raw openVuln advisory objects into backend-neutral CVERecords.

    Both the live client and the cache call this -- one code path, so replaying
    the frozen response produces byte-for-byte the same records the live API
    would have. That is what makes the cache an honest stand-in.

    Field-name sources are documented at the top of this module. Two shapes we
    stay flexible on (the docs describe `cves` as "CVE identifier(s)" without
    pinning list-vs-string, and we refuse to invent precision the docs don't
    give): `cves` may be a list or a single string, and `cvssBaseScore` is
    documented as numeric but is parsed defensively.
    """
    records: list[CVERecord] = []
    for adv in advisories:
        # CVE id(s): normalize to a list of strings.
        raw_cves = adv.get("cves", [])
        if isinstance(raw_cves, str):
            cve_list = [c.strip() for c in raw_cves.split(",") if c.strip()]
        else:
            cve_list = [str(c).strip() for c in raw_cves if str(c).strip()]
        # An advisory with no CVE at all still names a real vulnerability;
        # fall back to the advisory id rather than dropping it silently.
        primary = cve_list[0] if cve_list else str(adv.get("advisoryId", "unknown-advisory"))

        title = str(adv.get("advisoryTitle", "(untitled advisory)"))
        if len(cve_list) > 1:
            # One record per advisory. The extra CVEs are surfaced, not dropped.
            title = f"{title} (advisory also covers {', '.join(cve_list[1:])})"

        # CVSS: documented numeric; parse defensively. If Cisco ships something
        # unparseable we score it 0.0 (LOW) and leave the advisory URL in the
        # record so a human sees the real rating -- we do not invent a score.
        try:
            cvss = float(adv.get("cvssBaseScore", 0.0))
        except (TypeError, ValueError):
            cvss = 0.0

        # firstFixed: array of first-fixed releases on version queries.
        raw_fixed = adv.get("firstFixed") or []
        if isinstance(raw_fixed, str):
            raw_fixed = [raw_fixed]
        fixed = ", ".join(str(v) for v in raw_fixed) or "no first-fixed release listed"

        records.append(
            CVERecord(
                cve_id=primary,
                cvss=cvss,
                title=title,
                fixed_version=fixed,
                url=str(adv.get("publicationUrl", "")),
                # The API does not encode exposure conditions (e.g. "only if
                # the HTTP server is enabled") -- that nuance comes from the
                # advisory text and the agent's config reasoning, so we never
                # fabricate it here.
                condition="",
            )
        )
    return records


# ----------------------------------------------------------------------------
# Live backend: Cisco PSIRT openVuln API.
# ----------------------------------------------------------------------------


class PsirtCVESource:
    """Live version->advisory lookup against Cisco's PSIRT openVuln API.

    Credentials come from the environment ONLY: `PSIRT_CLIENT_ID` and
    `PSIRT_CLIENT_SECRET` (from a Cisco API Console application registered
    against the openVuln API). Never a file, never a CLI argument -- same rule
    as NETAGENT_PASSWORD, and for the same reason: a credential in a file is
    one careless commit away from being public.

    The OAuth2 access token is cached in memory and refreshed just before the
    server-reported expiry (docs show 3600s). Construction is side-effect free;
    credentials are read and the network is touched only when `lookup()` runs,
    so `ChainedCVESource` can hold this object even on a machine with no creds.
    """

    def __init__(
        self,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        # `transport` exists so tests can inject httpx.MockTransport; the
        # default is the real network.
        self._client = httpx.Client(timeout=timeout, transport=transport)
        self._token: str | None = None
        self._token_expires_at: float = 0.0  # time.monotonic() deadline
        self._last_call_at: float = 0.0

    # -- OAuth2 ---------------------------------------------------------------

    def _get_token(self) -> str:
        """Return a valid bearer token, fetching or refreshing as needed."""
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token

        client_id = os.environ.get("PSIRT_CLIENT_ID", "")
        client_secret = os.environ.get("PSIRT_CLIENT_SECRET", "")
        if not client_id or not client_secret:
            raise CVESourceUnavailable(
                "Cisco PSIRT credentials not set. Export PSIRT_CLIENT_ID and "
                "PSIRT_CLIENT_SECRET (from your Cisco API Console app) in the "
                "shell, or rely on the pinned cache fallback."
            )

        self._pace()
        try:
            resp = self._client.post(
                TOKEN_URL,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "client_credentials",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise CVESourceUnavailable(
                f"Could not reach the Cisco token endpoint ({TOKEN_URL}): {exc}"
            ) from exc

        if resp.status_code != 200:
            raise CVESourceUnavailable(
                f"Cisco token endpoint returned HTTP {resp.status_code}. "
                "Check PSIRT_CLIENT_ID / PSIRT_CLIENT_SECRET and that your API "
                "Console app is registered for the openVuln API."
            )

        body = resp.json()
        token = body.get("access_token")
        if not token:
            raise CVESourceUnavailable(
                "Token response had no 'access_token' field -- refusing to guess."
            )
        expires_in = int(body.get("expires_in", 3600))  # docs show 3600s
        self._token = token
        self._token_expires_at = (
            time.monotonic() + max(expires_in - _TOKEN_SAFETY_MARGIN_S, 30)
        )
        return token

    # -- the lookup -------------------------------------------------------------

    def fetch_raw(self, os_type: str, version: str) -> tuple[str, list[dict]]:
        """Query the API; return (request_url, raw advisory objects).

        The raw objects are what `generate_psirt_cache.py` freezes to disk, and
        exactly what `lookup()` normalizes -- so the cache file is provably the
        same input the live path consumes.
        """
        api_os = _normalize_os_type(os_type)
        if not version or version == "unknown":
            raise CVESourceError(
                "Refusing to query the PSIRT API without a parsed version -- "
                "an answer for the wrong version would be worse than no answer."
            )

        token = self._get_token()
        url = f"{API_BASE}/OSType/{api_os}"
        self._pace()
        try:
            resp = self._client.get(
                url,
                params={"version": version},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise CVESourceUnavailable(
                f"Could not reach the PSIRT openVuln API ({url}): {exc}"
            ) from exc

        request_url = str(resp.request.url)

        # 404 + NO_DATA_FOUND is Cisco affirmatively answering "no advisories
        # match" (see the verified note on _NO_DATA_ERROR_CODE above). That is
        # the ONLY path that returns an empty list.
        if resp.status_code == 404:
            try:
                err = resp.json()
            except ValueError:
                err = {}
            if err.get("errorCode") == _NO_DATA_ERROR_CODE:
                return request_url, []
            raise CVESourceUnavailable(
                f"PSIRT API returned HTTP 404 without the documented "
                f"NO_DATA_FOUND body (got: {err or resp.text[:200]!r}). "
                "Not treating that as 'no advisories'."
            )

        if resp.status_code == 429:
            raise CVESourceUnavailable(
                "PSIRT API rate limit hit (HTTP 429; quota is 5/s, 30/min, "
                "5000/day). Wait and retry, or use the pinned cache."
            )

        if resp.status_code != 200:
            raise CVESourceUnavailable(
                f"PSIRT API returned HTTP {resp.status_code} for {request_url}."
            )

        body = resp.json()
        advisories = body.get("advisories") if isinstance(body, dict) else None
        if not isinstance(advisories, list):
            # A 200 without the documented {"advisories": [...]} envelope is a
            # response we do not understand. Fail loudly; never coerce to [].
            raise CVESourceUnavailable(
                "PSIRT API 200 response did not contain the documented "
                "'advisories' list -- refusing to interpret it."
            )
        return request_url, advisories

    def lookup(self, os_type: str, version: str) -> list[CVERecord]:
        """CVESource implementation: live advisories affecting this version."""
        _, advisories = self.fetch_raw(os_type, version)
        return records_from_advisories(advisories)

    # -- plumbing ---------------------------------------------------------------

    def _pace(self) -> None:
        """Courtesy spacing between calls (see the rate-limit note above)."""
        elapsed = time.monotonic() - self._last_call_at
        if elapsed < _MIN_SECONDS_BETWEEN_CALLS:
            time.sleep(_MIN_SECONDS_BETWEEN_CALLS - elapsed)
        self._last_call_at = time.monotonic()


# ----------------------------------------------------------------------------
# Offline backend: a frozen copy of a real API response.
# ----------------------------------------------------------------------------

DEFAULT_CACHE_PATH = Path(__file__).parent / "data" / "psirt_cache.json"


class CachedCVESource:
    """Replays a pinned snapshot of a REAL PSIRT API response from disk.

    This exists so the lab runs without Cisco API credentials -- but it is not
    a hand-curated CVE list, and the design refuses to let it quietly become
    one. The file must carry a `snapshot` provenance block (when it was
    retrieved, from which endpoint, for which os_type + version), written by
    `scripts/generate_psirt_cache.py` from a live call. `provenance()` surfaces
    that block so, on camera, the cache can be shown for what it is: the API's
    answer, frozen, with a date on it.

    A frozen answer is only honest for the exact question it was asked. If the
    sweep asks about a different os_type or version than the snapshot covers,
    this raises instead of returning stale data for the wrong software.
    """

    def __init__(self, path: str | Path = DEFAULT_CACHE_PATH) -> None:
        self._path = Path(path)
        self._data: dict | None = None  # loaded lazily; see _load()

    def _load(self) -> dict:
        if self._data is not None:
            return self._data
        if not self._path.exists():
            raise CVESourceUnavailable(
                f"No PSIRT cache at {self._path}. Generate one from a live API "
                "response: set PSIRT_CLIENT_ID / PSIRT_CLIENT_SECRET, then run "
                "scripts/generate_psirt_cache.py --os-type iosxe "
                "--version <your version>. The cache is never hand-written."
            )
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise CVESourceError(f"PSIRT cache {self._path} is not valid JSON: {exc}") from exc

        snapshot = data.get("snapshot")
        advisories = data.get("advisories")
        required = ("retrieved_at", "endpoint", "os_type", "version")
        if (
            not isinstance(snapshot, dict)
            or not isinstance(advisories, list)
            or any(k not in snapshot for k in required)
        ):
            raise CVESourceError(
                f"PSIRT cache {self._path} is missing its provenance envelope "
                f"(need a 'snapshot' block with {', '.join(required)} and an "
                "'advisories' list). Regenerate it with "
                "scripts/generate_psirt_cache.py -- a cache without provenance "
                "cannot prove it came from the API."
            )
        self._data = data
        return data

    def provenance(self) -> dict:
        """The snapshot metadata: proof of where and when this answer came from."""
        return dict(self._load()["snapshot"])

    def lookup(self, os_type: str, version: str) -> list[CVERecord]:
        """CVESource implementation: replay the frozen answer -- exact match only."""
        data = self._load()
        snap = data["snapshot"]
        if (
            _normalize_os_type(os_type) != _normalize_os_type(str(snap["os_type"]))
            or version != str(snap["version"])
        ):
            raise CVESourceError(
                f"PSIRT cache was frozen for {snap['os_type']} {snap['version']} "
                f"but the sweep asked about {os_type} {version}. A pinned answer "
                "is only honest for the question it was asked -- regenerate the "
                "cache for this version."
            )
        return records_from_advisories(data["advisories"])


# ----------------------------------------------------------------------------
# The default: live first, cache as the honest fallback.
# ----------------------------------------------------------------------------


class ChainedCVESource:
    """Tries the live PSIRT API, falls back to the pinned cache, and says which.

    The point of recording `answered_by` is the on-camera evidence trail: a
    finding backed by "live Cisco PSIRT openVuln API" and one backed by
    "pinned cache retrieved 2026-07-04" are both honest, but they are not the
    same claim, and the difference should never be invisible.

    Only `CVESourceUnavailable` triggers the fallback -- that means "the live
    source could not answer." A `CVESourceError` (wrong version for the cache,
    unmappable OS family) propagates, because falling back would answer a
    different question than the one asked.
    """

    def __init__(
        self,
        primary: PsirtCVESource | None = None,
        fallback: CachedCVESource | None = None,
    ) -> None:
        self.primary = primary if primary is not None else PsirtCVESource()
        self.fallback = fallback if fallback is not None else CachedCVESource()
        self.answered_by: str | None = None  # set by lookup(); None until then
        self.fallback_reason: str | None = None  # why live didn't answer, if it didn't

    def lookup(self, os_type: str, version: str) -> list[CVERecord]:
        """CVESource implementation: live if possible, cache if not, loud if neither."""
        try:
            records = self.primary.lookup(os_type, version)
        except CVESourceUnavailable as exc:
            self.fallback_reason = str(exc)
            records = self.fallback.lookup(os_type, version)  # may itself raise -- good
            retrieved = self.fallback.provenance()["retrieved_at"]
            self.answered_by = f"pinned PSIRT cache (retrieved {retrieved})"
            return records
        self.answered_by = "live Cisco PSIRT openVuln API"
        self.fallback_reason = None
        return records
