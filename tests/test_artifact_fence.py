# ============================================================
# Module:       tests/test_artifact_fence.py
# Purpose:      The approval artifact must render untrusted device text inertly:
#               a running-config line containing ``` cannot break out of the
#               code fence and inject markdown into the human's review receipt.
# Usage:        pytest tests/test_artifact_fence.py
# Dependencies: pytest, pydantic>=2 (via netagent.models)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets.
# ============================================================
"""Device-controlled backticks stay inside the fence (no markdown injection)."""

from __future__ import annotations

from netagent.artifacts import _fence, _longest_backtick_run, _render
from netagent.models import ApprovalRequest, RemediationProposal


def test_longest_backtick_run_counts_the_longest_span():
    assert _longest_backtick_run("no backticks here") == 0
    assert _longest_backtick_run("a ` b `` c ``` d ``") == 3


def test_fence_is_plain_three_backticks_for_clean_content():
    # No behavior change for ordinary content -- byte-identical to before.
    assert _fence("clean content") == ["```", "clean content", "```"]
    assert _fence("clean", "diff") == ["```diff", "clean", "```"]


def test_fence_grows_past_embedded_backticks():
    out = _fence("- banner motd ``` evil markdown", "diff")
    assert out[0] == "````diff"   # 4-backtick fence
    assert out[2] == "````"
    assert "evil markdown" in out[1]


def test_render_contains_device_diff_without_breaking_out():
    # A running-config line with a literal ``` is device-controlled and must be
    # contained, not allowed to close the fence.
    proposal = RemediationProposal(
        finding_id="cve-x", device="core-rtr-01",
        config_commands=["no ip http server"],
        dry_run_diff="- banner motd ^C ``` heading injected\n+ (removed)",
    )
    text = _render("appr-test", ApprovalRequest(proposal=proposal))
    # The diff fence grew to contain the embedded ```; the payload is present
    # but inert (inside the longer fence).
    assert "````diff" in text
    assert "heading injected" in text


def test_render_is_unchanged_for_normal_content():
    proposal = RemediationProposal(
        finding_id="cve-x", device="core-rtr-01",
        config_commands=["no ip http server", "no ip http secure-server"],
        dry_run_diff="--- running-config (live)\n+++ intended\n-ip http server",
    )
    text = _render("appr-1", ApprovalRequest(proposal=proposal))
    assert "```diff" in text                     # plain 3-backtick fence
    assert "````" not in text                    # did not grow unnecessarily
    assert "no ip http server" in text
    assert "running-config (live)" in text
