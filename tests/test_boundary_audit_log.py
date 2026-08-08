# ============================================================
# Module:       tests/test_boundary_audit_log.py
# Purpose:      Unit tests for BUG 2: the boundary's audit log must be persisted
#               to an append-only JSONL file at a known, configurable path -- the
#               durable receipt -- while keeping the fast in-memory list.
# Usage:        pytest tests/  (from the network-agent-mcp directory)
# Dependencies: pytest, pydantic>=2 (via netagent.models)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets.
# ============================================================
"""Tests for the persisted, append-only audit log.

The boundary already builds one immutable ToolCallRecord per call in memory.
BUG 2: that log evaporated on restart and had no path to point a camera at.
These tests pin the fix: every record is also appended to a JSONL file at a
resolvable path, the path is surfaced, and a restart re-opens (appends) rather
than truncating.

Issue #6: the call record is persisted at decision time -- before the tool
runs -- so its on-disk `result_summary` is empty forever. The outcome must
land as a follow-up "result" record appended after execution, linked by
call_id. Append-only: the decision line is never rewritten.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netagent.boundary import Boundary, BoundaryViolation, ToolKind


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _fresh_boundary(path: Path) -> Boundary:
    b = Boundary(audit_log_path=path)
    b.register("run_show", ToolKind.READ)
    return b


class TestAuditLogPersistence:
    def test_allowed_and_blocked_calls_write_jsonl(self, tmp_path):
        path = tmp_path / "audit-log.jsonl"
        boundary = _fresh_boundary(path)

        # One ALLOWED read call...
        boundary.guard("run_show", {"device": "core-rtr-01"}, lambda: "ok")
        # ...and one BLOCKED call (unregistered tool -> default deny).
        try:
            boundary.guard("delete_everything", {}, lambda: "nope")
        except BoundaryViolation:
            pass

        assert path.exists()
        calls = [r for r in _read_jsonl(path) if r.get("record_type") == "call"]
        assert len(calls) == 2
        assert calls[0]["tool_name"] == "run_show"
        assert calls[0]["decision"] == "allowed"
        assert calls[1]["tool_name"] == "delete_everything"
        assert calls[1]["decision"] == "blocked"

        # The call records mirror the in-memory log (same count, same order).
        assert [r["tool_name"] for r in calls] == [
            r.tool_name for r in boundary.audit_log()
        ]

    def test_path_is_surfaced(self, tmp_path):
        path = tmp_path / "receipt.jsonl"
        boundary = _fresh_boundary(path)
        assert Path(boundary.audit_log_path) == path

    def test_default_path_honors_env(self, tmp_path, monkeypatch):
        target = tmp_path / "env-audit.jsonl"
        monkeypatch.setenv("NETAGENT_AUDIT_LOG", str(target))
        boundary = Boundary()  # no explicit path -> resolves from env
        assert Path(boundary.audit_log_path) == target

    def test_records_survive_restart_append_not_truncate(self, tmp_path):
        path = tmp_path / "audit-log.jsonl"

        first = _fresh_boundary(path)
        first.guard("run_show", {"device": "edge-rtr-01"}, lambda: "ok")

        # "Restart": a brand-new Boundary with an EMPTY in-memory log, same file.
        second = _fresh_boundary(path)
        assert second.audit_log() == []  # in-memory did not carry over
        second.guard("run_show", {"device": "core-rtr-01"}, lambda: "ok")

        calls = [r for r in _read_jsonl(path) if r.get("record_type") == "call"]
        assert len(calls) == 2  # the first process's record was NOT truncated
        assert calls[0]["arguments"]["device"] == "edge-rtr-01"
        assert calls[1]["arguments"]["device"] == "core-rtr-01"

    def test_no_full_payload_leaks_into_file(self, tmp_path):
        # The _summarize discipline must hold on disk too: a large read result is
        # summarized, never dumped verbatim into the receipt.
        path = tmp_path / "audit-log.jsonl"
        boundary = _fresh_boundary(path)
        secret_blob = "enable secret 9 $9$topsecrethash\n" * 200
        boundary.guard("run_show", {"device": "core-rtr-01"}, lambda: secret_blob)

        raw = path.read_text(encoding="utf-8")
        assert "topsecrethash" not in raw
        # A summary IS on disk (in the follow-up result record) -- without this,
        # the no-leak assertion above would pass vacuously (issue #6).
        results = [r for r in _read_jsonl(path) if r.get("record_type") == "result"]
        assert results and results[0]["result_summary"].startswith("str, ")


class TestResultRecords:
    """Issue #6: the outcome is APPENDED as a follow-up record, never a rewrite."""

    def test_result_summary_lands_in_a_follow_up_record(self, tmp_path):
        path = tmp_path / "audit-log.jsonl"
        boundary = _fresh_boundary(path)
        boundary.guard("run_show", {"device": "core-rtr-01"}, lambda: "interface up")

        records = _read_jsonl(path)
        calls = [r for r in records if r.get("record_type") == "call"]
        results = [r for r in records if r.get("record_type") == "result"]
        assert len(calls) == 1 and len(results) == 1
        # Linked by call_id, appended AFTER the decision line.
        assert results[0]["call_id"] == calls[0]["call_id"]
        assert records.index(calls[0]) < records.index(results[0])
        # Same summary the in-memory record carries.
        assert results[0]["result_summary"] == boundary.audit_log()[0].result_summary
        # The decision line itself was written pre-execution and stays that way.
        assert calls[0]["result_summary"] == ""

    def test_execution_error_summary_is_shape_only(self, tmp_path):
        # Issue #20: the error summary is shape-only, like _summarize. A device
        # I/O exception can carry payload (a netmiko read-timeout embeds the
        # buffer read so far, whose first line can be a secret), so the message
        # is withheld and only the exception TYPE is recorded.
        path = tmp_path / "audit-log.jsonl"
        boundary = _fresh_boundary(path)

        def boom() -> str:
            raise RuntimeError("device fell over: enable secret 9 $9$LEAKME")

        with pytest.raises(RuntimeError):
            boundary.guard("run_show", {"device": "core-rtr-01"}, boom)

        results = [r for r in _read_jsonl(path) if r.get("record_type") == "result"]
        assert len(results) == 1
        assert "ERROR during execution" in results[0]["result_summary"]
        assert "RuntimeError" in results[0]["result_summary"]  # type recorded
        # The message -- which can carry device output/secrets -- is NOT persisted.
        assert "LEAKME" not in results[0]["result_summary"]
        assert "device fell over" not in results[0]["result_summary"]

    def test_blocked_call_gets_no_result_record(self, tmp_path):
        path = tmp_path / "audit-log.jsonl"
        boundary = _fresh_boundary(path)
        with pytest.raises(BoundaryViolation):
            boundary.guard("delete_everything", {}, lambda: "nope")

        # Nothing executed -> the blocked decision line is the whole story.
        assert [r.get("record_type") for r in _read_jsonl(path)] == ["call"]
