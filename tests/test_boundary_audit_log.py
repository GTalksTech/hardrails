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
"""

from __future__ import annotations

import json
from pathlib import Path

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
        records = _read_jsonl(path)
        assert len(records) == 2
        assert records[0]["tool_name"] == "run_show"
        assert records[0]["decision"] == "allowed"
        assert records[1]["tool_name"] == "delete_everything"
        assert records[1]["decision"] == "blocked"

        # The file mirrors the in-memory log (same count, same order).
        assert [r["tool_name"] for r in records] == [
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

        records = _read_jsonl(path)
        assert len(records) == 2  # the first process's record was NOT truncated
        assert records[0]["arguments"]["device"] == "edge-rtr-01"
        assert records[1]["arguments"]["device"] == "core-rtr-01"

    def test_no_full_payload_leaks_into_file(self, tmp_path):
        # The _summarize discipline must hold on disk too: a large read result is
        # summarized, never dumped verbatim into the receipt.
        path = tmp_path / "audit-log.jsonl"
        boundary = _fresh_boundary(path)
        secret_blob = "enable secret 9 $9$topsecrethash\n" * 200
        boundary.guard("run_show", {"device": "core-rtr-01"}, lambda: secret_blob)

        raw = path.read_text(encoding="utf-8")
        assert "topsecrethash" not in raw
