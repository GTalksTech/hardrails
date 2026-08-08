# ============================================================
# Module:       tests/test_boundary_integrity.py
# Purpose:      Pin audit-log integrity under concurrency and faults (issue #20):
#               no torn/lost records when tool threads and the approval-surface
#               thread record on one Boundary; a mutation whose receipt cannot be
#               written is refused (fail-closed); an execution error's message is
#               never leaked into the receipt.
# Usage:        pytest tests/test_boundary_integrity.py
# Dependencies: pytest, pydantic>=2 (via netagent.models)
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets.
# ============================================================
"""Audit-log integrity: correct under concurrency, honest under faults."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from netagent.boundary import Boundary, BoundaryViolation, ToolKind
from netagent.models import (
    ApprovalChannel,
    ApprovalRequest,
    ApprovalState,
    RemediationProposal,
    ToolDecision,
)


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _trusted_approval() -> ApprovalRequest:
    proposal = RemediationProposal(
        finding_id="cve-x", device="core-rtr-01",
        config_commands=["no ip http server"], dry_run_diff="-",
    )
    return ApprovalRequest(
        proposal=proposal, state=ApprovalState.APPROVED,
        channel=ApprovalChannel.TRUSTED_PATH, approver="Garrett", reason="reviewed",
    )


class TestConcurrentAuditLog:
    """The process is concurrent: FastMCP tool worker threads AND the
    ThreadingHTTPServer approval surface both record on one Boundary. The log
    must survive that without torn or lost lines."""

    def test_no_torn_or_lost_records_under_threads(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        boundary = Boundary(audit_log_path=path)
        boundary.register("run_show", ToolKind.READ)

        n_threads = 12
        per_thread = 25
        start = threading.Barrier(n_threads)

        def worker(i: int) -> None:
            start.wait()  # release all threads together to maximise overlap
            for j in range(per_thread):
                if j % 2 == 0:  # a guarded tool call -> call + result record
                    boundary.guard("run_show", {"device": f"d{i}-{j}"}, lambda: "ok")
                else:  # the approval-surface path -> a single event record
                    boundary.record_event(
                        "trusted_path.resolve", {"i": i, "j": j},
                        ToolDecision.ALLOWED, "surface event",
                    )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Every line parses -> no torn lines from interleaved writes.
        records = _read_jsonl(path)
        calls = [r for r in records if r["record_type"] == "call"]
        results = [r for r in records if r["record_type"] == "result"]

        total = n_threads * per_thread
        guard_calls = n_threads * len([j for j in range(per_thread) if j % 2 == 0])
        assert len(calls) == total          # no lost call records
        assert len(results) == guard_calls  # exactly the guarded calls got results
        assert len(boundary.audit_log()) == total  # in-memory matches disk count
        call_ids = {r["call_id"] for r in calls}
        assert all(r["call_id"] in call_ids for r in results)  # every result links


class TestFailClosedAuditForMutations:
    def test_mutation_refused_when_receipt_cannot_be_written(self, tmp_path, monkeypatch):
        boundary = Boundary(audit_log_path=tmp_path / "audit.jsonl")
        boundary.register("apply_remediation", ToolKind.MUTATE)
        # Durable write fails (bad path / full disk / permissions).
        monkeypatch.setattr(boundary, "_persist", lambda record: False)

        ran: list[str] = []
        with pytest.raises(BoundaryViolation) as excinfo:
            boundary.guard(
                "apply_remediation", {"device": "core-rtr-01"},
                lambda: ran.append("APPLIED"), approval=_trusted_approval(),
            )
        assert ran == []  # execute() never ran -- fail-closed
        assert "audit" in str(excinfo.value).lower()

    def test_read_still_runs_when_receipt_cannot_be_written(self, tmp_path, monkeypatch):
        boundary = Boundary(audit_log_path=tmp_path / "audit.jsonl")
        boundary.register("run_show", ToolKind.READ)
        monkeypatch.setattr(boundary, "_persist", lambda record: False)
        # Reads are best-effort: a read that isn't logged changed nothing.
        assert boundary.guard("run_show", {"device": "core-rtr-01"}, lambda: "ok") == "ok"


class TestExceptionSummaryDoesNotLeak:
    def test_secret_in_exception_message_is_withheld(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        boundary = Boundary(audit_log_path=path)
        boundary.register("run_show", ToolKind.READ)
        secret = "enable secret 9 $9$SUPER_SECRET_HASH_VALUE"

        def boom() -> str:
            raise RuntimeError(f"device read failed mid-config: {secret}")

        with pytest.raises(RuntimeError):
            boundary.guard("run_show", {"device": "core-rtr-01"}, boom)

        raw = path.read_text(encoding="utf-8")
        assert "SUPER_SECRET_HASH_VALUE" not in raw   # not on disk
        assert "RuntimeError" in raw                   # the type IS recorded
        # ...and not in the in-memory record either.
        assert "SUPER_SECRET_HASH_VALUE" not in boundary.audit_log()[-1].result_summary
