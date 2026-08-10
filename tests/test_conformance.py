# ============================================================
# Module:       tests/test_conformance.py
# Purpose:      Guard the conformance self-test: all 8 checklist items pass
#               against the reference boundary, the CLI exits 0 and prints
#               CONFORMANT, and the checks have TEETH (a regressed invariant
#               turns its box red rather than passing vacuously).
# Usage:        pytest tests/test_conformance.py
# Dependencies: pytest; the [lab] extra (conformance C1 imports the server).
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/hardrails
# Notes:        Public by design. No credentials, no secrets. Offline.
# ============================================================
"""The conformance self-test must itself be trustworthy: green when the boundary
holds, and red when it doesn't."""

from __future__ import annotations

from netagent import conformance


def test_all_eight_items_pass_against_the_reference():
    results = conformance.run_conformance()
    assert [r.item for r in results] == ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"]
    failed = [(r.item, r.detail) for r in results if not r.passed]
    assert failed == [], f"conformance failures: {failed}"


def test_cli_exits_zero_and_prints_conformant(capsys):
    code = conformance.main()
    out = capsys.readouterr().out
    assert code == 0
    assert "CONFORMANT" in out
    assert out.count("[PASS]") == 8
    assert "[FAIL]" not in out


def test_c2_has_teeth_when_the_read_guard_regresses(monkeypatch):
    # If the command-level read guard regressed to allow-everything, C2 MUST
    # go red -- proving the check exercises the real guard, not a constant.
    monkeypatch.setattr(conformance.devices, "_read_command_rejection", lambda cmd: None)
    results = {r.item: r for r in conformance.run_conformance()}
    assert results["C2"].passed is False


def test_c3_has_teeth_when_the_gate_stops_requiring_trusted(monkeypatch):
    # If new boundaries stopped requiring the trusted channel, a relayed
    # (TOOL-channel) approval would slip through -> C4 (and the tool-channel leg
    # of C3) must go red.
    import netagent.boundary as boundary_mod

    original = boundary_mod.Boundary

    class _LaxBoundary(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.require_trusted_channel = False

    monkeypatch.setattr(conformance, "Boundary", _LaxBoundary)
    results = {r.item: r for r in conformance.run_conformance()}
    # C4 asserts a relayed approval is blocked and the default requires trusted;
    # with the gate lax, that expectation fails.
    assert results["C4"].passed is False


def test_cli_explains_cleanly_when_lab_extra_missing(monkeypatch, capsys):
    # The `hardrails-conformance` console script installs on a plain
    # `pip install hardrails` (base, no [lab]), but the checks need the runnable
    # agent. Simulate a base install (netmiko absent) and assert the CLI prints a
    # helpful "install hardrails[lab]" message and exits non-zero -- never a bare
    # ModuleNotFoundError traceback (issue #33).
    import importlib.util as ilu

    real_find_spec = ilu.find_spec

    def fake_find_spec(name, *args, **kwargs):
        if name == "netmiko":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(ilu, "find_spec", fake_find_spec)
    code = conformance.main([])
    out = capsys.readouterr().out
    assert code != 0
    assert "lab" in out.lower()
    assert "netmiko" in out.lower()
    assert "Traceback" not in out
