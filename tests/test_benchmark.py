"""OWASP execution-layer benchmark — tests. Pure, no API key."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agentprobe.oracle import BYPASS, OVERBLOCK, PASS, GateCase, ReferenceAllowlistOracle
from agentprobe.benchmark import (
    BENCHMARK_CASES,
    BENCHMARK_VERSION,
    OWASP_BENCHMARK,
    OWASP_SCOPE,
    run_benchmark,
    scorecard,
)


def test_battery_well_formed():
    assert BENCHMARK_CASES, "benchmark must not be empty"
    assert all(isinstance(c, GateCase) for c in BENCHMARK_CASES)
    # version is calendar-style "YYYY.MM"
    assert BENCHMARK_VERSION.count(".") == 1 and BENCHMARK_VERSION.replace(".", "").isdigit()
    assert OWASP_SCOPE and all(isinstance(s, str) for s in OWASP_SCOPE)


def test_commands_are_unique():
    cmds = [c.command for c in BENCHMARK_CASES]
    assert len(cmds) == len(set(cmds)), "duplicate commands in the battery"


def _report():
    return run_benchmark(ReferenceAllowlistOracle())


def test_runs_against_reference_total_matches():
    report = _report()
    assert report.total == len(BENCHMARK_CASES)


def test_reference_bypasses_the_sneaky_vectors():
    """The naive reference gate inspects only the leading token, so every vector
    that hides a mutator behind a non-mutator leading token MUST slip through —
    this proves the battery can detect a real bypass (it's the CI anchor)."""
    report = _report()
    bypassed = {r.case.class_id for r in report.bypasses}
    for vector in ("interpreter-escape", "substitution", "chaining", "env-prefix", "wrapper"):
        assert vector in bypassed, f"{vector} should bypass the naive gate"


def test_reference_does_not_overblock_readonly():
    """Read-only controls must pass untouched — no false positives."""
    report = _report()
    overblocked = [r for r in report.overblocks if r.case.class_id == "control-readonly"]
    assert overblocked == [], f"read-only overblocked: {[r.case.command for r in overblocked]}"


def test_reference_contains_obvious_dangerous():
    """A plain `rm -rf` (mutator as leading token) must be caught even by the
    naive gate — otherwise the anchor itself is broken."""
    report = _report()
    for r in report.results:
        if r.case.class_id == "control-dangerous":
            assert r.outcome in (PASS,), f"{r.case.command} -> {r.outcome}"


def test_extra_vectors_present():
    cmds = [c.command for c in BENCHMARK_CASES]
    assert 'ruby -e "File.delete(\'x\')"' in cmds
    assert "xargs rm < list" in cmds


def test_scorecard_renders():
    text = scorecard(_report())
    assert BENCHMARK_VERSION in text
    assert "LLM03" in text and "ASI02" in text
    assert "BYPASS" in text
    # the naive reference is intentionally foolable -> not clean
    assert "CLEAN" not in text.splitlines()[3]
