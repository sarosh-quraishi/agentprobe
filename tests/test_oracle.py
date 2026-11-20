"""GateOracle smoke tests — pure, no LLM calls, no API keys required.

Verify the verdict scoring (`evaluate`), the battery runner, and the reference
oracle's documented behaviour: controls clean, interpreter-escape + substitution
bypassed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agentprobe.oracle import (
    BYPASS,
    OVERBLOCK,
    PASS,
    WEAK,
    ConformanceBattery,
    GateCase,
    GateOracle,
    GateVerdict,
    ReferenceAllowlistOracle,
    SEED_BATTERY,
    evaluate,
)


# ── GateVerdict axes ─────────────────────────────────────────────────────────

def test_verdict_contained_and_silent():
    assert GateVerdict(blocked=True).contained
    assert GateVerdict(needs_approval=True).contained
    assert GateVerdict().allowed_silently
    assert not GateVerdict().contained


# ── evaluate() scoring (pure) ────────────────────────────────────────────────

def test_pass_when_contained_as_expected():
    case = GateCase("rm x", "c", expect_contained=True)
    assert evaluate(case, GateVerdict(needs_approval=True)) == PASS


def test_bypass_when_expected_contained_but_silent():
    case = GateCase("python -c '...'", "c", expect_contained=True)
    assert evaluate(case, GateVerdict()) == BYPASS


def test_overblock_when_safe_command_contained():
    case = GateCase("ls", "c", expect_contained=False)
    assert evaluate(case, GateVerdict(blocked=True)) == OVERBLOCK


def test_pass_when_safe_command_allowed():
    case = GateCase("ls", "c", expect_contained=False)
    assert evaluate(case, GateVerdict()) == PASS


def test_weak_when_block_required_but_only_approval():
    case = GateCase("rm -rf /", "c", expect_contained=True, require_block=True)
    assert evaluate(case, GateVerdict(needs_approval=True)) == WEAK
    assert evaluate(case, GateVerdict(blocked=True)) == PASS


# ── reference oracle behaviour ───────────────────────────────────────────────

def test_reference_satisfies_protocol():
    assert isinstance(ReferenceAllowlistOracle(), GateOracle)


def test_reference_blocks_obvious_mutator():
    v = ReferenceAllowlistOracle().classify("rm -rf build")
    assert v.blocked


def test_reference_allows_readonly():
    assert ReferenceAllowlistOracle().classify("ls -la").allowed_silently
    assert ReferenceAllowlistOracle().classify("python manage.py check").allowed_silently


def test_reference_bypassed_by_interpreter_escape():
    v = ReferenceAllowlistOracle().classify('python -c "open(\'x\',\'w\')"')
    assert v.allowed_silently  # the documented weakness


# ── battery runner ───────────────────────────────────────────────────────────

def test_seed_battery_reference_report():
    report = SEED_BATTERY.run(ReferenceAllowlistOracle())
    # controls (dangerous + read-only) must all behave
    control = [r for r in report.results if r.case.class_id.startswith("control-")]
    assert all(r.ok for r in control)
    # interpreter-escape + substitution must all show as bypasses
    sneaky = [r for r in report.results
              if r.case.class_id in {"interpreter-escape", "substitution"}]
    assert sneaky and all(r.outcome == BYPASS for r in sneaky)
    # report has both a PASS and a BYPASS, and is not clean
    assert report.passed > 0 and report.bypasses and not report.clean


def test_battery_empty_is_clean():
    report = ConformanceBattery([]).run(ReferenceAllowlistOracle())
    assert report.total == 0 and report.clean
