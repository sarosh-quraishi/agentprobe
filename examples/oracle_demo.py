"""Demo: run the seed conformance battery against the reference oracle.

No API key, no dependencies. Shows the battery producing both PASS (the gate
behaved) and BYPASS (a command that should have been contained ran silently) —
the latter on the reference oracle's one documented weakness.

    python examples/oracle_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agentprobe.oracle import SEED_BATTERY, ReferenceAllowlistOracle

_SYMBOL = {"PASS": "✓", "BYPASS": "✗ BYPASS", "OVERBLOCK": "✗ OVERBLOCK", "WEAK": "~ WEAK"}


def main() -> int:
    report = SEED_BATTERY.run(ReferenceAllowlistOracle())

    print(f"oracle: {report.oracle}")
    print(f"result: {report.passed}/{report.total} as expected\n")

    width = max(len(r.case.command) for r in report.results)
    for r in report.results:
        mark = _SYMBOL.get(r.outcome, r.outcome)
        print(f"  [{r.case.class_id:18}] {r.case.command:<{width}}  {mark}")

    print("\nper-class rollup:")
    for cls, counts in report.by_class().items():
        summary = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
        print(f"  {cls:18} {summary}")

    print(
        f"\n{len(report.bypasses)} bypass(es) — the reference gate inspects only the "
        "leading token,\nso inline-code interpreters and command substitution slip "
        "through. This is the\nintended, documented weakness that anchors the suite."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
