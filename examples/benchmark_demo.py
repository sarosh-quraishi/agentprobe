"""OWASP execution-layer benchmark demo — scores the naive reference gate.

Shows the benchmark as a report card: the deliberately-foolable reference gate
bypasses every inline-code / substitution / wrapper vector, while its read-only
controls pass clean. A real tool's shipped guard registers behind the same
`GateOracle` protocol and is scored on identical inputs.

    python examples/benchmark_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agentprobe import ReferenceAllowlistOracle, run_benchmark, scorecard

report = run_benchmark(ReferenceAllowlistOracle())
print(scorecard(report))
print(f"bypasses: {len(report.bypasses)}  overblocks: {len(report.overblocks)}  "
      f"weaks: {len(report.weaks)}")
