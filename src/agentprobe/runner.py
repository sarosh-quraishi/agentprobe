"""Harness runner — orchestrates probes and writes a report."""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

from agentprobe.probes.s2 import ProbeResult, run_s2_probes
from agentprobe.probes.s3 import S3Result, run_s3_probes
from agentprobe.target import Target


def write_report(
    s2_results: list[ProbeResult],
    s3_results: list[S3Result],
    path: Path,
) -> None:
    swaps    = [r for r in s2_results if r.verdict == "SWAP"]
    poisoned = [r for r in s3_results if r.verdict == "POISONED"]

    lines = [
        f"# agentprobe report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## S2 — Tool-call command swap",
        "",
        "| Verdict | Count |",
        "|---------|-------|",
        f"| SWAP    | {len(swaps)} |",
        f"| BENIGN  | {sum(1 for r in s2_results if r.verdict == 'BENIGN')} |",
        f"| BLOCKED | {sum(1 for r in s2_results if r.verdict == 'BLOCKED')} |",
    ]

    if swaps:
        lines += ["", "### SWAP findings", ""]
        for r in swaps:
            lines += [
                f"**{r.category} × {r.scenario}** (attempt {r.attempt})",
                f"- Expected: `{r.expected_fragment}`",
                f"- Got: `{r.captured_command}`",
                f"- Payload: `{r.payload}`",
                "",
            ]

    lines += [
        "",
        "## S3 — RAG / retrieval poisoning",
        "",
        "| Doc | Verdict |",
        "|-----|---------|",
    ]
    for r in s3_results:
        lines.append(f"| {r.doc_id} | {r.verdict} |")

    if poisoned:
        lines += ["", "### POISONED findings", ""]
        for r in poisoned:
            lines += [
                f"**{r.doc_id}**",
                f"- Output: `{r.output_snippet}`",
                "",
            ]

    path.write_text("\n".join(lines))
    print(f"\nReport written to {path}")


async def run(
    target: Target,
    probes: list[str] | None = None,
    only: set[str] | None = None,
    report_path: Path = Path("agentprobe_report.md"),
) -> dict:
    probes = probes or ["s2", "s3"]
    s2_results: list[ProbeResult] = []
    s3_results: list[S3Result] = []

    if "s2" in probes:
        s2_results = await run_s2_probes(target, only=only)
    if "s3" in probes:
        s3_results = await run_s3_probes(target)

    write_report(s2_results, s3_results, report_path)
    return {"s2": s2_results, "s3": s3_results}
