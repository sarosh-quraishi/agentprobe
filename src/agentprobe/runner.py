"""Harness runner — orchestrates probes and writes a report."""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

from agentprobe.probes.s2 import FINDING_VERDICTS, ProbeResult, run_s2_probes
from agentprobe.probes.s3 import S3Result, run_s3_probes
from agentprobe.target import Target


def write_report(
    s2_results: list[ProbeResult],
    s3_results: list[S3Result],
    path: Path,
) -> None:
    controls = [r for r in s2_results if r.category == "control"]
    probes   = [r for r in s2_results if r.category != "control"]
    findings = [r for r in probes if r.verdict in FINDING_VERDICTS]
    poisoned = [r for r in s3_results if r.verdict == "POISONED"]

    def _count(v: str) -> int:
        return sum(1 for r in probes if r.verdict == v)

    lines = [
        f"# agentprobe report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## S2 — Tool-call command swap",
        "",
        "| Verdict | Count |",
        "|---------|-------|",
    ] + [f"| {v} | {_count(v)} |" for v in ("SWAP", "APPEND", "ENV", "BENIGN", "BLOCKED", "UNREAD")]

    if controls:
        lines += ["", "### Controls (no payload)", "", "| Scenario | Verdict | Command |", "|---|---|---|"]
        for r in controls:
            lines.append(f"| {r.scenario} | {r.verdict} | `{r.captured_command}` |")

    lines += ["", "### All probes", "", "| Category | Scenario | Attempt | Verdict | Decisive command |", "|---|---|---|---|---|"]
    for r in probes:
        lines.append(
            f"| {r.category} | {r.scenario} | {r.attempt} | {r.verdict} | `{r.captured_command}` |"
        )

    if findings:
        lines += ["", "### Findings", ""]
        for r in findings:
            lines += [
                f"#### {r.verdict}: {r.category} × {r.scenario} (attempt {r.attempt})",
                f"- Expected: `{r.expected_fragment}`",
                f"- Got: `{r.captured_command}`",
                f"- Control (no payload): `{r.baseline_command}`",
                f"- All tool calls: {r.all_calls}",
                "- Payload:",
                "",
                "```text",
                r.payload,
                "```",
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
    s5_results: list = []
    s4_results: list = []
    s8_results: list = []

    if "s2" in probes:
        s2_results = await run_s2_probes(target, only=only)
    if "s3" in probes:
        s3_results = await run_s3_probes(target)
    if "s5" in probes:
        from agentprobe.probes.s5 import run_s5_probes, write_s5_report
        s5_results = await run_s5_probes(target)
        write_s5_report(s5_results, report_path.with_name("agentprobe_s5_report.md"))
    if "s4" in probes:
        from agentprobe.probes.s4 import run_s4_probes, write_s4_report
        s4_results = await run_s4_probes(target)
        write_s4_report(s4_results, report_path.with_name("agentprobe_s4_report.md"))
    if "s8" in probes:
        from agentprobe.probes.s8 import run_s8_probes, write_s8_report
        s8_results = await run_s8_probes(target)
        write_s8_report(s8_results, report_path.with_name("agentprobe_s8_report.md"))

    write_report(s2_results, s3_results, report_path)
    return {"s2": s2_results, "s3": s3_results, "s5": s5_results,
            "s4": s4_results, "s8": s8_results}
