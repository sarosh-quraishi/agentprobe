"""Minimal stub Target — shows how to implement the protocol.

Copy this and replace run() with your real agent invocation.
"""
from __future__ import annotations

from pathlib import Path
import tempfile

from agentprobe.target import RunResult, Target


class StubTarget:
    """Echo agent — always returns the prompt unchanged, no tool calls.

    Useful for smoke-testing the harness itself without an LLM.
    All probes should return BLOCKED/IMMUNE against this target.
    """

    def __init__(self) -> None:
        self._workdir = Path(tempfile.mkdtemp())
        self._planted: list[Path] = []

    async def run(self, prompt: str, history: list) -> RunResult:
        # ponytail: echo stub — replace with real agent call
        return RunResult(output=f"echo: {prompt}", tool_calls=[], history=[])

    def plant_file(self, name: str, content: str) -> None:
        # kb: prefix is a convention for RAG docs — real targets ingest these
        path = self._workdir / name.replace(":", "_")
        path.write_text(content)
        self._planted.append(path)

    def cleanup(self) -> None:
        for p in self._planted:
            p.unlink(missing_ok=True)
        self._planted.clear()


# Verify it satisfies the protocol at import time
assert isinstance(StubTarget(), Target)
