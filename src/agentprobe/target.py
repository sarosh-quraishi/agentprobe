"""Target protocol — the contract any agent must satisfy to be probed."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class RunResult:
    """What a probe needs back from a target after one run."""
    output: str
    tool_calls: list[str] = field(default_factory=list)  # tool invocations that fired
    history: list = field(default_factory=list)


@runtime_checkable
class Target(Protocol):
    """Any agent that can be probed implements this interface."""

    async def run(self, prompt: str, history: list) -> RunResult:
        """Run one prompt through the agent. Returns output + tool calls."""
        ...

    def plant_file(self, name: str, content: str) -> None:
        """Write a file into the agent's working directory."""
        ...

    def cleanup(self) -> None:
        """Remove any files planted during this probe."""
        ...
