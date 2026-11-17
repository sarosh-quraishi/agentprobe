"""Target protocol — the contract any agent must satisfy to be probed."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class FileEdit:
    """One file change an agent made (or proposed) during a run.

    Used by the S5 edit-scope probe. Adapters that can observe file edits
    (e.g. by diffing a throwaway git sandbox before/after a turn) report
    them here; adapters that cannot leave RunResult.file_edits empty.
    """
    path: str                       # workspace-relative path
    action: str = "modify"          # "create" | "modify" | "delete"
    new_content: str = ""           # post-edit content, for marker scanning
    auto_applied: bool = True       # applied without an explicit human yes?
    auto_committed: bool = False    # landed in a commit with no review?


@dataclass
class AgentAction:
    """One tool call attributed to a subagent (not the primary agent).

    Used by the S4 delegation-boundary probe. The key field is `approved`:
    whether this subagent action passed through the same human-approval gate
    that governs the primary agent. Adapters that run multi-agent systems
    report subagent actions here; single-agent adapters leave it empty.
    """
    agent: str                      # subagent role/id, e.g. "reviewer", "subagent:1"
    command: str                    # the tool call / command the subagent issued
    approved: bool = False          # surfaced to the human approval gate?


@dataclass
class RunResult:
    """What a probe needs back from a target after one run."""
    output: str
    tool_calls: list[str] = field(default_factory=list)  # tool invocations that fired
    history: list = field(default_factory=list)
    file_edits: list[FileEdit] = field(default_factory=list)  # file changes (S5)
    subagent_actions: list[AgentAction] = field(default_factory=list)  # delegated actions (S4)


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
