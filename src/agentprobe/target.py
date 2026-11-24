"""Target protocol — the contract any agent must satisfy to be probed."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from agentprobe.oracle import GateVerdict


@dataclass
class ToolSpec:
    """One tool the target exposes, for the S8 invocation-map probe.

    Targets *may* implement `tool_catalog()` to declare their tools so S8 can
    probe them systematically. `sensitive` flags tools whose silent, ungated
    invocation is a finding (exec, write, delete, network); targets that know
    their own tools should set it explicitly, otherwise S8 falls back to a
    name-based heuristic.
    """
    name: str                       # tool id, e.g. "bash", "write_file", "fetch_url"
    sensitive: bool | None = None   # None → let S8's heuristic decide
    description: str = ""


@dataclass
class GateEvent:
    """One tool invocation and how the agent's gate actually treated it.

    Used by the S8 auto-invocation probe. Where S4/S5 annotate authorization
    state on their own record types (AgentAction.approved, FileEdit.auto_applied),
    S8 needs the per-call gate decision, carried here as a GateVerdict — the same
    type GateOracle produces, so the probe-side map and the oracle share one
    taxonomy (allowed_silently / needs_approval / blocked).

    Adapters that can observe gate decisions report them; adapters that cannot
    leave RunResult.gate_events empty, and S8 returns UNOBSERVED for those tools.
    """
    tool: str                       # tool id that fired, e.g. "bash"
    command: str                    # concrete invocation / args, for the report
    verdict: GateVerdict            # how the gate treated it (silent | approval | blocked)
    triggered_by: str = ""          # which S8 trigger prompt induced it


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
    gate_events: list[GateEvent] = field(default_factory=list)  # tool-call gate decisions (S8)


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

    # Optional, duck-typed (not part of the Protocol so existing targets still
    # conform): a target MAY implement
    #     def tool_catalog(self) -> list[ToolSpec]: ...
    # to declare its tools so S8 can probe them systematically. If absent, S8
    # falls back to the tool list the agent self-reports during its interview.
