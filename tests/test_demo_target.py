"""Smoke test for DemoTarget — no API key required.

Verifies the adapter satisfies the Target protocol and that
tool_calls are captured correctly via the dispatch layer.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "examples"))

import os
os.environ.setdefault("OPENROUTER_API_KEY", "test-key")

from agentprobe.target import Target
from demo_target import DemoTarget


def test_demo_satisfies_protocol():
    with tempfile.TemporaryDirectory() as tmp:
        assert isinstance(DemoTarget(Path(tmp)), Target)


def test_plant_and_cleanup():
    with tempfile.TemporaryDirectory() as tmp:
        t = DemoTarget(Path(tmp))
        t.plant_file("context.txt", "hello")
        assert (Path(tmp) / "context.txt").exists()
        t.cleanup()
        assert not (Path(tmp) / "context.txt").exists()


def test_dispatch_read_file():
    with tempfile.TemporaryDirectory() as tmp:
        t = DemoTarget(Path(tmp))
        (Path(tmp) / "notes.txt").write_text("test content")
        result = t._dispatch("read_file", {"path": "notes.txt"})
        assert "test content" in result


def test_dispatch_bash_captured():
    with tempfile.TemporaryDirectory() as tmp:
        t = DemoTarget(Path(tmp))
        result = t._dispatch("bash", {"command": "echo hello"})
        assert "hello" in result


def test_run_captures_tool_calls():
    """Mock the LLM to return a bash tool call and verify tool_calls is populated."""
    with tempfile.TemporaryDirectory() as tmp:
        t = DemoTarget(Path(tmp))

        tool_call = MagicMock()
        tool_call.function.name = "bash"
        tool_call.function.arguments = '{"command": "pytest tests/"}'
        tool_call.id = "tc_001"

        first_msg = MagicMock()
        first_msg.tool_calls = [tool_call]
        first_msg.content = None

        second_msg = MagicMock()
        second_msg.tool_calls = None
        second_msg.content = "Tests ran successfully."

        first_resp = MagicMock()
        first_resp.choices = [MagicMock(message=first_msg)]

        second_resp = MagicMock()
        second_resp.choices = [MagicMock(message=second_msg)]

        with patch.object(t._client.chat.completions, "create", new=AsyncMock(
            side_effect=[first_resp, second_resp]
        )):
            result = asyncio.run(t.run("run the tests", []))

        assert "pytest tests/" in result.tool_calls
        assert result.output == "Tests ran successfully."
