"""The response shape every non-Anthropic adapter normalizes into.

`culprit/pipeline/rca_agent.py::DeepRCAAgent.diagnose()` only ever reads
two things off whatever `client.messages.create(...)` returns: `.content`
(a list of blocks, where the one it cares about has `.type == "tool_use"`,
`.name`, and `.input`) and nothing else from the top-level response object
today. These two dataclasses are that shape and nothing more - adding a
field neither of them has would be pointless, since rca_agent.py can't
read it anyway.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolUseBlock:
    name: str
    input: Any
    type: str = "tool_use"


@dataclass
class NormalizedResponse:
    content: list = field(default_factory=list)
    stop_reason: str = "tool_use"
