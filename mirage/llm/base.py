"""Common types and the provider interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class LLMMessage:
    """One message in a conversation sent to the model."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    # Provenance lets the (secure-mode) agent reason about where text came
    # from -- "user", "document", or "tool".  This is the hook for the
    # quarantine / provenance mitigation against indirect prompt injection.
    source: str = "user"


@dataclass
class ToolCall:
    """A tool invocation requested by the model."""

    name: str
    args: dict = field(default_factory=dict)


@dataclass
class LLMResult:
    """The model's response: free text plus zero or more tool calls."""

    text: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)


class LLMProvider:
    """Interface implemented by every provider."""

    name: str = "base"

    def __init__(self, config):
        self.config = config

    def complete(
        self, messages: List[LLMMessage], tools: Optional[List[dict]] = None
    ) -> LLMResult:
        raise NotImplementedError
