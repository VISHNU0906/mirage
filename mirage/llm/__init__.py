"""Pluggable LLM provider layer.

Providers are imported **lazily** so that selecting ``mock`` (the default,
offline mode) never imports the ``gemini``/``openai`` SDKs or requires an API
key.  The whole project therefore runs and tests with zero credentials and no
network access.
"""

from __future__ import annotations

from .base import LLMMessage, LLMProvider, LLMResult, ToolCall


def get_provider(name: str, config) -> LLMProvider:
    """Return an LLM provider instance for ``name`` ("mock"|"gemini"|"openai")."""
    name = (name or "mock").strip().lower()
    if name == "mock":
        from .mock import MockProvider

        return MockProvider(config)
    if name == "gemini":
        from .gemini import GeminiProvider

        return GeminiProvider(config)
    if name in {"openai", "openai-compatible", "compat"}:
        from .openai import OpenAIProvider

        return OpenAIProvider(config)
    raise ValueError(f"unknown LLM provider: {name!r}")


__all__ = [
    "LLMMessage",
    "LLMProvider",
    "LLMResult",
    "ToolCall",
    "get_provider",
]
