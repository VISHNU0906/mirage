"""OpenAI-compatible provider adapter.

Works with the OpenAI API or any compatible endpoint (set
``MIRAGE_LLM_BASE_URL``).  Selected with ``MIRAGE_LLM_PROVIDER=openai`` plus a
``MIRAGE_LLM_API_KEY``.  The ``openai`` SDK is imported lazily so mock mode
never needs it.
"""

from __future__ import annotations

from typing import List, Optional

from .base import LLMMessage, LLMProvider, LLMResult, ToolCall
from .mock import _TOOL_RE, _parse_kwargs


class OpenAIProvider(LLMProvider):
    name = "openai"

    def complete(
        self, messages: List[LLMMessage], tools: Optional[List[dict]] = None
    ) -> LLMResult:
        try:
            from openai import OpenAI  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "openai is not installed. Install it and set MIRAGE_LLM_API_KEY, "
                "or use MIRAGE_LLM_PROVIDER=mock."
            ) from exc

        api_key = getattr(self.config, "llm_api_key", "")
        if not api_key:
            raise RuntimeError("MIRAGE_LLM_API_KEY is required for the openai provider.")
        base_url = getattr(self.config, "llm_base_url", "") or None
        client = OpenAI(api_key=api_key, base_url=base_url)

        model_name = getattr(self.config, "llm_model", "") or "gpt-4o-mini"
        payload = [{"role": m.role, "content": m.content} for m in messages]
        resp = client.chat.completions.create(model=model_name, messages=payload)
        text = resp.choices[0].message.content or ""

        tool_calls: List[ToolCall] = []
        for match in _TOOL_RE.finditer(text):
            tool_calls.append(
                ToolCall(name=match.group(1).lower(), args=_parse_kwargs(match.group(2)))
            )
        return LLMResult(text=text, tool_calls=tool_calls)
