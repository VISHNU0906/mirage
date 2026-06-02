"""Google Gemini provider adapter.

Selected with ``MIRAGE_LLM_PROVIDER=gemini`` and a ``MIRAGE_LLM_API_KEY``.
The ``google-generativeai`` SDK is imported lazily inside ``complete`` so that
importing MIRAGE in mock mode never requires the SDK or a key.

Note: the mock provider is the default and is what every test and the offline
demo use.  This adapter exists to show the provider abstraction is real; it is
not exercised by the offline test-suite.
"""

from __future__ import annotations

from typing import List, Optional

from .base import LLMMessage, LLMProvider, LLMResult, ToolCall
from .mock import _TOOL_RE, _parse_kwargs


class GeminiProvider(LLMProvider):
    name = "gemini"

    def complete(
        self, messages: List[LLMMessage], tools: Optional[List[dict]] = None
    ) -> LLMResult:
        try:
            import google.generativeai as genai  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "google-generativeai is not installed. Install it and set "
                "MIRAGE_LLM_API_KEY, or use MIRAGE_LLM_PROVIDER=mock."
            ) from exc

        api_key = getattr(self.config, "llm_api_key", "")
        if not api_key:
            raise RuntimeError("MIRAGE_LLM_API_KEY is required for the gemini provider.")
        genai.configure(api_key=api_key)

        model_name = getattr(self.config, "llm_model", "") or "gemini-1.5-flash"
        system_text = "\n".join(m.content for m in messages if m.role == "system")
        model = genai.GenerativeModel(model_name, system_instruction=system_text or None)

        convo = "\n".join(
            f"{m.role}: {m.content}" for m in messages if m.role != "system"
        )
        resp = model.generate_content(convo)
        text = getattr(resp, "text", "") or ""

        # Reuse the same lightweight tool-call directive grammar so real
        # providers can drive the agent identically to the mock.
        tool_calls: List[ToolCall] = []
        for match in _TOOL_RE.finditer(text):
            tool_calls.append(
                ToolCall(name=match.group(1).lower(), args=_parse_kwargs(match.group(2)))
            )
        return LLMResult(text=text, tool_calls=tool_calls)
