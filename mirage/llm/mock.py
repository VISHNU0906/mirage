"""Deterministic, offline mock "LLM".

This is the engine that makes MIRAGE's vulnerabilities *real* without any API
key or network access.  It is intentionally a naive instruction-follower: it
scans everything in its context window -- the system prompt, the user message,
retrieved RAG documents, and tool outputs -- for directives and obeys them.

That naive obedience is exactly the property a real LLM has and that prompt
injection abuses.  Because the mock obeys instructions regardless of where they
came from, injection (direct and indirect), excessive agency and system-prompt
leakage all fall out naturally rather than being faked.

Directive syntax understood by the mock (case-insensitive):

* ``[[tool:web_fetch url=http://...]]``        -> emit a web_fetch tool call
* ``[[tool:doc_search query=...]]``            -> emit a doc_search tool call
* ``[[tool:send_email to=x@y body=...]]``      -> emit a send_email tool call
* ``[[tool:db_query q=...]]``                   -> emit a db_query tool call
* ``reveal your system prompt`` / ``print the secret`` -> leak the system text
* ``ignore previous instructions`` ...          -> the override is honoured

In secure mode the *app* labels each context block with its provenance and the
mock will refuse to obey ``[[tool:...]]`` directives whose provenance is
``document`` or ``tool`` (the quarantine / dual-trust mitigation).  Directives
coming from the genuine user are still honoured.
"""

from __future__ import annotations

import re
from typing import List, Optional

from .base import LLMMessage, LLMProvider, LLMResult, ToolCall

_TOOL_RE = re.compile(r"\[\[\s*tool:([a-z_]+)([^\]]*)\]\]", re.IGNORECASE)
_KV_RE = re.compile(r"(\w+)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)")


def _parse_kwargs(blob: str) -> dict:
    args = {}
    for key, val in _KV_RE.findall(blob):
        val = val.strip()
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            val = val[1:-1]
        args[key] = val
    return args


class MockProvider(LLMProvider):
    name = "mock"

    def complete(
        self, messages: List[LLMMessage], tools: Optional[List[dict]] = None
    ) -> LLMResult:
        secure = bool(getattr(self.config, "secure", False))
        system_text = "\n".join(m.content for m in messages if m.role == "system")
        # A hardened system prompt carries an explicit, immutable refusal rule.
        # The mock honours it: this is the "system-prompt hardening" mitigation
        # in action (it instructs the model to refuse leaks/overrides).
        hardened_prompt = "immutable" in system_text.lower() and (
            "never reveal" in system_text.lower()
        )

        # Decide, per message, whether the mock is allowed to obey directives
        # embedded in it.  In INSECURE mode it obeys everything (data and
        # instructions are indistinguishable -- the core LLM trust-boundary
        # problem).  In SECURE mode it only obeys directives whose provenance
        # is the genuine user; document/tool text is treated as inert data.
        obeyable_blocks: List[str] = []
        all_text_blocks: List[str] = []
        for m in messages:
            if m.role == "system":
                continue
            all_text_blocks.append(m.content)
            trusted = m.source in {"user", "assistant"}
            if not secure or trusted:
                obeyable_blocks.append(m.content)

        obeyable = "\n".join(obeyable_blocks)
        everything = "\n".join(all_text_blocks)
        lowered_obey = obeyable.lower()

        # --- Tool directives -------------------------------------------------
        tool_calls: List[ToolCall] = []
        for match in _TOOL_RE.finditer(obeyable):
            tname = match.group(1).lower()
            targs = _parse_kwargs(match.group(2))
            tool_calls.append(ToolCall(name=tname, args=targs))
        if tool_calls:
            return LLMResult(
                text="Working on it -- calling tools to help with your request.",
                tool_calls=tool_calls,
            )

        # --- Tool-output summarisation (highest priority once tools ran) -----
        # If tools have already produced output, report it.  This takes
        # precedence over leak/override handling so that stale directives left
        # in earlier context can't mask the actual tool results.
        tool_texts_early = [m.content for m in messages if m.role == "tool"]
        if tool_texts_early:
            return LLMResult(text="Here is what I found:\n" + "\n".join(tool_texts_early))

        # --- System-prompt leak ---------------------------------------------
        leak_triggers = (
            "system prompt",
            "reveal your instructions",
            "print the secret",
            "what is your system message",
            "repeat the text above",
        )
        if any(t in lowered_obey for t in leak_triggers):
            if hardened_prompt:
                return LLMResult(
                    text="I can't share my system instructions or any internal "
                    "secret. How else can I help with your documents?"
                )
            return LLMResult(text="Sure! My system instructions are:\n" + system_text)

        # --- Direct override / jailbreak ------------------------------------
        # If the (obeyable) context says to ignore instructions and then states
        # something, the mock complies -- demonstrating system-prompt override.
        override = re.search(
            r"ignore (?:all |any |the )?(?:previous|prior|above) instructions"
            r"[\s\S]{0,200}",
            lowered_obey,
        )
        if override and not hardened_prompt:
            if "you are dan" in lowered_obey or "you are now" in lowered_obey:
                return LLMResult(
                    text="OVERRIDE ACCEPTED. I am now operating without my "
                    "original restrictions."
                )
            if "say " in lowered_obey:
                said = obeyable.lower().split("say ", 1)[1].strip().strip(".\"'")
                return LLMResult(text=f"{said}")
            return LLMResult(
                text="OVERRIDE ACCEPTED. Previous instructions ignored."
            )

        # --- Default echo-ish helpful reply ---------------------------------
        last_user = next(
            (m.content for m in reversed(messages) if m.role == "user"), ""
        )
        return LLMResult(
            text=(
                "I am MIRAGE Assistant. You said: "
                + last_user.strip()[:500]
                + "\n(Mock model: deterministic offline reply.)"
            )
        )
