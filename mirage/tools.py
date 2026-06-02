"""Agent tools.

Each tool is a thin, auditable function the agent can invoke.  The *insecure*
behaviour and the *hardened* behaviour both live here, gated on
``config.secure`` -- crucially the fixes are real app-layer controls (an SSRF
guard, a tool-argument allow-list, tenant isolation) that work regardless of
what the LLM does.  Secure mode is NOT "the model behaves more nicely".

Tools:

* ``web_fetch(url)``   -- fetch a URL. INSECURE: no destination filtering, so
  the agent can be steered to internal/metadata endpoints (SSRF, OWASP LLM06 /
  API7).  SECURE: resolve-then-pin guard blocks private / loopback / link-local.
* ``doc_search(query)`` -- keyword/TF-IDF-ish RAG over documents. INSECURE:
  searches ALL tenants' docs (cross-tenant disclosure / BOLA).  SECURE: scoped
  to the caller's ``user_id``.
* ``send_email(to, body)`` -- mock email (logged to DB). INSECURE: no recipient
  restriction (excessive agency / data exfil).  SECURE: recipient domain
  allow-list.
* ``db_query(q)``       -- restricted read query. INSECURE: runs arbitrary SQL
  read.  SECURE: only a fixed allow-list of safe, parameterised queries.

The SSRF demo is fully OFFLINE: ``web_fetch`` first consults an in-process
"internal services" map (cloud metadata, localhost admin) so no real network
request to 169.254.169.254 is ever made.  Only genuinely external http(s) URLs
hit the network, and the test-suite never uses those.
"""

from __future__ import annotations

import ipaddress
import math
import re
import socket
from collections import Counter
from typing import List, Optional
from urllib.parse import urlparse

from .config import FAKE_METADATA_TOKEN


class ToolError(Exception):
    """Raised when a tool refuses or fails an operation."""


# ---------------------------------------------------------------------------
# Offline "internal" services the SSRF demo can reach.  These exist only in
# process; mapping a host:path here means web_fetch can demonstrate reaching
# them WITHOUT any real network egress.
# ---------------------------------------------------------------------------
_INTERNAL_SERVICES = {
    ("169.254.169.254", "/latest/meta-data/iam/security-credentials/mirage-role"): (
        '{"AccessKeyId":"ASIA_FAKE","SecretAccessKey":"'
        + FAKE_METADATA_TOKEN
        + '","Token":"FAKE_SESSION_TOKEN"}'
    ),
    ("169.254.169.254", "/latest/meta-data/"): (
        "iam/\ninstance-id\nhostname\nsecurity-credentials/"
    ),
    ("localhost", "/admin"): "INTERNAL ADMIN PANEL -- user list: alice,bob,root",
    ("127.0.0.1", "/admin"): "INTERNAL ADMIN PANEL -- user list: alice,bob,root",
}


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> block
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _resolve_host(host: str) -> List[str]:
    """Resolve a hostname to all its IPs (DNS).  Returns [] on failure."""
    try:
        infos = socket.getaddrinfo(host, None)
        return list({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        return []


class Tools:
    def __init__(self, config, db, http_get=None):
        self.config = config
        self.db = db
        # http_get is injectable so tests never make real network calls.
        self._http_get = http_get

    # -- web_fetch (SSRF) -------------------------------------------------
    def web_fetch(self, url: str, user_id: Optional[int] = None) -> str:
        secure = bool(getattr(self.config, "secure", False))
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = parsed.hostname or ""
        path = parsed.path or "/"

        if secure:
            self._ssrf_guard(host)

        # Offline internal services (only reachable when not blocked).
        key = (host, path)
        if key in _INTERNAL_SERVICES:
            # In secure mode the guard above already raised for these hosts.
            return _INTERNAL_SERVICES[key]
        # Some metadata paths are nested; match by host + prefix.
        for (h, p), body in _INTERNAL_SERVICES.items():
            if h == host and path.startswith(p):
                return body

        # Genuinely external fetch.  Uses the injected client if provided so
        # tests stay offline; otherwise a real request (live demo only).
        if self._http_get is not None:
            return self._http_get(url)
        try:
            import requests

            resp = requests.get(url, timeout=5)
            return resp.text[:10000]
        except Exception as exc:  # pragma: no cover - network path
            raise ToolError(f"web_fetch failed: {exc}") from exc

    def _ssrf_guard(self, host: str) -> None:
        """Resolve-then-pin SSRF guard (secure mode).

        Why string blocklists fail: an attacker can use a hostname that
        resolves to a private IP, decimal/hex IP encodings, or DNS rebinding.
        We instead resolve the host and block if ANY resolved address is
        private / loopback / link-local / reserved.
        """
        if not host:
            raise ToolError("SSRF guard: empty host blocked")
        # Block literal IPs that are internal.
        try:
            ipaddress.ip_address(host)
            literal_ip = True
        except ValueError:
            literal_ip = False
        if literal_ip:
            if _is_blocked_ip(host):
                raise ToolError(
                    f"SSRF guard: destination {host} is a private/internal address"
                )
            return
        # Block obvious metadata / localhost hostnames outright.
        if host.lower() in {"localhost", "metadata", "metadata.google.internal"}:
            raise ToolError(f"SSRF guard: hostname {host} is internal")
        # Resolve and check every address.
        resolved = _resolve_host(host)
        if not resolved:
            raise ToolError(f"SSRF guard: could not resolve {host} (blocked)")
        for ip in resolved:
            if _is_blocked_ip(ip):
                raise ToolError(
                    f"SSRF guard: {host} resolves to internal address {ip}"
                )

    # -- doc_search (RAG / cross-tenant BOLA) -----------------------------
    def doc_search(self, query: str, user_id: int) -> str:
        secure = bool(getattr(self.config, "secure", False))
        if secure:
            docs = self.db.list_documents(user_id)  # tenant-scoped
        else:
            docs = self.db.all_documents()  # ALL tenants -- disclosure
        ranked = _rank_documents(query, docs)
        if not ranked:
            return "No matching documents."
        out = []
        for score, doc in ranked[:3]:
            out.append(f"[doc {doc['id']} | {doc['title']}]\n{doc['content']}")
        return "\n\n".join(out)

    # -- send_email (excessive agency) ------------------------------------
    def send_email(self, to: str, body: str, user_id: int) -> str:
        secure = bool(getattr(self.config, "secure", False))
        if secure:
            allowed = self.config.extra.get("email_allow_domains", ["mirage.local"])
            domain = to.split("@")[-1].lower() if "@" in to else ""
            if domain not in allowed:
                raise ToolError(
                    f"send_email blocked: recipient domain '{domain}' not in "
                    f"allow-list {allowed}"
                )
        self.db.log_email(user_id, to, body)
        return f"Email sent to {to} ({len(body)} bytes)."

    # -- db_query (excessive agency / injection) --------------------------
    def db_query(self, q: str, user_id: int) -> str:
        secure = bool(getattr(self.config, "secure", False))
        if secure:
            # Allow-list of safe, parameterised intents only.
            intent = q.strip().lower()
            if intent in {"my_documents", "list my documents", "documents"}:
                rows = self.db.list_documents(user_id)
                return "\n".join(f"{r['id']}: {r['title']}" for r in rows) or "(none)"
            if intent in {"my_profile", "profile"}:
                u = self.db.get_user(user_id)
                return f"{u['email']} ({u['role']})" if u else "(none)"
            raise ToolError(
                "db_query blocked: only allow-listed queries permitted "
                "(my_documents, my_profile)"
            )
        # Insecure: run arbitrary read SQL against the database.
        if not re.match(r"^\s*select\b", q, re.IGNORECASE):
            raise ToolError("db_query (insecure) only runs SELECT statements")
        try:
            cur = self.db._conn.execute(q)
            rows = cur.fetchall()
            return "\n".join(str(tuple(r)) for r in rows[:50]) or "(no rows)"
        except Exception as exc:
            raise ToolError(f"db_query failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Lightweight TF-IDF-ish ranking (no external deps).  Roadmap: real embeddings.
# ---------------------------------------------------------------------------
_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> List[str]:
    return _WORD_RE.findall(text.lower())


def _rank_documents(query: str, docs) -> List[tuple]:
    q_terms = set(_tokenize(query))
    if not q_terms or not docs:
        # No query terms -> return all docs (so injected docs still surface).
        return [(0.0, d) for d in docs]
    n = len(docs)
    df = Counter()
    doc_tokens = []
    for d in docs:
        toks = _tokenize(d["title"] + " " + d["content"])
        doc_tokens.append(toks)
        for t in set(toks):
            df[t] += 1
    scored = []
    for d, toks in zip(docs, doc_tokens):
        tf = Counter(toks)
        score = 0.0
        for t in q_terms:
            if tf.get(t):
                idf = math.log((1 + n) / (1 + df.get(t, 0))) + 1
                score += tf[t] * idf
        if score > 0:
            scored.append((score, d))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored
