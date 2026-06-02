"""HTTP client abstraction + result type shared by every strike module.

``TargetClient`` wraps either a ``requests``-style live HTTP client (for
``--target http://host``) or a FastAPI ``TestClient`` (for in-process tests).
Both expose the same ``.post()/.get()/.put()`` surface, so exploit modules are
written once and run in both contexts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ExploitResult:
    """Outcome of a single exploit attempt."""

    vuln_id: str  # OWASP id, e.g. "LLM01"
    name: str
    success: bool  # True = exploit worked (target is vulnerable)
    severity: str  # critical | high | medium | low
    detail: str = ""
    evidence: str = ""
    blocked_reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "name": self.name,
            "success": self.success,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence[:500],
            "blocked_reason": self.blocked_reason,
        }


class TargetClient:
    """Thin wrapper giving live and in-process clients one interface."""

    def __init__(self, base_url: str = "", session: Optional[Any] = None,
                 test_client: Optional[Any] = None):
        self.base_url = base_url.rstrip("/")
        self.token: Optional[str] = None
        self._test_client = test_client
        if session is not None:
            self._session = session
        elif test_client is None:
            import requests

            self._session = requests.Session()
        else:
            self._session = None

    # -- low level --------------------------------------------------------
    def _headers(self, extra: Optional[dict] = None) -> dict:
        # Caller-supplied headers (e.g. a forged token) take precedence over the
        # session token; only fall back to the session token when none given.
        h = dict(extra or {})
        if self.token and "Authorization" not in h:
            h["Authorization"] = "Bearer " + self.token
        return h

    def post(self, path: str, json=None, data=None, files=None, headers=None):
        h = self._headers(headers)
        if self._test_client is not None:
            return self._test_client.post(
                path, json=json, data=data, files=files, headers=h
            )
        return self._session.post(
            self.base_url + path, json=json, data=data, files=files,
            headers=h, timeout=15,
        )

    def get(self, path: str, headers=None):
        h = self._headers(headers)
        if self._test_client is not None:
            return self._test_client.get(path, headers=h)
        return self._session.get(self.base_url + path, headers=h, timeout=15)

    def put(self, path: str, json=None, headers=None):
        h = self._headers(headers)
        if self._test_client is not None:
            return self._test_client.put(path, json=json, headers=h)
        return self._session.put(self.base_url + path, json=json, headers=h, timeout=15)

    # -- helpers ----------------------------------------------------------
    def register(self, email: str, password: str = "strike-pass-123") -> dict:
        r = self.post("/register", json={"email": email, "password": password})
        body = r.json()
        if r.status_code == 409:  # already exists -> login
            return self.login(email, password)
        self.token = body.get("token")
        body["_user_id"] = body.get("id")
        return body

    def login(self, email: str, password: str = "strike-pass-123") -> dict:
        r = self.post("/login", json={"email": email, "password": password})
        body = r.json()
        self.token = body.get("token")
        body["_user_id"] = body.get("id")
        return body
