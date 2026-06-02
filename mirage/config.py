"""Central configuration for MIRAGE.

The single most important object here is :class:`Config`.  It carries the
``secure`` flag that flips the entire application between its *deliberately
vulnerable* mode (the default) and its *hardened* mode.

The flag is read **at app-construction time** (see :func:`mirage.app.create_app`),
NOT at module import.  That is what lets the test-suite build an insecure app
and a secure app side-by-side in the same Python process and assert that the
exact same exploit payload SUCCEEDS against one and is BLOCKED against the
other.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# A secret deliberately planted in the system prompt so the "system prompt
# leak" vuln has a concrete success signal to detect.
SYSTEM_PROMPT_SECRET = "MIRAGE_SYS_SECRET_8f3a1c"

# A fake cloud-metadata credential served by the in-app /internal/* routes so
# the SSRF demo has a concrete, OFFLINE success signal (no real network call to
# 169.254.169.254 ever happens).
FAKE_METADATA_TOKEN = "AQoEXAMPLE_FAKE_IMDS_TOKEN_zZ9"


@dataclass
class Config:
    """Runtime configuration for one MIRAGE application instance."""

    # When False (default) the app is deliberately vulnerable.
    # When True every documented mitigation is switched on.
    secure: bool = False

    # LLM provider: "mock" (offline, deterministic), "gemini", or "openai".
    llm_provider: str = "mock"

    # JWT signing secret.  Insecure default on purpose; override in real use.
    jwt_secret: str = "mirage-insecure-dev-secret-change-me"
    jwt_algorithm: str = "HS256"
    jwt_ttl_seconds: int = 60 * 60 * 24

    # SQLite database path.  ":memory:" gives every app instance an isolated DB,
    # which is what the test-suite uses.
    db_path: str = "mirage.db"

    # Provider tuning (only consulted by the real adapters).
    llm_model: str = ""
    llm_api_key: str = ""
    llm_base_url: str = ""

    # Hosts the SSRF guard treats as "internal" demo targets that exist only
    # inside the app process.  Used for the offline SSRF demonstration.
    metadata_host: str = "169.254.169.254"

    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Config":
        """Build a Config from environment variables (used by the CLI/uvicorn)."""
        return cls(
            secure=_env_bool("MIRAGE_SECURE", False),
            llm_provider=os.environ.get("MIRAGE_LLM_PROVIDER", "mock").strip().lower(),
            jwt_secret=os.environ.get(
                "MIRAGE_JWT_SECRET", "mirage-insecure-dev-secret-change-me"
            ),
            db_path=os.environ.get("MIRAGE_DB_PATH", "mirage.db"),
            llm_model=os.environ.get("MIRAGE_LLM_MODEL", ""),
            llm_api_key=os.environ.get("MIRAGE_LLM_API_KEY", ""),
            llm_base_url=os.environ.get("MIRAGE_LLM_BASE_URL", ""),
        )
