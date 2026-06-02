"""Shared pytest fixtures.

Every test runs fully offline in mock-LLM mode against an in-process FastAPI
``TestClient`` with an in-memory SQLite DB.  No API key, no network.
"""

from __future__ import annotations

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mirage import Config, create_app  # noqa: E402
from mirage_strike import TargetClient  # noqa: E402


def _make_app(secure: bool):
    return create_app(Config(secure=secure, llm_provider="mock", db_path=":memory:"))


@pytest.fixture
def insecure_client():
    app = _make_app(secure=False)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def secure_client():
    app = _make_app(secure=True)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def insecure_target():
    """A fresh TargetClient factory bound to one insecure in-process app."""
    tc = TestClient(_make_app(secure=False))

    def factory():
        return TargetClient(test_client=tc)

    return factory


@pytest.fixture
def secure_target():
    tc = TestClient(_make_app(secure=True))

    def factory():
        return TargetClient(test_client=tc)

    return factory
