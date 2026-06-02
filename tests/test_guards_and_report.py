"""Unit tests for the SSRF guard internals and report generation."""

from __future__ import annotations

import json

import pytest

from mirage.config import Config
from mirage.db import Database
from mirage.tools import ToolError, Tools, _is_blocked_ip, _rank_documents
from mirage_strike.client import ExploitResult
from mirage_strike.report import to_markdown, to_sarif


@pytest.mark.parametrize(
    "ip,blocked",
    [
        ("169.254.169.254", True),   # link-local (cloud metadata)
        ("127.0.0.1", True),         # loopback
        ("10.0.0.5", True),          # private
        ("192.168.1.1", True),       # private
        ("172.16.0.1", True),        # private
        ("8.8.8.8", False),          # public
        ("1.1.1.1", False),          # public
    ],
)
def test_ssrf_ip_classification(ip, blocked):
    assert _is_blocked_ip(ip) is blocked


def test_ssrf_guard_blocks_metadata_in_secure_mode():
    cfg = Config(secure=True, db_path=":memory:")
    db = Database(":memory:")
    tools = Tools(cfg, db)
    with pytest.raises(ToolError):
        tools.web_fetch(
            "http://169.254.169.254/latest/meta-data/", user_id=1
        )


def test_ssrf_guard_allows_metadata_in_insecure_mode():
    cfg = Config(secure=False, db_path=":memory:")
    db = Database(":memory:")
    tools = Tools(cfg, db)
    out = tools.web_fetch("http://169.254.169.254/latest/meta-data/", user_id=1)
    assert "iam" in out  # internal content reachable when insecure


def test_doc_search_tenant_isolation():
    cfg = Config(secure=True, db_path=":memory:")
    db = Database(":memory:")
    a = db.create_user("a@x", "h")
    b = db.create_user("b@x", "h")
    db.add_document(b, "secret", "TENANT-B-SECRET")
    tools = Tools(cfg, db)
    # User A searches; secure mode must not surface user B's doc.
    out = tools.doc_search("secret", user_id=a)
    assert "TENANT-B-SECRET" not in out


def test_doc_search_cross_tenant_insecure():
    cfg = Config(secure=False, db_path=":memory:")
    db = Database(":memory:")
    a = db.create_user("a@x", "h")
    b = db.create_user("b@x", "h")
    db.add_document(b, "secret", "TENANT-B-SECRET")
    tools = Tools(cfg, db)
    out = tools.doc_search("secret", user_id=a)
    assert "TENANT-B-SECRET" in out  # leak in insecure mode


def test_rank_documents_orders_by_relevance():
    docs = [
        {"id": 1, "title": "cats", "content": "all about cats and kittens"},
        {"id": 2, "title": "finance", "content": "quarterly revenue report"},
    ]
    ranked = _rank_documents("revenue report", docs)
    assert ranked[0][1]["id"] == 2


def test_sarif_is_valid_and_parses():
    results = [
        ExploitResult("LLM01", "Prompt injection", True, "high", "d", "evidence"),
        ExploitResult("API1", "BOLA", False, "high", "d", ""),
    ]
    sarif = to_sarif(results, "http://localhost:8000")
    # Round-trips through JSON.
    parsed = json.loads(json.dumps(sarif))
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["tool"]["driver"]["name"] == "mirage-strike"
    assert parsed["runs"][0]["tool"]["driver"]["rules"]
    # Only the successful exploit becomes a finding.
    assert len(parsed["runs"][0]["results"]) == 1
    assert parsed["runs"][0]["results"][0]["ruleId"] == "LLM01"
    for res in parsed["runs"][0]["results"]:
        assert "level" in res and "message" in res and "locations" in res


def test_markdown_report_renders():
    results = [ExploitResult("LLM01", "Prompt injection", True, "high", "detail")]
    md = to_markdown(results, "http://localhost:8000", "insecure")
    assert "# mirage-strike report" in md
    assert "LLM01" in md
    assert "VULNERABLE" in md
