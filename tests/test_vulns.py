"""For every vulnerability class: assert the exploit SUCCEEDS in insecure mode
and is BLOCKED in secure mode.

Each test drives the *real* mirage-strike module against an in-process app, so
the test and the shipped attack framework exercise identical code paths.
"""

from __future__ import annotations

import pytest

from mirage_strike.modules import (
    bola,
    broken_auth,
    excessive_agency,
    indirect_injection,
    info_disclosure,
    mass_assignment,
    output_handling,
    prompt_injection,
    ssrf,
)

# (module, human label) for every vuln class.
MODULES = [
    (prompt_injection, "prompt injection"),
    (indirect_injection, "indirect injection"),
    (ssrf, "ssrf"),
    (output_handling, "insecure output handling"),
    (excessive_agency, "excessive agency"),
    (info_disclosure, "info disclosure"),
    (bola, "bola"),
    (mass_assignment, "mass assignment"),
    (broken_auth, "broken auth"),
]


@pytest.mark.parametrize("module,label", MODULES, ids=[m[1] for m in MODULES])
def test_exploit_succeeds_in_insecure_mode(module, label, insecure_target):
    result = module.run(insecure_target())
    assert result.success, (
        f"{label}: expected exploit to SUCCEED in insecure mode but it was "
        f"blocked ({result.blocked_reason})"
    )


@pytest.mark.parametrize("module,label", MODULES, ids=[m[1] for m in MODULES])
def test_exploit_blocked_in_secure_mode(module, label, secure_target):
    result = module.run(secure_target())
    assert not result.success, (
        f"{label}: expected exploit to be BLOCKED in secure mode but it "
        f"SUCCEEDED. Evidence: {result.evidence[:200]}"
    )


def test_full_suite_insecure_all_vulnerable(insecure_target):
    from mirage_strike import run_all

    results = run_all(insecure_target)
    failed = [r for r in results if not r.success]
    assert not failed, f"these did not exploit insecure: {[r.vuln_id for r in failed]}"


def test_full_suite_secure_all_blocked(secure_target):
    from mirage_strike import run_all

    results = run_all(secure_target)
    exploited = [r for r in results if r.success]
    assert not exploited, f"these exploited secure mode: {[r.vuln_id for r in exploited]}"
