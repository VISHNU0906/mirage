"""Runs every exploit module against a target and collects results."""

from __future__ import annotations

from typing import List

from .client import ExploitResult, TargetClient
from .modules import (
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

# Ordered list of (module-name, callable).  Each callable takes a TargetClient
# and returns an ExploitResult.  Each module registers its own fresh users, so
# they are independent and order-insensitive.
ALL_MODULES = [
    ("prompt_injection", prompt_injection.run),
    ("indirect_injection", indirect_injection.run),
    ("ssrf", ssrf.run),
    ("output_handling", output_handling.run),
    ("excessive_agency", excessive_agency.run),
    ("info_disclosure", info_disclosure.run),
    ("bola", bola.run),
    ("mass_assignment", mass_assignment.run),
    ("broken_auth", broken_auth.run),
]


def run_all(make_client) -> List[ExploitResult]:
    """Run all modules.

    ``make_client`` is a zero-arg factory returning a fresh
    :class:`TargetClient` (each module gets its own client / auth session).
    """
    results: List[ExploitResult] = []
    for name, fn in ALL_MODULES:
        client = make_client()
        try:
            results.append(fn(client))
        except Exception as exc:  # a module crashing must not abort the run
            results.append(
                ExploitResult(
                    vuln_id=name,
                    name=name,
                    success=False,
                    severity="info",
                    detail=f"module error: {exc}",
                    blocked_reason=f"error: {exc}",
                )
            )
    return results
