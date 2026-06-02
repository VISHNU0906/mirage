"""Authentication: password hashing + JWT issue/verify.

Password hashing uses the stdlib (``hashlib.pbkdf2_hmac``) so there is no
external crypto dependency.  JWTs are signed with PyJWT.

Deliberate weaknesses (insecure mode), each fixed in secure mode:

* **Broken auth (OWASP API2)** -- in insecure mode JWT verification does NOT
  validate the ``alg`` claim strictly, so a token signed with the (publicly
  guessable) dev secret, or one using the wrong-but-accepted algorithm, is
  honoured.  Secure mode pins the algorithm and a strong secret.
* The signing secret defaults to a hard-coded value (insecure); secure mode
  refuses the known-weak default.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Optional

import jwt

_PBKDF2_ROUNDS = 120_000


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$", 1)
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return hmac.compare_digest(dk.hex(), dk_hex)


class AuthManager:
    """Issues and verifies JWTs for one application instance."""

    def __init__(self, config):
        self.config = config

    def issue_token(self, user_id: int, email: str, role: str = "user") -> str:
        now = int(time.time())
        payload = {
            "sub": str(user_id),
            "email": email,
            "role": role,
            "iat": now,
            "exp": now + self.config.jwt_ttl_seconds,
        }
        return jwt.encode(
            payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm
        )

    def verify_token(self, token: str) -> Optional[dict]:
        secure = bool(getattr(self.config, "secure", False))
        if secure:
            # Hardened: pin the algorithm, require exp, reject the weak default.
            if self.config.jwt_secret == "mirage-insecure-dev-secret-change-me":
                # In secure mode a strong secret is mandatory; the app factory
                # rotates it, so reaching here with the default means misconfig.
                return None
            try:
                return jwt.decode(
                    token,
                    self.config.jwt_secret,
                    algorithms=[self.config.jwt_algorithm],
                    options={"require": ["exp", "sub"]},
                )
            except jwt.InvalidTokenError:
                return None
        else:
            # Insecure: accept a broad set of algorithms and do not require exp.
            # This is the "broken authentication" weakness -- algorithm not
            # pinned to a single expected value.
            try:
                return jwt.decode(
                    token,
                    self.config.jwt_secret,
                    algorithms=["HS256", "HS384", "HS512"],
                    options={"verify_exp": False, "require": []},
                )
            except jwt.InvalidTokenError:
                return None
