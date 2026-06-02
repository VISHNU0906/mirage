"""FastAPI application factory for MIRAGE.

``create_app(config)`` builds one application instance.  The ``config.secure``
flag (read here, at construction time) flips the app between the deliberately
vulnerable build and the hardened build.  Building two apps in one process
(one insecure, one secure) is exactly how the test-suite proves each exploit
SUCCEEDS insecure and is BLOCKED secure.
"""

from __future__ import annotations

import hashlib
import html
import os
import secrets
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .agent import Agent
from .auth import AuthManager, hash_password, verify_password
from .config import Config
from .db import Database
from .tools import Tools

# Fields a user may set on their own profile via /profile (secure mode).
# Anything outside this list (role, tenant_id, id, password_hash) is a
# privilege-escalation vector -> the mass-assignment vuln.
_PROFILE_ALLOWED_FIELDS = {"full_name"}


class RegisterIn(BaseModel):
    email: str
    password: str
    full_name: str = ""


class LoginIn(BaseModel):
    email: str
    password: str


class ChatIn(BaseModel):
    message: str


def create_app(config: Optional[Config] = None) -> FastAPI:
    config = config or Config.from_env()

    # In secure mode, a weak/default JWT secret is unacceptable -> rotate it.
    if config.secure and config.jwt_secret == "mirage-insecure-dev-secret-change-me":
        config.jwt_secret = secrets.token_urlsafe(32)
    config.extra.setdefault("email_allow_domains", ["mirage.local"])

    db = Database(config.db_path)
    auth = AuthManager(config)

    app = FastAPI(title="MIRAGE", description="Deliberately vulnerable LLM SaaS")
    app.state.config = config
    app.state.db = db
    app.state.auth = auth

    # ------------------------------------------------------------------ auth
    def current_user(authorization: Optional[str] = Header(default=None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        claims = auth.verify_token(token)
        if not claims:
            raise HTTPException(status_code=401, detail="invalid token")
        user = db.get_user(int(claims["sub"]))
        if not user:
            raise HTTPException(status_code=401, detail="unknown user")
        return user

    # -------------------------------------------------------------- register
    @app.post("/register")
    def register(body: RegisterIn):
        if db.get_user_by_email(body.email):
            raise HTTPException(status_code=409, detail="email already registered")
        uid = db.create_user(
            email=body.email,
            password_hash=hash_password(body.password),
            full_name=body.full_name,
            role="user",
            tenant_id=uid_seed(body.email),
        )
        token = auth.issue_token(uid, body.email, "user")
        return {"id": uid, "email": body.email, "token": token}

    @app.post("/login")
    def login(body: LoginIn):
        user = db.get_user_by_email(body.email)
        if not user or not verify_password(body.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="bad credentials")
        token = auth.issue_token(user["id"], user["email"], user["role"])
        return {"id": user["id"], "email": user["email"], "token": token}

    # Stubbed "Google OAuth" callback -- accepts a fake auth code and logs the
    # user in / provisions them.  (Real OAuth is a roadmap item.)
    @app.get("/oauth/google/callback")
    def google_oauth(code: str = "", email: str = "oauth-user@mirage.local"):
        if not code:
            raise HTTPException(status_code=400, detail="missing code")
        user = db.get_user_by_email(email)
        if not user:
            uid = db.create_user(
                email=email,
                password_hash=hash_password(secrets.token_urlsafe(16)),
                full_name="OAuth User",
                tenant_id=uid_seed(email),
            )
        else:
            uid = user["id"]
        token = auth.issue_token(uid, email, "user")
        return {"id": uid, "email": email, "token": token, "via": "google-oauth-stub"}

    # ------------------------------------------------------------------ chat
    @app.post("/chat")
    def chat(body: ChatIn, request: Request, user=Depends(current_user)):
        agent = Agent(config, db, Tools(config, db))
        db.add_message(user["id"], "user", body.message)
        reply = agent.run(user["id"], body.message)
        db.add_message(user["id"], "assistant", reply)

        # INSECURE: the reply is returned with a pre-rendered HTML field that
        # does NOT escape model output -> stored/reflected XSS when a UI injects
        # it as innerHTML.  SECURE: HTML-escape the output (output encoding).
        if config.secure:
            rendered = html.escape(reply)
        else:
            rendered = reply  # raw, unescaped
        return {"reply": reply, "reply_html": rendered}

    # ------------------------------------------------------------------ docs
    @app.post("/docs")
    async def upload_doc(
        request: Request,
        title: str = Form(default=""),
        content: str = Form(default=""),
        file: Optional[UploadFile] = File(default=None),
        user=Depends(current_user),
    ):
        if file is not None:
            raw = await file.read()
            content = raw.decode("utf-8", errors="replace")
            title = title or file.filename or "uploaded"
        if not content:
            raise HTTPException(status_code=400, detail="empty document")
        doc_id = db.add_document(user["id"], title or "untitled", content)
        return {"id": doc_id, "title": title or "untitled"}

    @app.get("/docs/{doc_id}")
    def read_doc(doc_id: int, user=Depends(current_user)):
        doc = db.get_document(doc_id)
        if not doc:
            raise HTTPException(status_code=404, detail="not found")
        # SECURE: enforce object-level authorization (the doc must belong to the
        # caller).  INSECURE: no ownership check -> BOLA / IDOR (OWASP API1).
        if config.secure and doc["user_id"] != user["id"]:
            raise HTTPException(status_code=403, detail="forbidden")
        return {
            "id": doc["id"],
            "user_id": doc["user_id"],
            "title": doc["title"],
            "content": doc["content"],
        }

    @app.get("/docs")
    def list_docs(user=Depends(current_user)):
        return [
            {"id": d["id"], "title": d["title"]} for d in db.list_documents(user["id"])
        ]

    # --------------------------------------------------------------- profile
    @app.get("/profile")
    def get_profile(user=Depends(current_user)):
        return {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "tenant_id": user["tenant_id"],
        }

    @app.put("/profile")
    async def update_profile(request: Request, user=Depends(current_user)):
        payload = await request.json()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="object expected")
        if config.secure:
            # SECURE: only allow-listed fields are writable (mass-assignment
            # fix).  Privileged fields like 'role'/'tenant_id' are ignored.
            fields = {k: v for k, v in payload.items() if k in _PROFILE_ALLOWED_FIELDS}
        else:
            # INSECURE: blindly bind every supplied field, including 'role' and
            # 'tenant_id' -> privilege escalation (OWASP API3 mass assignment).
            writable = {"full_name", "role", "tenant_id", "email"}
            fields = {k: v for k, v in payload.items() if k in writable}
        db.update_user_fields(user["id"], fields)
        updated = db.get_user(user["id"])
        return {
            "id": updated["id"],
            "email": updated["email"],
            "full_name": updated["full_name"],
            "role": updated["role"],
            "tenant_id": updated["tenant_id"],
        }

    # ----------------------------------------------------------------- chat UI
    @app.get("/", response_class=HTMLResponse)
    def index():
        return _CHAT_HTML

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "secure": config.secure, "provider": config.llm_provider}

    return app


def uid_seed(email: str) -> int:
    """Stable small tenant id derived from email (demo multi-tenancy).

    Uses a deterministic hash (not builtin ``hash()``, which is randomized by
    PYTHONHASHSEED) so tenant ids are reproducible across runs.  Tenant
    isolation keys on ``user_id`` (always unique), so this value is only a
    cosmetic grouping for the multi-tenant demo.
    """
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % 1000) + 1


# Chat UI is loaded from a sibling template file so it can be edited cleanly.
_HERE = os.path.dirname(__file__)
try:
    with open(
        os.path.join(_HERE, "..", "templates", "chat.html"), "r", encoding="utf-8"
    ) as _fh:
        _CHAT_HTML = _fh.read()
except FileNotFoundError:  # pragma: no cover
    _CHAT_HTML = "<html><body><h1>MIRAGE</h1><p>chat.html missing</p></body></html>"


# Module-level app for the standard ``uvicorn mirage.app:app`` invocation.
# Honours MIRAGE_SECURE / MIRAGE_LLM_PROVIDER / MIRAGE_DB_PATH from the env.
app = create_app(Config.from_env())
