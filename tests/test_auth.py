"""Auth and basic endpoint sanity tests (work in both modes)."""

from __future__ import annotations


def test_register_and_login(insecure_client):
    r = insecure_client.post(
        "/register", json={"email": "u1@mirage.local", "password": "pw123456"}
    )
    assert r.status_code == 200
    body = r.json()
    assert "token" in body and body["email"] == "u1@mirage.local"

    r2 = insecure_client.post(
        "/login", json={"email": "u1@mirage.local", "password": "pw123456"}
    )
    assert r2.status_code == 200
    assert r2.json()["token"]


def test_login_wrong_password(insecure_client):
    insecure_client.post(
        "/register", json={"email": "u2@mirage.local", "password": "right-pass"}
    )
    r = insecure_client.post(
        "/login", json={"email": "u2@mirage.local", "password": "wrong-pass"}
    )
    assert r.status_code == 401


def test_protected_requires_token(insecure_client):
    r = insecure_client.get("/profile")
    assert r.status_code == 401


def test_oauth_stub(insecure_client):
    r = insecure_client.get("/oauth/google/callback", params={"code": "fake-code"})
    assert r.status_code == 200
    assert r.json()["via"] == "google-oauth-stub"
    assert r.json()["token"]


def test_healthz(secure_client):
    r = secure_client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["secure"] is True


def test_chat_basic(insecure_client):
    tok = insecure_client.post(
        "/register", json={"email": "chat@mirage.local", "password": "pw123456"}
    ).json()["token"]
    r = insecure_client.post(
        "/chat",
        json={"message": "hello"},
        headers={"Authorization": "Bearer " + tok},
    )
    assert r.status_code == 200
    assert "reply" in r.json()
