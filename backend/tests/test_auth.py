"""Authentication: registration, login, tokens, and the password policy.

These pin the security-relevant contracts:
* a password is never stored or returned in the clear;
* unknown-email and wrong-password logins are indistinguishable (no user
  enumeration);
* every rejection path is a clean ``401``/``409``/``422``, never a 500;
* a token is required for the data endpoints and a *stale* token (bumped
  ``token_version``, bad signature, or expired) is refused.
"""
from __future__ import annotations

import asyncio
import time

import jwt
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.database import SessionLocal
from app.models import User
from tests.conftest import DEFAULT_EMAIL, DEFAULT_PASSWORD, auth_headers, register_user


def _user_by_email(email: str) -> User:
    async def _query() -> User:
        async with SessionLocal() as session:
            return (await session.execute(select(User).where(User.email == email))).scalar_one()

    return asyncio.run(_query())


def _set_token_version(email: str, version: int) -> None:
    async def _update() -> None:
        async with SessionLocal() as session:
            user = (await session.execute(select(User).where(User.email == email))).scalar_one()
            user.token_version = version
            await session.commit()

    asyncio.run(_update())


# --- registration -----------------------------------------------------------


def test_register_returns_token_and_never_the_password(anon_client):
    resp = anon_client.post(
        "/api/auth/register",
        json={"email": "new.user@example.com", "password": "a-strong-passphrase"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["user"]["email"] == "new.user@example.com"
    assert body["expires_in"] > 0
    # The hash is never serialised, and the plaintext never appears anywhere.
    assert "password" not in body["user"]
    assert "a-strong-passphrase" not in resp.text


def test_password_is_stored_hashed(anon_client):
    anon_client.post(
        "/api/auth/register",
        json={"email": "hash.check@example.com", "password": "another-strong-passphrase"},
    )
    user = _user_by_email("hash.check@example.com")
    assert user.password_hash != "another-strong-passphrase"
    assert user.password_hash.startswith("$2")  # bcrypt marker


def test_duplicate_email_is_rejected(anon_client):
    payload = {"email": "dupe@example.com", "password": "a-strong-passphrase"}
    assert anon_client.post("/api/auth/register", json=payload).status_code == 201
    again = anon_client.post("/api/auth/register", json=payload)
    assert again.status_code == 409


@pytest.mark.parametrize("password", ["short", "1234567"])
def test_short_password_is_rejected(anon_client, password):
    resp = anon_client.post(
        "/api/auth/register", json={"email": "weak@example.com", "password": password}
    )
    assert resp.status_code == 422


def test_overlong_password_is_rejected(anon_client):
    """bcrypt hashes at most 72 bytes; we refuse rather than truncate silently."""
    resp = anon_client.post(
        "/api/auth/register", json={"email": "long@example.com", "password": "x" * 73}
    )
    assert resp.status_code == 422


def test_invalid_email_is_rejected(anon_client):
    resp = anon_client.post(
        "/api/auth/register", json={"email": "not-an-email", "password": "a-strong-passphrase"}
    )
    assert resp.status_code == 422


# --- login ------------------------------------------------------------------


def test_login_succeeds_with_correct_credentials(anon_client):
    anon_client.post(
        "/api/auth/register",
        json={"email": "login.ok@example.com", "password": "a-strong-passphrase"},
    )
    resp = anon_client.post(
        "/api/auth/login",
        json={"email": "login.ok@example.com", "password": "a-strong-passphrase"},
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_wrong_password_and_unknown_email_are_indistinguishable(anon_client):
    anon_client.post(
        "/api/auth/register",
        json={"email": "enum@example.com", "password": "a-strong-passphrase"},
    )
    wrong = anon_client.post(
        "/api/auth/login",
        json={"email": "enum@example.com", "password": "wrong-passphrase"},
    )
    unknown = anon_client.post(
        "/api/auth/login",
        json={"email": "nobody@example.com", "password": "wrong-passphrase"},
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]


# --- current user -----------------------------------------------------------


def test_me_requires_a_token(anon_client):
    assert anon_client.get("/api/auth/me").status_code == 401


def test_me_returns_the_authenticated_user(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.json()["email"] == DEFAULT_EMAIL


def test_malformed_and_foreignly_signed_tokens_are_rejected(anon_client):
    assert (
        anon_client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.jwt"}).status_code
        == 401
    )
    foreign = jwt.encode({"sub": "x", "ver": 0}, "a-different-key", algorithm="HS256")
    assert (
        anon_client.get("/api/auth/me", headers=auth_headers(foreign)).status_code == 401
    )
    assert anon_client.get("/api/auth/me", headers={"Authorization": "Bearer"}).status_code == 401


def test_expired_token_is_rejected(anon_client, client):
    user_id = client.get("/api/auth/me").json()["id"]
    settings = get_settings()
    expired = jwt.encode(
        {
            "sub": user_id,
            "ver": 0,
            "iat": int(time.time()) - 1000,
            "exp": int(time.time()) - 10,
        },
        settings.auth_secret_key,
        algorithm=settings.auth_algorithm,
    )
    assert anon_client.get("/api/auth/me", headers=auth_headers(expired)).status_code == 401


def test_token_version_bump_invalidates_old_tokens(anon_client):
    """Server-side invalidation: bumping ``token_version`` kills old tokens."""
    token = register_user(anon_client, "bump@example.com")
    assert anon_client.get("/api/auth/me", headers=auth_headers(token)).status_code == 200

    _set_token_version("bump@example.com", 1)
    assert anon_client.get("/api/auth/me", headers=auth_headers(token)).status_code == 401

    # A fresh login mints a token carrying the new version and works again.
    fresh = anon_client.post(
        "/api/auth/login",
        json={"email": "bump@example.com", "password": DEFAULT_PASSWORD},
    ).json()["access_token"]
    assert anon_client.get("/api/auth/me", headers=auth_headers(fresh)).status_code == 200


# --- logout + protected surface --------------------------------------------


def test_logout_is_acknowledged(client):
    assert client.post("/api/auth/logout").status_code == 204


def test_public_endpoints_need_no_token(anon_client):
    assert anon_client.get("/api/health").status_code == 200
    assert anon_client.get("/").status_code == 200
    assert anon_client.get("/api/demo").status_code == 200


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/investigations"),
        ("post", "/api/demo/some-case"),
        ("get", "/api/investigations/anything"),
    ],
)
def test_protected_endpoints_reject_anonymous_access(anon_client, method, path):
    resp = getattr(anon_client, method)(path)
    assert resp.status_code == 401


def test_analyze_endpoints_require_a_token(anon_client):
    assert anon_client.post("/api/analyze/text", json={"text": "hello"}).status_code == 401
    assert anon_client.post("/api/analyze/url", data={"url": "http://example.com"}).status_code == 401
