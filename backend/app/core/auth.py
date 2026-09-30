"""Authentication primitives: password hashing, tokens, current-user dependency.

Design choices (kept deliberately small and standard — no home-grown crypto):

* **Passwords** are hashed with bcrypt (the ``bcrypt`` library).  The plaintext
  is never stored, never logged, and never returned.  bcrypt only consumes the
  first 72 bytes, so longer inputs are rejected at the schema boundary rather
  than silently truncated.
* **Tokens** are signed JWTs (``HS256``, the ``PyJWT`` library).  They are
  stateless: the server holds no session table.  ``token_version`` on the user
  row provides server-side invalidation — bumping it (e.g. on a password
  change) makes every previously issued token fail the ``ver`` check.  A
  client-side "logout" simply discards the token; see ``docs/SECURITY.md``.
* The signing key comes from the environment (``AUTH_SECRET_KEY``); the
  development default is flagged loudly at startup.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database import get_db
from app.models import User

# auto_error=False so a missing header surfaces as our own 401 JSON body
# rather than Starlette's default, keeping the API contract uniform.
_bearer = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


class PasswordPolicyError(ValueError):
    """Raised when a password does not meet the policy."""


def validate_password(password: str) -> None:
    """Enforce the password policy. Raises :class:`PasswordPolicyError`."""
    settings = get_settings()
    if len(password) < settings.auth_password_min_length:
        raise PasswordPolicyError(
            f"Password must be at least {settings.auth_password_min_length} characters."
        )
    if len(password.encode("utf-8")) > settings.auth_password_max_bytes:
        # bcrypt hashes at most 72 bytes; refuse rather than truncate silently.
        raise PasswordPolicyError("Password is too long (max 72 bytes).")


def hash_password(password: str) -> str:
    """Return a salted bcrypt hash suitable for storage."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time comparison of a candidate password against a stored hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        # Malformed stored hash: treat as a failed login, never as a crash.
        return False


def create_access_token(subject: str, token_version: int = 0) -> str:
    """Sign a short-lived access token for ``subject`` (the user id)."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "ver": token_version,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.auth_token_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.auth_secret_key, algorithm=settings.auth_algorithm)


def decode_access_token(token: str) -> dict:
    """Decode and verify a token, raising the uniform 401 on any problem."""
    settings = get_settings()
    try:
        return jwt.decode(token, settings.auth_secret_key, algorithms=[settings.auth_algorithm])
    except jwt.PyJWTError as exc:  # expired, bad signature, malformed, …
        raise _UNAUTHORIZED from exc


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency: resolve the authenticated :class:`User` or raise 401.

    Every protected route depends on this.  The token is validated
    cryptographically, then the subject is loaded from the database and its
    ``token_version`` is compared with the token's ``ver`` claim so a bumped
    version (password change) invalidates old tokens.
    """
    if credentials is None or not credentials.credentials:
        raise _UNAUTHORIZED

    payload = decode_access_token(credentials.credentials)
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise _UNAUTHORIZED

    user = await db.get(User, subject)
    if user is None:
        raise _UNAUTHORIZED

    if int(payload.get("ver", 0)) != int(user.token_version or 0):
        raise _UNAUTHORIZED

    return user


def normalize_email(email: str) -> str:
    """Canonicalise an email for storage and lookup (trim + lowercase)."""
    return email.strip().lower()
