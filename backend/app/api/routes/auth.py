"""Authentication endpoints: register, login, current user, logout.

These are the only endpoints (besides health) reachable without a token.  Every
investigation endpoint requires a bearer token — see
``docs/API.md`` for the public/protected split.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import (
    PasswordPolicyError,
    create_access_token,
    get_current_user,
    hash_password,
    normalize_email,
    validate_password,
    verify_password,
)
from app.core.config import get_settings
from app.core.rate_limit import rate_limit
from app.database import get_db
from app.models import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserPublic

logger = logging.getLogger("scaminvestigator.auth")

# Rate-limited because both routes are brute-force / enumeration surfaces.
router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(rate_limit())])


def _token_response(user: User) -> TokenResponse:
    settings = get_settings()
    return TokenResponse(
        access_token=create_access_token(user.id, token_version=user.token_version or 0),
        expires_in=settings.auth_token_expire_minutes * 60,
        user=UserPublic(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            created_at=user.created_at,
        ),
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Create an account and return an access token.

    Email uniqueness is enforced both here (for a clean 409) and by the unique
    index (for correctness under a race).
    """
    email = normalize_email(str(payload.email))
    try:
        validate_password(payload.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="An account with that email already exists.")

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        display_name=(payload.display_name or None),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("registered user %s", user.id)
    return _token_response(user)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Exchange email + password for an access token.

    The failure message is identical whether the email is unknown or the
    password is wrong, so the endpoint cannot be used to enumerate accounts.
    """
    email = normalize_email(str(payload.email))
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    return _token_response(user)


@router.get("/me", response_model=UserPublic)
async def me(current_user: User = Depends(get_current_user)) -> UserPublic:
    """Return the authenticated account."""
    return UserPublic(
        id=current_user.id,
        email=current_user.email,
        display_name=current_user.display_name,
        created_at=current_user.created_at,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(current_user: User = Depends(get_current_user)) -> None:
    """Acknowledge logout.

    Tokens are stateless, so there is nothing for the server to delete: the
    client discards its token.  Server-side invalidation is available by
    bumping ``User.token_version`` (e.g. on a password change), which makes
    every outstanding token fail validation.  This endpoint exists so the
    client has a single, explicit place to call and so the behaviour is
    documented rather than implied.
    """
    return None
