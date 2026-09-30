"""Pytest fixtures.

Environment must be configured BEFORE ``app`` is imported anywhere, because
the engine/settings are created at import time.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="scaminv_tests_")
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_TMP}/test.db")
os.environ.setdefault("OCR_PROVIDER", "mock")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "1000")
# Deterministic signing key so tokens minted in one test verify in another.
os.environ.setdefault("AUTH_SECRET_KEY", "test-only-signing-key-not-a-secret")

# The offline suite must stay hermetic: a developer's local ``backend/.env``
# (real provider keys, live LLM) must never turn `pytest` into a live-network
# test run or change the calibration assertions.  Environment variables take
# precedence over the ``.env`` file in pydantic-settings, so forcing them
# empty here pins every provider to its deterministic mock implementation.
# The opt-in live tests in ``test_threat_intel_live.py`` are exempt so their
# documented RUN_LIVE_*_TESTS=1 workflow keeps working with real keys.
_LIVE_OPT_IN = (
    os.environ.get("RUN_LIVE_INTEL_TESTS", "") == "1"
    or os.environ.get("RUN_LIVE_LLM_TESTS", "") == "1"
)
if not _LIVE_OPT_IN:
    os.environ["LLM_PROVIDER"] = "mock"
    os.environ["LLM_API_KEY"] = ""
    os.environ["GOOGLE_SAFE_BROWSING_API_KEY"] = ""
    os.environ["VIRUSTOTAL_API_KEY"] = ""
# Trained model saved by scripts/ml_training/train.py
_model = Path(__file__).resolve().parents[1] / "app" / "ml" / "models" / "lr_scam_model.joblib"
if _model.exists():
    os.environ.setdefault("ML_MODEL_PATH", str(_model))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


DEFAULT_PASSWORD = "correct-horse-battery-staple"
DEFAULT_EMAIL = "default@example.com"
SECOND_EMAIL = "second@example.com"


def register_user(tc, email: str, password: str = DEFAULT_PASSWORD) -> str:
    """Register a user through the API and return its access token."""
    resp = tc.post("/api/auth/register", json={"email": email, "password": password})
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def client():
    """A TestClient authenticated as the default user.

    The whole existing suite submits investigations through the API, and those
    endpoints now require a token.  Rather than thread a header through every
    call, the client carries an ``Authorization`` default header so the tests
    read exactly as before.  Authorization/isolation tests use ``anon_client``
    and ``second_client`` to act as a different, or no, user.
    """
    with TestClient(app) as c:
        token = register_user(c, DEFAULT_EMAIL)
        c.headers["Authorization"] = f"Bearer {token}"
        yield c


@pytest.fixture(scope="session")
def anon_client():
    """An unauthenticated TestClient (for 401 / public-endpoint tests)."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def second_client():
    """A TestClient authenticated as a *different* user (isolation tests)."""
    with TestClient(app) as c:
        token = register_user(c, SECOND_EMAIL)
        c.headers["Authorization"] = f"Bearer {token}"
        yield c


BANKING_PHISH = (
    "URGENT: Your account at National Trust Bank has been suspended due to unusual activity. "
    "Verify your identity within 24 hours or your account will be permanently closed. "
    "Click here to confirm now: http://nationaltrust-bank-secure.example/login "
    "Enter your password and the OTP code sent to your phone."
)

BENIGN_NOTE = (
    "Hi Sarah, just confirming our meeting tomorrow at 10am. "
    "The quarterly report is attached — please review before we chat. Thanks!"
)
