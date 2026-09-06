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
os.environ.setdefault("LLM_PROVIDER", "mock")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "1000")
# Trained model saved by scripts/ml_training/train.py
_model = Path(__file__).resolve().parents[1] / "app" / "ml" / "models" / "lr_scam_model.joblib"
if _model.exists():
    os.environ.setdefault("ML_MODEL_PATH", str(_model))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
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
