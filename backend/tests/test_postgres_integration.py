"""Opt-in PostgreSQL integration suite.

The default test run never touches PostgreSQL: it needs a real server, and the
project must stay runnable with the zero-setup SQLite fallback.  Enable it with
an explicit database URL::

    RUN_POSTGRES_TESTS=1 \
    POSTGRES_TEST_DATABASE_URL='postgresql+asyncpg://user:pass@localhost:5432/scaminv_test' \
        pytest tests/test_postgres_integration.py -q

The heavy lifting lives in ``scripts/postgres_integration.py`` so the exact
same check can be run bare from the command line and from CI.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_POSTGRES_TESTS") != "1",
    reason="PostgreSQL integration tests are opt-in (set RUN_POSTGRES_TESTS=1 and POSTGRES_TEST_DATABASE_URL).",
)


def test_postgres_end_to_end():
    url = os.environ.get("POSTGRES_TEST_DATABASE_URL")
    if not url:
        pytest.skip("POSTGRES_TEST_DATABASE_URL is not set")

    env = {**os.environ, "DATABASE_URL": url}
    proc = subprocess.run(
        [sys.executable, "-m", "scripts.postgres_integration"],
        cwd=str(BACKEND_DIR),
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
    assert "POSTGRES INTEGRATION OK" in proc.stdout
