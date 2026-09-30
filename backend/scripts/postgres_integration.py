"""PostgreSQL end-to-end integration check.

This is the *only* place PostgreSQL is exercised, and it is opt-in: it runs
migrations against a real server and then drives the full application
(registration → investigation → history → cross-user isolation → delete)
through the ASGI app, exactly as a deployment would.

Usage (from ``backend/``)::

    DATABASE_URL='postgresql+asyncpg://user:pass@localhost:5432/scaminv_test' \
        python -m scripts.postgres_integration

Exit code 0 means every step passed.  Any failure prints the step and exits
non-zero.  Emails are unique per run, so the script is re-runnable against the
same database.

NOTE: this cannot run without a reachable PostgreSQL server.  When none is
available the suite reports PostgreSQL as **unverified** — never as passing.
"""
from __future__ import annotations

import os
import subprocess
import sys
import uuid


def _fail(step: str, detail: object = "") -> int:
    print(f"FAILED: {step} {detail}")
    return 1


def _run_migrations() -> int:
    """Apply Alembic migrations using the same DATABASE_URL the app will use."""
    print("== alembic upgrade head ==")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=dict(os.environ),
    )
    return proc.returncode


def main() -> int:
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith("postgresql"):
        print("DATABASE_URL must be a postgresql+asyncpg:// URL; refusing to run.")
        return 2

    rc = _run_migrations()
    if rc != 0:
        return _fail("migrations")

    # Import the app only after the environment is final: the engine is built
    # from DATABASE_URL at import time.
    from fastapi.testclient import TestClient

    from app.main import app

    tag = uuid.uuid4().hex[:8]
    email_a = f"pg.a.{tag}@example.com"
    email_b = f"pg.b.{tag}@example.com"
    password = "postgres-integration-passphrase"

    with TestClient(app) as client:
        health = client.get("/api/health").json()
        if health.get("database") != "postgresql":
            return _fail("health reports database", health.get("database"))
        print("health.database =", health["database"])

        a = client.post("/api/auth/register", json={"email": email_a, "password": password})
        if a.status_code != 201:
            return _fail("register user A", a.text)
        ha = {"Authorization": f"Bearer {a.json()['access_token']}"}

        b = client.post("/api/auth/register", json={"email": email_b, "password": password})
        if b.status_code != 201:
            return _fail("register user B", b.text)
        hb = {"Authorization": f"Bearer {b.json()['access_token']}"}

        created = client.post(
            "/api/investigations",
            data={"text": "URGENT: verify your account within 24 hours at http://bank-secure.example/login"},
            headers=ha,
        )
        if created.status_code != 200:
            return _fail("create investigation", created.text)
        inv_id = created.json()["investigation_id"]
        if created.json()["status"] != "completed":
            return _fail("investigation status", created.json()["status"])
        print("investigation completed:", inv_id)

        listed = client.get("/api/investigations", headers=ha).json()
        if inv_id not in [i["id"] for i in listed["items"]]:
            return _fail("history does not include the new investigation")

        # Filter by scam type — exercises the PostgreSQL JSON ``.astext`` path.
        filtered = client.get("/api/investigations", params={"scam_type": "banking_scam"}, headers=ha)
        if filtered.status_code != 200:
            return _fail("scam_type filter on PostgreSQL", filtered.text)

        if client.get(f"/api/investigations/{inv_id}", headers=hb).status_code != 404:
            return _fail("user B could read user A's investigation")
        if client.delete(f"/api/investigations/{inv_id}", headers=hb).status_code != 404:
            return _fail("user B could delete user A's investigation")

        if client.delete(f"/api/investigations/{inv_id}", headers=ha).status_code != 204:
            return _fail("owner could not delete own investigation")

    print("POSTGRES INTEGRATION OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
