"""Throwaway smoke test — runs the full API pipeline against a temp SQLite DB.

Usage:  .venv/Scripts/python.exe smoke_test.py
"""
import os
import sys
import tempfile
from pathlib import Path

# allow `import app.*` regardless of the invocation directory
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

tmpdir = tempfile.mkdtemp(prefix="scaminv_smoke_")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{tmpdir}/smoke.db"
os.environ["ML_MODEL_PATH"] = str(BACKEND_DIR / "app" / "ml" / "models" / "lr_scam_model.joblib")
os.environ.setdefault("AUTH_SECRET_KEY", "smoke-test-signing-key-32-bytes-minimum")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def _authenticate(client) -> None:
    """Register a throwaway user; the data endpoints require a bearer token."""
    import uuid

    resp = client.post(
        "/api/auth/register",
        json={
            "email": f"smoke-{uuid.uuid4().hex[:8]}@example.com",
            "password": "smoke-test-passphrase",
        },
    )
    if resp.status_code != 201:
        raise SystemExit(f"smoke test could not authenticate: {resp.status_code} {resp.text[:300]}")
    client.headers["Authorization"] = f"Bearer {resp.json()['access_token']}"


def main() -> None:
    with TestClient(app) as client:
        # health
        r = client.get("/api/health")
        print("health:", r.status_code, r.json().get("status"))

        _authenticate(client)

        # demo cases (no paid APIs)
        demos = client.get("/api/demo").json()["cases"]
        print("demo cases:", [d["slug"] for d in demos])

        failed = []
        ok = 0
        for d in demos:
            resp = client.post(f"/api/demo/{d['slug']}")
            if resp.status_code >= 400:
                print(f"  run {d['slug']} FAILED: {resp.status_code} {resp.text[:300]}")
                failed.append(d["slug"])
                continue
            inv = resp.json()
            ok += 1
            print(f"  {d['slug']}: {inv['status']} risk={inv.get('risk', {}).get('level')} "
                  f"score={inv.get('risk', {}).get('score')}")
            last_id = inv["investigation_id"]

        # custom text+url submission
        resp = client.post(
            "/api/investigations",
            data={
                "text": "Your PayPal account is suspended! Verify now at http://paypa1-secure-verify.xyz/login "
                        "or your funds will be frozen within 24h. Enter your password and OTP.",
                "title": "Custom phishing",
            },
        )
        inv = resp.json()
        ok += 1
        print("custom:", resp.status_code, "status=", inv["status"], "risk=", inv.get("risk", {}).get("level"),
              inv.get("risk", {}).get("score"))

        # details + history
        r = client.get(f"/api/investigations/{last_id}")
        print("details:", r.status_code, "timeline stages:", [t["stage"] for t in r.json().get("timeline", [])])
        r = client.get("/api/investigations")
        body = r.json()
        print("history count:", len(body.get("items", [])), "total:", body.get("total"))
        r = client.get("/api/investigations?risk_level=HIGH")
        print("filter HIGH:", r.json().get("total"))
        r = client.delete(f"/api/investigations/{last_id}")
        print("delete:", r.status_code)
        if r.status_code != 204:
            failed.append("delete")
        print("OK:", ok, "FAILED:", failed if failed else "none")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
