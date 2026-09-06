"""Integration tests: FastAPI endpoints end-to-end with a real graph run."""
from __future__ import annotations

from io import BytesIO

from PIL import Image

from tests.conftest import BANKING_PHISH, BENIGN_NOTE


def _png_bytes() -> bytes:
    buf = BytesIO()
    Image.new("RGB", (120, 60), color=(240, 240, 240)).save(buf, format="PNG")
    return buf.getvalue()


def test_health_reports_providers(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["providers"]["llm"]["is_mock"] is True
    assert body["providers"]["ml"]["available"] is True


def test_text_submission_high_risk(client):
    resp = client.post("/api/investigations", data={"text": BANKING_PHISH, "title": "phish test"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["risk"]["score"] >= 40
    assert body["risk"]["level"] in ("MEDIUM", "HIGH", "CRITICAL")
    # explanation + structured evidence exist
    assert body["evidence"]
    assert body["report"]["summary"]
    assert body["report"]["recommendations"]
    # timeline complete and free of duplicates
    stages = [t["stage"] for t in body["timeline"]]
    assert len(stages) == len(set(stages))
    assert "risk" in stages and "explain" in stages


def test_benign_text_low_risk(client):
    resp = client.post("/api/investigations", data={"text": BENIGN_NOTE})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["risk"]["score"] < 25
    assert body["risk"]["level"] == "LOW"


def test_json_analyze_text_endpoint(client):
    resp = client.post("/api/analyze/text", json={"text": BANKING_PHISH})
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


def test_explicit_url_submission(client):
    resp = client.post(
        "/api/analyze/url",
        data={"url": "http://secure-verify-account.example/login?u=99"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    url_entities = body["entities"]["urls"]
    assert url_entities


def test_image_upload_runs_with_mock_ocr(client):
    resp = client.post(
        "/api/analyze/image",
        files={"image": ("shot.png", _png_bytes(), "image/png")},
        data={"text": "help"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert any("OCR" in w or "Screenshot" in w for w in body["warnings"])


def test_investigation_history_and_filters(client):
    resp = client.get("/api/investigations", params={"page_size": 5})
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body and body["total"] >= 1
    # list items carry risk/scam summaries
    assert all("risk_level" in i for i in body["items"])

    resp = client.get("/api/investigations", params={"risk_level": "HIGH"})
    assert resp.status_code == 200


def test_detail_and_delete_roundtrip(client):
    created = client.post("/api/investigations", data={"text": BANKING_PHISH}).json()
    inv_id = created["investigation_id"]

    detail = client.get(f"/api/investigations/{inv_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["processing_metadata"]["stages"]["ml"]["status"] == "ok"
    assert body["risk"]["score"] >= 0
    assert body["report"]["summary"]
    assert body["analyses"]  # per-stage analysis rows
    # structured evidence rows are stored per signal, not a single blob
    assert all(isinstance(e, dict) and e.get("source") for e in body["evidence"])

    missing = client.get("/api/investigations/does-not-exist")
    assert missing.status_code == 404

    deleted = client.delete(f"/api/investigations/{inv_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/investigations/{inv_id}").status_code == 404


def test_empty_submission_rejected(client):
    resp = client.post("/api/investigations", data={"text": ""})
    assert resp.status_code == 422
