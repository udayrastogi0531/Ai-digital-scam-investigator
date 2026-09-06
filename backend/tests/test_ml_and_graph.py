"""Tests: ML feature extraction and the LangGraph workflow (no HTTP)."""
from __future__ import annotations

import asyncio

import pytest

from app.graph import run_investigation
from app.ml.features import FEATURE_NAMES, extract_features, feature_vector
from app.ml.service import predict_scam
from app.schemas.evidence import InputPayload
from app.services.investigation_service import prepare_state
from tests.conftest import BANKING_PHISH, BENIGN_NOTE


def test_feature_vector_ordered_and_complete():
    features = extract_features(
        "URGENT verify http://paypal-secure.xyz/login now, send OTP",
    )
    assert set(features) == set(FEATURE_NAMES)
    vec = feature_vector(features)
    assert len(vec) == len(FEATURE_NAMES)
    assert features["url_count"] == 1.0
    assert features["otp_request"] == 1.0
    assert 0.0 <= features["uppercase_ratio"] <= 1.0


def test_ml_prediction_uses_trained_model():
    p = predict_scam(BANKING_PHISH)
    assert p.is_mock is False
    assert p.model == "LogisticRegression"
    assert p.label == "scam"
    assert p.probability_scam > 0.5

    q = predict_scam(BENIGN_NOTE)
    assert q.label == "benign"
    assert q.probability_scam < 0.5


@pytest.mark.asyncio
async def test_graph_runs_full_pipeline():
    payload = InputPayload(text=BANKING_PHISH, title="graph test")
    state = prepare_state("graph-1", payload)
    result = await run_investigation(state)

    assert result["status"] == "completed"
    assert result["risk"] is not None
    assert result["report"] is not None
    assert result["explanation"] is not None
    assert result["classification"] is not None

    stages = {t["stage"] for t in result["timeline"]}
    expected = {"parse", "analyze", "ml", "correlate", "risk", "explain", "report"}
    assert expected <= stages
    # URL-bearing text triggers the URL branch + threat-intel lookup
    assert {"url_analysis", "threat_intel"} <= stages
    # entity mention (PayPal-ish/bank) may trigger brand analysis
    # — not asserted; conditional.

    evidence = result["evidence"]
    sources = {e.source for e in evidence}
    assert "ml_classifier" in sources
    assert "scam_pattern" in sources


@pytest.mark.asyncio
async def test_graph_benign_short_circuit():
    payload = InputPayload(text=BENIGN_NOTE)
    state = prepare_state("graph-2", payload)
    result = await run_investigation(state)
    assert result["status"] == "completed"
    assert result["risk"].level == "LOW"
    # no URL branch executed
    stages = {t["stage"] for t in result["timeline"]}
    assert "url_analysis" not in stages
