"""Trained scam classifier with honest fallback.

The model is a scikit-learn pipeline (StandardScaler + LogisticRegression)
trained by ``ml/training/train.py``.  When no trained model is available
the classifier reports ``is_mock=True`` and returns a calibrated
heuristic probability instead of pretending a model exists.
"""
from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np

from app.core.config import get_settings
from app.ml.features import FEATURE_NAMES, feature_vector
from app.schemas.analysis import MLPrediction

logger = logging.getLogger("scaminvestigator.ml")


class ScamClassifier:
    """Thin wrapper around a persisted sklearn pipeline."""

    def __init__(self, model_path: Path | None = None):
        self.model_path = model_path or get_settings().ml_model_path
        self._pipeline = None
        self._load_error: str | None = None
        self._load()

    def _load(self) -> None:
        if not self.model_path.exists():
            self._load_error = f"model file not found: {self.model_path}"
            logger.warning(self._load_error)
            return
        try:
            self._pipeline = joblib.load(self.model_path)
            if not hasattr(self._pipeline, "predict_proba"):
                raise ValueError("persisted object is not a classifier pipeline")
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"failed to load model: {exc}"
            logger.exception(self._load_error)

    @property
    def available(self) -> bool:
        return self._pipeline is not None

    @property
    def model_name(self) -> str:
        if not self.available:
            return "none"
        return type(self._pipeline.named_steps.get("clf")).__name__

    def predict(self, features: dict[str, float]) -> MLPrediction:
        """Return the ML prediction for a feature dict."""
        vec = np.array([feature_vector(features)], dtype=float)
        if not self.available:
            proba = self._heuristic_proba(features)
            return MLPrediction(
                probability_scam=round(proba, 4),
                label="scam" if proba >= get_settings().ml_decision_threshold else "benign",
                features=features,
                model="none",
                is_mock=True,
                feature_importance={},
            )
        try:
            proba = float(self._pipeline.predict_proba(vec)[0][1])
        except Exception as exc:  # noqa: BLE001
            logger.exception("ML inference failed")
            proba = self._heuristic_proba(features)
            return MLPrediction(
                probability_scam=round(proba, 4),
                label="scam" if proba >= get_settings().ml_decision_threshold else "benign",
                features=features,
                model=self.model_name,
                is_mock=True,
                feature_importance={},
            )
        threshold = get_settings().ml_decision_threshold
        return MLPrediction(
            probability_scam=round(proba, 4),
            label="scam" if proba >= threshold else "benign",
            features=features,
            model=self.model_name,
            is_mock=False,
            feature_importance=self._importance(),
        )

    def _importance(self) -> dict[str, float]:
        if not self.available:
            return {}
        try:
            coefs = self._pipeline.named_steps["clf"].coef_[0]
            return {name: round(float(abs(c)), 4) for name, c in zip(FEATURE_NAMES, coefs)}
        except Exception:  # noqa: BLE001
            return {}

    @staticmethod
    def _heuristic_proba(features: dict[str, float]) -> float:
        """Calibrated fallback probability when no model is loaded.

        Based on a small subset of high-precision features; explicitly
        marked as mock so it is never mistaken for a trained model.
        """
        score = 0.0
        score += 0.22 * features.get("scam_keyword_hits", 0.0) * 0.33
        score += 0.20 * features.get("payment_request", 0.0)
        score += 0.20 * features.get("credential_request", 0.0)
        score += 0.15 * features.get("otp_request", 0.0)
        score += 0.15 * features.get("suspicious_tld_count", 0.0)
        score += 0.12 * features.get("ip_url_count", 0.0)
        score += 0.12 * features.get("shortener_count", 0.0)
        score += 0.10 * features.get("sensitive_info_request", 0.0)
        score += 0.08 * features.get("fear_threat_score", 0.0)
        score += 0.05 * features.get("urgency_score", 0.0)
        score += 0.05 * features.get("reward_score", 0.0)
        score += 0.05 * features.get("pressure_score", 0.0)
        score += 0.04 * features.get("authority_score", 0.0)
        return max(0.0, min(1.0, score))