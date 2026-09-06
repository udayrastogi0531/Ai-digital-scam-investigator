"""ML inference entry point used by the graph."""
from __future__ import annotations

from functools import lru_cache

from app.ml.classifier import ScamClassifier
from app.ml.features import extract_features
from app.schemas.analysis import MLPrediction


@lru_cache(maxsize=1)
def get_classifier() -> ScamClassifier:
    return ScamClassifier()


def predict_scam(
    text: str,
    *,
    entities=None,
    text_signals=None,
    url_analyses=None,
) -> MLPrediction:
    """Extract features and run the classifier in one call."""
    features = extract_features(
        text, entities=entities, text_signals=text_signals, url_analyses=url_analyses
    )
    return get_classifier().predict(features)