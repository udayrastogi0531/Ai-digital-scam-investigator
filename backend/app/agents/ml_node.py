"""ML node: run the scam classifier on extracted features."""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.graph.state import InvestigationState
from app.ml import predict_scam
from app.schemas.evidence import EvidenceSignal


@timed_node("ml")
def ml_node(state: InvestigationState) -> InvestigationState:
    text = state.get("normalized_text", "")
    entities = state.get("entities")
    text_signals = state.get("text_signals")
    urls = state.get("urls")

    prediction = predict_scam(
        text,
        entities=entities,
        text_signals=text_signals,
        url_analyses=urls,
    )

    severity = "medium" if prediction.probability_scam >= 0.5 else "info"
    mock_note = " [heuristic fallback, no trained model]" if prediction.is_mock else ""
    signals: list[EvidenceSignal] = [
        EvidenceSignal(
            source="ml_classifier",
            signal="ml_probability_high" if prediction.probability_scam >= 0.5 else "ml_probability_low",
            severity=severity,
            confidence=min(0.9, 0.4 + prediction.probability_scam),
            description=(
                f"Machine-learning model{mock_note} estimates {prediction.probability_scam * 100:.0f}% "
                f"probability of scam-related content (label: {prediction.label}, model: {prediction.model})."
            ),
            detail={
                "probability": prediction.probability_scam,
                "label": prediction.label,
                "model": prediction.model,
                "is_mock": prediction.is_mock,
            },
        )
    ]

    return state_update(state, ml_prediction=prediction, evidence=signals)