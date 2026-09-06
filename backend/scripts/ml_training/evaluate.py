"""Evaluate a saved classifier against a labelled dataset.

Usage (from ``backend/``):::

    .venv/Scripts/python.exe scripts/ml_training/evaluate.py --dataset path/to/labelled.csv

Reuses the exact feature extraction + model the live backend loads, so the
reported numbers reflect production inference.  The dataset goes through the
validated loader (``app/ml/dataset.py``); scam-category checks are relaxed
for evaluation-only runs, but required fields, valid labels, duplicates and
malformed rows are still enforced.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.core.config import get_settings  # noqa: E402
from app.ml.dataset import DatasetValidationError, load_dataset  # noqa: E402
from app.ml.features import extract_features, feature_vector  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True, help="CSV/JSON/JSONL with text,label[,scam_category]")
    parser.add_argument("--model", type=Path, default=None, help="saved pipeline (default: ML_MODEL_PATH)")
    args = parser.parse_args()

    model_path = args.model or get_settings().ml_model_path
    if not model_path.exists():
        print(f"model not found: {model_path} (run scripts/ml_training/train.py first)")
        return 1

    try:
        rows, stats = load_dataset(args.dataset, require_categories=False)
    except DatasetValidationError as exc:
        print(f"dataset rejected: {exc}")
        return 1
    if stats.errors:
        print(f"NOTE: {len(stats.errors)} validation error(s); invalid rows were excluded")
    print(stats.summary())

    pipeline = joblib.load(model_path)
    X = [feature_vector(extract_features(r["text"])) for r in rows if r.get("text")]
    y = [1 if r["label"] == "scam" else 0 for r in rows if r.get("text")]
    if len(set(y)) < 2:
        print("dataset must contain both scam and benign rows for binary evaluation")
        return 1

    pred = pipeline.predict(X)
    proba = pipeline.predict_proba(X)[:, 1]
    print(f"evaluated {len(rows)} rows with {model_path}")
    print(f"accuracy : {accuracy_score(y, pred):.4f}")
    print(f"precision: {precision_score(y, pred):.4f}")
    print(f"recall   : {recall_score(y, pred):.4f}")
    print(f"f1       : {f1_score(y, pred):.4f}")
    print(f"roc_auc  : {roc_auc_score(y, proba):.4f}")
    print("confusion matrix (TN, FP / FN, TP):")
    print(confusion_matrix(y, pred).tolist())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
