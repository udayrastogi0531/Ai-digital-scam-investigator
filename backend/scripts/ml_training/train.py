"""Train + evaluate the scam classifier.

Usage (from ``backend/``):::

    .venv/Scripts/python.exe scripts/ml_training/generate_dataset.py
    .venv/Scripts/python.exe scripts/ml_training/train.py
    # train on your own vetted dataset instead:
    .venv/Scripts/python.exe scripts/ml_training/train.py --dataset data/datasets/real/my_vetted_set.csv

Pipeline: StandardScaler -> LogisticRegression on the same features the
live backend extracts (``app.ml.features``).  The fitted pipeline is saved
to the path ``ML_MODEL_PATH`` (default ``app/ml/models/lr_scam_model.joblib``)
and an honest evaluation report is written next to the dataset.

Data honesty (see ``app/ml/dataset.py`` for the enforced rules):

* the dataset goes through the validated loader (required fields, valid
  labels/categories, duplicates, malformed rows) and a stratified
  train / validation / test split;
* the evaluation corpus (``data/evaluation/``) is refused as training data;
* metrics printed here are for the *dataset you trained on*.  For the
  bundled default dataset those are SYNTHETIC-only numbers and are
  indicative, not production evidence.  Retrain on a real, vetted corpus
  before relying on the model operationally.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]  # backend/
sys.path.insert(0, str(ROOT))  # allow `import app.*`

from app.core.config import get_settings  # noqa: E402
from app.ml.dataset import DatasetValidationError, load_dataset, stratified_split  # noqa: E402
from app.ml.features import FEATURE_NAMES, extract_features, feature_vector  # noqa: E402

logging.basicConfig(level=logging.WARNING)

DEFAULT_DATASET = ROOT / "data" / "datasets" / "scam_messages.csv"
REPORT = ROOT / "data" / "datasets" / "evaluation_report.json"
SEED = 42


def _features_and_labels(rows: list[dict]) -> tuple[list[list[float]], list[int]]:
    X = [feature_vector(extract_features(r["text"])) for r in rows]
    y = [1 if r["label"] == "scam" else 0 for r in rows]
    return X, y


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="validated CSV/JSON/JSONL dataset (default: synthetic demo dataset)",
    )
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        help="train on repeated rows too (their frequency is part of the distribution). "
        "The synthetic generator's template draws repeat; the Phase-2 model used them.",
    )
    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"dataset not found: {args.dataset}\nrun generate_dataset.py first (or point --dataset at a real file)")
        return 1

    try:
        rows, stats = load_dataset(args.dataset, deduplicate=not args.keep_duplicates)
    except DatasetValidationError as exc:
        print(f"dataset rejected: {exc}")
        return 1

    print(stats.summary())
    if stats.errors:
        print(f"NOTE: {len(stats.errors)} validation error(s) — rows were rejected:")
        for err in stats.errors[:10]:
            print(f"  - {err}")
    if stats.origin == "synthetic":
        print("WARNING: this is the SYNTHETIC demo dataset. Metrics below are indicative only "
              "and are NOT evidence of real-world performance.")
    else:
        print("NOTE: training on an external dataset. Confirm it is vetted, labelled and "
              "permissioned before relying on the resulting model.")

    try:
        train_rows, val_rows, test_rows = stratified_split(
            rows, test_size=args.test_size, val_size=args.val_size, seed=args.seed
        )
    except DatasetValidationError as exc:
        print(f"split failed: {exc}")
        return 1

    X_train, y_train = _features_and_labels(train_rows)
    X_val, y_val = _features_and_labels(val_rows)
    X_test, y_test = _features_and_labels(test_rows)

    print(
        f"split (stratified by label, seed={args.seed}): "
        f"train={len(X_train)} val={len(X_val)} test={len(X_test)}"
    )
    print(f"train label distribution: {Counter(y_train)}  (1=scam, 0=benign)")
    print(f"val   label distribution: {Counter(y_val)}")
    print(f"test  label distribution: {Counter(y_test)}")

    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(max_iter=2000, C=0.8, class_weight="balanced"),
            ),
        ]
    )
    pipeline.fit(X_train, y_train)

    proba_test = pipeline.predict_proba(X_test)[:, 1]
    pred_test = pipeline.predict(X_test)
    metrics = {
        "dataset": str(args.dataset),
        "dataset_origin": stats.origin,
        "n_samples": len(rows),
        "n_train": len(X_train),
        "n_val": len(X_val),
        "n_test": len(X_test),
        "class_distribution": {"scam": stats.label_counts.get("scam", 0), "benign": stats.label_counts.get("benign", 0)},
        "accuracy": round(accuracy_score(y_test, pred_test), 4),
        "precision": round(precision_score(y_test, pred_test), 4),
        "recall": round(recall_score(y_test, pred_test), 4),
        "f1": round(f1_score(y_test, pred_test), 4),
        "roc_auc": round(roc_auc_score(y_test, proba_test), 4),
        "confusion_matrix": confusion_matrix(y_test, pred_test).tolist(),
        "model": "StandardScaler+LogisticRegression",
        "honesty_note": (
            "metrics measured on a held-out split of the dataset named above. For the bundled "
            "synthetic dataset they are NOT production evidence — retrain on vetted real data."
            if stats.origin == "synthetic"
            else "metrics measured on the external dataset named above."
        ),
    }
    print(json.dumps(metrics, indent=2))

    model_path = get_settings().ml_model_path
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)
    print(f"saved model -> {model_path}")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"saved evaluation report -> {REPORT}")

    # top contributing features (by |coefficient|)
    coefs = pipeline.named_steps["clf"].coef_[0]
    ranked = sorted(zip(FEATURE_NAMES, coefs), key=lambda kv: abs(kv[1]), reverse=True)
    print("top features:", [(name, round(c, 3)) for name, c in ranked[:12]])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
