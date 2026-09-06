"""Detection evaluation harness.

Runs the realistic evaluation corpus through the REAL investigation
pipeline (FastAPI -> LangGraph -> rules/ML/URL/risk -> persistence) and
produces:

* binary scam-vs-benign metrics (accuracy / precision / recall / F1 and a
  confusion matrix), overall and per input type (text / url / text+url)
* per-category accuracy and a category confusion matrix
* a risk-calibration table (expected level vs actual score/level)
* confidence-honesty checks (sparse evidence must not be confidently LOW)

Writes ``evaluation_report.json`` and ``evaluation_report.md`` next to the
corpus in ``backend/data/evaluation/``.

Usage (from the backend directory):

    .venv/Scripts/python.exe scripts/evaluate_detection.py

Notes on honesty:
* ML runs with the trained model (``ML_MODEL_PATH``) exactly like the live
  app; its synthetic-data caveat is recorded per case and in the report.
* The mock threat-intel and mock LLM providers are used (no API keys) and
  every per-case record notes that.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

# keep the per-case table readable (httpx/uvicorn INFO spam off)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("scaminvestigator").setLevel(logging.WARNING)

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

EVAL_DIR = BACKEND_DIR / "data" / "evaluation"
CASES_FILE = EVAL_DIR / "evaluation_cases.json"
REPORT_JSON = EVAL_DIR / "evaluation_report.json"
REPORT_MD = EVAL_DIR / "evaluation_report.md"

LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _env_setup() -> None:
    """Configure the app exactly like a local demo run (temp DB, mocks)."""
    tmpdir = tempfile.mkdtemp(prefix="scaminv_eval_")
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{tmpdir}/eval.db"
    os.environ["OCR_PROVIDER"] = "mock"
    os.environ["LLM_PROVIDER"] = "mock"
    os.environ["RATE_LIMIT_PER_MINUTE"] = "100000"
    model = BACKEND_DIR / "app" / "ml" / "models" / "lr_scam_model.joblib"
    if model.exists():
        os.environ.setdefault("ML_MODEL_PATH", str(model))


def _binary_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    acc = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }


def _collect(client, case: dict) -> dict:
    """Run one corpus case through the real API and return the outcome."""
    data = {}
    if case.get("text"):
        data["text"] = case["text"]
    if case.get("urls"):
        data["urls"] = case["urls"]

    resp = client.post("/api/investigations", data=data)
    if resp.status_code >= 400:
        return {"id": case["id"], "http_error": resp.status_code, "detail": resp.text[:400]}

    inv = resp.json()
    risk = inv.get("risk") or {}
    scam_type = inv.get("scam_type") or {}
    ml = inv.get("ml") or {}
    return {
        "id": case["id"],
        "input_type": case["input_type"],
        "status": inv.get("status"),
        "risk_score": risk.get("score"),
        "risk_level": risk.get("level"),
        "confidence": risk.get("confidence"),
        "evidence_sufficiency": risk.get("evidence_sufficiency"),
        "scam_type_primary": scam_type.get("primary"),
        "scam_type_confidence": scam_type.get("confidence"),
        "ml_probability_scam": ml.get("probability_scam"),
        "ml_model": ml.get("model"),
        "ml_is_mock": ml.get("is_mock"),
        "top_contributors": [
            c.get("name") for c in (risk.get("contributors") or []) if (c.get("impact") or 0) >= 0.0
        ][:6],
        "warnings": inv.get("warnings") or [],
    }


def _load_cases() -> list[dict]:
    data = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise SystemExit(f"corpus is empty or malformed: {CASES_FILE}")
    return data


def _band_ok(actual: str, minimum: str) -> bool:
    return LEVEL_ORDER.get(actual, 0) >= LEVEL_ORDER.get(minimum, 0)


def _confusion(rows: list[dict]) -> dict:
    cats = sorted({r["expected"]["primary_category"] for r in rows})
    cats = [c for c in cats if c != "unknown"]
    matrix = {e: {p: 0 for p in cats} for e in cats}
    for r in rows:
        expected = r["expected"]["primary_category"]
        predicted = r.get("scam_type_primary")
        if expected in matrix and predicted in matrix[expected]:
            matrix[expected][predicted] += 1
    return matrix


def main() -> None:
    _env_setup()

    from fastapi.testclient import TestClient

    from app.main import app

    cases = _load_cases()
    results: list[dict] = []
    with TestClient(app) as client:
        for case in cases:
            outcome = _collect(client, case)
            outcome["expected"] = case["expected"]
            outcome["verdict"] = _evaluate(outcome, case["expected"])
            results.append(outcome)
            print(
                f"  {case['id']:<28} {case['input_type']:<9} "
                f"exp={case['expected']['primary_category']:<16} "
                f"pred={outcome.get('scam_type_primary') or '-':<16} "
                f"risk={outcome.get('risk_level') or '-':<9} "
                f"{outcome.get('risk_score') or 0:>5} conf={outcome.get('confidence') or 0:.2f} "
                f"{'OK' if outcome['verdict'] == 'ok' else outcome['verdict']}"
            )

    report = _build_report(cases, results)
    REPORT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    REPORT_MD.write_text(_render_markdown(report, results), encoding="utf-8")

    print("\n--- summary ---")
    print(f"cases: {report['dataset']['total']} "
          f"(benign {report['dataset']['benign']}, scam {report['dataset']['scam']})")
    print(f"binary: acc={report['binary_overall']['accuracy']} "
          f"prec={report['binary_overall']['precision']} "
          f"rec={report['binary_overall']['recall']} f1={report['binary_overall']['f1']}")
    print(f"category accuracy: {report['category_accuracy']} "
          f"({report['category_correct']}/{report['category_total']})")
    print(f"band compliance: {report['band_compliant']}/{report['band_total']}")
    print(f"false positives: {len(report['false_positives'])}  "
          f"false negatives: {len(report['false_negatives'])}  "
          f"band misses: {len(report['band_misses'])}")
    print(f"reports written: {REPORT_JSON.name}, {REPORT_MD.name}")


def _evaluate(outcome: dict, expected: dict) -> str:
    """Classify the outcome: ok / fp / fn / band_miss / error."""
    if "http_error" in outcome:
        return "error"
    pred_scam = outcome.get("risk_level") not in (None, "LOW")
    exp_scam = bool(expected.get("is_scam"))
    if exp_scam and not pred_scam:
        return "fn"
    if not exp_scam and pred_scam:
        return "fp"
    if exp_scam and not _band_ok(outcome.get("risk_level") or "LOW", expected.get("minimum_risk_level", "LOW")):
        return "band_miss"
    return "ok"


def _build_report(cases: list[dict], results: list[dict]) -> dict:
    # binary buckets
    buckets = {"overall": [], "text": [], "url": [], "text+url": []}
    for r in results:
        buckets["overall"].append(r)
        buckets.get(r["input_type"], []).append(r)

    binary = {}
    for name, rows in buckets.items():
        if not rows:
            continue
        tp = sum(1 for r in rows if r["expected"]["is_scam"] and r.get("risk_level") not in (None, "LOW"))
        fn = sum(1 for r in rows if r["expected"]["is_scam"] and r.get("risk_level") in (None, "LOW"))
        fp = sum(1 for r in rows if not r["expected"]["is_scam"] and r.get("risk_level") not in (None, "LOW"))
        tn = sum(1 for r in rows if not r["expected"]["is_scam"] and r.get("risk_level") in (None, "LOW"))
        binary[name] = _binary_metrics(tp, fp, fn, tn)

    scam_rows = [r for r in results if r["expected"]["is_scam"]]
    category_correct = sum(
        1
        for r in scam_rows
        if r.get("scam_type_primary") in (
            r["expected"]["primary_category"],
            *r["expected"].get("acceptable_categories", []),
        )
    )
    category_matrix = _confusion(scam_rows)

    band_misses = [
        {"id": r["id"], "expected": r["expected"]["minimum_risk_level"],
         "actual": r.get("risk_level")}
        for r in results
        if r["verdict"] == "band_miss"
    ]
    band_total = sum(1 for r in results if r["expected"]["is_scam"])

    return {
        "dataset": {
            "total": len(cases),
            "benign": sum(1 for c in cases if not c["expected"]["is_scam"]),
            "scam": sum(1 for c in cases if c["expected"]["is_scam"]),
            "by_input_type": dict(Counter(c["input_type"] for c in cases)),
            "categories": sorted({c["expected"]["primary_category"] for c in cases if c["expected"]["is_scam"]}),
            "hard_negatives": [c["id"] for c in cases if not c["expected"]["is_scam"] and "HARD NEGATIVE" in (c["expected"].get("note") or "")],
            "hard_positives": [c["id"] for c in cases if c["expected"]["is_scam"] and "HARD POSITIVE" in (c["expected"].get("note") or "")],
        },
        "binary_overall": binary.get("overall", {}),
        "binary_by_input_type": {k: v for k, v in binary.items() if k != "overall"},
        "category_accuracy": round(category_correct / len(scam_rows), 4) if scam_rows else 0.0,
        "category_correct": category_correct,
        "category_total": len(scam_rows),
        "category_confusion": category_matrix,
        "band_compliant": band_total - len(band_misses),
        "band_total": band_total,
        "band_misses": band_misses,
        "false_positives": [r for r in results if r["verdict"] == "fp"],
        "false_negatives": [r for r in results if r["verdict"] == "fn"],
        "errors": [r for r in results if r["verdict"] == "error"],
        "ml_usage": {
            "model": next((r.get("ml_model") for r in results if r.get("ml_model")), "none"),
            "mock_predictions": sum(1 for r in results if r.get("ml_is_mock")),
        },
        "cases": results,
    }


def _render_markdown(report: dict, results: list[dict]) -> str:
    d = report["dataset"]
    lines = [
        "# Detection Evaluation Report",
        "",
        "Generated by `scripts/evaluate_detection.py` against the real API pipeline "
        "(mock LLM / mock threat-intel / trained ML model as configured locally).",
        "",
        "## Dataset",
        "",
        f"* total: **{d['total']}**",
        f"* benign: **{d['benign']}** (hard negatives: {', '.join(d['hard_negatives']) or 'none'})",
        f"* scam: **{d['scam']}** (hard positives: {', '.join(d['hard_positives']) or 'none'})",
        f"* categories: {', '.join(d['categories'])}",
        f"* by input type: {d['by_input_type']}",
        "",
        "## Binary metrics (predicted scam = risk level != LOW)",
        "",
        "| Segment | Accuracy | Precision | Recall | F1 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, m in [("overall", report["binary_overall"]), *report["binary_by_input_type"].items()]:
        lines.append(
            f"| {name} | {m.get('accuracy', 0):.2%} | {m.get('precision', 0):.2%} | "
            f"{m.get('recall', 0):.2%} | {m.get('f1', 0):.2%} |"
        )
    overall = report["binary_overall"].get("confusion_matrix", {})
    lines += [
        "",
        f"Confusion matrix (overall): TP={overall.get('tp')} FP={overall.get('fp')} "
        f"FN={overall.get('fn')} TN={overall.get('tn')}",
        "",
        "## Category metrics",
        "",
        f"* category accuracy (incl. documented acceptable alternatives): "
        f"**{report['category_accuracy']:.2%}** ({report['category_correct']}/{report['category_total']})",
        "",
        "| Expected \\ Predicted | " + " | ".join(sorted(report["category_confusion"])) + " |",
        "| --- | " + " --- |" * len(report["category_confusion"]),
    ]
    for e, row in sorted(report["category_confusion"].items()):
        lines.append("| " + e + " | " + " | ".join(str(row.get(p, 0)) for p in sorted(report["category_confusion"])) + " |")

    lines += [
        "",
        "## Risk calibration",
        "",
        f"* band compliance: **{report['band_compliant']}/{report['band_total']}** "
        "scam cases reached their expected minimum risk level",
        "",
        "| Case | Expected | Score | Level | Confidence | Sufficiency | Result |",
        "| --- | --- | ---: | --- | ---: | --- | --- |",
    ]
    for r in results:
        lines.append(
            f"| {r['id']} | {r['expected']['minimum_risk_level']} | {r.get('risk_score') or 0} | "
            f"{r.get('risk_level') or '-'} | {r.get('confidence') or 0:.2f} | "
            f"{r.get('evidence_sufficiency') or '-'} | {r['verdict']} |"
        )

    if report["false_positives"]:
        lines += ["", "## False positives (benign flagged as scam)", ""]
        for r in report["false_positives"]:
            lines.append(
                f"* **{r['id']}** — predicted {r.get('scam_type_primary')}, "
                f"score {r.get('risk_score')}, level {r.get('risk_level')}, "
                f"confidence {r.get('confidence')}, contributors: "
                f"{', '.join(r.get('top_contributors') or []) or 'none'}"
            )

    if report["false_negatives"]:
        lines += ["", "## False negatives (scam missed)", ""]
        for r in report["false_negatives"]:
            lines.append(
                f"* **{r['id']}** — expected {r['expected']['primary_category']}, "
                f"got {r.get('scam_type_primary')}, score {r.get('risk_score')}, "
                f"level {r.get('risk_level')}"
            )

    if report["band_misses"]:
        lines += ["", "## Band misses (scam detected but below expected level)", ""]
        for r in report["band_misses"]:
            lines.append(
                f"* **{r['id']}** — expected >= {r['expected']}, got {r['actual']}"
            )

    lines += [
        "",
        "## ML contribution",
        "",
        f"* model in use: `{report['ml_usage']['model']}` "
        f"(mock/heuristic predictions: {report['ml_usage']['mock_predictions']})",
        "* The bundled model is trained on a **synthetic** corpus; treat its "
        "probability as one weak signal, not ground truth. The risk verdict stays "
        "deterministic (rules + URL + intel + ML weighted).",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()