"""Labeled-dataset loading, validation and splitting for the scam classifier.

Data-layer honesty rules (enforced here, not just documented):

* **Synthetic vs real.** ``data/datasets/scam_messages.csv`` is the
  synthetic/demo training set used to keep the training pipeline exercised
  offline.  It is labelled as synthetic in every report.
* **Evaluation is never training.** The evaluation corpus
  (``data/evaluation/evaluation_cases.json``) measures the *whole* pipeline
  and is never loaded by this module — its rows must never reach a model
  fit.  ``load_dataset`` rejects paths inside the evaluation directory and,
  when a dataset carries ``id`` values, rejects any row whose id matches an
  evaluation-corpus id (overlap guard).
* **No fabricated real-world data.** If you have a vetted, permissioned
  real dataset, drop it into ``data/datasets/real/`` (see the README there)
  and point ``train.py --dataset`` at it.  Nothing in this repository
  fabricates real training data.

Recommended real-dataset schema (CSV or JSON/JSON-lines).  Only ``text``
and ``label`` are required; everything else is validated when present::

    id, text, urls, label, scam_category, source, language,
    timestamp, annotation_confidence, notes

* ``text``        — the message/communication content (required unless ``urls`` is set)
* ``urls``        — JSON array string, or space/comma separated list (optional)
* ``label``       — ``scam`` | ``benign`` (required)
* ``scam_category`` — one of the rule-engine categories for scam rows
* ``source``      — e.g. ``email`` | ``sms`` | ``social`` | ``internal_soc``
* ``language``    — ISO 639-1 code, e.g. ``en``
* ``timestamp``   — ISO-8601 when the message was seen/collected
* ``annotation_confidence`` — 0..1 human agreement for the label
* ``notes``       — free text, e.g. ground-truth justification

No private/personal information belongs in committed datasets; the loader
does not strip it (it cannot know), but the repository policy is that only
fictional or permissioned/anonymised data may be committed.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
EVALUATION_CORPUS = BACKEND_DIR / "data" / "evaluation" / "evaluation_cases.json"

VALID_LABELS = {"scam", "benign"}

# Recognized categories for ``scam_category`` (rule-engine taxonomy plus the
# labels legitimately used for benign rows and open taxonomy rows).
from app.patterns.rules import CATEGORY_LABELS  # noqa: E402

KNOWN_CATEGORIES = set(CATEGORY_LABELS) | {"benign", "other"}

DATASET_SCHEMA_COLUMNS = [
    "id",
    "text",
    "urls",
    "label",
    "scam_category",
    "source",
    "language",
    "timestamp",
    "annotation_confidence",
    "notes",
]


@dataclass
class DatasetStats:
    """Statistics describing a validated dataset."""

    path: str
    origin: str  # "synthetic" | "real"
    total_rows: int = 0
    rows_after_dedup: int = 0
    duplicates_removed: int = 0
    malformed_rows: int = 0
    label_counts: dict[str, int] = field(default_factory=dict)
    category_counts: dict[str, int] = field(default_factory=dict)
    language_counts: dict[str, int] = field(default_factory=dict)
    source_counts: dict[str, int] = field(default_factory=dict)
    url_present: int = 0
    id_present: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"dataset: {self.path} (origin: {self.origin})",
            f"rows: {self.rows_after_dedup} (duplicates removed: {self.duplicates_removed}, "
            f"malformed rows: {self.malformed_rows})",
            f"labels: {self.label_counts}",
        ]
        if self.category_counts:
            lines.append(f"categories: {self.category_counts}")
        if self.language_counts:
            lines.append(f"languages: {self.language_counts}")
        if self.source_counts:
            lines.append(f"sources: {self.source_counts}")
        lines.append(f"rows with URL evidence: {self.url_present}")
        return "\n".join(lines)


class DatasetValidationError(ValueError):
    """Raised when a dataset cannot be used for training."""


def _is_evaluation_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(EVALUATION_CORPUS.parent.resolve())
        return True
    except ValueError:
        return False


def _origin_for(path: Path) -> str:
    if "scam_messages.csv" in path.name or path.parent.name == "datasets" and path.name.startswith("synthetic"):
        return "synthetic"
    return "real"


def _load_raw_rows(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Read CSV / JSON / JSON-lines into dict rows.

    Returns ``(rows, malformed_count)`` where malformed rows (not dicts, or
    undecodable) are skipped and counted.
    """
    suffix = path.suffix.lower()
    malformed = 0
    rows: list[dict[str, Any]] = []
    try:
        if suffix == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="") as fh:
                for row in csv.DictReader(fh):
                    if row is None:
                        malformed += 1
                        continue
                    cleaned = {k.strip(): (v if v is not None else "") for k, v in row.items() if k and k.strip()}
                    rows.append(cleaned)
        elif suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("rows"), list):
                data = data["rows"]
            if not isinstance(data, list):
                raise DatasetValidationError("JSON dataset must be a list of row objects (or {rows: [...]}).")
            for item in data:
                if isinstance(item, dict):
                    rows.append(dict(item))
                else:
                    malformed += 1
        elif suffix in (".jsonl", ".ndjson"):
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                if isinstance(item, dict):
                    rows.append(dict(item))
                else:
                    malformed += 1
        else:
            raise DatasetValidationError(f"unsupported dataset format: {suffix} (use .csv, .json or .jsonl)")
    except UnicodeDecodeError as exc:
        raise DatasetValidationError(f"dataset is not valid UTF-8 text: {exc}") from exc
    return rows, malformed


def _field(row: dict[str, Any], *names: str) -> str:
    """Read a value by any of several column aliases."""
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _row_errors(
    row: dict[str, Any], index: int, known_categories: set[str], require_categories: bool
) -> list[str]:
    errors: list[str] = []
    prefix = f"row {index}"
    label = _field(row, "label").lower()
    text = _field(row, "text")
    urls_raw = _field(row, "urls", "url")
    if not text and not urls_raw:
        errors.append(f"{prefix}: no content — provide 'text' and/or 'urls'")
    if not label:
        errors.append(f"{prefix}: missing required 'label'")
    elif label not in VALID_LABELS:
        errors.append(f"{prefix}: invalid label '{label}' (allowed: {sorted(VALID_LABELS)})")
    category = _field(row, "scam_category", "category")
    if category:
        if category not in known_categories:
            errors.append(f"{prefix}: unknown scam_category '{category}'")
        elif label == "benign" and category not in ("benign", "unknown", "other"):
            errors.append(f"{prefix}: benign row has scam category '{category}'")
    elif label == "scam" and require_categories:
        errors.append(f"{prefix}: scam row missing 'scam_category'")
    conf_raw = _field(row, "annotation_confidence")
    if conf_raw:
        try:
            conf = float(conf_raw)
            if not 0.0 <= conf <= 1.0:
                errors.append(f"{prefix}: annotation_confidence out of range 0..1")
        except ValueError:
            errors.append(f"{prefix}: annotation_confidence not numeric")
    return errors


def _evaluation_ids() -> set[str]:
    if not EVALUATION_CORPUS.exists():
        return set()
    data = json.loads(EVALUATION_CORPUS.read_text(encoding="utf-8"))
    return {str(c.get("id", "")).strip() for c in data if isinstance(c, dict) and c.get("id")}


def load_dataset(
    path: str | Path, *, require_categories: bool = True, deduplicate: bool = True
) -> tuple[list[dict[str, Any]], DatasetStats]:
    """Load and validate a labeled dataset.

    Returns ``(rows, stats)`` where ``rows`` are validated records (raw
    dicts, with a normalized ``label``).  Rows with validation errors are
    rejected and listed in ``stats.errors`` — the loader never silently
    trains on malformed data.

    ``require_categories=False`` relaxes only the scam-category checks (for
    quick model evaluation on rough labels); training should keep the
    default strict validation.

    ``deduplicate=True`` (default) drops exact duplicate rows (by ``id`` or
    normalized ``text``) and reports how many were removed.  Pass
    ``deduplicate=False`` when duplicate rows carry distributional meaning
    (e.g. the synthetic generator repeats template draws); the count is
    still reported.

    Raises :class:`DatasetValidationError` when the *file itself* is unusable
    (unsupported format, not UTF-8) or when the dataset is the evaluation
    corpus / overlaps evaluation ids.
    """
    path = Path(path)
    if not path.exists():
        raise DatasetValidationError(f"dataset not found: {path}")
    if _is_evaluation_path(path):
        raise DatasetValidationError(
            "refusing to load the evaluation corpus as training data — the evaluation corpus "
            "measures the pipeline and must never be trained on"
        )

    rows, malformed = _load_raw_rows(path)
    if not rows:
        raise DatasetValidationError(f"dataset contains no rows: {path}")

    ev_ids = _evaluation_ids()
    valid: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_text: set[str] = set()
    seen_ids: set[str] = set()
    duplicates = 0

    for index, row in enumerate(rows, start=2):  # 1-based with header
        row_errors = _row_errors(row, index, KNOWN_CATEGORIES, require_categories)
        label = _field(row, "label").lower()
        text = _field(row, "text")
        row_id = _field(row, "id")
        if row_id and row_id in ev_ids:
            row_errors.append(f"row {index}: id '{row_id}' matches an evaluation-corpus id (contamination guard)")
        if row_errors:
            errors.extend(row_errors)
            continue

        # duplicate detection: prefer a stable id, else normalized text.
        if deduplicate:
            if row_id:
                if row_id in seen_ids:
                    duplicates += 1
                    continue
                seen_ids.add(row_id)
            else:
                norm_text = " ".join(text.lower().split()) if text else text
                if norm_text and norm_text in seen_text:
                    duplicates += 1
                    continue
                seen_text.add(norm_text)

        normalized = dict(row)
        normalized["label"] = label
        valid.append(normalized)

    stats = DatasetStats(
        path=str(path),
        origin=_origin_for(path),
        total_rows=len(rows),
        rows_after_dedup=len(valid),
        duplicates_removed=duplicates,
        malformed_rows=malformed,
        errors=errors[:200],  # keep the report readable
    )
    if not deduplicate:
        # duplicates were intentionally kept: report them but do not count
        # them as removed.
        stats.duplicates_removed = 0
    for row in valid:
        stats.label_counts[_field(row, "label")] = stats.label_counts.get(_field(row, "label"), 0) + 1
        cat = _field(row, "scam_category", "category")
        if cat:
            stats.category_counts[cat] = stats.category_counts.get(cat, 0) + 1
        lang = _field(row, "language")
        if lang:
            stats.language_counts[lang] = stats.language_counts.get(lang, 0) + 1
        source = _field(row, "source")
        if source:
            stats.source_counts[source] = stats.source_counts.get(source, 0) + 1
        if _field(row, "urls", "url"):
            stats.url_present += 1
        if _field(row, "id"):
            stats.id_present += 1
    return valid, stats


def stratified_split(
    rows: list[dict[str, Any]],
    *,
    test_size: float = 0.2,
    val_size: float = 0.1,
    seed: int = 42,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Stratified train / validation / test split (by ``label``).

    Deterministic for a given ``seed`` so training runs are reproducible.
    """
    if not rows:
        raise DatasetValidationError("cannot split an empty dataset")
    try:
        from sklearn.model_selection import train_test_split
    except ImportError as exc:  # pragma: no cover - sklearn is a training dependency
        raise DatasetValidationError("scikit-learn is required for splitting") from exc

    labels = [str(r.get("label", "")).lower() for r in rows]
    if len(set(labels)) < 2:
        raise DatasetValidationError("dataset must contain both 'scam' and 'benign' rows to split stratified")

    train_val, test = train_test_split(
        rows, test_size=test_size, random_state=seed, stratify=labels
    )
    val_frac = val_size / (1.0 - test_size) if test_size < 1.0 else 0.0
    train_val_labels = [str(r.get("label", "")).lower() for r in train_val]
    train, val = train_test_split(
        train_val, test_size=val_frac, random_state=seed, stratify=train_val_labels
    )
    return train, val, test
