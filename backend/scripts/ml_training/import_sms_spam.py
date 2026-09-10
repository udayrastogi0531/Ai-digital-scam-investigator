"""Import the UCI SMS Spam Collection (v.1) into the repository's canonical schema.

What this does
--------------
Downloads the publicly available **UCI SMS Spam Collection v.1** (CC BY 4.0,
see ``data/datasets/README.md`` for provenance), validates every row, maps
the corpus labels onto the repository's vocabulary (``ham`` -> ``benign``,
``spam`` -> ``scam``) and writes a canonical CSV under
``data/datasets/real/sms_spam_uci.csv`` that ``train.py --dataset`` can load
directly.

Why a conversion script
-----------------------
The raw corpus is a two-column TSV (``label<TAB>message``) with no header,
ids, categories or provenance columns.  This repository's training loader
expects its documented schema (``text`` + ``label`` required, optional
``id``/``source``/``language``/``notes``), so the raw file is normalized
*once* here instead of special-casing the format inside ``app/ml/dataset.py``.

Honesty notes
-------------
* No category is invented for spam rows: the corpus has no ``scam_category``
  labels, so those columns are left empty and ``train.py`` is run with
  ``--no-categories`` (scam-category validation is relaxed for this corpus).
* Rows are not re-labelled or re-scored; ``ham``/``spam`` are mapped 1:1.
* The corpus contains real (publicly published) SMS content — see the
  provenance section in ``data/datasets/README.md`` before redistributing.

Usage (from ``backend/``)::

    .venv/Scripts/python.exe scripts/ml_training/import_sms_spam.py
    .venv/Scripts/python.exe scripts/ml_training/train.py \\
        --dataset data/datasets/real/sms_spam_uci.csv --no-categories
"""
from __future__ import annotations

import argparse
import csv
import io
import sys
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # backend/

UCI_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
RAW_DIR = ROOT / "data" / "datasets" / "raw"
RAW_TSV = RAW_DIR / "SMSSpamCollection"
OUT_DEFAULT = ROOT / "data" / "datasets" / "real" / "sms_spam_uci.csv"

LABEL_MAP = {"ham": "benign", "spam": "scam"}

SCHEMA = [
    "id",
    "text",
    "label",
    "scam_category",
    "source",
    "language",
    "timestamp",
    "annotation_confidence",
    "notes",
]

PROVENANCE_NOTE = (
    "UCI SMS Spam Collection v.1 (CC BY 4.0) — see data/datasets/README.md for provenance"
)


def download_raw(target: Path) -> None:
    """Download and extract the UCI zip into ``data/datasets/raw/``."""
    target.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {UCI_URL}")
    with urllib.request.urlopen(UCI_URL, timeout=90) as resp:  # noqa: S310 - pinned public research dataset
        data = resp.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        member = zf.read("SMSSpamCollection")
    target.write_bytes(member)
    print(f"saved raw corpus -> {target}")


def parse_tsv(path: Path) -> tuple[list[dict], int]:
    """Parse ``label\\tmessage`` lines into canonical rows."""
    rows: list[dict] = []
    malformed = 0
    seen_text: set[str] = set()
    duplicates = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            parts = line.split("\t", 1)
            if len(parts) != 2 or parts[0].strip() not in LABEL_MAP:
                malformed += 1
                continue
            label = parts[0].strip()
            text = parts[1].strip()
            if not text:
                malformed += 1
                continue
            norm = " ".join(text.lower().split())
            if norm in seen_text:
                duplicates += 1
                continue
            seen_text.add(norm)
            rows.append(
                {
                    "id": f"sms-uci-{len(rows) + 1:05d}",
                    "text": text,
                    "label": LABEL_MAP[label],
                    "scam_category": "",
                    "source": "sms",
                    "language": "en",
                    "timestamp": "",
                    "annotation_confidence": "",
                    "notes": PROVENANCE_NOTE,
                }
            )
    return rows, malformed, duplicates


def write_csv(rows: list[dict], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=SCHEMA)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote canonical dataset -> {out}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=RAW_TSV, help="path to the raw SMSSpamCollection TSV")
    parser.add_argument("--out", type=Path, default=OUT_DEFAULT, help="canonical CSV output path")
    parser.add_argument(
        "--download",
        action="store_true",
        help="download the corpus from UCI if the raw TSV is missing",
    )
    args = parser.parse_args()

    if not args.source.exists():
        if not args.download:
            print(
                f"raw corpus not found at {args.source}. "
                "Re-run with --download to fetch it from UCI, or pass --source <path>."
            )
            return 1
        download_raw(args.source)

    rows, malformed, duplicates = parse_tsv(args.source)
    if not rows:
        print("no valid rows parsed — aborting")
        return 1

    labels = Counter(r["label"] for r in rows)
    print(f"parsed {len(rows)} rows (malformed: {malformed}, exact-duplicate texts removed: {duplicates})")
    print(f"labels: {dict(labels)}")
    write_csv(rows, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())