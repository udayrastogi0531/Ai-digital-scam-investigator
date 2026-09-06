# Real labelled training data (staging)

This directory is reserved for **vetted, real-world labelled scam messages**.
It intentionally contains none today: no trustworthy real dataset is bundled
with this repository, and none is fabricated.

When a dataset is available (permissioned and anonymised as required):

1. Add it here as CSV / JSON / JSON-lines following the schema documented in
   [`../README.md`](../README.md).
2. Train with:
   `python scripts/ml_training/train.py --dataset data/datasets/real/<your_file>.csv`
3. Confirm the printed origin is `real` and review the validation statistics.

Rules:

* Never commit private/personal message content.  Anonymise (names, phone
  numbers, emails, addresses) or obtain explicit permission.
* Never copy rows from `data/evaluation/` into here — the loader rejects
  evaluation-corpus ids anyway.
* Do not store labels of anything *this* tool produced (auto-labelled
  predictions are not ground truth).
