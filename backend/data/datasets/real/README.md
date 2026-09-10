# Real labelled training data (staging)

This directory holds **vetted, real-world labelled scam messages** with
documented provenance.

## Currently included

| File | Origin | License | Notes |
|---|---|---|---|
| `sms_spam_uci.csv` | **Real** — UCI SMS Spam Collection v.1 | CC BY 4.0 | 5,159 rows (4,517 benign / 642 scam), English SMS; imported by `scripts/ml_training/import_sms_spam.py`; full provenance in [`../README.md`](../README.md) |

## Importing another real dataset

1. Add it here as CSV / JSON / JSON-lines following the schema documented in
   [`../README.md`](../README.md).
2. Update the provenance table above (name, source, URL, license, date
   acquired, preprocessing, limitations).
3. Train with:
   `python scripts/ml_training/train.py --dataset data/datasets/real/<your_file>.csv`
   (add `--no-categories` if the corpus has no `scam_category` labels).
4. Confirm the printed origin is `real` and review the validation statistics.

## Rules

* Never commit private/personal message content unless the dataset license
  explicitly permits redistribution (as the UCI SMS corpus does under
  CC BY 4.0). For example, the SpamAssassin public corpus states that
  copyright remains with the original senders, so its raw messages are
  **not** committed here.
* Never copy rows from `data/evaluation/` into here — the loader rejects
  evaluation-corpus ids anyway.
* Do not store labels of anything *this* tool produced (auto-labelled
  predictions are not ground truth).