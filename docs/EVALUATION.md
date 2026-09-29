# Evaluation — AI Digital Scam Investigator

> **Read this before quoting any number.** This project has **two independent measurement regimes**
> and their results are **not interchangeable**:
>
> | Regime | What it measures | Current result |
> |---|---|---|
> | **A — end-to-end calibration corpus** | The whole pipeline (API → LangGraph → rules/ML/URL/risk) on 64 fictional cases | accuracy / precision / recall / F1 = 1.00, 0 FP, 0 FN |
> | **B — ML held-out evaluation** | The logistic-regression classifier *alone*, on a held-out split of its own real training corpus | accuracy 0.9312 · precision 0.6748 · recall 0.8594 · F1 0.7560 · ROC-AUC 0.9707 |
>
> Regime A is a **regression harness on a small fictional corpus**, not a real-world detection-accuracy
> claim. Regime B is a genuine held-out generalisation estimate, but only for SMS spam/ham. Neither
> number should ever be presented as the other, and neither should be combined into a single headline.

Everything below is reproducible from a clean checkout with the commands shown, no API keys and no
network access.

---

## Contents

| # | Section |
|---|---|
| 1 | [Regime A — the calibration corpus](#1-regime-a--the-calibration-corpus) |
| 2 | [What a 100% calibration result does and does not mean](#2-what-a-100-calibration-result-does-and-does-not-mean) |
| 3 | [Failure modes this corpus has caught](#3-failure-modes-this-corpus-has-caught) |
| 4 | [Regime B — ML held-out evaluation](#4-regime-b--ml-held-out-evaluation) |
| 5 | [Why the two regimes must never be combined](#5-why-the-two-regimes-must-never-be-combined) |
| 6 | [Reproducing everything](#6-reproducing-everything) |
| 7 | [What is deliberately not measured](#7-what-is-deliberately-not-measured) |

---

## 1. Regime A — the calibration corpus

### 1.1 What it is

`backend/data/evaluation/evaluation_cases.json` holds **64 hand-written, fully fictional cases**. It is
committed to the repository deliberately, so a fresh clone can run the same assertions a maintainer
runs. Each case is a small JSON object:

| Field | Meaning |
|---|---|
| `id` | Stable identifier — also the regression fingerprint |
| `input_type` | `text`, `url`, or `text+url` |
| `text` / `urls` | The submitted content |
| `expected.is_scam` | Ground truth for the binary verdict |
| `expected.primary_category` | Expected deterministic category (`unknown` means "no category may be asserted") |
| `expected.acceptable_categories` | Documented acceptable alternatives, so a defensible reclassification is not a failure |
| `expected.minimum_risk_level` | The band the case must reach |
| `expected.note` | Why the case exists and what it is guarding |
| `known_hard_case` | Opts a case out of band assertions when the deterministic engine honestly cannot disambiguate it. **No case currently carries this flag** — the last one (an unsolicited shared-document link) is now detected by the shared-document link-bait rule and is asserted like any other scam case |

### 1.2 Composition

| Group | Count |
|---|---|
| Total | 64 |
| Benign (all must stay `LOW`) | 24 |
| Scam (must reach their expected band and category) | 40 |
| Input type — `text` | 45 |
| Input type — `url` | 11 |
| Input type — `text+url` | 8 |
| Named scam categories represented | 14 |
| Cases whose expected category is `unknown` | 2 (scam cases where no category may be asserted) |
| Declared hard negatives | 9 |
| Declared hard positives | 4 |

The corpus does **not** leave its adversarial cases implicit. It declares them:

- **`hard_negatives`** — benign content that *looks* alarming: official OTP warnings, device-security
  alerts, delivery-tracking notices with real carrier links, recruiter salary offers, investment
  disclaimers, password-reset mail, payment receipts, two-factor codes, and a benign official URL
  wrapped in scammy marketing words. Any of these scoring above `LOW` fails the suite.
- **`hard_positives`** — scams that are deliberately understated: a subtle shared-document link, a
  low-key banking message, a quiet job offer, a restrained investment pitch. These must still be
  caught without loud keywords.

Category coverage, honest about its imbalance (phishing dominates at 9 cases; `identity_theft`,
`lottery_scam`, `romance_scam` and `tech_support_scam` have one case each):

`phishing` 9 · `banking_scam` 4 · `crypto_scam` 3 · `payment_scam` 3 · `delivery_scam` 3 ·
`impersonation_scam` 3 · `account_takeover` 3 · `job_scam` 2 · `advance_fee` 2 · `investment_scam` 2 ·
`tech_support_scam` 1 · `lottery_scam` 1 · `romance_scam` 1 · `identity_theft` 1 · (unlabelled) 2.

### 1.3 How it runs

`scripts/evaluate_detection.py` submits every case through the **real API pipeline** — FastAPI routes,
LangGraph workflow, deterministic rules, the shipped ML artifact, the risk engine and persistence — and
writes `evaluation_report.json` / `evaluation_report.md` next to the corpus.

The harness is deliberately configured to be hermetic and honest:

| Choice | Reason |
|---|---|
| `DATABASE_URL` pointed at a temporary SQLite file | The run never touches the developer's `backend/data/app.db` |
| `LLM_PROVIDER=mock`, `OCR_PROVIDER=mock` | No network, no cost, no run-to-run drift |
| `GOOGLE_SAFE_BROWSING_API_KEY` / `VIRUSTOTAL_API_KEY` / `LLM_API_KEY` **blanked explicitly** | A developer's real `backend/.env` must not silently turn the harness into a live-API run |
| The **real** shipped `.joblib` model, not a stub | The ML channel is measured as it actually behaves in production |
| Every per-case record notes the provider mode | The report cannot be misread as a live-provider result |

### 1.4 Current result

| Metric | Value |
|---|---|
| Cases | 64 — 24 benign / 40 scam |
| Confusion matrix | TP 40 · FP 0 · FN 0 · TN 24 |
| Accuracy | 1.00 |
| Precision | 1.00 |
| Recall | 1.00 |
| F1 | 1.00 |
| Category accuracy | 1.00 (40/40) |
| Band compliance | 40/40 |
| False positives / false negatives / band misses | 0 / 0 / 0 |
| Errors | 0 |

| Segment | Accuracy | Confusion |
|---|---|---|
| `text` | 1.00 | TP 28 · FP 0 · FN 0 · TN 17 |
| `url` only | 1.00 | TP 6 · FP 0 · FN 0 · TN 5 |
| `text+url` | 1.00 | TP 6 · FP 0 · FN 0 · TN 2 |

### 1.5 How the corpus is enforced as a regression suite

`tests/test_evaluation_corpus.py` runs the same corpus through the same pipeline in-process and asserts
per case, so a calibration regression fails `pytest`:

1. every benign case — **including all nine hard negatives** — must be `LOW`;
2. every scam case must reach at least its `minimum_risk_level`, and must be classified as its expected
   category or one of its documented acceptable alternatives;
3. sparse evidence must stay uncertain: a sparse URL submission must report confidence ≤ 0.55 and
   `INSUFFICIENT`/`PARTIAL` sufficiency — it must not be *confidently* declared safe;
4. multi-channel corroborated evidence must be more confident than sparse evidence (≥ 0.80);
5. unit-level signal semantics are pinned directly: protective warnings are not credential requests,
   a two-factor code is not an OTP request, a receipt is not a payment request, punycode homoglyphs are
   detected, and alarm rules are suppressed by protective wording but not by "do not share …" appended
   to an actual request.

The band assertions pin the **band**, not the exact score, so calibration changes stay intentional
without making the suite brittle.

### 1.6 Adding a case

A new case is a meaningful contribution and a permanent assertion, so it comes with obligations:

1. add the case object to `evaluation_cases.json`;
2. set `expected.primary_category` to `unknown` if the pipeline should *not* assert a category, and list
   `acceptable_categories` for genuinely defensible alternatives rather than loosening the assertion;
3. put it in the appropriate `hard_negatives` / `hard_positives` list if it is adversarial;
4. run the detector **and** `pytest` — a case that only passes the standalone script but fails the suite
   is not finished;
5. never add a case whose ground truth you would not defend in review, and never adjust an existing
   expectation to make a regression disappear.

---

## 2. What a 100% calibration result does and does not mean

**Do:**

- treat it as evidence that the documented behaviours are stable and that each frozen case still lands
  where it was decided it should;
- treat it as a **regression gate**: the value is in the suite failing when a rule change breaks a hard
  negative, not in the percentage;
- read it as a statement about 64 specific, hand-written, fictional messages.

**Do not:**

- describe it as real-world detection accuracy, or as "the system catches 100% of scams";
- compare it to published detection benchmarks, which use different corpora, different definitions of a
  positive, and real messages;
- present it as a generalisation estimate. The corpus is small, English-only, hand-authored, and was
  written by the same people who wrote the rules — it measures conformance, not generalisation;
- imply live providers were involved. Threat intelligence and the LLM run in mock mode here, and the
  report records that per case.

The repository states this in the README, in the generated report, and in this document on purpose:
a number that is easy to misread should be surrounded by the reading instructions.

---

## 3. Failure modes this corpus has caught

The corpus earns its keep by having caught two real defects. Both are fixed in the deterministic
engine; the original live-run observations are preserved as observed rather than rewritten.

| Symptom | Root cause | Fix |
|---|---|---|
| An obvious "guaranteed 40% returns / risk-free" investment scam scored `LOW` | Rule matching compared literal keyword strings with word boundaries, so a token *inside* a keyword phrase (`guaranteed 40% returns`) and the hyphenated `risk-free` never matched | Rules now also evaluate declarative **regex variants** (`ScamRule.patterns`) over the normalised text, with numeric pressure/reward signals; the case is now classified `investment_scam` by the deterministic rules alone |
| A legitimate receipt mentioning "parcel" was labelled `delivery_scam` (band correctly `LOW`) | Status-only delivery rules fired on topic words without scam context | Rules gained a `requires_request_context` gate: a status notice is evidence only when the message also asks for something or applies pressure |

Because rule matching also produces the model's `scam_keyword_hits` feature, the first fix required
retraining and re-validating the shipped artifact on the same corpus — see [§4](#4-regime-b--ml-held-out-evaluation).
That coupling is why `patterns/rules.py` changes are treated as a two-part change: rules *and* artifact.

---

## 4. Regime B — ML held-out evaluation

### 4.1 Corpus and provenance

`backend/data/datasets/real/sms_spam_uci.csv` — the real **UCI SMS Spam Collection v.1** (CC BY 4.0),
imported by `scripts/ml_training/import_sms_spam.py`. Full provenance, license, attribution, row counts
and importer behaviour are documented in [`data/datasets/README.md`](../backend/data/datasets/README.md).

| Property | Value |
|---|---|
| Rows committed | 5,159 (415 exact-duplicate texts removed during import) |
| Labels | `benign` 4,517 · `scam` 642 (≈ 12.4% scam prevalence) |
| Language / channel | English · SMS |
| Category labels | **None** — training runs with `--no-categories` |
| URL-bearing rows | Effectively none, which is why URL-presence features were removed from the model |

### 4.2 Protocol

`scripts/ml_training/train.py --dataset data/datasets/real/sms_spam_uci.csv --no-categories`:

1. `ml/dataset.py` validates the schema, rejects malformed rows, removes duplicates and **refuses**
   anything under `data/evaluation/` or whose ids collide with evaluation cases — the contamination
   guard is code, not convention;
2. deterministic stratified split (`seed=42`): **3,611 train / 516 validation / 1,032 test**;
3. `StandardScaler` → `LogisticRegression(max_iter=2000, C=0.8, class_weight="balanced")`;
4. the reported metrics come from the **held-out test split** only;
5. the report is written to `data/datasets/evaluation_report.json` (committed, so the numbers are
   auditable without rerunning training).

### 4.3 Results

Held-out test split (1,032 rows, confusion matrix `[[851, 53], [18, 110]]` — `[benign, scam]`):

| Metric | Value |
|---|---|
| Accuracy | 0.9312 |
| Precision | 0.6748 |
| Recall | 0.8594 |
| F1 | 0.7560 |
| ROC-AUC | 0.9707 |

A separate **full-corpus sanity run** (`scripts/ml_training/evaluate.py`, which applies the shipped
model to all 5,159 rows rather than to a held-out split) reports accuracy 0.9353 · precision 0.6920 ·
recall 0.8645 · F1 0.7687 · ROC-AUC 0.9741. It is a diagnostic for artifact/code consistency, **not** a
generalisation estimate — it includes the rows the model was trained on.

**Read the precision honestly.** 0.6748 means roughly one in three messages the model flags is actually
ham. That is reported as-is rather than tuned into a nicer-looking number by moving the threshold on
the test split. The classifier is deliberately the **smallest** weighted channel in the risk engine
(0.10), so a single probabilistic false positive cannot by itself push a submission into a scam band.

### 4.4 Honest limits

The corpus is SMS spam/ham supervision — 12.4% scam prevalence, English-only, no URL-bearing rows. It
cannot represent phishing URLs, lookalike domains, crypto wallet drains, executive impersonation or
screenshot-only evidence. Categories beyond SMS spam are carried by the deterministic channels. **SMS
training is not evidence that the model detects every kind of scam**, and the model is never the
decision-maker (see [`ARCHITECTURE.md`](ARCHITECTURE.md) §8 and §11).

### 4.5 Artifact invalidation

`extract_features` is shared between training and `agents/ml_node.py`, and the `scam_keyword_hits`
feature is derived from rule matching. Therefore **any change to `patterns/rules.py` or the rule engine
invalidates the shipped artifact**; it must be retrained and re-validated before the change ships.
URL-presence features were removed for a related reason: because this product investigates suspicious
URLs by design, presence is uninformative, and training on it made the model flag any URL-bearing
message.

---

## 5. Why the two regimes must never be combined

| | Regime A | Regime B |
|---|---|---|
| Unit under test | Whole pipeline | The classifier alone |
| Data | 64 fictional, hand-written cases | 5,159 real SMS messages |
| Split | All cases are assertions (no train/test split) | Deterministic 70/10/20 stratified split |
| Providers | Mock intel + mock LLM, real ML artifact | No providers at all |
| Question answered | "Do the documented behaviours still hold?" | "How well does this model generalise on this corpus?" |
| Valid claim | Regression conformance on a calibration corpus | Held-out generalisation for SMS spam/ham |

Averaging them, or quoting one as the other, would produce a number that answers no question. The
README keeps them in two clearly separated sections for the same reason.

---

## 6. Reproducing everything

No API keys, no network. From `backend/`:

```bash
# Regime A — whole-pipeline calibration + report artifacts
.venv/Scripts/python.exe scripts/evaluate_detection.py

# Regime A — the same corpus as a pytest regression suite
.venv/Scripts/python.exe -m pytest tests/test_evaluation_corpus.py tests/test_calibration.py -q

# Regime B — retrain + held-out report (deterministic; rewrites data/datasets/evaluation_report.*)
.venv/Scripts/python.exe scripts/ml_training/train.py --dataset data/datasets/real/sms_spam_uci.csv --no-categories

# Regime B — full-corpus sanity diagnostic
.venv/Scripts/python.exe scripts/ml_training/evaluate.py --dataset data/datasets/real/sms_spam_uci.csv

# End-to-end application smoke (12 flows: demo cases, custom submit, detail, history, filter, delete)
.venv/Scripts/python.exe scripts/end_to_end_smoke.py

# Whole test suite
.venv/Scripts/python.exe -m pytest tests/ -q
```

The generated evaluation reports under `backend/data/evaluation/` are **git-ignored** — they are
artifacts of a run, and regenerating them is expected. The committed evidence is the corpus itself
(`evaluation_cases.json`), the ML report (`data/datasets/evaluation_report.json`) and the tests.

Opt-in live suites exist for real providers and are never part of the default run:
`RUN_LIVE_INTEL_TESTS=1` (Safe Browsing / VirusTotal), `RUN_LIVE_LLM_TESTS=1` (LLM grounding),
`RUN_LIVE_OCR_TESTS=1` (system Tesseract). They require real credentials and assert the **integration
contract** (provider selection, verdict normalisation, honesty of failures) rather than any accuracy
figure — live reputation services return whatever they return on the day.

---

## 7. What is deliberately not measured

Stating the gaps is part of the evaluation, not an omission from it:

- **No real-world detection accuracy.** There is no held-out corpus of real, current, labelled scam
  traffic from live channels. Everything above is either fictional or SMS-corpus-scoped.
- **No adversarial evaluation.** No attacker is adapting to these specific rules, so mutation-based
  evasion (character substitution, image-only payloads, non-English social engineering) is untested.
- **No human agreement study.** The calibration corpus has one authorial ground truth; `expected.note`
  documents the reasoning per case, but inter-annotator agreement was not measured.
- **No live-provider accuracy.** Threat-intel verdicts depend on Google/VirusTotal coverage on the day;
  the live suites verify normalisation and failure honesty, not provider recall.
- **No latency, throughput or cost benchmark.** Request latency is dominated by live provider calls and
  is not characterised here; the pipeline is synchronous with no queue (see
  [`ARCHITECTURE.md`](ARCHITECTURE.md) §17).
- **No frontend behavioural test suite.** `npm run typecheck` and `npm run build` are the enforced
  frontend gates; there are no component or browser tests, and `npm run lint` is not usable because
  `next lint` opens an interactive configuration prompt.

If you extend the evaluation, extend this list of limits with it — a metric without its scope is a
claim, not a measurement.
