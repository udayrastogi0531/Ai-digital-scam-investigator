# Architecture

## Investigation pipeline

```
                     ┌─────────────────────────────┐
 user submission ───▶│ API (FastAPI)               │
   text / urls / img │  validation · rate limit    │
                     └─────────────┬───────────────┘
                                   ▼
                     ┌─────────────────────────────┐
                     │ LangGraph workflow          │
                     │  START ─ (image?) OCR       │
                     │      └──▶ parse             │
                     │          └▶ analyze         │
                     │              └─ conditional fan-out
                     │                ├ URL analysis ─▶ threat intel lookup
                     │                ├ brand/entity analysis
                     │                └ ML classifier
                     │              (equal-depth branches merge at correlate)
                     │          correlate ─▶ assess risk ─▶ explain ─▶ report
                     └─────────────┬───────────────┘
                                   ▼
                     ┌─────────────────────────────┐
                     │ Persistence (SQLAlchemy)    │
                     │  investigations, evidence,  │
                     │  entities, analysis_results,│
                     │  risk_assessments, reports  │
                     └─────────────────────────────┘
```

## How findings stay honest

1. **Evidence is structured first.** Text analysis, URL analysis, scam rules and the ML model emit
   typed signals (`source`, `signal`, `severity`, `confidence`, `description`, `detail`) rather
   than free-form claims.
2. **Risk is deterministic.** The risk engine combines component scores with configurable weights;
   the LLM is never the source of the score. Classification refinement and explanations cannot
   change the risk assessment.
3. **The LLM is a synthesizer.** Explanation/report agents receive only the structured evidence
   (`ReportContext`) and are constrained by an evidence-only prompt contract — no inventing
   reputation results or external facts. Malformed, empty or failed LLM output falls back to the
   deterministic explanation/report (`provider = "deterministic-fallback"`).
4. **Mocks are labelled.** Demo threat-intel, OCR and explanation providers mark their output
   (`is_mock`, `[DEMO]`, provider_mode) which the UI surfaces as warnings.
5. **Uncertainty is explicit.** Every risk assessment carries an `evidence_sufficiency` label
   (INSUFFICIENT / PARTIAL / SUFFICIENT). LOW + INSUFFICIENT/PARTIAL is worded as
   "low risk based on available evidence — not a verified safe result" in conclusions, reports
   and the UI; sparse inputs never get a confident verdict.

## Risk calibration

- Weights live in `DEFAULT_WEIGHTS` (`risk/engine.py`, JSON-overridable via `RISK_WEIGHTS_PATH`)
  and are tuned against `data/evaluation/evaluation_cases.json` (run
  `scripts/evaluate_detection.py`). Current distribution: pattern rules `0.35`, threat intel
  `0.25`, URL `0.18`, requests (credential/OTP `0.12` each, payment `0.10`, suspicious
  instructions `0.08`), ML `0.10`, entity impersonation `0.08`, urgency `0.07`, consistency `0.05`.
- The synthetic-trained ML model carries the *smallest* deterministic weight on purpose; it was
  observed over-trusting surface keywords (OTP/password mentions) on benign messages before the
  request-intent feature fix.
- Request channels are requestive-only: a *mention* of OTP/password/payment never counts as a
  request unless a requestive verb (enter/reply with/send us/…) is present, and protective
  warnings ("never share your OTP") plus reassurance ("no action needed") suppress credential/
  account alarm rules. This is what keeps legit 2FA texts, receipts and security notices LOW.
- **URL-anchored normalization.** Submissions normalize over *applicable* channels only, and when
  the assessment is URL-anchored — a URL with structural risk ≥ `URL_ANCHOR_MIN` (0.4), or a
  threat-intel verdict of suspicious/malicious — channels that are applicable but *silent* (score
  < `CHANNEL_SILENT_MAX` 0.2) drop out of the normalization denominator too. A strong lookalike/
  credential URL next to neutral text therefore keeps its URL/intel evidence weight instead of
  being diluted to LOW (the `suspicious_url` demo now reaches HIGH/CRITICAL). The anchor is
  decided from generic structured evidence (never domains/test cases); an official domain with a
  benign URL never anchors, so benign text next to an official URL stays LOW.
- **Intel channel applicability is evidence-gated.** Threat-intel weight counts in the
  denominator only when a provider returned an informative verdict (`safe`/`suspicious`/`malicious`
  with `status=ok`). Unknown/no-record/error/unavailable/rate-limited lookups carry no
  information: they neither contribute nor dilute and never look like a clean result.

## LangGraph notes

- Typed `InvestigationState`; reducer annotations on `evidence`/`timeline`/`warnings`/
  `processing_metadata` allow parallel branches to merge safely.
- Conditional edges run only needed branches (e.g. OCR only when an image is present).
- langgraph 0.2.x mis-schedules merges of branches with *unequal* depth (the downstream subgraph
  executes twice). The builder therefore pads branches so every active branch reaches the merge
  node in the same superstep; the final state also de-duplicates timeline entries defensively.

## Provider abstraction

| Concern          | Interface                    | Default (demo)              | Live option                        |
|------------------|------------------------------|-----------------------------|------------------------------------|
| Threat intel     | `ThreatIntelProvider`        | `MockThreatIntelProvider`   | Google Safe Browsing, VirusTotal   |
| LLM              | `LLMProvider`                | deterministic local         | OpenAI-compatible (any base URL)   |
| OCR              | `OCRProvider`                | mock (no tesseract)         | pytesseract                        |
| ML               | `ScamClassifier`             | trained LogisticRegression  | retrained pipeline via trainer     |

Threat-intel providers are queried by URL only (no server-side fetching of
arbitrary URLs — no SSRF surface) and their raw API payloads are normalized
at the boundary into `ThreatIntelResult` (`provider`, `verdict`
`safe|suspicious|malicious|unknown`, `status` `ok|error|unavailable|rate_limited`,
`risk_score`, `reputation`, `categories`, `hits`, safe `detail`, `checked_at`,
`error`). The manager queries configured providers concurrently, merges
worst-verdict-wins, and surfaces every per-provider outcome (including
failures) in the merged `detail["providers"]` list so the UI can show who
said what and who was down.

Failure behaviour is a hard invariant:

* a provider exception/outage/timeout/rate limit becomes `verdict=unknown`
  with a non-`ok` status — it is *no information*, never a clean verdict;
* failures never crash an investigation, never lower the merged risk and
  never add weight to the risk-engine denominator;
* the risk engine only treats `status=ok` + an informative verdict as
  evidence.

## ML data layer (training vs evaluation)

* `data/datasets/scam_messages.csv` — synthetic/demo training set
  (generated deterministically; origin reported as `synthetic`).
* `data/datasets/real/` — staging for vetted, permissioned real data
  (empty by design; schema + policy in `data/datasets/README.md`).
* `data/evaluation/evaluation_cases.json` — end-to-end corpus. The loader
  (`app/ml/dataset.py`) refuses to load it as training data and rejects rows
  whose ids overlap evaluation cases, so train/evaluation separation is
  enforced in code.
* `app/ml/dataset.py` validates required fields, labels, categories,
  annotation confidence, duplicates and malformed rows; reports dataset
  statistics; and provides a deterministic stratified train/val/test split.

`scripts/ml_training/train.py` reports dataset size, class distribution,
split sizes, precision/recall/F1 and the confusion matrix for the test
split, labels the dataset origin (synthetic vs real) and never claims
synthetic metrics as real-world evidence.

## Data model

PostgreSQL / SQLite tables: `investigations`, `evidence`, `extracted_entities`,
`analysis_results`, `risk_assessments`, `reports` — evidence signals are stored as rows
(structured), with JSON columns reserved for flexible AI metadata.
