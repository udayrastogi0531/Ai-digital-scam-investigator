# Glossary — AI Digital Scam Investigator

This project uses a dense, precise vocabulary, and several pairs of terms look interchangeable but are
not (`verdict` vs `status`, band vs score, mention vs request). Definitions below are what the **code**
does, with the location so you can verify any of them.

---

## Contents

| # | Group |
|---|---|
| 1 | [Evidence and signals](#1-evidence-and-signals) |
| 2 | [Risk](#2-risk) |
| 3 | [Detection rules](#3-detection-rules) |
| 4 | [Threat intelligence](#4-threat-intelligence) |
| 5 | [Machine learning](#5-machine-learning) |
| 6 | [Evaluation](#6-evaluation) |
| 7 | [Pipeline and architecture](#7-pipeline-and-architecture) |

---

## 1. Evidence and signals

| Term | Meaning | Where |
|---|---|---|
| **Evidence signal** | One typed observation produced by one channel. The currency of the pipeline — stages exchange these, never prose | `schemas/evidence.py::EvidenceSignal` |
| **Source** | Which channel produced a signal: `url_analysis`, `threat_intelligence`, `scam_pattern`, `text_analysis`, `entity_analysis`, `ml_classifier`, `ocr` | `EvidenceSignal.source` |
| **Signal code** | Short machine-readable identifier for the observation, e.g. `URL_RISK`, `CREDENTIAL_REQUEST`, `PATTERN_MATCH` | `EvidenceSignal.signal` |
| **Severity** | Severity of that single observation: `low` < `medium` < `high` < `critical`, ordered as 1–4 by the rank map `_SEV` in the correlation step | `EvidenceSignal.severity`, `risk/correlation.py` |
| **Confidence** | 0–1 confidence in *that one observation*, not in the overall verdict | `EvidenceSignal.confidence` |
| **Detail** | Structured payload attached to a signal (matched rule, URL findings, per-provider verdicts) | `EvidenceSignal.detail` |
| **Timeline** | Ordered, de-duplicated list of pipeline stages with their outputs, persisted and returned to the UI | `graph/state.py`, `analysis_results` table |

## 2. Risk

| Term | Meaning | Where |
|---|---|---|
| **Score** | Deterministic 0–100 value from the weighted engine | `risk/engine.py` |
| **Band** (risk level) | `LOW` 0–24 · `MEDIUM` 25–49 · `HIGH` 50–74 · `CRITICAL` 75–100. **The band gates the verdict**; the category label does not | `risk/engine.py` |
| **Confidence** | 0–1 confidence in the *assessment*, distinct from the score | `RiskAssessment.confidence` |
| **Sufficiency** | How much independent evidence backs the assessment: `INSUFFICIENT` (≤ 0.35) · `PARTIAL` · `SUFFICIENT` (≥ 0.60) | `RiskAssessment.evidence_sufficiency` |
| **Contributor** | A factor that moved the score, with `impact` in −1…1 and the evidence sources behind it. Drives the "Why this score?" panel from real arithmetic | `schemas/risk.py::RiskContributor` |
| **Channel** | A scored input to the engine (pattern rules, threat intel, URL risk, credential request, ML, …) | `risk/engine.py::DEFAULT_WEIGHTS` |
| **Applicability** | Whether a channel *could* have fired for this submission. Inapplicable channels are excluded from the denominator rather than counted as zero | `risk/engine.py` |
| **URL anchor** | A signal strong enough to make the assessment URL-driven (`url_risk ≥ 0.4`, or a suspicious/malicious intel verdict). When anchored, applicable-but-**silent** channels are also dropped, so a credential-harvesting URL beside neutral text is not diluted to LOW | `URL_ANCHOR_MIN`, `CHANNEL_SILENT_MAX` |
| **Silent channel** | An applicable channel whose score is below `CHANNEL_SILENT_MAX` (0.2) — evidence looked, found nothing | `risk/engine.py` |
| **Correlation** | Pre-LLM aggregation of signals into themes, with corroboration and conflict detection | `risk/correlation.py` |
| **Theme** | A group of related signals: `url_risk`, `external_reputation`, `scam_pattern`, `language_signals`, `brand_impersonation`, `ml_prediction` | `risk/correlation.py` |
| **Corroborating theme** | A theme whose worst signal is `medium` or above | `risk/correlation.py` |
| **Conflict** | Contradiction between channels (e.g. a provider says *safe* while local signals are suspicious) | `risk/correlation.py` |
| **Consistency score** | 0.4 with no corroboration · 0.75 for one theme · 0.9 for two · 1.0 for three or more, **minus 0.2** on conflict. It is itself a weighted channel | `risk/correlation.py` |

## 3. Detection rules

| Term | Meaning | Where |
|---|---|---|
| **Scam rule** | Declarative definition: id, category, keywords, optional regex `patterns`, weight, severity, `required_entities`, `requires_request_context` | `patterns/rules.py::ScamRule` |
| **Keyword match** | Literal token-sequence match with word boundaries on the normalised text | `patterns/engine.py` |
| **Regex variant** | A compiled declarative pattern for surface variations a literal keyword misses (`guaranteed 40% returns`, `risk-free`). Added after a documented calibration gap | `ScamRule.patterns` |
| **`required_entities`** | Gate: the rule only fires when a matching entity (bank, company, URL, …) was extracted | `patterns/rules.py` |
| **`requires_request_context`** | Gate: a status-only rule (delivery, tracking) fires only when the message also asks for something or applies pressure | `patterns/rules.py` |
| **Request vs mention** | A mention of OTP, password or payment is not a *request*; request channels need a requestive verb | `analysis/text_signals.py` |
| **Status vs demand** | "Your parcel could not be delivered" is a status; only a demand for payment or action lifts the gate | `patterns/rules.py` |
| **Protective warning** | Language telling the recipient *not* to share credentials. Suppresses alarm rules and prevents OTP/password mentions from counting as requests | `analysis/text_signals.py` |
| **Reassurance** | Language saying no action is needed; distinguished from a request for the same reason | `analysis/text_signals.py` |
| **Ambiguous classification** | `unknown`, or confidence < 0.5 — the only condition under which the LLM may be asked to refine a category | `patterns/engine.py::is_ambiguous` |
| **`pattern_score`** | `min(1.0, Σ matched rule weights / 4.0)` — four full-weight rules saturate the channel | `agents/risk_node.py` |
| **Primary category** | The rules-ranked scam category; `unknown` means no category may be asserted | `patterns/rules.py::CATEGORY_LABELS` |
| **Acceptable alternative** | A documented category the corpus accepts as an alternative to the expected one, so a defensible reclassification is not a failure | `evaluation_cases.json` |

## 4. Threat intelligence

| Term | Meaning | Where |
|---|---|---|
| **Verdict** | The reputation *finding*: `safe`, `suspicious`, `malicious`, `unknown` | `schemas/analysis.py::ThreatIntelResult` |
| **Status** | Whether the *lookup* worked: `ok`, `error`, `unavailable`, `rate_limited` | same |
| **Informative verdict** | `status == "ok"` **and** verdict in (`safe`, `suspicious`, `malicious`). Only informative results may participate in the intel channel | `agents/risk_node.py` |
| **No information** | Any failure state. It never raises risk, never lowers it, and is never rendered as "clean" | `intelligence/base.py::failure_result` |
| **Failure result** | The normalised non-verdict returned for a failed lookup | `intelligence/base.py` |
| **`lookupable_url`** | Guard that rejects anything that is not a well-formed absolute `http(s)` URL, because reputations services answer "not listed" for input they cannot check | `intelligence/base.py` |
| **Worst verdict wins** | Merge rule: `safe 0 < unknown 1 < suspicious 2 < malicious 3`; score is the maximum | `intelligence/manager.py::_merge` |
| **`is_mock` / `uses_mock`** | Whether a result came from the labelled mock provider; `uses_mock` is true only when every provider is a mock | `manager.py`, `/api/health` |

## 5. Machine learning

| Term | Meaning | Where |
|---|---|---|
| **Feature vector** | 18 numeric features; the same `extract_features` runs in training and inference | `ml/features.py::FEATURE_NAMES` |
| **`scam_keyword_hits`** | Feature derived from rule matching — which is why editing rules invalidates the artifact | `ml/features.py` |
| **Artifact** | The joblib-persisted `StandardScaler` + `LogisticRegression` pipeline | `ml/models/lr_scam_model.joblib` |
| **Decision threshold** | `0.55`, chosen on the validation split. Affects only the **reported label**; the engine consumes the raw probability | `ML_DECISION_THRESHOLD` |
| **Held-out split** | The 1,032-row stratified test split the reported metrics come from | `ml/dataset.py` |
| **Contamination guard** | The loader refuses `data/evaluation/` and any row whose id collides with an evaluation case | `ml/dataset.py` |
| **`dataset_origin`** | `real` or `synthetic`, recorded in the training report so the two can never be confused | `ml/dataset.py` |
| **Deterministic fallback** | A heuristic used when the artifact is missing or unreadable — labelled as such, never as a model prediction | `ml/service.py` |

## 6. Evaluation

| Term | Meaning | Where |
|---|---|---|
| **Calibration corpus** | The 64 hand-written fictional cases used as a regression gate | `data/evaluation/evaluation_cases.json` |
| **Hard negative** | A benign case that looks alarming (an OTP warning, a carrier notice, a receipt). Any of these above `LOW` fails the suite | corpus `hard_negatives` |
| **Hard positive** | A deliberately understated scam that must still be caught | corpus `hard_positives` |
| **`known_hard_case`** | Opts a case out of band assertions when the engine honestly cannot disambiguate it. **No case currently carries this flag** | corpus |
| **Band compliance** | Fraction of scam cases landing in or above their expected band | `scripts/evaluate_detection.py` |
| **TP / FP / FN / TN** | Predicted scam = band above `LOW`. A **false positive** on a benign case is the most serious failure class | harness |
| **Regime A / Regime B** | Whole-pipeline calibration on fictional cases vs the classifier alone on real held-out SMS. Never combined | [EVALUATION.md](EVALUATION.md) |

## 7. Pipeline and architecture

| Term | Meaning | Where |
|---|---|---|
| **Investigation** | One submission and everything computed about it | `Investigation` table |
| **Pipeline** | The ordered stages: parse → analyse → (URL, intel, brand, ML) → correlate → risk → explain → report | `graph/builder.py` |
| **Node** | One LangGraph stage; implemented as an `agents/*_node.py` function | `agents/` |
| **Reducer** | How parallel branches merge into shared state (`operator.add` for evidence/timeline/errors, `merge_metadata` for nested dicts) | `graph/state.py` |
| **Pad node** | A zero-op node (`brand_pad`, `ml_pad`, …) giving every active branch equal depth, working around a langgraph 0.2.x double-merge scheduling bug | `graph/builder.py` |
| **Channel/analysis package** | A detection module. Analysis packages never import from `agents/` | `app/*` |
| **Deterministic risk engine** | The authoritative scorer. Nothing an LLM returns can change it | `risk/engine.py` |
| **Evidence-only contract** | The shared system prompt requiring the LLM to reason solely from supplied evidence | `llm/prompts/common.py` |
| **Rejected suggestion** | A model-proposed category discarded because no deterministic evidence supported it; recorded rather than hidden | `classification_suggestion_rejected` |
| **`method`** | Provenance of a classification: `rules` (deterministic engine), `hybrid(rules+llm)` (LLM-adopted refinement), or `hybrid` (rebuilt from the persisted report) | `ScamClassification.method` |
| **Demo mode** | Fully offline default: mock LLM and mock threat intel, **real** ML artifact, local SQLite | `core/config.py::using_mock_llm`, `/api/health` |
| **Hermetic suite** | Tests that cannot reach the network: `conftest.py` pins providers to mocks and blanks keys so a developer's real credentials cannot change an assertion | `tests/conftest.py` |
| **Opt-in live suite** | Tests against real providers, enabled by an explicit `RUN_LIVE_*` switch and excluded from the default run | `tests/test_*_live.py` |
