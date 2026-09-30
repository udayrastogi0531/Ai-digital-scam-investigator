# Testing — AI Digital Scam Investigator

Five checks gate a change: the backend suite, the detection harness, the end-to-end smoke, and the two
frontend commands. This page covers what each one is, what it does *not* cover, and how to run the
opt-in live suites.

Every command below is run from `backend/` with the venv interpreter
(`.venv/Scripts/python.exe` on Windows, `.venv/bin/python` elsewhere) or from `frontend/` with npm.

---

## Contents

| # | Section |
|---|---|
| 1 | [The five gates](#1-the-five-gates) |
| 2 | [Suite map](#2-suite-map) |
| 3 | [Why the offline suites are hermetic](#3-why-the-offline-suites-are-hermetic) |
| 4 | [What is not covered](#4-what-is-not-covered) |
| 5 | [Opt-in live suites](#5-opt-in-live-suites) |
| 6 | [Writing a test](#6-writing-a-test) |
| 7 | [Interpreting a failure](#7-interpreting-a-failure) |

---

## 1. The five gates

```bash
cd backend
.venv/Scripts/python.exe -m pytest tests/ -q                     # 198 passed, 11 skipped
.venv/Scripts/python.exe scripts/evaluate_detection.py           # 64 cases, 0 FP, 0 FN, band 40/40
.venv/Scripts/python.exe scripts/end_to_end_smoke.py              # 12/12 flows

cd ../frontend
npm run typecheck                                                 # tsc --noEmit
npm run build                                                     # Next production build
```

Which gates apply to which change is tabulated in
[CONTRIBUTING.md §4](CONTRIBUTING.md#4-test-gates-by-change-type).

`npm run lint` is deliberately **not** a gate: `next lint` opens an interactive prompt to configure
ESLint and no ESLint config is committed. `typecheck` and `build` are the enforced frontend checks.

---

## 2. Suite map

216 tests are collected; 205 pass offline and 11 skip (the live suites).

| File | Tests | Covers |
|---|---|---|
| `test_evaluation_corpus.py` | 74 | Every case in the 64-case calibration corpus through the real API pipeline, plus unit-level signal semantics (protective warnings, OTP vs two-factor, receipt vs payment request, punycode lookalikes, rule suppression) |
| `test_phase3.py` | 36 | Provider contracts and normalisation, malformed-input handling, graph completion when every provider fails, LLM fallback on malformed/empty/exception output, dataset loader validation, deduplication, split reproducibility, contamination guard |
| `test_regressions.py` | 26 | Previously-fixed defects, including that the LLM cannot invent a category without deterministic evidence |
| `test_calibration.py` | 14 | Risk-band regression cases for representative scams and their benign hard negatives, with exact inputs inline |
| `test_extraction.py` | 10 | URL structure analysis, entity extraction, suspicious TLD/keyword handling |
| `test_api_integration.py` | 9 | Health, text/URL/image submissions, history filters, detail and delete roundtrip, empty-submission rejection |
| `test_upload_security.py` | 14 | Every upload-rejection branch: empty, oversized, non-image bytes behind an image content type, the 64 M-pixel cap (asserting the decode is never reached), Pillow's bomb error *and* bomb warning, a decode-time `MemoryError`, filename sanitisation, no investigation created on rejection, and no file written to disk for a valid upload |
| `test_image_concurrency.py` | 5 | The bounded image-concurrency gate: the configured limit is respected, an in-flight investigation causes the next image request to get a retryable `503`, capacity is restored once it finishes, and the slot is released after an exception and after a rejected upload |
| `test_ssrf_guard.py` | 2 | The no-SSRF property, behaviourally: every outbound request during a submission containing internal addresses is captured, and only the configured reputation hosts may appear |
| `test_rate_limit.py` | 4 | The limiter directly: client key extraction (forwarded header preferred), the limit producing a `429`, the window reopening after a minute, and per-client isolation |
| `test_patterns_risk.py` | 7 | Rule matching, category ranking, risk engine weighting and banding |
| `test_ml_and_graph.py` | 4 | ML prediction shape and graph state wiring |
| `test_ocr_live.py` | 7 | **Opt-in.** Real Tesseract contracts (skipped offline) |
| `test_threat_intel_live.py` | 4 | **Opt-in.** Real Safe Browsing / VirusTotal / LLM contracts (skipped offline) |

Two supporting scripts are not pytest suites but are part of the gate:

| Script | What it asserts |
|---|---|
| `scripts/evaluate_detection.py` | Binary metrics, per-input-type metrics, category accuracy, band compliance and confidence honesty across the whole corpus; writes `evaluation_report.json` / `.md` |
| `scripts/end_to_end_smoke.py` | 12 flows against the running application: the eleven demo cases, a custom submission, detail retrieval, history, a risk filter and delete |

The distinction matters: `test_evaluation_corpus.py` pins **bands** and categories per case, while
`evaluate_detection.py` reports **aggregate metrics**. A corpus failure is a broken regression; the
harness tells you the shape of the damage.

---

## 3. Why the offline suites are hermetic

A developer's real `backend/.env` must never change what `pytest` asserts. `tests/conftest.py`
guarantees that, and it is worth knowing before you debug a surprising pass or failure:

| Mechanism | Effect |
|---|---|
| `DATABASE_URL` → a fresh temp SQLite file | Tests never touch `backend/data/app.db`, and never write into your history |
| `OCR_PROVIDER=mock` | No dependency on a system Tesseract for the default run |
| `RATE_LIMIT_PER_MINUTE=1000` | The limiter cannot fail an unrelated test |
| `LLM_PROVIDER=mock` and **blanked** `LLM_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY` | Environment variables outrank the `.env` file, so providers are pinned to their deterministic mocks even if you have live keys configured |
| `ML_MODEL_PATH` → the shipped artifact | The ML channel behaves as it does in production |

The blanking is skipped when `RUN_LIVE_INTEL_TESTS=1` or `RUN_LIVE_LLM_TESTS=1`, so the documented
opt-in workflow still sees real keys. `scripts/evaluate_detection.py` blanks the same keys for the same
reason and points `DATABASE_URL` at its own temp file — a harness that silently called live public APIs
would report numbers nobody could reproduce.

---

## 4. What is not covered

Stated plainly, because an undocumented gap is indistinguishable from an oversight:

| Gap | Detail |
|---|---|
| **No frontend component or browser tests** | `typecheck` and `build` are the enforced frontend gates. Nothing asserts rendering, routing or interaction behaviour |
| **No adversarial / evasion suite** | No attacker is adapting to these rules, so character substitution, image-only payloads and non-English social engineering are untested |
| **No latency, throughput or memory tests** | Request latency is dominated by live provider calls and is not characterised |
| **No load, throughput or memory testing** | The image-concurrency cap has behavioural tests but no stress test, no *measured* memory ceiling and no multi-worker characterisation; the rate limiter is in-process and SQLite is single-writer, and neither is stress-tested |
| **No dependency or licence audit** | Versions are pinned; nothing scans them for advisories |

---

## 5. Opt-in live suites

These require real credentials and are never part of the default run. They assert the **integration
contract** — provider selection, verdict normalisation and the honesty of failures — not any accuracy
figure, because live reputation services return whatever they return on the day.

| Suite | Enable with | Also requires |
|---|---|---|
| `test_threat_intel_live.py` | `RUN_LIVE_INTEL_TESTS=1` | `GOOGLE_SAFE_BROWSING_API_KEY` and/or `VIRUSTOTAL_API_KEY` |
| `test_threat_intel_live.py` (LLM test) | `RUN_LIVE_LLM_TESTS=1` | `LLM_PROVIDER=openai_compatible` + a non-empty `LLM_API_KEY` |
| `test_ocr_live.py` | `RUN_LIVE_OCR_TESTS=1` | A `tesseract` binary on `PATH` |

```bash
cd backend
RUN_LIVE_INTEL_TESTS=1 RUN_LIVE_LLM_TESTS=1 .venv/Scripts/python.exe -m pytest tests/test_threat_intel_live.py -q
RUN_LIVE_OCR_TESTS=1 .venv/Scripts/python.exe -m pytest tests/test_ocr_live.py -q
```

Skipped tests are the expected outcome when the switches are unset — that is why the default run reports
`11 skipped` rather than a failure. Never set these switches in CI.

---

## 6. Writing a test

Conventions this repository follows:

- Use the `client` fixture (`fastapi.TestClient`) for anything that should exercise the real pipeline
  through HTTP — that is what the corpus suite does, and it is why its assertions are trustworthy.
- Prefer **band** assertions over exact-score assertions. Scores are calibration-sensitive; bands are the
  contract. Exact-score assertions make a suite brittle without making it stronger.
- Test the honesty paths, not just the happy path: a provider failure must be *no information*, a mock
  must be labelled, an unreadable image must produce an error rather than fabricated text.
- Parametrise over the corpus when the assertion is uniform across cases (see
  `test_evaluation_corpus.py`).
- If you fix a detection bug, add the input as a corpus case — see
  [EVALUATION.md §1.6](EVALUATION.md#16-adding-a-case). A fix without a case is a fix that can regress
  silently.

---

## 7. Interpreting a failure

| Failure | Meaning |
|---|---|
| A corpus case fails its band | A calibration regression. Fix the engine or, if the engine genuinely cannot decide, flag the case `known_hard_case` with a written reason — never loosen the expectation silently |
| A benign hard negative scores above `LOW` | A false positive, the most serious class of bug here. It means a rule or signal is firing without requiring scam context |
| `evaluate_detection.py` reports F1 below 1.0 | Aggregate damage from the same regression; read the per-case table it prints to find which cases moved |
| A live suite fails | Almost always the environment: missing key, exhausted quota, or a changed upstream response. These suites verify contract shape, so a genuine failure means the normalisation no longer matches reality |
| The frontend build fails but typecheck passes | Usually a server/client boundary issue — a client component importing server-only code |
| Tests pass locally but the harness numbers differ | You have uncommitted rule or corpus edits, or a stale `.joblib` artifact. Retrain if the rule matcher changed |

If a failure looks impossible, confirm which revision and which database you are on
(`git rev-parse HEAD`, and the `database` field in `/api/health`) before assuming the test is wrong.
