# Contributing — AI Digital Scam Investigator

Contributions are welcome: bug reports, detection rules, provider integrations, tests, documentation,
and honest pushback on design decisions.

This document is the long form. The README carries the short version.

**Out of scope for now:** authentication, multi-tenancy, and anything that turns this single-tenant
local tool into a hosted service. Those are architectural changes, not patches — open an issue to
discuss the direction first.

---

## Contents

| # | Section |
|---|---|
| 1 | [Development setup](#1-development-setup) |
| 2 | [Repository map: where to change what](#2-repository-map-where-to-change-what) |
| 3 | [Invariants you must preserve](#3-invariants-you-must-preserve) |
| 4 | [Test gates by change type](#4-test-gates-by-change-type) |
| 5 | [Changing detection logic](#5-changing-detection-logic) |
| 6 | [Adding an evaluation case](#6-adding-an-evaluation-case) |
| 7 | [Adding or changing a provider](#7-adding-or-changing-a-provider) |
| 8 | [Frontend changes](#8-frontend-changes) |
| 9 | [Documentation duties](#9-documentation-duties) |
| 10 | [Commits and pull requests](#10-commits-and-pull-requests) |
| 11 | [What will not be merged](#11-what-will-not-be-merged) |
| 12 | [Review checklist](#12-review-checklist) |

---

## 1. Development setup

No API keys are needed for anything below: the default configuration is fully offline and
deterministic (**demo mode** — mock threat intel, mock LLM, real ML artifact, local SQLite).

```bash
# Backend
cd backend
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt                   # macOS / Linux

# Frontend
cd ../frontend
npm install
```

Run them in two terminals — `uvicorn app.main:app --reload --port 8000` and `npm run dev`
(`http://localhost:3000`). The Next dev server proxies `/api/*` to the backend, so the browser never
needs CORS or the backend origin. Full walkthrough: [README Quick start](../README.md#quick-start).

Optional, and never required for a normal contribution:

| Switch | Enables |
|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` / `VIRUSTOTAL_API_KEY` | Live threat intel |
| `LLM_PROVIDER=openai_compatible` + `LLM_API_KEY` (+ `LLM_BASE_URL`, `LLM_MODEL`) | Live explanations |
| A `tesseract` binary on `PATH` | Real OCR (`OCR_PROVIDER=auto` picks it up) |
| `RUN_LIVE_INTEL_TESTS=1` / `RUN_LIVE_LLM_TESTS=1` / `RUN_LIVE_OCR_TESTS=1` | The opt-in live test suites |

Keys belong in `backend/.env` (git-ignored) or the process environment — never in source, never in the
frontend, never in a URL query parameter. Start from `backend/.env.example`, which leaves
`DATABASE_URL` unset so the verified local SQLite store is used.

---

## 2. Repository map: where to change what

| I want to change… | Edit | Watch out for |
|---|---|---|
| A scam rule (keywords, regex variants, weight, category) | `backend/app/patterns/rules.py` | Invalidates the ML artifact — see [§5](#5-changing-detection-logic) |
| Category ranking / rule matching | `backend/app/patterns/engine.py` | Feeds the model's `scam_keyword_hits` feature |
| Linguistic signal phrases | `backend/app/analysis/text_signals.py` | Request-vs-mention semantics live here |
| URL structural analysis | `backend/app/extraction/url_analysis.py` | Must stay non-fetching |
| Entity/brand detection | `backend/app/extraction/entity_extractor.py` | — |
| Risk weights, bands, applicability, sufficiency | `backend/app/risk/engine.py` | The decision path — tests will notice |
| Evidence correlation / consistency | `backend/app/risk/correlation.py` | Runs before the LLM, on purpose |
| Pipeline stages or routing | `backend/app/agents/*`, `backend/app/graph/builder.py` | Equal-depth `*_pad` branches exist for a LangGraph reason — read [ARCHITECTURE.md](ARCHITECTURE.md) §4 first |
| ML features | `backend/app/ml/features.py` | Shared by training and inference; requires retraining |
| Training / split / metrics | `backend/scripts/ml_training/` | Deterministic seed; contamination guard in `ml/dataset.py` |
| A threat-intel provider | `backend/app/intelligence/` | Normalise to `ThreatIntelResult`; failures are never clean |
| An LLM provider | `backend/app/llm/` | The LLM stays out of the decision path |
| OCR behaviour | `backend/app/extraction/ocr.py` | Never fabricate extracted text |
| API routes or contracts | `backend/app/api/routes/`, `backend/app/schemas/` | Document in [API.md](API.md) |
| Persistence / filters | `backend/app/services/investigation_service.py` | Filters must stay portable across SQLite and PostgreSQL |
| Config or limits | `backend/app/core/config.py`, `.env.example` | Keep README/DEPLOYMENT tables in sync |
| UI, pages, components | `frontend/app/`, `frontend/components/` | Render provider state from `/api/health`; never fabricate data |
| Evaluation corpus | `backend/data/evaluation/evaluation_cases.json` | See [§6](#6-adding-an-evaluation-case) |

Interpreter for every backend command in this document: `backend/.venv/Scripts/python.exe` (Windows)
or `backend/.venv/bin/python` (macOS/Linux).

---

## 3. Invariants you must preserve

These are enforced in code, and a change that breaks one is a bug even if tests pass:

1. **Evidence stays structured and typed.** Stages exchange `EvidenceSignal` objects, not prose.
2. **Risk stays deterministic.** `risk/engine.py` owns the score, band, confidence and sufficiency. No
   LLM output may move any of them.
3. **Applicability drives normalisation.** Channels that could not have fired never dilute the score;
   URL-anchored assessments may also drop applicable-but-silent channels.
4. **No information is never good news.** Provider errors, timeouts, rate limits and malformed inputs
   contribute nothing and never lower risk or produce a clean verdict.
5. **Uncertainty is reported.** `evidence_sufficiency` and confidence accompany every band, and a LOW
   conclusion must not read as "verified safe".
6. **Mocks announce themselves.** `is_mock`, `[DEMO]`, provider modes and the `demo_mode` health flag
   stay truthful and visible.
7. **The application never fetches user-supplied URLs.** Do not add a code path that dereferences a
   submitted link.
8. **The calibration corpus stays green** — `0` false positives on benign cases (including the hard
   negatives) and every scam case reaching its documented band and category.

What to do with a case you believe the engine genuinely cannot decide: do **not** quietly loosen an
expectation. Either fix the engine, or flag the case `known_hard_case` with a written reason so the
honest limitation is visible in the corpus.

---

## 4. Test gates by change type

Run the gates that cover what you touched, and paste the output into the pull request.

| Change | Gates |
|---|---|
| Anything backend | `pytest tests/ -q` |
| Detection rules, signals, URL analysis, risk engine, correlation | `pytest tests/ -q` **and** `scripts/evaluate_detection.py` |
| API routes, schemas, persistence | `pytest tests/ -q` **and** `scripts/end_to_end_smoke.py` |
| ML features or training | `pytest tests/ -q`, then retrain, then `scripts/evaluate_detection.py` |
| Frontend | `npm run typecheck` **and** `npm run build` |
| Documentation only | none required — but verify links and commands you changed |

```bash
cd backend
.venv/Scripts/python.exe -m pytest tests/ -q
.venv/Scripts/python.exe scripts/evaluate_detection.py
.venv/Scripts/python.exe scripts/end_to_end_smoke.py

cd ../frontend
npm run typecheck
npm run build
```

`npm run lint` is **not** a usable gate: `next lint` opens an interactive prompt to configure ESLint,
and no ESLint config is committed. Please do not add a lint config just to report a passing badge —
if you want linting, propose it as a deliberate, configured change.

Live suites are opt-in and are excluded from the default run on purpose; the offline suites are
hermetic (`tests/conftest.py` pins providers to their mocks so a developer's real keys cannot turn
`pytest` into a network run).

---

## 5. Changing detection logic

Rules are the highest-leverage and highest-risk change in this repository, because **rule matching also
produces the model's `scam_keyword_hits` feature**. Changing rules without retraining leaves the shipped
artifact inconsistent with the code that feeds it.

Workflow for a rule change:

1. Add or adjust the rule in `patterns/rules.py`. If the trigger is a phrase that can appear in
   variations (`guaranteed 40% returns`, `risk-free`, hyphenation, spacing), add a declarative **regex
   variant** (`ScamRule.patterns`) rather than a literal keyword — the literal matcher compares a whole
   token sequence with word boundaries and will miss it.
2. If the phrase is harmful only in context, add the appropriate gate
   (`requires_request_context`, `required_entities`) instead of raising the weight. A status notice
   that merely *mentions* a parcel is not evidence; a status notice that *demands payment* is.
3. Check the hard negatives in `tests/test_calibration.py` and the corpus's `hard_negatives` — a rule
   that lifts a genuine receipt, carrier notice, security warning or OTP message above `LOW` is a
   regression, not a win.
4. Run the gates in [§4](#4-test-gates-by-change-type).
5. **Retrain and re-validate**:
   ```bash
   cd backend
   .venv/Scripts/python.exe scripts/ml_training/train.py \
     --dataset data/datasets/real/sms_spam_uci.csv --no-categories
   ```
   Report the held-out metrics from `data/datasets/evaluation_report.json` in the pull request, even if
   they are unchanged or slightly worse. Do not tune the threshold on the test split.
6. If you added a rule to fix a real miss, add the message as an evaluation case ([§6](#6-adding-an-evaluation-case)).

---

## 6. Adding an evaluation case

An evaluation case is a permanent assertion, so it comes with obligations. The full protocol is in
[EVALUATION.md §1.6](EVALUATION.md#16-adding-a-case); the short version:

- Add the case to `backend/data/evaluation/evaluation_cases.json` with `expected.is_scam`,
  `expected.minimum_risk_level` and `expected.primary_category` (`unknown` when no category may be
  asserted).
- List `acceptable_categories` only for alternatives you would defend in review.
- Register genuinely adversarial cases in the `hard_negatives` / `hard_positives` lists.
- Run the harness **and** `pytest` — a case that passes one and not the other is not finished.
- Never edit an existing expectation to silence a regression, and never present the resulting
  calibration percentage as real-world accuracy.

---

## 7. Adding or changing a provider

Threat-intel providers implement `intelligence/base.py` and must return the normalised
`ThreatIntelResult`. Requirements:

- **Normalise at the boundary** — nothing downstream should see a provider-specific payload.
- **Failures are no information**: HTTP errors, timeouts, 5xx and rate limits become `verdict="unknown"`
  with the correct `status` (`error` / `unavailable` / `rate_limited`). Never map a failure to `safe`,
  and never map a `404` "not seen" to clean.
- **Authenticate by header**, never by URL query parameter — request URLs leak into client and proxy
  logs.
- **Label mocks** with `is_mock=True` and keep `is_mock` accurate in the merged result.
- **Register it in `_default_providers()`** so `/api/health` reports it truthfully, and update the
  provider table in [ARCHITECTURE.md](ARCHITECTURE.md) §9 and the status table in the README.
- **Test both directions**: a real verdict and a failure (see `tests/test_phase3.py` for the pattern).
- Add an opt-in live test gated on your key, following `tests/test_threat_intel_live.py`.

The same contract discipline applies to an LLM provider, with one extra rule: it must not be able to
change the verdict, and a malformed or failed response must fall back to deterministic output.

---

## 8. Frontend changes

- Gates: `npm run typecheck` and `npm run build` (these are the enforced checks).
- **Never** introduce a `NEXT_PUBLIC_*` variable. Provider keys are backend-only; the UI displays
  provider *status* from `/api/health`, never values.
- Render provider and demo state honestly: if the backend reports `is_mock` / `uses_mock` /
  `demo_mode`, the UI must say so rather than implying a live integration.
- **No fabricated data.** Dashboard KPI cards, charts and trends come from real API responses only;
  placeholder "trend" numbers are not acceptable.
- Keep result rendering driven by real fields — the "Why this score?" panel reads the `contributors`
  array, not a written narrative.
- Accessibility and keyboard navigation for interactive controls are appreciated and reviewed.

---

## 9. Documentation duties

Documentation is part of the change, not a follow-up:

- Behaviour, configuration, metrics or endpoints changed → update the affected doc **in the same pull
  request**. The docs to consider: [README](../README.md), [ARCHITECTURE](ARCHITECTURE.md),
  [EVALUATION](EVALUATION.md), [API](API.md), [SECURITY](SECURITY.md), [DEPLOYMENT](DEPLOYMENT.md),
  [ROADMAP](ROADMAP.md), [data/datasets/README](../backend/data/datasets/README.md).
- **Never overstate.** Do not present calibration-corpus numbers as real-world accuracy, do not claim a
  deployment, integration or database path was verified when it was not, and do not add badges or
  screenshots that do not correspond to something real.
- If you introduce a limitation, document it. An undocumented limitation is indistinguishable from an
  oversight.

---

## 10. Commits and pull requests

- Commit messages follow the repository's conventional style: `feat:`, `fix:`, `docs:`, `chore:`, with
  an optional scope — e.g. `fix(patterns): …`, `docs(evaluation): …`. Describe **why** the change is
  needed, not just what moved.
- One logical change per commit. Empty, whitespace-only and "fix typo in previous commit" commits are
  not wanted; squash before opening the pull request.
- Keep the diff focused. Unrelated reformatting makes review harder and is usually asked to be split
  out.
- Never commit: `.env` files or any credential, database files (`*.db`), generated evaluation reports
  under `backend/data/evaluation/`, uploaded images, or editor/session metadata.
- Never force-push a shared branch.

---

## 11. What will not be merged

| Change | Why |
|---|---|
| Fabricated screenshots or screenshots of a mock UI presented as live | The README deliberately ships a placeholder until real captures exist |
| A CI or coverage badge with no workflow behind it | No `.github/` workflows exist; a badge would be a false claim |
| "100% accurate" / "detects all scams" wording, or calibration results framed as real-world accuracy | The corpus is 64 fictional cases; the ML metrics are SMS-scoped |
| Removing or softening an honesty caveat (mock labelling, `demo_mode`, failure semantics, LOW-means-insufficient wording) | Those caveats are features |
| Hardcoding a key, endpoint secret or user credential | Also a security incident |
| Committing `.env`, `*.db`, uploads or generated reports | Runtime artifacts, never source |
| Weakening or deleting a test/expectation to make a regression disappear | Fix the engine or document the limitation |
| Silent mock/fallback substitution in place of a real provider failure | Degradation must be visible |

---

## 12. Review checklist

Before opening a pull request:

- [ ] I ran the gates for what I touched ([§4](#4-test-gates-by-change-type)) and will paste the output.
- [ ] Detection logic changes: I retrained the artifact and reported the held-out metrics.
- [ ] The eight invariants ([§3](#3-invariants-you-must-preserve)) still hold.
- [ ] No secret, `.env`, database file, upload or generated report is included in the diff.
- [ ] Documentation is updated where behaviour, configuration, metrics or endpoints changed.
- [ ] Nothing in the change overstates what was verified, deployed or measured.
- [ ] The diff is focused, and the commit messages explain the why.
