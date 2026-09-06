# AI Digital Scam Investigator

An agentic cybersecurity application that investigates suspicious digital communications —
emails, SMS/WhatsApp, social-media messages, job offers, payment requests, URLs and screenshots —
and produces a structured, evidence-backed risk report.

It is **not** a "send text to an LLM and ask if it is a scam" wrapper. Submissions go through a
deterministic, multi-step investigation pipeline:

```
INPUT → evidence extraction → LangGraph investigation (parallel, conditional branches)
     → evidence correlation → deterministic risk scoring → LLM explanation → investigation report
```

## Features

- **Multiple evidence types** — text, explicit URLs, screenshots (local OCR with graceful fallback),
  or any combination in one submission.
- **Structured evidence extraction** — URLs (structural + heuristic analysis), emails, phone
  numbers, monetary amounts, dates, OTP/code references, known organizations/brands.
- **Deterministic scam-pattern rules** — a declarative rule engine across 10+ scam categories
  (job, banking, investment, delivery, lottery, tech-support, romance, account takeover, crypto,
  advance-fee, phishing, payment…), configurable rather than prompt-hacked.
- **Real ML layer** — Logistic Regression trained on a generated (fictional) dataset using the same
  feature extractor the live backend uses; ships as a `.joblib` pipeline with an honest evaluation
  report. No model → calibrated heuristic fallback clearly marked as *mock*. The training pipeline
  uses a validated dataset loader (CSV/JSON/JSON-lines) with documented schema, duplicate/format
  validation, a stratified train/validation/test split and hard guards that keep the evaluation
  corpus out of training data — so a vetted real dataset drops in without code changes.
- **LangGraph orchestration** — typed state, conditional routing, parallel specialised branches.
  Unneeded agents (OCR/URL/entity analysis) never run.
- **Threat-intelligence provider abstraction** — `MockThreatIntelProvider` (default),
  `GoogleSafeBrowsingProvider`, `VirusTotalProvider`. Providers activate only when keys are
  configured; mock results are always labelled as mock. Provider responses are normalized at the
  boundary (`verdict`/`status`/`categories`/`reputation`/timestamp), queried concurrently, and a
  provider outage, timeout or rate limit never crashes an investigation and is never treated as a
  clean verdict.
- **LLM provider abstraction** — deterministic local provider by default; OpenAI-compatible
  provider when `LLM_API_KEY` is set. LLMs only ever receive structured evidence and are bound by
  an evidence-only prompt contract; malformed/empty LLM output falls back to the deterministic
  explanation, and the LLM can never change the deterministic risk score.
- **Deterministic risk engine** — weighted 0–100 score with level (LOW/MEDIUM/HIGH/CRITICAL),
  confidence, configurable weights, and per-factor contributing evidence.
- **URL-anchored normalization** — when strong URL evidence exists (brand impersonation, punycode/
  homoglyph lookalikes, credential/phishing paths, or a suspicious/malicious intel verdict) the
  engine stops letting *silent* text channels dilute the score, so a strong malicious link next to
  neutral text stays meaningfully risky while an official URL next to benign text stays LOW.
- **Evidence sufficiency** — every assessment is labelled INSUFFICIENT / PARTIAL / SUFFICIENT and
  the UI/report wording makes clear that “low risk based on little evidence” is not “verified
  safe”. Sparse inputs never get a confident verdict.
- **Evidence correlation** — signals are grouped into themes, checked for corroboration/conflicts,
  and used to explain *why* a conclusion was reached.
- **Investigation reports** — summary, risk, scam type, timeline, suspicious indicators, likely
  objective, recommended actions, limitations.
- **FastAPI + PostgreSQL** (SQLite zero-setup local fallback), **Next.js dashboard**, **Docker**,
  **structured logging**, upload validation, rate limiting.

## Tech stack

| Layer    | Technology |
|----------|------------|
| Backend  | Python 3.13, FastAPI, Pydantic v2, SQLAlchemy 2 (async) |
| Agentic  | LangGraph (typed state, conditional edges, parallel branches) |
| ML/NLP   | scikit-learn, custom regex/rule engines |
| OCR      | pytesseract (auto-detected) with mock fallback |
| Database | PostgreSQL 16 (docker) or SQLite (local fallback) |
| Frontend | Next.js 15 (App Router), React 19, TypeScript, Tailwind |
| Infra    | Docker Compose |

## Repository layout

```
backend/
  app/
    api/            FastAPI routers (health, investigations, analyze, demo)
    agents/         LangGraph nodes (parser, OCR, analysis, risk, explain, report…)
    analysis/       linguistic text-signal detection
    core/           config, logging, security, rate limiting
    extraction/     text/entity/URL extraction, OCR provider
    graph/          typed LangGraph state + workflow builder
    intelligence/   threat-intel providers + manager
    llm/            provider abstraction + prompt templates
    ml/             feature extraction, classifier, inference service, saved model
    models/         SQLAlchemy ORM models
    patterns/       declarative scam rules + matching engine
    risk/           deterministic risk engine + evidence correlation
    schemas/        Pydantic contracts
    services/       investigation service, demo cases
    main.py         FastAPI entry point
  scripts/evaluate_detection.py   realistic-corpus detection evaluation harness
  scripts/ml_training/            dataset generator, trainer, evaluator
  data/evaluation/                realistic corpus + generated evaluation reports
  tests/                          unit + integration tests
  requirements.txt
frontend/
  app/              pages (dashboard, investigate, results/[id], history)
  components/       UI atoms + investigation views
  lib/              API client + shared types
ml (in backend/scripts/ml_training)      training pipeline artifacts
docker-compose.yml  postgres + backend + frontend
.env.example        all configurable variables
```

## Quick start (no Docker required)

Local mode uses SQLite and demo providers — everything runs without paid APIs or a database server.

### Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt                   # macOS/Linux

.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000
```

OpenAPI docs: http://localhost:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
```

The Next dev server proxies `/api/*` to `http://localhost:8000` (set `BACKEND_URL` to override).

### Try it

- Dashboard → “Try a sample investigation” runs one of the fictional demo cases end-to-end.
- New investigation → paste a message, add URLs, upload a screenshot.

## Docker (PostgreSQL + backend + frontend)

```bash
cp .env.example .env     # optional — demo mode works without it
docker compose up --build
```

- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs
- PostgreSQL: `scaminv` / `scaminv` on port 5432 (internal to the compose network)

## Environment variables

See `.env.example`. Summary:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///…/app.db` | `postgresql+asyncpg://…` in docker |
| `LLM_PROVIDER` | `mock` | `mock` or `openai_compatible` |
| `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL` | — | Enable live LLM explanations |
| `GOOGLE_SAFE_BROWSING_API_KEY` | — | Live URL reputation checks |
| `VIRUSTOTAL_API_KEY` | — | Live VT lookup |
| `OCR_PROVIDER` / `TESSERACT_BINARY` | `auto` | `auto`/`tesseract`/`mock` |
| `RATE_LIMIT_PER_MINUTE`, `MAX_UPLOAD_MB`, `MAX_TEXT_LENGTH` | 30 / 10 / 50000 | API hardening |

Keys are read from the environment or a `.env` file in `backend/` (docker reads root `.env`).
Never commit real keys.

## Detection evaluation (calibration corpus)

A realistic corpus of 64 fully fictional cases (24 benign — including hard
negatives like legit 2FA / OTP warnings, receipts and an official-URL
security notice with scam-like vocabulary — plus 40 scams across 14
categories, URL-only attacks, combined submissions and Phase-3
URL-anchoring/insufficient-evidence cases) measures how well the
investigation engine distinguishes benign from scam content:

```bash
cd backend
.venv/Scripts/python.exe scripts/evaluate_detection.py
```

Every case runs through the **real** API pipeline. The harness reports binary
metrics (accuracy / precision / recall / F1, overall and per input type),
category accuracy with a confusion matrix, a risk-calibration table, and
confidence-honesty checks into `data/evaluation/evaluation_report.{json,md}`.

Calibration semantics: benign cases must stay LOW (a false positive on any
hard negative fails the corpus regression tests), several independent
signals land MEDIUM, and HIGH requires corroboration from request channels
(OTP/credential/payment/suspicious-instructions) or URL/intel evidence.
A strong URL next to neutral text must NOT be diluted to LOW (URL-anchored
normalization), and sparse inputs are reported with INSUFFICIENT/PARTIAL
evidence rather than confident verdicts. Cases the deterministic engine
honestly cannot disambiguate (e.g. an unsolicited shared-document link) are
marked `known_hard_case` with a documented reason instead of being forced
into a verdict.

Live-provider positive/negative verdicts, provider outages/timeouts/rate
limits and LLM failure modes are covered by dedicated opt-in integration
tests (see “Testing” below) — a corpus entry cannot carry per-run provider
state, so those scenarios are exercised with mocked transports offline and
real keys when configured.

## Machine learning

The classifier is trained on the *same* feature extractor used at inference time.

```bash
cd backend
.venv/Scripts/python.exe scripts/ml_training/generate_dataset.py --per-category 130
.venv/Scripts/python.exe scripts/ml_training/train.py
# optional: evaluate any labelled dataset against the saved model
.venv/Scripts/python.exe scripts/ml_training/evaluate.py --dataset path/to/labelled.csv
```

- Saves pipeline → `app/ml/models/lr_scam_model.joblib`
- Writes an honest evaluation report → `data/datasets/evaluation_report.json`
- `train.py` validates the dataset through `app/ml/dataset.py` (required fields, valid labels,
  category checks, duplicate/malformed-row handling), prints dataset statistics, performs a
  stratified train/validation/test split, and reports precision/recall/F1 + confusion matrix on
  the test split. The dataset's origin (`synthetic` vs `real`) is printed and stored.
- The evaluation corpus (`data/evaluation/`) is **refused as training data** and row-ids that
  overlap evaluation cases are rejected, so the calibration corpus can never contaminate a model.
- The documented real-dataset schema and data-honesty policy live in
  `backend/data/datasets/README.md`; stage vetted real data in
  `backend/data/datasets/real/` and train with `--dataset`.
- The bundled metrics were measured on a held-out split of the **synthetic** demo dataset and are
  indicative only — retrain on a real, vetted corpus before operational use.
- `train.py --keep-duplicates` keeps repeated template draws in the synthetic set (the shipped
  Phase-2-compatible model is trained this way); real datasets default to duplicate removal.

## API

| Method | Path | Description |
|---|---|---|
| POST | `/api/investigations` | Submit text + URLs + image (multipart) → runs full investigation |
| POST | `/api/analyze/text` | JSON convenience: `{text, urls?, title?}` |
| POST | `/api/analyze/url` | Analyse one URL |
| POST | `/api/analyze/image` | Screenshot (+optional text) |
| GET  | `/api/investigations` | History with `search`, `risk_level`, `scam_type`, paging |
| GET  | `/api/investigations/{id}` | Full detail view |
| DELETE | `/api/investigations/{id}` | Remove an investigation |
| GET  | `/api/demo` / POST `/api/demo/{slug}` | List / run fictional demo cases |
| GET  | `/api/health` | Status incl. which providers are live vs mock |

## Testing

```bash
cd backend
.venv/Scripts/python.exe -m pytest tests/ -q        # unit + API + graph + corpus + Phase-3 tests
.venv/Scripts/python.exe scripts/end_to_end_smoke.py   # 12 end-to-end smoke flows
.venv/Scripts/python.exe scripts/evaluate_detection.py # 64-case corpus harness
```

Frontend typecheck/build: `cd frontend && npm run typecheck && npm run build`.

### Live integration tests (opt-in)

The normal suite is fully offline/deterministic. Live provider and LLM checks
run only when explicitly enabled with **both** the switch and the matching
key (otherwise they are skipped):

```bash
# Windows (export on POSIX)
set RUN_LIVE_INTEL_TESTS=1
set GOOGLE_SAFE_BROWSING_API_KEY=...
set VIRUSTOTAL_API_KEY=...
python -m pytest tests/test_threat_intel_live.py -q

set RUN_LIVE_LLM_TESTS=1
set LLM_PROVIDER=openai_compatible
set LLM_API_KEY=...
python -m pytest tests/test_threat_intel_live.py::test_live_llm_explanation_is_grounded_and_non_mock -q
```

The live tests only query public benign sample URLs (example.com,
wikipedia.org) — never private content. Without a key (or the switch) those
tests are skipped. Provider outage/timeout/rate-limit behaviour and LLM
malformed/empty-output fallback are exercised offline with mocked transports
in `tests/test_phase3.py`, so the default suite never depends on the network.

Configuration status (demo vs live) is always visible: `GET /api/health`
reports which providers are active (`providers.llm.is_mock`,
`providers.threat_intel.active`/`uses_mock`, `providers.ocr.is_mock`) plus a
`demo_mode` boolean — key values are never included.

## Security & privacy notes

- All submitted content is treated as untrusted; uploads are size/MIME-limited and never executed.
- URL analysis is metadata/structural only — no fetching of arbitrary URLs from the backend, so no
  SSRF surface. Real reputation checks go through provider APIs; there is no URL fetching, no
  redirect following and no localhost/private-IP access from the server.
- API keys live only on the backend; the frontend never sees them, they are never logged, never
  stored in reports/evidence, and never committed (`.env` is git-ignored).
- Threat-intel provider failures are normalized into `unavailable`/`rate_limited`/`error` states
  with `verdict=unknown` — an outage can never masquerade as a clean result.
- OCR and demo providers run locally; in demo mode no content is sent anywhere.
- LLM calls (when configured) send the supplied evidence to the configured provider — run a local
  OpenAI-compatible endpoint for fully air-gapped operation.
- Structured logging tracks investigation IDs, stages and durations without logging message bodies.

## Demo mode & honesty

Without API keys the app runs fully in demo mode, and says so in the UI and API:
- explanations are **deterministic** (rule-based), clearly labelled instead of pretending to be LLM output;
- threat intelligence and OCR use honest mocks (labelled `[DEMO]`);
- the ML model is real once trained; otherwise a labelled heuristic fallback is used.

## Known limitations

- Demo dataset is synthetic; model metrics are not production evidence (see ML section).
- There is no committed real-world training dataset yet — the pipeline, schema and validation are
  ready, but no metrics are claimed from real data.
- The 7-digit phone pattern can produce false positives on short numeric strings in context.
- The rule/keyword engines are English-centric.
- Deterministic explanations are concise; LLM mode adds nuance but never external facts.
- Live providers are queried per-URL sequentially; very long submissions with many URLs can take a
  while when multiple live providers are configured.
- The bundled langgraph 0.2.x release mis-schedules uneven branch merges — the workflow builder
  equalizes branch depth to work around it (see `backend/app/graph/builder.py` notes).

## Future improvements

- Real training corpus + model registry, per-category multiclass head.
- User accounts, per-investigation sharing, PDF/email report export.
- Additional intel providers (URLScan, PhishTank, domain-age WHOIS), IP/ASN enrichment.
- OCR fine-tuning for screenshots; multilingual keyword dictionaries.
- Background job queue for long investigations; timeline streaming during runs.
