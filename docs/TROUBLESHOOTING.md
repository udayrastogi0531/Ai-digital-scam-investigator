# Troubleshooting — AI Digital Scam Investigator

Symptom → cause → fix. Start with the two things that answer most questions:

```bash
curl -s http://localhost:8000/api/health | python -m json.tool   # which providers are really live
git rev-parse HEAD                                              # what revision you are running
```

`/api/health` reports **effective** state, not configuration, so it resolves most "it says live but
behaves like demo" reports on its own.

---

## Contents

| # | Area |
|---|---|
| 1 | [Installation and startup](#1-installation-and-startup) |
| 2 | [Configuration and providers](#2-configuration-and-providers) |
| 3 | [Results that look wrong](#3-results-that-look-wrong) |
| 4 | [Uploads and OCR](#4-uploads-and-ocr) |
| 5 | [Frontend and the proxy](#5-frontend-and-the-proxy) |
| 6 | [Database](#6-database) |
| 7 | [Tests, evaluation and tooling](#7-tests-evaluation-and-tooling) |
| 8 | [Windows specifics](#8-windows-specifics) |
| 9 | [Docker and PostgreSQL](#9-docker-and-postgresql) |
| 10 | [Reporting something that is not on this page](#10-reporting-something-that-is-not-on-this-page) |

---

## 1. Installation and startup

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'app'` | Started from the wrong directory, or the venv was never created | Run `uvicorn` from `backend/`, using the venv interpreter: `cd backend && .venv/Scripts/python.exe -m uvicorn app.main:app --port 8000` |
| `No module named uvicorn` | The venv is active but requirements were never installed into it | `.venv/Scripts/python.exe -m pip install -r requirements.txt` |
| `python` resolves to the wrong interpreter | A system Python was invoked instead of the venv | Always call the venv interpreter explicitly (`backend/.venv/Scripts/python.exe` on Windows, `backend/.venv/bin/python` elsewhere) |
| Port 8000 already in use | A previous run is still listening | Pick another port (`--port 8001`) and point the frontend at it with `BACKEND_URL`, or stop the old process |
| Port 3000 already in use | Same, for Next.js | `npm run dev -- -p 3001` |
| Windows error about `python` or `python3` not found | The launcher name differs by platform | Use `python`; the README shows the interpreter path to call, which sidesteps the question entirely |
| Node errors during `npm install` | Node older than 20 | Install Node ≥ 20; the project uses Next 15 / React 19 |

The application runs with **no configuration at all** — demo mode is fully offline. If startup fails,
it is an environment problem, not a missing key.

---

## 2. Configuration and providers

| Symptom | Cause | Fix |
|---|---|---|
| `/api/health` → `providers.llm.is_mock: true` | `LLM_PROVIDER` is `mock`, or `LLM_API_KEY` is empty | Set both. The key must be non-empty — the factory falls back to mock when either is missing |
| `/api/health` → `providers.threat_intel.uses_mock: true` | Neither reputation key is set | Set `GOOGLE_SAFE_BROWSING_API_KEY` and/or `VIRUSTOTAL_API_KEY` |
| `/api/health` → `providers.ocr.provider: "mock"` | No `tesseract` binary on `PATH` | Install Tesseract, or run the bundled Dockerfile, which installs it |
| Keys are set but the app still reports demo mode | They were set on the **frontend** service | Keys belong to the backend only. There is no `NEXT_PUBLIC_*` variable in this project and there must not be one |
| `backend/.env` seems to be ignored | Real environment variables take precedence over the file | Unset the variable in your shell, or change the shell value — `config.py` gives the process environment priority |
| A local run tries to reach PostgreSQL | You copied the repository's **root** `.env.example` into `backend/.env` — it is the docker-compose template and points `DATABASE_URL` at the `postgres` service name | Use `backend/.env.example` instead, or delete the `DATABASE_URL` line. SQLite is the verified local default |
| Every submission reports the same LOW score in demo mode | Expected: mock threat intel returns a fictional blocklist and the LLM is templated | Configure real providers, or accept demo mode — the ML classifier is real even in demo mode |
| Explanations read as templated even with a key set | The provider failed and the **deterministic fallback** produced the text — by design, so the investigation still completes | Look for `LLM HTTP <code>` in the logs. A 404 usually means the model id is not available to your key; a 429 means quota |
| `HTTP 429 from VirusTotal` | Public API rate limit | Space out lookups. The provider maps it to `status: "rate_limited"` and never treats it as clean |

---

## 3. Results that look wrong

| Symptom | Cause | Fix |
|---|---|---|
| A suspicious message scored `LOW` | `LOW` means "no significant evidence found", not "verified safe" | Check `evidence_sufficiency`. `INSUFFICIENT`/`PARTIAL` means the submission was sparse — submit the full message text, not a fragment, and include URLs explicitly if they appeared in a screenshot |
| A benign message scored above `LOW` | A rule or signal fired without scam context | This is a false positive and a bug worth reporting. Capture the exact input and the `contributors` array, and see [CONTRIBUTING.md](CONTRIBUTING.md#6-adding-an-evaluation-case) for adding it as a regression case |
| A URL-only submission lands below `HIGH` | Without surrounding text there is little corroborating evidence | Add the message the link arrived in — correlation across channels is what lifts URL-anchored assessments |
| The scam **category** looks wrong but the band is right | Categories are decided by deterministic rules; benign look-alikes can inherit a nearby label | The **band** gates the verdict, not the label. Report the mislabel with the input if it is reproducible |
| An LLM suggestion appears to have been ignored | By design: a category the deterministic evidence does not support is recorded as rejected (`classification_suggestion_rejected`) | Nothing to fix — this is the containment working. See [SECURITY.md](SECURITY.md#4-llm-containment-and-prompt-injection) |
| The score changed but no code did | Weights or rules changed, or a provider started answering differently | Compare `risk.weights` and the `contributors` array with a previous run; live reputation coverage changes over time |
| Scores differ between two machines on the same input | One machine has live provider keys and the other does not | Compare `/api/health` on both |

---

## 4. Uploads and OCR

| Symptom | Cause | Fix |
|---|---|---|
| `400 Uploaded file is not a valid image` | The bytes are not decodable by Pillow. The declared content type is deliberately **not** trusted | Re-export the screenshot as PNG/JPEG. A renamed `.txt` will still be rejected, which is the intent |
| `400 File too large (max N MB)` | The upload exceeds `MAX_UPLOAD_MB` (default 10) | Crop or downscale the image, or raise the limit deliberately |
| `400 Image dimensions are too large` | The image header declares more than the 64 M-pixel cap. The cap is applied before the pixels are decoded, so nothing was decompressed | Downscale the image before uploading |
| `400 Image is too large to process safely` | Pillow's own decompression-bomb guard tripped while reading the header (above ~178 M pixels), or the decode ran out of memory | Downscale the image. This is a deliberate rejection, not a bug — see [`SECURITY.md`](SECURITY.md) §2 |
| `503 Image processing is at capacity (N concurrent investigation(s))` | More image investigations are in flight than `MAX_CONCURRENT_IMAGE_OPS` (default 4) permits | Retry after the `Retry-After: 1` interval. Raise the limit deliberately if the host has memory headroom — it is **per process**, so a multi-worker deployment allows that many per worker |
| `OCR unavailable (...) — continuing without extracted text` | No `tesseract` binary, or the process failed | Install Tesseract (`OCR_PROVIDER=auto` detects it), or install `tesseract-ocr` via the Dockerfile |
| OCR extracts text but the investigation still looks thin | OCR text joins the same pipeline as typed text; a screenshot of a short message yields weak evidence | Add the message context as text alongside the image |
| Nothing is ever written to `backend/data/uploads/` | Correct — screenshots are decoded and analysed **in memory** and are never persisted. The directory may exist from an older revision | Nothing to fix. This is a privacy property, not a failure |

---

## 5. Frontend and the proxy

| Symptom | Cause | Fix |
|---|---|---|
| The page loads but every request returns 502 | `BACKEND_URL` is wrong, or the backend is down | Confirm `/api/health` answers directly, then set `BACKEND_URL` correctly and restart the dev server |
| Requests go to the wrong host | The Next proxy target is read from `BACKEND_URL` at startup | Restart `npm run dev` after changing it |
| A CORS error appears | You are calling the backend origin directly rather than through the Next proxy | Use the proxy (the default), or add the origin to `CORS_ORIGINS` |
| Pages render "not configured" while keys are set | Keys live on the frontend service, or the backend needs a restart to pick them up | Move the keys to the backend; the UI reflects `/api/health` on the next load |
| `npm run lint` opens an interactive prompt | `next lint` has no committed ESLint config by design | Do not use it as a gate. `npm run typecheck` and `npm run build` are the enforced frontend checks — see [TESTING.md](TESTING.md) |

---

## 6. Database

| Symptom | Cause | Fix |
|---|---|---|
| `sqlite3.OperationalError: database is locked` | Concurrent writes against SQLite (single-writer by design) | Reduce concurrent submissions, or use PostgreSQL for multi-worker setups |
| Tables look empty after a restart | A different database file is in play | Check the `database` field in `/api/health`; with `DATABASE_URL` unset the file is `backend/data/app.db` |
| `asyncpg` connection refused | `DATABASE_URL` points at a PostgreSQL that is not running | Start PostgreSQL, or remove `DATABASE_URL` to fall back to SQLite |
| A schema error after pulling a change | There is no migration framework; `create_tables()` only adds missing tables | Use a fresh database (delete `backend/data/app.db`) or write the migration yourself |
| History has rows you did not create | The store is a single shared table with no tenancy — every run and test writes into it unless a temp URL is set | Delete rows via the API, or point `DATABASE_URL` at a scratch file for experiments |

---

## 7. Tests, evaluation and tooling

| Symptom | Cause | Fix |
|---|---|---|
| A live test is `skipped` | The opt-in switches are unset — this is intentional | Export the relevant `RUN_LIVE_*` variable *and* provide credentials (see [TESTING.md](TESTING.md#5-opt-in-live-suites)) |
| Calibration assertions fail locally but pass in CI/another machine | A real `backend/.env` was picked up | The suites blank provider keys for exactly this reason; if you still see drift, confirm you have not edited the corpus or the rule engine |
| `Untagged`/unexpected classification after changing the model | The `.joblib` artifact no longer matches the feature code | Retrain: `scripts/ml_training/train.py --dataset data/datasets/real/sms_spam_uci.csv --no-categories` |
| `data/evaluation/evaluation_report.*` shows in `git status` after running the harness | It is a generated artifact and is git-ignored | Expected — do not commit it |
| Evaluation numbers differ from the README | You changed the corpus, the rules, or the artifact | Regenerate and report the new numbers honestly; see [EVALUATION.md](EVALUATION.md) |

---

## 8. Windows specifics

| Symptom | Cause | Fix |
|---|---|---|
| `curl -F` uploads fail or `curl` prints a progress table | PowerShell aliases `curl` to `Invoke-WebRequest`, which does not accept `-F` | Use Git Bash / WSL, or `curl.exe`, for the documented commands — or use the Swagger UI at `http://localhost:8000/docs` |
| A multi-line `curl` with `\` does not work | PowerShell uses a backtick for line continuation | Run it in Git Bash, or keep it on one line |
| `npm run dev` reports `EPERM` on a port | Another process holds the port | Change the port (`npm run dev -- -p 3001`) |
| Python scripts print `UnicodeEncodeError` | The console code page cannot render a character | Set `PYTHONIOENCODING=utf-8`, or use Git Bash |
| A JSON file read gives `UnicodeDecodeError` | Some generated reports contain non-UTF-8 bytes | Read them with `encoding="utf-8"`, as the application code does |

---

## 9. Docker and PostgreSQL

These paths are **configuration only** in this repository — they have never been executed here (see
[DEPLOYMENT.md](DEPLOYMENT.md) for the verified/unverified split). If you exercise them:

| Symptom | Cause | Fix |
|---|---|---|
| `docker compose up` warns about the env file or fails to parse it | The root `.env` was hand-edited into something that is not `KEY=value` | Recreate it from the root `.env.example` |
| The backend container cannot reach the database | `DATABASE_URL` points at `localhost` inside a container | Use the compose service name: `postgresql+asyncpg://scaminv:scaminv@postgres:5432/scaminv` |
| OCR works locally but not in the container | Tesseract missing from the image | The bundled `backend/Dockerfile` installs `tesseract-ocr`; use it rather than a stock Python image |
| The frontend container cannot reach the backend | `BACKEND_URL` still points at `localhost` | Set it to `http://backend:8000` |
| Health checks flap | PostgreSQL not ready when the backend starts | The compose file has a `pg_isready` healthcheck with `depends_on` — keep it |

---

## 10. Reporting something that is not on this page

For a correctness or detection-quality problem, open a GitHub issue with:

1. the exact input (redact anything real or personal),
2. the response's `risk` block — score, level, `evidence_sufficiency` and `contributors`,
3. your `/api/health` output (it states which providers were live),
4. the revision you ran (`git rev-parse HEAD`).

For a security concern, do **not** open a public issue — use the private advisory flow described in
[SECURITY.md](SECURITY.md#8-reporting-a-vulnerability).
