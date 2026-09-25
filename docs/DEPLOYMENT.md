# Deployment Guide — ScamIntelligence / AI Digital Scam Investigator

This guide covers deploying the two application services and their data store.

| Component | Runtime | Suggested host |
|---|---|---|
| Frontend (Next.js 15) | Node.js 20/22 | Vercel (or any Node host) |
| Backend (FastAPI + LangGraph) | Python 3.13 | Railway / Render / Fly.io / any container host |
| Database | SQLite (local) or PostgreSQL 16 | Managed PostgreSQL |

> **Verified scope.** The instructions below are derived from the repository's own configuration
> (`docker-compose.yml`, `Dockerfile`s, `backend/app/core/config.py`, `frontend/next.config.mjs`).
> Only the local SQLite path and the live provider integrations were executed and verified — see
> [Live integration status](../README.md#live-integration-status). No cloud deployment was performed
> from this environment, and the Docker path could not be exercised because the Docker CLI is not
> installed here.

---

## 1. Architecture at a glance

```text
Browser
  └─> Frontend (Next.js)                     public origin
        ├─ /, /dashboard, /investigate, /history, /results/[id]
        └─ /api/*  ──proxied──> Backend (FastAPI) on the private network
                                  ├─ LangGraph investigation pipeline
                                  ├─ deterministic risk engine
                                  ├─ ML classifier (bundled .joblib)
                                  ├─ threat intel (Safe Browsing, VirusTotal)
                                  ├─ LLM (any OpenAI-compatible endpoint)
                                  └─ OCR (system Tesseract)
                                        └─> Database (SQLite local / PostgreSQL prod)
```

The frontend proxies `/api/*` to the backend (`next.config.mjs` rewrites, target `BACKEND_URL`).
This means:

- the browser only ever talks to the frontend origin — no CORS configuration is needed for the UI;
- **provider API keys stay on the backend** and are never sent to the browser. There is no
  `NEXT_PUBLIC_*` variable in this project, and there must not be one.

---

## 2. Environment variables

### 2.1 Backend

The backend reads `backend/.env` (see `backend/app/core/config.py`); real environment variables
present in the process take precedence over that file, which is how container hosts inject them.
`backend/.env` is git-ignored and must never be committed.

| Variable | Required | Notes |
|---|---|---|
| `DATABASE_URL` | Production | `postgresql+asyncpg://USER:PASSWORD@HOST:5432/DB`. Omit locally to use SQLite. |
| `LLM_PROVIDER` | No | `mock` (default) or `openai_compatible`. |
| `LLM_API_KEY` | For live LLM | Server-side only. |
| `LLM_BASE_URL` | For live LLM | Any OpenAI-compatible `/v1` base. Gemini: `https://generativelanguage.googleapis.com/v1beta/openai`. |
| `LLM_MODEL` | For live LLM | e.g. `gemini-3.5-flash-lite`, `gpt-4o-mini`. Never hardcoded in source. |
| `LLM_TIMEOUT_SECONDS` | No | Default `45`. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | For live intel | Sent as the `x-goog-api-key` **header**, never as a query parameter. |
| `VIRUSTOTAL_API_KEY` | For live intel | Sent as the `x-apikey` header. |
| `THREAT_INTEL_TIMEOUT_SECONDS` | No | Default `10`. |
| `OCR_PROVIDER` | No | `auto` (default) / `tesseract` / `mock`. |
| `TESSERACT_BINARY` | No | Default `tesseract`; must be on `PATH`. |
| `MAX_UPLOAD_MB` / `MAX_TEXT_LENGTH` / `MAX_URLS_PER_SUBMISSION` | No | Defaults `10` / `50000` / `20`. |
| `RATE_LIMIT_PER_MINUTE` | No | Default `30` per IP. |
| `CORS_ORIGINS` | Yes, if the browser calls the API directly | JSON list. Not needed when the frontend proxy is used. |
| `ML_MODEL_PATH` | No | Defaults to the bundled artifact. |
| `ML_DECISION_THRESHOLD` | No | Default `0.55`. |
| `RISK_WEIGHTS_PATH` | No | Optional JSON overrides for the risk weights. |
| `DEBUG` | No | Leave `false` in production. |

### 2.2 Frontend

| Variable | Required | Notes |
|---|---|---|
| `BACKEND_URL` | Yes in containers | e.g. `http://backend:8000` (compose) or `https://api.example.com`. Defaults to `http://localhost:8000`. Server-side only. |

### 2.3 Where keys go — and where they must not

- Put keys in the **backend** environment (or `backend/.env` locally). Never in the frontend.
- Never commit `.env` / `.env.local`; `.gitignore` excludes them (`*.env`, `!*.example`).
- Never pass an API key as a URL query parameter — request URLs are logged by HTTP clients and
  proxies. The Safe Browsing provider deliberately authenticates by header for this reason.

---

## 3. Frontend — Vercel

1. Import the repository and set **Root Directory** to `frontend`.
2. Framework preset: **Next.js**. Build command `npm run build`, output handled automatically.
3. Environment variable (Production + Preview):

   ```text
   BACKEND_URL=https://<your-backend-host>
   ```

4. Deploy. The rewrites proxy `/api/*` to `BACKEND_URL`, so the browser keeps talking only to the
   Vercel origin.

> The rewrite target is resolved at build/runtime from `BACKEND_URL`. If the backend host changes,
> redeploy (or set the variable and redeploy) so the proxy target is refreshed.

---

## 4. Backend — Railway / Render / container host

Container hosts (Railway, Render, Fly.io, ECS, Kubernetes) work directly with the bundled
`backend/Dockerfile`:

- Base image `python:3.13-slim`, `tesseract-ocr` installed via `apt` (so live OCR works without a
  host dependency).
- Exposes port `8000`; starts `uvicorn app.main:app --host 0.0.0.0 --port 8000`.

Steps:

1. Create the service from this repository with **Root Directory** `backend` (or build with
   `docker build -f backend/Dockerfile backend`).
2. Set the environment variables from §2.1. At minimum: `DATABASE_URL`, and whichever provider keys
   you have.
3. Attach a managed PostgreSQL instance and set `DATABASE_URL` from its connection string
   (`postgresql+asyncpg://…`).
4. Health check path: `/api/health`.
5. Ensure the platform terminates TLS in front of the service.

The app creates its schema on startup (`create_tables()` in the FastAPI lifespan). There is no
migration framework in this repository; schema creation is idempotent for a fresh database.

---

## 5. Database

- **Local development:** omit `DATABASE_URL` entirely. SQLite is used at
  `backend/data/app.db` (git-ignored). This is the verified path.
- **Production:** PostgreSQL 16 via `postgresql+asyncpg://…`. Filters were written to be portable
  across both engines (`json_extract` on SQLite vs `->>`/`.astext` on PostgreSQL in
  `backend/app/services/investigation_service.py`).
- Do not commit database files (`*.db` is git-ignored).

### docker-compose alternative

`docker-compose.yml` runs PostgreSQL 16, the backend, and the frontend together, reading provider
keys from the **root** `.env`:

```bash
cp .env.example .env      # then fill in values
docker compose up --build
```

`docker compose config` / `build` / `up` were **not** executed in this environment (no Docker CLI).

---

## 6. CORS

With the frontend proxy in place, no CORS entries are required. If you choose to have the browser
call the backend directly, set:

```text
CORS_ORIGINS=["https://your-frontend-domain"]
```

`allow_credentials=False` and wildcard methods/headers are configured in `backend/app/main.py`.
Keep the origin list explicit — do not use `*` in production.

---

## 7. Post-deployment smoke test

Run these against the deployed URLs.

```bash
# 1. Backend health — must report which providers are really live
curl -s https://<backend-host>/api/health | python -m json.tool
```

Expect `status: "ok"` and a truthful `providers` block. `is_mock: true` / `uses_mock: true` means
that integration is **not** configured; `demo_mode: true` means both the LLM and threat intel are
running in demo mode.

```bash
# 2. End-to-end investigation through the API
curl -s -X POST https://<backend-host>/api/investigations \
  -F 'text=URGENT: your account is suspended, verify now at http://paypa1-verify.example.net/login and enter your password and OTP'
```

Expect `"status": "completed"` with a `risk` block. A `HIGH`/`CRITICAL` band here is expected for
that content.

```bash
# 3. History
curl -s https://<backend-host>/api/investigations | head -c 400
```

Then in the browser: open the frontend root, run one investigation from `/investigate`, and confirm
the result page renders the risk gauge, evidence groups and timeline. Confirm `/dashboard` shows
provider status and that no notice claims "no external API is configured" while live keys are set.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/api/health` shows `llm.is_mock: true` | `LLM_PROVIDER` is `mock`, or `LLM_API_KEY` is empty | Set both; the key must be non-empty. |
| `/api/health` shows `threat_intel.uses_mock: true` | Neither provider key is set | Set `GOOGLE_SAFE_BROWSING_API_KEY` and/or `VIRUSTOTAL_API_KEY`. |
| `/api/health` shows `ocr.provider: "mock"` | Tesseract is not on `PATH` | Use the bundled Dockerfile, or install `tesseract-ocr`. |
| LLM explanations look templated | The provider failed and the **deterministic fallback** was used — this is by design | Check backend logs for `LLM HTTP <code>`; a 404 usually means the model name is unavailable to your key, a 429 means quota. |
| HTTP 429 from VirusTotal | Public API rate limit | Space out lookups; the provider maps 429 to `status: "rate_limited"` and never treats it as clean. |
| Frontend loads but API calls 502 | `BACKEND_URL` wrong or backend down | Fix `BACKEND_URL` and redeploy; verify `/api/health` directly. |
| Frontend pages show "not configured" while keys are set | Keys were set on the frontend service | Keys belong to the **backend** service only. |
| `Untagged`/unexpected results after changing the model | The `.joblib` artifact must match the feature code | Retrain with `scripts/ml_training/train.py`. |
| CORS error in a direct-to-backend setup | Origin not listed | Add it to `CORS_ORIGINS`. |

---

## 9. Security checklist before going live

- [ ] `DEBUG=false`.
- [ ] `CORS_ORIGINS` lists explicit origins only.
- [ ] All provider keys set on the backend service, none on the frontend.
- [ ] `.env` files are git-ignored and absent from the repository and image layers.
- [ ] `RATE_LIMIT_PER_MINUTE` set to a value appropriate for your traffic.
- [ ] `MAX_UPLOAD_MB` / `MAX_TEXT_LENGTH` reviewed for your plan.
- [ ] TLS terminated in front of both services.
- [ ] `/api/health` verified from outside the cluster.
- [ ] Log aggregation confirmed to **not** capture request URLs containing credentials (the app
      silences HTTP-client request logging, and no provider key is placed in a URL).
- [ ] A monitored backup schedule for PostgreSQL.

---

## 10. Scaling notes

- The backend is stateless apart from the database, so it scales horizontally. Investigation work is
  in-process (LangGraph) — scale by adding replicas, not threads.
- Live provider calls dominate latency (threat intel and LLM typically dominate a request; the
  offline path is ~milliseconds). Budget accordingly for concurrency and upstream rate limits.
- SQLite is single-writer: use PostgreSQL for any multi-replica deployment.
