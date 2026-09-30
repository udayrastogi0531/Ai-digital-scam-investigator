# HTTP API — AI Digital Scam Investigator

> **Base URL.** Locally the backend serves `http://localhost:8000` and the frontend proxies `/api/*`
> to it, so from a browser you always call the frontend origin (`http://localhost:3000/api/...`).
> All routes below are relative to the `/api` prefix. `API_PREFIX` changes the prefix;
> `/docs` (Swagger UI) and `/openapi.json` are served by FastAPI while the server runs.

**Authentication: none.** Every route is open to anyone who can reach the port. Do not expose this
service to a network you do not control — see [`SECURITY.md`](SECURITY.md) §6.

**Content types.** `POST /api/investigations`, `/api/analyze/url`, `/api/analyze/image` and
`/api/demo/{slug}` take **multipart form data**. `POST /api/analyze/text` takes a **JSON body**.

**Synchronous by design.** A submission returns only after the whole investigation finishes, so
response time includes every live provider call it makes (threat intel and LLM dominate; the fully
offline path is milliseconds). There is no job id to poll and no queue.

---

## Contents

| # | Section |
|---|---|
| 1 | [Endpoint summary](#1-endpoint-summary) |
| 2 | [Rate limiting](#2-rate-limiting) |
| 3 | [Errors](#3-errors) |
| 4 | [Health](#4-health) |
| 5 | [Submitting an investigation](#5-submitting-an-investigation) |
| 6 | [Convenience analysis endpoints](#6-convenience-analysis-endpoints) |
| 7 | [History: list, detail, delete](#7-history-list-detail-delete) |
| 8 | [Demo cases](#8-demo-cases) |
| 9 | [Response objects](#9-response-objects) |
| 10 | [End-to-end walkthrough](#10-end-to-end-walkthrough) |

---

## 1. Endpoint summary

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/api/health` | — | Provider/mode status, database, version |
| `POST` | `/api/investigations` | multipart: `text`, `urls[]`, `title`, `source_label`, `image` | `InvestigationSummary` |
| `GET` | `/api/investigations` | query: `page`, `page_size`, `search`, `risk_level`, `scam_type`, `input_type` | `PaginatedInvestigations` |
| `GET` | `/api/investigations/{id}` | — | `InvestigationView` |
| `DELETE` | `/api/investigations/{id}` | — | `204 No Content` |
| `POST` | `/api/analyze/text` | JSON `{text?, urls?, title?, source_label?}` | `InvestigationSummary` |
| `POST` | `/api/analyze/url` | multipart: `url` (required), `title` | `InvestigationSummary` |
| `POST` | `/api/analyze/image` | multipart: `image` (required), `text`, `title` | `InvestigationSummary` |
| `GET` | `/api/demo` | — | Demo case index |
| `POST` | `/api/demo/{slug}` | — | `InvestigationSummary` |

Rate-limited routes: every `POST` above, plus `GET /api/demo` (the demo and analyze routers attach the
limiter at router level). The investigation list, detail, delete and health routes are not rate-limited.

---

## 2. Rate limiting

A per-IP sliding window (60 s) applies to all submission routes — `POST /api/investigations`,
`POST /api/analyze/*` and `POST /api/demo/{slug}` — and also to `GET /api/demo`. Default
`RATE_LIMIT_PER_MINUTE=30`.

Exceeding it returns **`429`** with `{"detail": "Rate limit exceeded — try again in a moment (max 30/minute)."}`.

Two honest caveats: the limiter is **in-memory and per process**, so it resets on restart and is not
shared across replicas; and the client key comes from `x-forwarded-for` when present, which a client can
spoof unless a trusted proxy sets or strips that header.

Image submissions (`POST /api/analyze/image` and `POST /api/investigations` **with** an `image` part)
are additionally bounded by an in-process concurrency gate: at most `MAX_CONCURRENT_IMAGE_OPS`
(default 4) run at once, and a request beyond the cap gets **`503`** with a `Retry-After: 1` header
instead of queueing. Text- and URL-only submissions are not affected. This cap is also per process.

---

## 3. Errors

Errors use FastAPI's standard envelope and are the only error shape you need to handle:

```json
{ "detail": "Provide text, at least one URL, or an image." }
```

| Status | When |
|---|---|
| `400` | Rejected upload: empty file, oversized, not a decodable image, or dimensions above the pixel cap |
| `404` | Unknown investigation id, unknown demo slug |
| `422` | Validation failure — no input supplied, text over 50,000 characters, more than 20 URLs, or a malformed query parameter (e.g. an invalid `risk_level`) |
| `429` | Rate limit exceeded |
| `503` | Image processing is at capacity (`MAX_CONCURRENT_IMAGE_OPS`, default 4) — sent only on image submissions; retry after the `Retry-After` interval |
| `500` | An unexpected failure during the run. The detail includes the underlying exception text, which is useful locally but verbose for a public deployment (a documented limitation, not a design goal) |

Note that **an investigation that fails internally is not an HTTP error.** The request succeeds and the
response carries `"status": "failed"` with the error list in `warnings`, so a provider or node fault
degrades one investigation rather than the API.

---

## 4. Health

```bash
curl -s http://localhost:8000/api/health
```

```json
{
  "status": "ok",
  "app": "AI Digital Scam Investigator",
  "version": "1.0.0",
  "database": "sqlite (local fallback)",
  "providers": {
    "llm":         { "name": "mock", "is_mock": true, "model": null },
    "threat_intel":{ "active": ["mock"], "uses_mock": true },
    "ml":          { "available": true, "model": "StandardScaler+LogisticRegression" },
    "ocr":         { "provider": "mock", "is_mock": true }
  },
  "demo_mode": true
}
```

This is the operational truth source, and it reports **effective** state rather than configuration:
`is_mock` / `uses_mock` mean that integration is not live, and `demo_mode` is true only when both the
LLM and threat intel are mocked. The dashboard renders from this endpoint, so the UI cannot claim to be
live while the backend is not.

---

## 5. Submitting an investigation

`POST /api/investigations` — multipart form:

| Field | Required | Notes |
|---|---|---|
| `text` | one of these three | Message text, max `MAX_TEXT_LENGTH` (50,000) characters |
| `urls` | one of these three | Repeat the field for multiple URLs, max `MAX_URLS_PER_SUBMISSION` (20); blanks are stripped |
| `image` | one of these three | Screenshot; validated, decoded and analysed locally by OCR |
| `title` | no | Your own label, max 255 characters |
| `source_label` | no | e.g. `email`, `sms`, `whatsapp`, max 64 characters |

At least one of `text`, `urls` or `image` is required (`422` otherwise).

```bash
curl -s -X POST http://localhost:8000/api/investigations \
  -F 'title=Suspicious bank SMS' \
  -F 'source_label=sms' \
  -F 'text=Meridian Bank: your account is suspended. Verify now at http://meridian-secure-verify.example.com/login and enter your password and the OTP we sent you.' \
  -F 'urls=http://meridian-secure-verify.example.com/login'
```

Add a screenshot to the same request with `-F 'image=@screenshot.png'`; the OCR text is merged into the
same evidence pool rather than analysed on a separate path.

The response is an `InvestigationSummary` — a compact result that still contains the full `risk` block,
`scam_type`, `entities`, `evidence`, `report`, `ml` and `timeline`. Fetch
`GET /api/investigations/{id}` for the extended `InvestigationView` (adds `processing_metadata` and
`analyses`).

---

## 6. Convenience analysis endpoints

Thin wrappers over the same pipeline, for callers that only have one kind of input. They create and
store an investigation exactly like `/api/investigations`.

```bash
# JSON body
curl -s -X POST http://localhost:8000/api/analyze/text \
  -H 'Content-Type: application/json' \
  -d '{"text": "You have been selected… pay the $99 registration fee today.", "urls": []}'

# A single URL
curl -s -X POST http://localhost:8000/api/analyze/url \
  -F 'url=http://paypa1-secure-login.example.com/account/verify'

# A screenshot (OCR runs locally; no image is uploaded anywhere)
curl -s -X POST http://localhost:8000/api/analyze/image \
  -F 'image=@phishing-screenshot.png'
```

`/api/analyze/text` requires `text` or `urls` (`422` otherwise). `/api/analyze/url` and
`/api/analyze/image` take their required field as a multipart form field.

---

## 7. History: list, detail, delete

```bash
# Paginated, filterable list
curl -s 'http://localhost:8000/api/investigations?page=1&page_size=20&risk_level=HIGH&search=bank'

# Full detail (drives the /results/[id] page)
curl -s http://localhost:8000/api/investigations/<id>

# Delete (204 on success, 404 when absent). There is no stored screenshot to remove —
# uploads are analysed in memory and never written to disk.
curl -s -X DELETE http://localhost:8000/api/investigations/<id> -o /dev/null -w '%{http_code}\n'
```

| Query parameter | Type | Constraint |
|---|---|---|
| `page` | int | ≥ 1, default 1 |
| `page_size` | int | 1–100, default 20 |
| `search` | string | max 200 characters |
| `risk_level` | string | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` (case-insensitive) |
| `scam_type` | string | max 64 characters, e.g. `phishing` |
| `input_type` | string | `text` \| `url` \| `image` (case-insensitive) |

A non-conforming `risk_level` or `input_type` is a `422`, not an empty list — the filters are declared
as validated patterns rather than free text.

---

## 8. Demo cases

```bash
curl -s http://localhost:8000/api/demo
curl -s -X POST http://localhost:8000/api/demo/banking_phishing
```

Eleven **fictional** cases, all with invented domains, numbers and people. They run the real pipeline
end-to-end so the product can be exercised without typing anything (`benign_message` is the control
case):

`banking_phishing` · `job_scam` · `investment_scam` · `delivery_scam` · `lottery_scam` ·
`tech_support` · `romance_scam` · `account_takeover` · `crypto_scam` · `benign_message` ·
`suspicious_url`

An unknown slug is a `404`. Both demo routes are rate-limited (the limiter is attached at router level,
so the index read counts too).

---

## 9. Response objects

### `InvestigationSummary`

| Field | Type | Notes |
|---|---|---|
| `investigation_id` | string | Use with `GET /api/investigations/{id}` |
| `title` | string | Your title, or a generated one |
| `status` | string | `completed` \| `failed` (also `running` transiently in storage) |
| `input_types` | string[] | Any of `text`, `url`, `image` |
| `risk` | object \| null | See `RiskAssessment`; **this is the authoritative verdict** |
| `scam_type` | object \| null | `{primary, alternatives, confidence, method, rationale}`; `method` is `rules` \| `llm` \| `hybrid` |
| `entities` | object \| null | Grouped extracted entities (`urls`, `emails`, `phones`, `companies`, `banks`, `organizations`, `amounts`, `dates`, `other`) |
| `evidence` | array | `EvidenceSignal[]` — the structured basis for the score |
| `report` | object \| null | Generated report (summary, objective, indicators, recommended actions, sections) |
| `ml` | object \| null | `{probability_scam, label, features, model, is_mock, feature_importance}` |
| `timeline` | array | One entry per pipeline stage, ordered and de-duplicated |
| `created_at` | timestamp | UTC |
| `warnings` | string[] | Human-readable degradations — OCR unavailable, demo providers, failed run details |

`InvestigationView` extends it with `processing_metadata` and `analyses`.

### `RiskAssessment`

| Field | Type | Notes |
|---|---|---|
| `score` | float | 0–100, deterministic |
| `level` | string | `LOW` (0–24) · `MEDIUM` (25–49) · `HIGH` (50–74) · `CRITICAL` (75–100) |
| `confidence` | float | 0–1 |
| `contributors` | array | `RiskContributor[]`: `{name, impact (−1…1), detail, evidence_sources}` — the arithmetic behind the score, used by the "Why this score?" panel |
| `weights` | object | The weights actually applied to the participating channels |
| `method` | string | `deterministic_weighted` |
| `evidence_sufficiency` | string \| null | `INSUFFICIENT` \| `PARTIAL` \| `SUFFICIENT` |

**Reading a result correctly:** `LOW` means no significant evidence was found, **not** that the content
was verified safe. When `evidence_sufficiency` is `INSUFFICIENT` or `PARTIAL`, the honest reading is
"little to go on" — and the conclusion text is written to avoid implying a clean bill of health. Only a
non-`LOW` band is a positive finding.

### `EvidenceSignal`

| Field | Notes |
|---|---|
| `source` | Producing channel: `url_analysis`, `threat_intelligence`, `scam_pattern`, `text_analysis`, `entity_analysis`, `ml_classifier`, `ocr` |
| `signal` | Machine-readable code, e.g. `URL_RISK`, `CREDENTIAL_REQUEST`, `PATTERN_MATCH` |
| `severity` | `low` \| `medium` \| `high` \| `critical` |
| `confidence` | 0–1 confidence in that single observation |
| `description` | Human-readable text for the UI |
| `detail` | Structured payload — matched rule, URL findings, per-provider verdicts, feature contributions |

### Threat-intel entries inside `evidence[].detail`

The intel channel normalises every provider to the same shape, and the distinction between the two
fields is load-bearing: **`verdict`** is the reputation finding (`safe` / `suspicious` / `malicious` /
`unknown`) and **`status`** is whether the lookup itself worked (`ok` / `error` / `unavailable` /
`rate_limited`). `verdict: "unknown"` with `status: "rate_limited"` means *no information*, never
"clean". A `404` from VirusTotal is reported as "not seen", not as safe.

### `PaginatedInvestigations`

```json
{
  "items": [
    {
      "id": "…", "title": "…", "status": "completed",
      "risk_score": 64.2, "risk_level": "HIGH", "scam_type": "phishing",
      "input_types": ["url"], "evidence_sufficiency": "SUFFICIENT",
      "created_at": "2026-09-29T09:14:56Z"
    }
  ],
  "total": 12,
  "page": 1,
  "page_size": 20
}
```

---

## 10. End-to-end walkthrough

```bash
BASE=http://localhost:8000

# 1. Confirm which providers are actually live
curl -s $BASE/api/health | python -m json.tool

# 2. Submit evidence (text + URL + screenshot)
ID=$(curl -s -X POST $BASE/api/investigations \
  -F 'text=URGENT: your parcel is held. Pay the $2.99 redelivery fee at http://track-parcel.example/fee within 24 hours.' \
  -F 'urls=http://track-parcel.example/fee' \
  -F 'image=@screenshot.png' | python -c 'import json,sys; print(json.load(sys.stdin)["investigation_id"])')

# 3. Read the full result
curl -s $BASE/api/investigations/$ID | python -m json.tool

# 4. Confirm it landed in history and can be filtered
curl -s "$BASE/api/investigations?risk_level=MEDIUM" | python -m json.tool

# 5. Clean up
curl -s -X DELETE $BASE/api/investigations/$ID -o /dev/null -w '%{http_code}\n'
```

The same flows are exercised automatically by `scripts/end_to_end_smoke.py` (12 flows) and by
`tests/test_api_integration.py`.
