# Provider Integration Guide — AI Digital Scam Investigator

Two external services can be plugged in: **threat intelligence** (URL reputation) and an **LLM**
(explanation only). Both sit behind narrow contracts, and both share one non-negotiable rule:

> **A failure is never a clean verdict.** No information neither raises nor lowers risk, and it must
> never be presented as "safe".

This guide documents the contracts, the semantics of the shipped implementations, how to add a
provider, and what the tests will require of you. Architectural context is in
[ARCHITECTURE.md §9 and §11](ARCHITECTURE.md#9-threat-intelligence-architecture).

---

## Contents

| # | Section |
|---|---|
| 1 | [Threat-intelligence contract](#1-threat-intelligence-contract) |
| 2 | [Shipped threat-intelligence providers](#2-shipped-threat-intelligence-providers) |
| 3 | [How results are merged](#3-how-results-are-merged) |
| 4 | [LLM contract](#4-llm-contract) |
| 5 | [Shipped LLM providers](#5-shipped-llm-providers) |
| 6 | [Configuration reference](#6-configuration-reference) |
| 7 | [Adding a provider](#7-adding-a-provider) |
| 8 | [Health reporting](#8-health-reporting) |

---

## 1. Threat-intelligence contract

Implement `ThreatIntelProvider` (`app/intelligence/base.py`) and return a normalised
`ThreatIntelResult`:

| Field | Meaning |
|---|---|
| `provider` | Provider name; the manager joins multiple names with `+` |
| `verdict` | `safe` \| `suspicious` \| `malicious` \| `unknown` — **the reputation finding** |
| `status` | `ok` \| `error` \| `unavailable` \| `rate_limited` — **whether the lookup worked** |
| `risk_score` | 0–1 contribution from this provider |
| `reputation` | Human-readable summary surfaced in the UI |
| `categories` | Provider taxonomy mapped to strings (e.g. GSB threat types) |
| `hits` | Number of distinct findings |
| `is_mock` | True only for the mock provider |
| `error` | Populated whenever the lookup did not produce a verdict |
| `detail` | Provider-specific payload — kept here so nothing downstream sees raw API shapes |

Keeping `verdict` and `status` separate is the whole point: `verdict="unknown"` with
`status="rate_limited"` means *no information*, not "clean".

**Required failure semantics.** Never return `safe` for input you did not actually check:

- HTTP `429` → `rate_limited`; `5xx` → `unavailable`; anything else → `error`. Use
  `status_from_http(code)` rather than mapping by hand.
- Network errors and timeouts → `unavailable` via `failure_result(...)`.
- **Malformed input → `error`, not `safe`.** Call `lookupable_url(url)` first: it returns `None` for a
  string that is not a well-formed absolute `http(s)` URL with a real hostname or IP literal (spaces,
  no host, a bare single-label name, an unparseable IPv6 literal, over 2000 characters). Every
  reputation service answers "not listed" for such input, which would otherwise read as a clean
  verdict. Return `invalid_url_result(name, url)` and make **no HTTP call**.
- `404` "not seen" is not "safe". The shipped VirusTotal provider reports
  `verdict="unknown"`, `reputation="not seen by VirusTotal"` for that case.
- **Authenticate by header, never by query parameter.** Request URLs end up in client, proxy and access
  logs — which is why the Safe Browsing provider uses `x-goog-api-key` instead of the documented
  `?key=` form, and VirusTotal uses `x-apikey`.

Providers are queried by URL **as a value**. Never dereference a submitted URL; see
[SECURITY.md §2](SECURITY.md#2-threat-model).

---

## 2. Shipped threat-intelligence providers

| Provider | Endpoint | Auth header | Enabled by |
|---|---|---|---|
| `google_safe_browsing` | `POST https://safebrowsing.googleapis.com/v4/threatMatches:find` | `x-goog-api-key` | `GOOGLE_SAFE_BROWSING_API_KEY` |
| `virustotal` | `GET {VIRUSTOTAL_BASE_URL}/urls/{url_id}` | `x-apikey` | `VIRUSTOTAL_API_KEY` |
| `mock` | — | — | Used only when no key is configured; always `is_mock=True` |

**Google Safe Browsing** sends the four threat types (`MALWARE`, `SOCIAL_ENGINEERING`,
`UNWANTED_SOFTWARE`, `POTENTIALLY_HARMFUL_APPLICATION`) for `ANY_PLATFORM` / `URL` entries:

- any `matches` → `malicious`, `risk_score 0.95`, `categories` = the sorted threat-type set,
  `hits` = match count;
- no `matches` → `safe`, `risk_score 0.05`, `reputation="not listed by Google Safe Browsing"`.

**VirusTotal** derives the URL id as the **base64url encoding of the URL with `=` padding stripped**,
then maps `last_analysis_stats`:

| Condition | Verdict | Score |
|---|---|---|
| `malicious >= 2` | `malicious` | `0.5 + 0.08 × min(hits, 6)`, capped at `0.98` |
| `malicious == 1` or `suspicious >= 2` | `suspicious` | same formula |
| exactly one `suspicious` | `suspicious` | `0.45` |
| none | `safe` | `0.1` |

`reputation` is rendered as `"N malicious / M suspicious out of T engines"`, and the raw `stats` block is
preserved in `detail`. Because the public API is rate-limited, a `429` is expected in normal use and is
reported as `rate_limited` — never as a clean result.

---

## 3. How results are merged

`ThreatIntelManager` (`app/intelligence/manager.py`) instantiates one provider per configured key (mock
only as the fallback), queries them **concurrently** with `asyncio.gather`, and wraps every call so a
provider exception becomes a normalised failure rather than a crashed investigation:

- **Worst verdict wins** — `safe 0 < unknown 1 < suspicious 2 < malicious 3`, with `risk_score` taken as
  the maximum. Safety-first: one malicious verdict is not averaged away by a clean one.
- **Status resolution** — `ok` as soon as *any* provider returned a real verdict; otherwise the most
  severe failure state is surfaced (`error < unavailable < rate_limited`), so an outage stays visible
  instead of looking like "no result".
- **Nothing is discarded** — `hits` is summed, `categories` unioned, and every provider's own row kept
  in `detail.providers` for the UI and the audit trail.
- `uses_mock` is true only when *every* configured provider is a mock.

Downstream, the risk engine's intel channel participates **only** when the merged result is informative
(`status="ok"` with a `safe` / `suspicious` / `malicious` verdict). `unknown`, `error`, `unavailable` and
`rate_limited` neither contribute nor dilute the score — see
[ARCHITECTURE.md §7](ARCHITECTURE.md#7-risk-engine).

---

## 4. LLM contract

Implement `LLMProvider` (`app/llm/base.py`). Three domain methods, so the graph never talks to a raw
chat API:

| Method | Purpose | May fail how |
|---|---|---|
| `classify(context)` | Refine an **ambiguous** category only | Return `None` to skip |
| `explain(context)` | Human-readable explanation | Must return something usable |
| `generate_report(context)` | The structured report | Must return something usable |

Every method receives a `ReportContext` — the structured evidence bundle — and the shared
`EVIDENCE_ONLY_SYSTEM` prompt contract requires the model to:

1. use only facts present in the context;
2. never invent URLs, domains, phone numbers, reputation results or "the company confirmed…";
3. separate observation from inference and label inference as such;
4. prefer calibrated wording over certainty;
5. say so explicitly when evidence is insufficient (there is a dedicated `limitations` field);
6. never give the attacker useful instructions.

None of this is advisory. A classification the deterministic evidence does not support is **rejected
and recorded** (`classification_suggestion_rejected`), and the risk score is computed before the LLM is
ever called — see [ARCHITECTURE.md §11](ARCHITECTURE.md#11-llm-grounding-architecture).

---

## 5. Shipped LLM providers

| Provider | When it is used | Behaviour |
|---|---|---|
| `openai_compatible` | `LLM_PROVIDER=openai_compatible` **and** a non-empty `LLM_API_KEY` | `POST {LLM_BASE_URL}/chat/completions` with `Authorization: Bearer`, `temperature 0.2`, `max_tokens 1600`, and `response_format={"type":"json_object"}` |
| `mock` | Default, or whenever the key is empty | Deterministic local output, `is_mock=True` |
| `deterministic` | Fallback text generator | Templates derived from the evidence; labelled `provider="deterministic-fallback"` |

The OpenAI-compatible client is deliberately forgiving, because creative output is not an error:

- If the endpoint rejects `response_format` with a `400`, the request is retried once **without** it —
  which is what makes non-OpenAI gateways (Gemini's OpenAI-compatible endpoint, Ollama, LM Studio, vLLM)
  work without provider-specific code.
- Output is parsed as JSON, tolerating ``` fences and surrounding prose by extracting the outermost
  `{...}` object.
- Each method retries once, then falls back: `explain` and `generate_report` return
  `deterministic_*` output, and `classify` returns `None` (leaving the deterministic category in place).
- A successful classification is tagged `method="hybrid(rules+llm)"` so its origin is visible in the
  response.

Because of the fallback chain, **an LLM outage cannot fail an investigation** — it changes the wording
of the explanation and nothing else.

---

## 6. Configuration reference

| Variable | Default | Effect |
|---|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | — | Enables the Safe Browsing provider |
| `VIRUSTOTAL_API_KEY` | — | Enables the VirusTotal provider |
| `VIRUSTOTAL_BASE_URL` | `https://www.virustotal.com/api/v3` | Override for a proxy or mock server |
| `THREAT_INTEL_TIMEOUT_SECONDS` | `10` | Per-request timeout |
| `LLM_PROVIDER` | `mock` | `mock` \| `openai_compatible` |
| `LLM_API_KEY` | — | Server-side only; an empty value forces the mock |
| `LLM_BASE_URL` | OpenAI | Any OpenAI-compatible `/v1` base |
| `LLM_MODEL` | `gpt-4o-mini` | Must be a model your key can access |
| `LLM_TIMEOUT_SECONDS` | `45` | Per-request timeout |
| `OCR_PROVIDER` / `TESSERACT_BINARY` | `auto` / `tesseract` | The local OCR provider (not an external API) |

Keys belong in `backend/.env` (git-ignored) or the process environment, and are never sent to the
browser. Start from [`backend/.env.example`](../backend/.env.example).

---

## 7. Adding a provider

1. **Implement the contract** in `app/intelligence/` or `app/llm/`, normalising at the boundary.
2. **Register it** so `_default_providers()` (or `get_llm_provider()`) can select it from configuration.
3. **Set `is_mock` accurately** — the manager's `uses_mock` and the health endpoint depend on it.
4. **Authenticate by header** if the service supports it.
5. **Test both directions.** A real verdict *and* a failure path:
   - a clean result is informative (`verdict="safe"`, `status="ok"`);
   - a `5xx` is `unavailable`, a `429` is `rate_limited`, a timeout is `unavailable`;
   - malformed input is `error` and performs **no HTTP call**;
   - a provider that raises does not crash the investigation.
   `tests/test_phase3.py` has the pattern to copy, including
   `test_providers_never_report_malformed_input_as_clean`.
6. **Add an opt-in live test** gated behind a `RUN_LIVE_*` switch, asserting the integration contract
   rather than an accuracy figure — see
   [TESTING.md §5](TESTING.md#5-opt-in-live-suites) and `tests/test_threat_intel_live.py`.
7. **Update the tables** in this file, the provider table in
   [ARCHITECTURE.md §9](ARCHITECTURE.md#9-threat-intelligence-architecture), and the status table in the
   README.

---

## 8. Health reporting

`GET /api/health` reports **effective** state, which is how a misconfigured deployment becomes visible
instead of surfacing as unexplained low-risk results:

```json
"providers": {
  "llm":          { "name": "mock", "is_mock": true, "model": null },
  "threat_intel": { "active": ["mock"], "uses_mock": true },
  "ml":           { "available": true, "model": "StandardScaler+LogisticRegression" },
  "ocr":          { "provider": "mock", "is_mock": true }
},
"demo_mode": true
```

`active` lists the providers actually instantiated — if your key is set and its name is absent, the
provider was not constructed. `demo_mode` is true only when both the LLM and threat intel are mocked
(the ML classifier is real in demo mode).
