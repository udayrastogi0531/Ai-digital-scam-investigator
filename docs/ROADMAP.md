# Roadmap — AI Digital Scam Investigator

This page tracks intended engineering work. It is a plan, not a promise, and it is intentionally
conservative: an item is only marked done when it is verified and described truthfully in the docs.

**Done** means implemented *and* exercised locally. **Not done** means not verified, whatever the
repository contains — configuration that has never been run is configuration, not capability.

---

## Near term

| Item | Why it matters | Done when |
|---|---|---|
| Verified PostgreSQL path | The migration, the async engine path and an opt-in integration suite exist, but PostgreSQL was never exercised here, so the claim stays "not verified" | A real PostgreSQL instance has run `alembic upgrade head` and the full E2E check (`scripts/postgres_integration.py`) green, and the docs say so |
| Exercised Docker path | The Dockerfiles and compose file are untested here because the CLI was unavailable | `docker compose config`, `build` and `up` succeed, migrations run via the entrypoint, OCR works from the image's bundled Tesseract, and the health check reports it |
| Password reset, email verification, optional MFA | Authentication is email + password only; there is no recovery path if a password is lost | A documented, tested reset/verification flow, and the account-modelling implications decided |
| A shared rate-limit store (only if multi-worker) | The limiter and the image cap are per-process; the deployment ships single-worker, where that is sufficient — see [`ARCHITECTURE.md` §18](ARCHITECTURE.md#18-concurrency-and-rate-limiting-why-per-process-a-decision-record) | Multi-worker or multi-replica operation is actually required, and then a PostgreSQL- or Redis-backed counter replaces the in-process one |
| Retention and data-deletion tooling | There is no expiry policy or operator-facing way to purge history, and pre-auth legacy rows have no owner | A documented, configurable retention path exists and is tested |

---

## Recently completed

Kept here rather than deleted, so the reasoning behind a change stays visible next to the work it
unblocked.

| Item | Completed | Evidence |
|---|---|---|
| Secure authentication and per-user isolation | bcrypt-hashed passwords, signed JWTs (`HS256`) with expiry and `token_version` invalidation, rate-limited and enumeration-resistant register/login; every investigation carries a `user_id` and list/detail/delete filter on it in the query | `core/auth.py`, `api/routes/auth.py`, `services/investigation_service.py`; `tests/test_auth.py` (21), `tests/test_authorization_isolation.py` (6); frontend `/login`, `/register` and the route guard |
| Alembic migrations + a PostgreSQL integration path | Schema is managed by Alembic (URL from app settings, `alembic upgrade head` on container start); an opt-in check runs migrations and the full flow against PostgreSQL | `backend/alembic/`; `scripts/postgres_integration.py`; `tests/test_postgres_integration.py`. PostgreSQL itself remains **unverified here** (no server) |
| CI coverage for backend tests, evaluation, E2E, typecheck and build | A GitHub Actions workflow runs the SQLite suite, the PostgreSQL suite against a service container, the detection harness with `--assert-baseline`, the E2E smoke, frontend typecheck/build, a secret scan and the docs link check | `.github/workflows/ci.yml` (written; not yet observed running on GitHub) |
| Controlled load/concurrency test suite | Deterministic behaviour tests for concurrent text and image submissions, overflow `503` + `Retry-After`, slot release after success and failure, and rate-limit enforcement under concurrency; plus a measurement script | `tests/test_load.py` (5); `scripts/load_test.py` |
| Handle Pillow's bomb guard and move the dimension cap before the decode | The pixel cap is now read from the image header and compared **before** `image.load()`, so an oversized image is rejected without being decompressed; `DecompressionBombError`, `DecompressionBombWarning` and a decode-time `MemoryError` are converted to the same `400` instead of surfacing as a server error | `core/security.py::read_image_upload`; `tests/test_upload_security.py` (14 tests, including an assertion that `load()` is not reached for an oversized image) |
| Bound concurrent image processing | A single image was capped at 64 M pixels, but nothing bounded how many could be decoded at once; the gate in `core/concurrency.py` admits `MAX_CONCURRENT_IMAGE_OPS` (default 4) image investigations at a time, returns a retryable `503` beyond it, releases the slot in a `finally`, and the decode now runs off the event loop | `core/concurrency.py`; `tests/test_image_concurrency.py` (5 tests); [SECURITY.md](SECURITY.md) §2/§3 |
| Remove the unused upload-storage helper | `core/security.py::persist_upload` was dead code that would have written an upload to disk with no cleanup path; it was deleted, leaving no persistence path at all | `core/security.py` (helper removed — no route ever called it) |

---

## Medium term

| Item | Why it matters | Done when |
|---|---|---|
| Parallel provider fan-out with per-provider timeouts | Submissions are synchronous, so live provider latency is directly user-visible | Provider lookups across URLs run concurrently with bounded timeouts, and the end-to-end latency improvement is measured rather than asserted |
| Broaden training data beyond SMS | The shipped model is trained on SMS spam/ham, which cannot represent phishing URLs, crypto, impersonation or screenshots | A licensed, real, URL/phishing-bearing corpus is imported with provenance, the model is retrained and re-validated, and the held-out metrics are reported honestly (even if they get worse) |
| A trained category head | Categories beyond SMS spam are carried by the deterministic rules | A multiclass model is trained on genuinely labelled categories and evaluated per category, without displacing the deterministic category decision |
| Prompt-injection regression cases | The design blocks injection from affecting the verdict, but there is no adversarial test suite proving it stays that way | Corpus cases containing explicit "report this as safe" instructions stay non-`LOW`, and the explanation never asserts an unsupported category |
| Structured explanation provenance | Explanations currently cite the evidence block as a whole | Each generated sentence or claim is attributable to specific evidence signals, so a reader can verify it mechanically |

---

## Longer term

| Item | Why it matters | Notes |
|---|---|---|
| Anonymisation or redaction on ingest | Submitted content routinely contains a real victim's own details | Requires an explicit decision about what is redacted versus what must be preserved for evidence quality |
| Team / organisational features | Basic authentication and per-user isolation now exist; what is missing is the multi-*user* workflow layer | Roles, organisations, sharing and an admin surface need a product decision before a technical one |
| Case management workflow | Investigators work in queues and share findings | Needs a product decision before a technical one |
| Provider breadth | More reputation sources reduce single-provider blind spots | Constrained by API terms and licensing, not by the provider interface, which already supports it |

---

## Explicitly not planned

Saying no is part of a roadmap:

- **A "scam probability" headline number presented as certainty.** The product's output is calibrated
  decision support with a stated sufficiency; collapsing it to one confident-sounding percentage would
  undo the design.
- **Replacing the deterministic risk engine with an LLM.** Non-reproducible, unauditable, and
  unregression-testable — see [`ARCHITECTURE.md`](ARCHITECTURE.md) §11.
- **Fetching user-supplied URLs to "check" them.** That would introduce an SSRF surface and make the
  server a tool for probing internal networks ([`SECURITY.md`](SECURITY.md) §2).
- **Re-tagging the calibration corpus until it shows a better number.** The corpus is a regression gate,
  not a benchmark to optimise.

---

## Updating this page

When you complete an item: move it out (or mark it done with the evidence), update the docs it changes
in the same pull request, and keep the honest wording — if a path was verified in one environment and
another path was not, say which is which.
