# Changelog — AI Digital Scam Investigator

**There are no releases or tags in this repository yet**, and nothing is deployed, so this is not a
release changelog. It is a record of what changed and *why*, derived from the commit history, newest
first. Entries name the commits so any claim here can be checked with `git show <sha>`.

Convention: the project follows conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`, with an
optional scope such as `fix(patterns):`). See [CONTRIBUTING.md §10](CONTRIBUTING.md#10-commits-and-pull-requests).

---

## 2026-09-29 — documentation closeout

The engineering is fully described; this day was about making the documentation match the code and
removing the places where a reader could draw a wrong conclusion.

**New pages**

| Commit | Added |
|---|---|
| `cc0370c` | `docs/EVALUATION.md` — both measurement regimes, corpus composition, harness protocol, how to add a case, and what is deliberately not measured |
| `d5fdb21` | `docs/SECURITY.md` — threat model, per-threat controls and residual risk, LLM containment, data flows, non-goals |
| `fea2324` | `docs/API.md` — endpoint reference, error semantics, response objects, worked walkthrough |
| `6e66a3a` | `docs/TROUBLESHOOTING.md` — symptom/cause/fix by area, grounded in the error strings the code raises |
| `ea9e2c0` | `docs/TESTING.md` — suite map with per-file counts, hermetic design, opt-in live suites, coverage gaps |
| `467091a` | `docs/FAQ.md` — the sceptical questions (is 100% real, why is precision 0.67, is a URL fetched, is a screenshot stored) |
| `e24b139` | `docs/PROVIDERS.md` — threat-intel and LLM contracts, merge semantics, scoring, extension checklist |
| `ed005ae` | `docs/GLOSSARY.md` — the vocabulary, with the file that defines each term |
| `2929129` | `docs/CHANGELOG.md` — this file |

**Test suites added** (the suite grew from 180 to 198 passing tests)

| Commit | Added |
|---|---|
| `0603bd8` | `tests/test_upload_security.py` — every upload-rejection branch, plus an assertion that a valid upload leaves no file on disk. Exposed two gaps: the 64 M-pixel cap is applied *after* Pillow decodes, and Pillow's `DecompressionBombError` (derived from `Exception`, not `OSError`) surfaces as a server error instead of a `400` |
| `42d3027` | `tests/test_ssrf_guard.py` — the no-SSRF property asserted behaviourally rather than inferred: every outbound request during a submission of internal addresses is captured, and only reputation hosts may appear |
| `f462c9e` | `tests/test_rate_limit.py` — the limiter had no coverage at all: client keying, the `429`, window rollover and per-client isolation |

**Rebuilt**

- `376841b` — `docs/ARCHITECTURE.md` rebuilt from 155 to 561 lines around the invariants enforced in
  code: evidence-before-opinion, deterministic risk, applicability-driven normalisation, "no information
  is never good news", uncertainty as a first-class output, labelled mocks, and never fetching a
  submitted URL. Adds the LangGraph routing rules, the equal-depth `*_pad` workaround, and dedicated
  sections for threat intelligence, OCR, LLM grounding, persistence, security boundaries, failure
  handling, logging, the frontend/backend contract and deployment.
- `f63d432` — README rebuilt as a product landing page.
- `d4f63e4` — the 10-line contribution checklist became `docs/CONTRIBUTING.md`: repository map, gates by
  change type, the rule-change workflow including artifact retraining, and a not-merged list.
- `23cea49` — documentation map pairing each document with the question it answers.

**Corrected**

- `751abe7` — the deployment guide now labels every path **VERIFIED**, **NOT VERIFIED** or **OPTIONAL**
  instead of leaving the reader to infer which instructions had ever been run.
- `07e007e` — removed a first-run trap: the quick start told readers to copy the *docker-compose* env
  template into `backend/.env`, which points `DATABASE_URL` at a PostgreSQL that a local run cannot
  reach. Added a SQLite-first `backend/.env.example`. Also dropped the version from the FastAPI badge,
  where the requirement floor read as a pin.
- `23cea49` — the two live test rows are now labelled as recorded acceptance-run observations rather
  than a promise about the reader's environment.
- `f198bac` — **screenshots are not stored on disk.** Three documents claimed uploads were written to a
  git-ignored directory under a `uuid4` name, and two promised a cleanup task to delete those files.
  Neither was true: `core/security.py` defines `persist_upload` but no route calls it, and the live path
  keeps the image in memory for the request only. The imagined storage and its lifecycle problem are
  gone, replaced by the real property and by the real open issue — an unused helper that would need a
  lifecycle before it could be enabled.
- `ea80394` — the six new pages added to the documentation map, the project-structure tree and the
  contributing guide's "update the affected doc" list.

## 2026-09-28 — detection correctness

Two real detection defects fixed, both surfaced by the live acceptance run and both now frozen as
regression cases.

- `bd700b8` `fix(patterns)` — the rule matcher compared literal keyword strings with word boundaries, so
  `guaranteed 40% returns` (a token inside the keyword phrase) and the hyphenated `risk-free` never
  matched, and an obvious investment scam stayed at LOW. Rules now also evaluate declarative **regex
  variants** (`ScamRule.patterns`) with numeric pressure/reward signals. The same commit added
  `requires_request_context`, so a status-only delivery notice is evidence only when the message also
  demands something — a legitimate receipt mentioning "parcel" no longer inherits `delivery_scam`.
  Because the matcher feeds the model's `scam_keyword_hits` feature, the shipped artifact was retrained
  and re-validated on the same corpus.
- `b788d6a` `fix(classify)` — an LLM could override the deterministic category. Refinement now requires
  deterministic evidence to support the suggestion; otherwise it is recorded as rejected
  (`classification_suggestion_rejected`) instead of replacing an honest `unknown`.
- `e2eb547` `docs(evaluation)` — retired the last documented hard case and corrected stale metrics. No
  case carries `known_hard_case` any more: the unsolicited shared-document link is now caught by the
  link-bait rule and asserted like any other scam case.
- `f63d432` — README rewritten as a product landing page.

## 2026-09-26

- `1198df0` `chore` — `.gitignore` extended to every `.env.*` variant, preventing a credential file from
  being committed by accident.

## 2026-09-25 — live integrations

- `a4ee915` `chore` — finalised the live integration path: provider normalisation and failure taxonomy in
  `intelligence/base.py` (`status_from_http`, `failure_result`, `lookupable_url` so malformed input can
  never read as clean), HTTP-client request logging silenced in `core/logging.py` because request URLs
  carry credentials, opt-in live OCR contracts added (`tests/test_ocr_live.py`), `docs/DEPLOYMENT.md`
  written, and the results page made honest about mock versus live providers.
- `1ae5ec8` / `4928e79` — roadmap and contribution checklist pages added.

## 2026-09-10 — real training data

- `04f0224` `feat` — replaced the synthetic-only classifier with one trained on the real **UCI SMS Spam
  Collection v.1** (CC BY 4.0), imported with full provenance by
  `scripts/ml_training/import_sms_spam.py`. URL-*presence* features were removed from the model, because
  this product investigates suspicious URLs by design and training on presence made the model flag any
  URL-bearing message. Added the contamination guard, a deterministic split, and the dataset README.

## 2026-09-06 — initial project

- `e9b95ee` / `44db8e5` — initial commit: FastAPI + LangGraph backend, deterministic risk engine,
  Next.js frontend, SQLite persistence and the demo cases.
- `00c4c06` — frontend and detection refinements.
- `929c15a` `docs` — README rewritten as an engineering-level overview.

---

## How this file is maintained

- Add an entry when a change alters behaviour, configuration, metrics, endpoints or a documented claim —
  in the same commit series as the change, not later.
- Name the commit SHAs so entries stay verifiable.
- **Do not** backfill entries you cannot substantiate from the history, and do not describe a change as
  verified that was only configured. If a path was never executed, say so — as
  [DEPLOYMENT.md](DEPLOYMENT.md) does for PostgreSQL and Docker.
