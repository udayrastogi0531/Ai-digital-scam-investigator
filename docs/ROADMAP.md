# Roadmap — AI Digital Scam Investigator

This page tracks intended engineering work. It is a plan, not a promise, and it is intentionally
conservative: an item is only marked done when it is verified and described truthfully in the docs.

**Done** means implemented *and* exercised locally. **Not done** means not verified, whatever the
repository contains — configuration that has never been run is configuration, not capability.

---

## Near term

| Item | Why it matters | Done when |
|---|---|---|
| CI coverage for backend tests, evaluation, E2E, typecheck and build | Every gate currently depends on a human remembering to run it; there is no `.github/` workflow at all | A workflow runs the commands in [`CONTRIBUTING.md`](CONTRIBUTING.md#4-test-gates-by-change-type) on every push, and its badge is added only after it has actually run green |
| Verified PostgreSQL path | The code path and compose file exist, but PostgreSQL was never exercised here, so the claim stays "not verified" | `docker compose up --build` (or a managed instance) has been run, the full E2E smoke passes against it, and the docs can say so |
| Exercised Docker path | The Dockerfiles and compose file are untested here because the CLI was unavailable | `docker compose config`, `build` and `up` succeed, OCR works from the image's bundled Tesseract, and the health check reports it |
| Tests for upload rejection branches | Oversized files, non-image bytes and the pixel-bomb cap are implemented but covered only by inspection, and the same is true of the no-SSRF guarantee | Dedicated tests fail if a rejection path or the no-fetch property regresses |
| Remove the unused upload-storage helper | `core/security.py::persist_upload` writes an upload to disk but no route calls it, so it is dead code that invites a future change to enable persistence without a cleanup path | The helper is either deleted, or wired in together with image lifecycle handling and a test |
| Retention and data-deletion tooling | There is no expiry policy or operator-facing way to purge history | A documented, configurable retention path exists and is tested |

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
| Multi-user operation | The application is single-tenant, with no auth or isolation | A genuine architectural change; out of scope for a patch (see [`CONTRIBUTING.md`](CONTRIBUTING.md)) |
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
