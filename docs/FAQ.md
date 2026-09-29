# FAQ — AI Digital Scam Investigator

Short answers to the questions this project actually gets asked, each pointing at the document that
explains it properly. If your question is "how do I run it" or "why did this fail", see
[README Quick start](../README.md#quick-start) and [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## Contents

| # | Section |
|---|---|
| 1 | [What it is and why it exists](#1-what-it-is-and-why-it-exists) |
| 2 | [The numbers](#2-the-numbers) |
| 3 | [Running and deploying it](#3-running-and-deploying-it) |
| 4 | [Behaviour and limits](#4-behaviour-and-limits) |
| 5 | [Engineering decisions](#5-engineering-decisions) |

---

## 1. What it is and why it exists

**What is this, in one paragraph?**
An evidence-first investigation system for suspicious messages, URLs and screenshots. It extracts typed
evidence from a submission, analyses each channel independently (URL structure, linguistic signals,
declarative scam rules, entities, ML, live threat intelligence, OCR), correlates the result, and lets a
**deterministic risk engine** produce the score, band and sufficiency. An optional LLM then writes an
explanation strictly from that evidence. Full detail: [ARCHITECTURE.md](ARCHITECTURE.md).

**Why not just ask an LLM whether a message is a scam?**
Because the output would be non-reproducible, unauditable, impossible to regression-test, and free to
invent findings. Here the LLM is an explanation layer: it cannot move the score, and a category it
suggests is rejected unless deterministic evidence already supports it. See
[SECURITY.md §4](SECURITY.md#4-llm-containment-and-prompt-injection) and the one test that pins it,
`test_llm_cannot_invent_a_category_without_deterministic_evidence`.

**Why not simple keyword matching?**
Because it is trivially bypassed (`guaranteed 40% returns`, `risk-free`, homoglyph domains) while
firing on legitimate receipts and security notices. This project started with exactly that bug: two of
the documented failure modes in [EVALUATION.md §3](EVALUATION.md#3-failure-modes-this-corpus-has-caught)
are keyword-matcher misses.

**Is this a product or a demonstration?**
An engineering demonstration: actively built, tested and documented, but not deployed and not operated
as a service. It is honest about that everywhere.

---

## 2. The numbers

**Is the "100% accuracy" real?**
No — and the repository never claims it is. The 64-case calibration corpus produces accuracy / precision
/ recall / F1 of 1.00, and that number is a **regression result on 64 hand-written fictional cases**.
Its purpose is to keep documented failure modes fixed and hard negatives at `LOW`. It is not a
real-world detection-accuracy claim. Read [EVALUATION.md](EVALUATION.md) before quoting it.

**Why is the ML precision only 0.6748?**
Because it is reported as measured, including the uncomfortable part: roughly one in three messages the
classifier flags as scam is actually ham. Tuning that number on the test split would make the table
prettier and the system no better. The classifier is deliberately the **smallest** weighted channel
(0.10), so one probabilistic false positive cannot by itself push a submission into a scam band.

**Why does the ML model carry the smallest weight?**
Its corpus is SMS spam/ham: English-only, ~12% prevalence, and effectively zero URL-bearing rows. It
cannot represent phishing URLs, lookalike domains, crypto drains or impersonation, so it contributes
one probabilistic signal while the deterministic channels carry the categories. See
[ARCHITECTURE.md §8](ARCHITECTURE.md#8-ml-architecture).

**What is the difference between risk level and confidence?**
`level` is the band your score falls into (LOW 0–24, MEDIUM 25–49, HIGH 50–74, CRITICAL 75–100).
`confidence` and `evidence_sufficiency` describe how much independent evidence backs that band. A LOW
band at `INSUFFICIENT` sufficiency is the honest output for "Check this." — and the conclusion text is
written so it cannot read as "verified safe".

**Do the calibration numbers and the ML numbers combine into one headline?**
No. They measure different things on different data: the whole pipeline on fictional cases versus one
model on a held-out split of real SMS. [EVALUATION.md §5](EVALUATION.md#5-why-the-two-regimes-must-never-be-combined)
lays out why they are not interchangeable.

---

## 3. Running and deploying it

**How long does an investigation take?**
It is a synchronous request, so the answer is "however long the providers take". With live keys, threat
intel and the LLM dominate (seconds); fully offline in demo mode it is milliseconds. There is no queue
to absorb latency.

**Can I run it with no API keys at all?**
Yes — that is the default. Demo mode uses deterministic explanations, a labelled mock threat-intel
provider and mock OCR, with the **real** ML artifact and a local SQLite store.

**Is it deployed somewhere I can try?**
No. No cloud deployment exists. [DEPLOYMENT.md](DEPLOYMENT.md) documents the intended paths and marks
each one verified, unverified or optional.

**Was the Docker path ever run?**
No. The Dockerfiles and compose file are committed but were never executed in this environment because
the Docker CLI was unavailable. They are documented as **not verified**.

**And PostgreSQL?**
Same answer: the code path, engine-portable filters and compose configuration exist, but PostgreSQL was
never configured or exercised here. SQLite is the verified local store.

**Why is there no CI badge?**
Because there is no `.github/` workflow. A badge with nothing behind it would be a false claim, so the
README carries a real test-count badge (180 passing, 11 skipped) instead.

**Why does `npm run lint` not work?**
`next lint` opens an interactive prompt to configure ESLint, and no ESLint config is committed. Rather
than add one just to show a passing badge, `typecheck` and `build` are the enforced frontend gates. See
[TESTING.md](TESTING.md).

---

## 4. Behaviour and limits

**Is a LOW result a clean bill of health?**
No. LOW means no significant evidence was found. Provider failures, timeouts and rate limits count as
*no information* — they can never lower a score or produce a clean verdict, which is why
`verdict: "unknown"` with `status: "rate_limited"` must not be read as "safe". See
[API.md §9](API.md#9-response-objects).

**Does the server fetch the URLs I submit?**
No, and that is deliberate: the URL is parsed structurally and sent to reputation providers **as a
value**. Adding a fetch would create an SSRF surface — someone could submit an internal address
(`http://169.254.169.254/...`) and use the server to probe networks. See
[SECURITY.md §2](SECURITY.md#2-threat-model).

**Are my screenshots stored?**
No. Images are size-checked, decoded and analysed **in memory** and are never written to disk. The only
thing persisted from a submission is the extracted text and the structured results. See
[SECURITY.md §5.2](SECURITY.md#52-what-is-stored-and-where).

**What leaves my machine when I enable live providers?**
The URL strings go to Google Safe Browsing and VirusTotal; a structured context including a
2,000-character text preview goes to your LLM provider. Screenshots never leave. In demo mode nothing
leaves at all. The full table is in [SECURITY.md §5.1](SECURITY.md#51-what-leaves-the-machine--and-only-when-keys-are-configured).

**Can it handle non-English scams?**
Detection is English-centric. The linguistic signals, rules and training corpus are English, so
non-English content will produce sparse evidence and low-confidence results.

**Why does a legitimate message sometimes get a scam category?**
Categories come from deterministic rules, and a benign look-alike can inherit a nearby label even when
the band is correctly LOW (a real file-sharing notification inheriting a phishing label, for example).
The **band**, not the label, gates the verdict, and the LLM may not invent a category. Reported
misclassifications are worth an issue.

**Why do results change over time on identical input?**
Because live provider coverage changes: reputation databases add and remove URLs, and the LLM's prose
varies. The **score** is deterministic given the same evidence and weights — compare `risk.weights` and
`contributors` between runs.

**Why do some tests show as skipped?**
The live provider suites are opt-in and require real credentials (or a system Tesseract). They are
excluded from the default run so that the suite is hermetic and a developer's keys cannot turn `pytest`
into a network run.

**Is this production-ready?**
No. There is no authentication, no tenancy, no encryption at rest, no retention policy, and the rate
limiter is in-process. It is a single-tenant local tool. [SECURITY.md §6](SECURITY.md#6-known-limitations-and-non-goals)
lists the accepted risks rather than leaving them implied.

---

## 5. Engineering decisions

**Why LangGraph?**
It gives a typed state, conditional fan-out and a legible execution graph, so the pipeline reads as
stages rather than a chain of function calls. The cost is one real quirk — langgraph 0.2.x mis-schedules
unequal-depth branch merges — which is why every branch has an equal-depth `*_pad` node. See
[ARCHITECTURE.md §4](ARCHITECTURE.md#4-langgraph-workflow).

**Why is the risk score a weighted sum instead of a model?**
Because a verdict a human is asked to trust must be reproducible and explainable line by line. Every
assessment returns `contributors` rows showing the arithmetic, so the UI's "Why this score?" panel is
rendered from real numbers rather than a narrative.

**Why do some channels not count toward the score?**
A channel that could not have fired for a submission (URL risk on a text-only message) is excluded from
the denominator rather than counted as zero. When an assessment is URL-anchored, applicable-but-silent
channels are dropped too, so a credential-harvesting URL beside neutral text is not diluted to LOW. See
[ARCHITECTURE.md §7](ARCHITECTURE.md#7-risk-engine).

**Why `patterns.py` and `ml/features.py` in the same sentence?**
Rule matching produces the `scam_keyword_hits` model feature, so editing rules invalidates the shipped
artifact and requires retraining. That coupling is the single most important thing to know before
touching detection — see [CONTRIBUTING.md §5](CONTRIBUTING.md#5-changing-detection-logic).

**Why keep both a synthetic dataset and a real one?**
The synthetic set proves the pipeline end-to-end and is useless as evidence; the real UCI corpus gives a
genuine held-out estimate but only for SMS spam. The loader records `dataset_origin` so the two can
never be confused — see [backend/data/datasets/README.md](../backend/data/datasets/README.md).

**Where do I add a scam rule, a provider or an evaluation case?**
[CONTRIBUTING.md §2](CONTRIBUTING.md#2-repository-map-where-to-change-what) maps change type to file, and
[EVALUATION.md §1.6](EVALUATION.md#16-adding-a-case) covers corpus additions.

---

Still stuck? [TROUBLESHOOTING.md](TROUBLESHOOTING.md) has symptom-by-symptom fixes, and
[CONTRIBUTING.md](CONTRIBUTING.md) explains what a good issue or pull request contains.
