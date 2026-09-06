"""Classification-refinement node (ambiguous cases only).

Flow: rules engine produces the initial classification.  Only when that
classification is *ambiguous* (unknown category or low confidence) is the
category refined.  Two refiners run, in priority order:

1. deterministic URL-derived classification — when the submission has no
   textual evidence but the URL structure shows brand impersonation or
   credential-harvesting intent (brand lookalikes, login/verify keywords),
   the category is derived from the URL so a HIGH-risk URL-only case is not
   left as "unknown";
2. LLM refinement — only when a live LLM is configured; it receives the
   same structured evidence and its output is Pydantic-validated.  The mock
   provider returns ``None`` so demo mode stays deterministic.

A refinement can never change the risk score — risk stays deterministic.
"""
from __future__ import annotations

import logging

from app.agents.common import state_update, timed_node
from app.agents.explain_node import build_context
from app.graph.state import InvestigationState
from app.llm import get_llm_provider
from app.patterns.engine import is_ambiguous
from app.schemas.analysis import ScamClassification, URLAnalysis
from app.schemas.evidence import EvidenceSignal

logger = logging.getLogger("scaminvestigator.agents")

# Keywords that indicate credential-harvesting / account-verification intent.
_CREDENTIAL_INTENT = {
    "login", "signin", "verify", "verification", "account", "secure", "confirm",
    "password", "credential", "otp", "2fa", "authenticate", "webscr",
    "update", "unlock", "suspend", "blocked", "billing", "payment",
}
# Official registrable domains that must never be flagged by keyword intent.
_OFFICIAL_DOMAINS = {
    "paypal.com", "apple.com", "icloud.com", "microsoft.com", "live.com",
    "outlook.com", "office.com", "netflix.com", "amazon.com", "google.com",
    "gmail.com", "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com",
    "twitter.com", "x.com", "chase.com", "wellsfargo.com", "hsbc.com",
    "barclays.com", "santander.com", "citi.com", "bankofamerica.com",
}


def _url_derived_classification(state: InvestigationState) -> ScamClassification | None:
    """Classify a URL-only submission from URL structure (no text required)."""
    if (state.get("normalized_text") or "").strip() or (state.get("ocr_text") or "").strip():
        return None  # text evidence exists; the rules engine already ran on it

    # ``classify_refine`` runs in parallel with ``url_analysis``, so analyze
    # the candidate URLs here rather than waiting on that branch's results.
    urls: list[URLAnalysis] = list(state.get("urls") or [])
    if not urls:
        entities = state.get("entities")
        raw = [e.value for e in (entities.urls if entities else [])] or list(state.get("explicit_urls") or [])
        if not raw:
            return None
        from app.extraction.url_analysis import analyze_url

        urls = [analyze_url(u) for u in raw]
    if not urls:
        return None

    claims: list[str] = []
    # "Strong" URLs (high structural risk) anchor the confidence; keyword
    # intent is checked on every URL so a credential-path host is classified
    # as phishing even when its aggregate risk is only moderate.
    strong = [u for u in urls if u.risk_score >= 0.4]
    for u in urls:
        lookalike = (u.detail or {}).get("brand_lookalike")
        if isinstance(lookalike, dict) and lookalike.get("claimed_brand"):
            claims.append(lookalike["claimed_brand"])
        keywords = set(u.suspicious_keywords or [])
        domain = (u.domain or "").lower()
        official = any(domain == d or domain.endswith("." + d) for d in _OFFICIAL_DOMAINS)
        if not official and (keywords & _CREDENTIAL_INTENT or u.risk_score >= 0.5):
            claims.append(domain)

    if not claims:
        return None

    brand_note = (
        f" hostname resembles '{claims[0]}'" if (urls[0].detail or {}).get("brand_lookalike") else ""
    )
    return ScamClassification(
        primary="phishing",
        alternatives=["impersonation_scam"] if claims else [],
        confidence=round(min(0.75, 0.45 + 0.15 * len(strong)), 2),
        method="url_analysis",
        rationale=(
            "No textual evidence was submitted; URL structure shows brand impersonation"
            f"{brand_note} or credential-harvesting intent ({claims[0]}), consistent with phishing."
        ),
    )


@timed_node("llm_classify")
async def classify_refine_node(state: InvestigationState) -> InvestigationState:
    rules = state.get("classification")
    if not is_ambiguous(rules):
        return state_update(state)

    url_cls = _url_derived_classification(state)
    provider = get_llm_provider()

    refined: ScamClassification | None = None
    if not provider.is_mock:
        try:
            refined = await provider.classify(build_context(state))
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM classification refinement failed: %s", exc)
    if refined is None:
        # demo/unavailable: prefer deterministic URL-derived, else rules result
        refined = url_cls if url_cls is not None else rules

    if refined is None or refined.primary == (rules.primary if rules else None):
        # nothing changed — no evidence to record
        return state_update(state, classification=refined) if refined is not None else state_update(state)

    evidence: list[EvidenceSignal] = []
    source = "url_classification" if refined.method == "url_analysis" else "llm_classification"
    evidence.append(
        EvidenceSignal(
            source=source,
            signal="classification_refined",
            severity="info",
            confidence=max(refined.confidence, 0.4),
            description=(
                f"Rules classification was ambiguous; {refined.method} refinement suggests "
                f"'{refined.primary}' (confidence {refined.confidence:.0%}) using the supplied evidence."
            ),
            detail={"provider": provider.name, "is_mock": provider.is_mock, "method": refined.method},
        )
    )
    return state_update(state, classification=refined, evidence=evidence)
