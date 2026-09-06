"""Threat-intelligence node: query configured providers per URL."""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.graph.state import InvestigationState
from app.intelligence import get_manager
from app.schemas.evidence import EvidenceSignal


@timed_node("threat_intel")
async def threat_intel_node(state: InvestigationState) -> InvestigationState:
    urls = state.get("urls") or []
    if not urls:
        return state_update(state)

    manager = get_manager()
    results = []
    for u in urls:
        result = await manager.analyze(u.url)
        results.append(result)

    signals: list[EvidenceSignal] = []
    warnings: list[str] = []
    for u, result in zip(urls, results):
        if result.error:
            warnings.append(f"Threat-intel lookup for {u.hostname} failed ({result.error}).")
        if result.status == "rate_limited":
            warnings.append(f"Threat-intel provider {result.provider} is rate-limited; no verdict for {u.hostname}.")
        if result.verdict in ("malicious", "suspicious"):
            severity = "critical" if result.verdict == "malicious" else "high"
        elif result.verdict == "safe":
            severity = "low"
        elif result.status != "ok":
            # A failed lookup produced no verdict: record it as informational
            # (never as a clean/low-risk signal).
            severity = "info"
        else:
            severity = "info"
        mock_note = " [DEMO]" if result.is_mock else ""
        signals.append(
            EvidenceSignal(
                source="threat_intelligence",
                signal=f"threat_intel_{result.verdict}",
                severity=severity,
                confidence=min(0.95, 0.3 + result.risk_score),
                description=(
                    f"Threat intelligence verdict{mock_note}: {result.verdict} "
                    f"(provider: {result.provider}, reputation: {result.reputation or 'n/a'}, "
                    f"status: {result.status})."
                ),
                detail={
                    "url": u.url,
                    "provider": result.provider,
                    "verdict": result.verdict,
                    "status": result.status,
                    "risk_score": result.risk_score,
                    "reputation": result.reputation,
                    "categories": list(result.categories),
                    "is_mock": result.is_mock,
                    "hits": result.hits,
                    "error": result.error,
                    "checked_at": result.checked_at,
                    # Per-provider normalized breakdown (incl. failures) so
                    # the UI can show exactly who said what and who failed.
                    "providers": (result.detail or {}).get("providers") or [],
                },
            )
        )
    if manager.uses_mock:
        warnings.append("Demo mode: no threat-intelligence API keys configured — using local mock intelligence (not real external data).")

    return state_update(
        state,
        threat_intel=results,
        evidence=signals,
        warnings=warnings,
    )