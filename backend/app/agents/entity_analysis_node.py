"""Entity/brand analysis node.

Checks whether a claimed organization is being impersonated.  Impersonation
is only flagged when a claimed brand is accompanied by a non-official URL
host or lookalike domain — never from the brand mention alone.
"""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.extraction.entity_extractor import (
    brand_name_for_hostname,
    hostname_matches_official,
    official_hostnames_for,
)
from app.graph.state import InvestigationState
from app.schemas.analysis import EntityAnalysis
from app.schemas.evidence import EvidenceSignal


@timed_node("entity_analysis")
def entity_analysis_node(state: InvestigationState) -> InvestigationState:
    entities = state.get("entities")
    urls = state.get("urls") or []

    claimed: list[str] = []
    if entities:
        claimed = [e.value for e in [*entities.companies, *entities.banks, *entities.organizations]]

    official_hosts = {
        e.metadata.get("canonical_key"): e.metadata.get("official_hostnames", [])
        for e in (entities.companies + entities.banks + entities.organizations if entities else [])
        if e.metadata.get("canonical_key")
    }

    indicators: list[str] = []
    notes: list[str] = []
    signals: list[EvidenceSignal] = []

    hostnames = [u.hostname for u in urls if u.hostname]
    for canonical, hosts in official_hosts.items():
        # any URL whose host does NOT belong to the claimed brand → flag
        for hostname in hostnames:
            if hostname_matches_official(hostname, hosts):
                continue
            # only flag when the URL plausibly claims to be the brand
            brand = brand_name_for_hostname(hostname)
            if brand and brand == canonical:
                indicators.append(f"URL host '{hostname}' claims to be '{canonical}' but is not an official domain")
                signals.append(
                    EvidenceSignal(
                        source="entity_analysis",
                        signal="brand_lookalike_host",
                        severity="high",
                        confidence=0.8,
                        description=f"Host '{hostname}' invokes brand '{canonical}' but is not an official domain for it.",
                        detail={"hostname": hostname, "claimed_brand": canonical, "official_hosts": hosts},
                    )
                )
            elif canonical in hostname.lower():
                indicators.append(f"URL host '{hostname}' contains brand name '{canonical}' outside its official domains")
                signals.append(
                    EvidenceSignal(
                        source="entity_analysis",
                        signal="brand_mention_in_host",
                        severity="medium",
                        confidence=0.6,
                        description=f"Brand name '{canonical}' embedded in unrelated host '{hostname}'.",
                        detail={"hostname": hostname, "claimed_brand": canonical},
                    )
                )

    if claimed and not indicators:
        notes.append("Claimed organizations detected but no non-official hostnames found to corroborate impersonation.")

    if not claimed:
        notes.append("No well-known organizations detected in the content.")

    return state_update(
        state,
        entity_analysis=EntityAnalysis(
            claimed_entities=claimed,
            matched_known=list(official_hosts.keys()),
            impersonation_indicators=indicators,
            notes="; ".join(notes) if notes else None,
        ),
        evidence=signals,
    )