"""Input-parser node: normalize the submission and extract entities."""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.extraction.entity_extractor import extract_known_entities
from app.extraction.text_extractor import extract_all, extract_urls
from app.graph.state import InvestigationState
from app.schemas.evidence import EvidenceSignal, ExtractedEntities
from app.utils.text import normalize_text


@timed_node("parse")
def parse_node(state: InvestigationState) -> InvestigationState:
    raw = state.get("raw_inputs", {})
    text = normalize_text(raw.get("text", ""))
    explicit_urls = list(raw.get("urls") or [])
    source_label = raw.get("source_label")

    # merge OCR text if a previous node (or the service) added it
    ocr_text = normalize_text(state.get("ocr_text"))
    combined_text = f"{text}\n{ocr_text}".strip()

    entities = extract_all(combined_text) if combined_text else ExtractedEntities()
    # explicit URLs may not appear in text — add them as entities
    for url in explicit_urls:
        if not any(e.value == url for e in entities.urls):
            entities.urls.append(extract_urls(url)[0] if extract_urls(url) else _url_entity(url))

    known = extract_known_entities(combined_text)
    entities.companies.extend(known.companies)
    entities.banks.extend(known.banks)
    entities.organizations.extend(known.organizations)

    input_types = list(raw.get("input_types") or [])
    if "text" not in input_types and combined_text:
        input_types.append("text")
    if explicit_urls:
        input_types.append("url")
    if raw.get("image") is not None:
        input_types.append("image")

    evidence: list[EvidenceSignal] = []
    if combined_text:
        evidence.append(
            EvidenceSignal(
                source="input_parser",
                signal="input_received",
                severity="info",
                confidence=1.0,
                description=f"Received {len(input_types)} input type(s); extracted {len(entities.all())} entities.",
                detail={"entity_counts": _counts(entities)},
            )
        )
    return state_update(
        state,
        normalized_text=combined_text,
        explicit_urls=explicit_urls,
        entities=entities,
        input_types=input_types,
        evidence=evidence,
        status="running",
    )


def _url_entity(url: str):
    from app.schemas.evidence import ExtractedEntity

    return ExtractedEntity(entity_type="url", value=url, context="explicit submission")


def _counts(entities: ExtractedEntities) -> dict[str, int]:
    return {name: len(getattr(entities, name)) for name in entities.model_fields}