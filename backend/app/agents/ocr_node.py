"""OCR node: extract text from an uploaded screenshot.

Gracefully falls back (mock OCR reports nothing) with a visible warning.
"""
from __future__ import annotations

import asyncio

from app.agents.common import state_update, timed_node
from app.extraction.ocr import get_ocr_provider
from app.graph.state import InvestigationState
from app.schemas.evidence import EvidenceSignal


@timed_node("ocr")
async def ocr_node(state: InvestigationState) -> InvestigationState:
    raw = state.get("raw_inputs", {})
    image_bytes = raw.get("image_bytes")
    warnings: list[str] = []
    evidence: list[EvidenceSignal] = []

    if not image_bytes:
        return state_update(state, warnings=warnings, evidence=evidence)

    provider = get_ocr_provider()
    result = await provider.extract(image_bytes)
    if result.error:
        warnings.append(f"OCR unavailable ({result.error}) — continuing without extracted text.")
    if result.is_mock:
        warnings.append("Demo mode: OCR provider is a mock — no text was extracted from the image.")
        evidence.append(
            EvidenceSignal(
                source="ocr",
                signal="ocr_mock",
                severity="info",
                confidence=1.0,
                description="Screenshot received but OCR was unavailable; no text extracted.",
            )
        )
    else:
        evidence.append(
            EvidenceSignal(
                source="ocr",
                signal="ocr_extracted",
                severity="info",
                confidence=result.confidence,
                description=f"Extracted {len(result.text.split())} words from the screenshot (OCR, confidence {result.confidence:.0%}).",
            )
        )

    return state_update(
        state,
        ocr_text=result.text,
        ocr_confidence=result.confidence,
        ocr_provider=result.provider,
        ocr_mock=result.is_mock,
        warnings=warnings,
        evidence=evidence,
    )