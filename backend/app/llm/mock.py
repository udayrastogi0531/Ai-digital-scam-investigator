"""Mock LLM provider.

Generates explanations and reports deterministically from structured
evidence (see :mod:`app.llm.deterministic`).  Output is always labeled as
mock so the UI can show that no real LLM was consulted.
"""
from __future__ import annotations

from app.llm.base import LLMProvider
from app.llm.deterministic import deterministic_explain, deterministic_report
from app.schemas.analysis import ScamClassification
from app.schemas.llm import ExplanationResult, ReportContext
from app.schemas.report import InvestigationReport


class MockLLMProvider(LLMProvider):
    name = "mock"
    is_mock = True

    async def classify(self, context: ReportContext) -> ScamClassification | None:
        # There is no real LLM in mock mode: ambiguous classifications stay
        # exactly as the deterministic rule engine produced them.  Returning
        # None keeps the graph on the rules result instead of pretending an
        # LLM refined it.
        return None

    async def explain(self, context: ReportContext) -> ExplanationResult:
        return deterministic_explain(context)

    async def generate_report(self, context: ReportContext) -> InvestigationReport:
        return deterministic_report(context)