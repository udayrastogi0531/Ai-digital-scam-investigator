"""LLM provider abstraction.

Providers implement three domain methods — classification refinement,
explanation and report generation — so the graph never talks to a raw
chat API directly.  Every provider MUST:

* only use facts from the supplied :class:`ReportContext`
* mark uncertainty explicitly
* never invent reputation results or organization confirmations
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.analysis import ScamClassification
from app.schemas.llm import ExplanationResult, ReportContext
from app.schemas.report import InvestigationReport


class LLMProvider(ABC):
    name: str = "base"
    is_mock: bool = False

    @abstractmethod
    async def classify(self, context: ReportContext) -> ScamClassification | None:
        """Refine classification from evidence.  May return None to skip."""

    @abstractmethod
    async def explain(self, context: ReportContext) -> ExplanationResult:
        """Produce a human-readable explanation strictly from evidence."""

    @abstractmethod
    async def generate_report(self, context: ReportContext) -> InvestigationReport:
        """Produce the full structured investigation report."""