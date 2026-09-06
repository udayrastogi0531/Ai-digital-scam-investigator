"""OpenAI-compatible LLM provider.

Talks to any ``/chat/completions`` endpoint (OpenAI, OpenRouter, Ollama,
LM Studio, vLLM, …) via ``LLM_BASE_URL``.  Structured JSON output is
validated with Pydantic; invalid output triggers one safe retry, then a
controlled deterministic fallback so the investigation never fails.
"""
from __future__ import annotations

import json
import logging

import httpx
from pydantic import ValidationError

from app.core.config import get_settings
from app.llm import prompts
from app.llm.base import LLMProvider
from app.llm.deterministic import deterministic_explain, deterministic_report
from app.schemas.analysis import ScamClassification
from app.schemas.llm import ExplanationResult, ReportContext
from app.schemas.report import InvestigationReport

logger = logging.getLogger("scaminvestigator.llm")

_MAX_TOKENS = 1600


class LLMOutputError(RuntimeError):
    """Raised when the LLM returns unparseable output after retries."""


class OpenAICompatibleProvider(LLMProvider):
    name = "openai_compatible"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ):
        settings = get_settings()
        self.api_key = api_key or settings.llm_api_key
        self.base_url = (base_url or settings.llm_base_url or "https://api.openai.com/v1").rstrip("/")
        self.model = model or settings.llm_model
        self.timeout = timeout or settings.llm_timeout_seconds

    async def _chat(self, system: str, user: str, json_mode: bool = True) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": _MAX_TOKENS,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=body)
            if resp.status_code == 400 and json_mode:
                # endpoint may not support response_format; retry without it
                body.pop("response_format", None)
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, headers=headers, json=body)
            if resp.status_code != 200:
                raise LLMOutputError(f"LLM HTTP {resp.status_code}: {resp.text[:300]}")
            content = resp.json()["choices"][0]["message"]["content"]
        except httpx.HTTPError as exc:
            raise LLMOutputError(f"LLM request failed: {exc}") from exc
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise LLMOutputError(f"malformed LLM response: {exc}") from exc
        return content.strip()

    @staticmethod
    def _parse_json(text: str) -> dict:
        text = text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end <= start:
                raise LLMOutputError("no JSON object in LLM output")
            return json.loads(text[start : end + 1])

    async def classify(self, context: ReportContext) -> ScamClassification | None:
        if not context.classification:
            return None
        user = prompts.classification.build_classification_user(context)
        for attempt in (1, 2):
            try:
                raw = await self._chat(prompts.classification.SYSTEM, user)
                data = self._parse_json(raw)
                cls = ScamClassification.model_validate(data)
                cls.method = "hybrid(rules+llm)"
                return cls
            except (LLMOutputError, ValidationError, json.JSONDecodeError) as exc:
                logger.warning("LLM classification attempt %d failed: %s", attempt, exc)
                if attempt == 2:
                    return None
        return None

    async def explain(self, context: ReportContext) -> ExplanationResult:
        user = prompts.explanation.build_explanation_user(context)
        for attempt in (1, 2):
            try:
                raw = await self._chat(prompts.explanation.SYSTEM, user)
                data = self._parse_json(raw)
                result = ExplanationResult.model_validate(data)
                result.provider = self.name
                result.model = self.model
                result.is_mock = False
                return result
            except (LLMOutputError, ValidationError, json.JSONDecodeError) as exc:
                logger.warning("LLM explanation attempt %d failed: %s", attempt, exc)
                if attempt == 2:
                    break
        fallback = deterministic_explain(context)
        fallback.provider = "deterministic-fallback"
        return fallback

    async def generate_report(self, context: ReportContext) -> InvestigationReport:
        user = prompts.report.build_report_user(context)
        for attempt in (1, 2):
            try:
                raw = await self._chat(prompts.report.SYSTEM, user)
                data = self._parse_json(raw)
                report = InvestigationReport.model_validate(data)
                report.provider = self.name
                report.model = self.model
                return report
            except (LLMOutputError, ValidationError, json.JSONDecodeError) as exc:
                logger.warning("LLM report attempt %d failed: %s", attempt, exc)
                if attempt == 2:
                    break
        fallback = deterministic_report(context)
        fallback.provider = "deterministic-fallback"
        return fallback