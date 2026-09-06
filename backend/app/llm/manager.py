"""LLM provider factory honoring settings."""
from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.llm.base import LLMProvider
from app.llm.mock import MockLLMProvider
from app.llm.openai_compatible import OpenAICompatibleProvider


@lru_cache(maxsize=1)
def get_llm_provider() -> LLMProvider:
    settings = get_settings()
    if settings.llm_provider == "openai_compatible" and settings.llm_api_key:
        return OpenAICompatibleProvider()
    return MockLLMProvider()