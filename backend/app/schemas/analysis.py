"""Analysis result schemas produced by graph nodes."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TextSignals(BaseModel):
    """Structured linguistic signals from the text-analysis node."""

    urgency_score: float = Field(0.0, ge=0.0, le=1.0)
    fear_threat_score: float = Field(0.0, ge=0.0, le=1.0)
    reward_score: float = Field(0.0, ge=0.0, le=1.0)
    pressure_score: float = Field(0.0, ge=0.0, le=1.0)
    authority_impersonation: bool = False
    payment_request: bool = False
    credential_request: bool = False
    otp_request: bool = False
    sensitive_info_request: bool = False
    suspicious_instructions: bool = False
    # Context flags: a *protective* warning tells the recipient never to
    # share credentials; a *reassurance* says no action is needed.  Both
    # distinguish genuine security notices from credential-harvesting
    # requests so the engine does not treat "OTP" / "password" mentions as
    # requests by themselves.
    protective_warning: bool = False
    reassurance: bool = False
    urgent_phrases: list[str] = Field(default_factory=list)
    authority_phrases: list[str] = Field(default_factory=list)
    reward_phrases: list[str] = Field(default_factory=list)
    payment_phrases: list[str] = Field(default_factory=list)
    credential_phrases: list[str] = Field(default_factory=list)
    threat_phrases: list[str] = Field(default_factory=list)
    summary: str | None = None


class URLAnalysis(BaseModel):
    url: str
    domain: str | None = None
    hostname: str | None = None
    tld: str | None = None
    path: str | None = None
    query_params: list[str] = Field(default_factory=list)
    scheme: str | None = None
    is_https: bool = False
    url_length: int = 0
    has_ip_address: bool = False
    has_punycode: bool = False
    is_shortened: bool = False
    suspicious_symbols: list[str] = Field(default_factory=list)
    suspicious_keywords: list[str] = Field(default_factory=list)
    excessive_subdomains: bool = False
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    signals: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelResult(BaseModel):
    """Normalized threat-intelligence outcome for one URL.

    Provider-specific payloads are converted to these fields at the
    provider boundary so the rest of the application never sees raw API
    formats.  ``verdict`` expresses the reputation finding
    (safe/suspicious/malicious/unknown); ``status`` expresses whether the
    lookup itself succeeded.  A failed lookup is ``verdict=unknown`` with a
    non-``ok`` status and must never be mistaken for a clean result.
    """

    provider: str = "none"
    is_mock: bool = False
    verdict: str = "unknown"  # safe | suspicious | malicious | unknown
    # ok | error | unavailable | rate_limited
    status: str = "ok"
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    reputation: str = "unknown"
    categories: list[str] = Field(default_factory=list)
    hits: int = 0
    detail: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    checked_at: str | None = None  # ISO-8601 UTC timestamp of the lookup


class MLPrediction(BaseModel):
    probability_scam: float = Field(0.0, ge=0.0, le=1.0)
    label: str = "benign"  # benign | scam
    features: dict[str, Any] = Field(default_factory=dict)
    model: str = "none"
    is_mock: bool = False
    feature_importance: dict[str, float] = Field(default_factory=dict)


class ScamClassification(BaseModel):
    primary: str = "unknown"
    alternatives: list[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    method: str = "rules"  # rules | llm | hybrid
    rationale: str | None = None


class EntityAnalysis(BaseModel):
    claimed_entities: list[str] = Field(default_factory=list)
    matched_known: list[str] = Field(default_factory=list)
    impersonation_indicators: list[str] = Field(default_factory=list)
    notes: str | None = None