"""Scam-pattern matching engine.

Evaluates the declarative rule set against normalized text and extracted
entities, then produces a category ranking (primary + alternatives with
confidence) and structured signals for the evidence store.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.patterns.rules import CATEGORY_LABELS, RULES, ScamRule
from app.schemas.analysis import ScamClassification
from app.schemas.evidence import EvidenceSignal, ExtractedEntities, ExtractedEntity
from app.utils.text import normalize_text


def is_ambiguous(classification: ScamClassification | None) -> bool:
    """Whether the rules-based classification needs refinement.

    ``True`` when no category could be picked confidently (unknown) or the
    top category only barely out-scored the alternatives.
    """
    if classification is None:
        return True
    if classification.primary in ("unknown", "other"):
        return True
    return classification.confidence < 0.5


@dataclass
class RuleMatch:
    rule: ScamRule
    matched_keywords: list[str] = field(default_factory=list)


# Credential/account-alarm rules that must NOT fire when the message is a
# protective warning or reassurance with no actual request (e.g. "never
# share your OTP", "a new device logged in — no action needed").  These are
# exactly the rules that would otherwise treat a mention as a request.
_ALARM_RULE_IDS = {
    "bank_otp_request",
    "bank_login_verification",
    "bank_kyc_request",
    "bank_account_suspension",
    "bank_card_blocked",
    "phishing_generic",
    "account_unusual_activity",
    "account_verify_identity",
}


def _suppress_alarm_rules(text_signals) -> bool:
    """Whether credential/account alarm rules should be skipped.

    True when the message is protective or reassuring AND nothing is being
    requested (no credential/OTP/sensitive request intent).  A scam that
    asks for a code while also saying "never share it" still requests it,
    so requestive intent always wins.
    """
    if text_signals is None:
        return False
    if not (text_signals.protective_warning or text_signals.reassurance):
        return False
    return not (
        text_signals.credential_request
        or text_signals.otp_request
        or text_signals.sensitive_info_request
    )


def match_rules(
    text: str,
    entities: ExtractedEntities | None = None,
    text_signals=None,
) -> list[RuleMatch]:
    """Match all rules against the normalized text and entity inventory."""
    normalized = normalize_text(text)
    lowered = normalized.lower()
    entity_types = {e.entity_type for e in entities.all()} if entities else set()
    suppress_alarms = _suppress_alarm_rules(text_signals)

    matches: list[RuleMatch] = []
    for rule in RULES:
        if suppress_alarms and rule.id in _ALARM_RULE_IDS:
            continue
        if rule.required_entities and not rule.required_entities.intersection(entity_types):
            continue
        hits = [
            kw
            for kw in rule.keywords
            if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", lowered)
        ]
        if hits:
            matches.append(RuleMatch(rule=rule, matched_keywords=hits))
    return matches


def classify(
    text: str,
    entities: ExtractedEntities | None = None,
    text_signals=None,
) -> tuple[ScamClassification, list[RuleMatch]]:
    """Rank scam categories by matched-rule weight.

    Returns the classification plus raw matches so callers can build
    evidence signals from the same pass.
    """
    matches = match_rules(text, entities, text_signals)

    category_scores: dict[str, float] = {}
    category_hits: dict[str, int] = {}
    for match in matches:
        cat = match.rule.category
        category_scores[cat] = category_scores.get(cat, 0.0) + match.rule.weight
        category_hits[cat] = category_hits.get(cat, 0) + len(match.matched_keywords)

    # category boost from structured text signals
    if text_signals is not None:
        if text_signals.otp_request:
            category_scores["banking_scam"] = category_scores.get("banking_scam", 0.0) + 1.0
        if text_signals.credential_request:
            category_scores["phishing"] = category_scores.get("phishing", 0.0) + 0.75
        if text_signals.payment_request:
            category_scores["payment_scam"] = category_scores.get("payment_scam", 0.0) + 0.5

    if not category_scores:
        return (
            ScamClassification(
                primary="unknown",
                alternatives=[],
                confidence=0.0,
                method="rules",
                rationale="No scam pattern matched; evidence insufficient for classification.",
            ),
            matches,
        )

    # rank by matched weight, breaking near-ties by keyword coverage so a
    # category with several concrete matched phrases wins over a tie by one
    # broad keyword (e.g. a parcel notice hitting one banking phrase)
    ranked = sorted(
        category_scores.items(),
        key=lambda kv: (kv[1], category_hits.get(kv[0], 0)),
        reverse=True,
    )
    primary, primary_score = ranked[0]
    total = sum(s for _, s in ranked)
    alternatives = [cat for cat, _ in ranked[1:] if cat != primary]
    confidence = round(min(0.95, primary_score / total), 2)
    if len(ranked) == 1:
        confidence = min(0.9, 0.4 + 0.1 * primary_score)

    return (
        ScamClassification(
            primary=primary,
            alternatives=alternatives,
            confidence=confidence,
            method="rules",
            rationale=(
                f"Matched {len(matches)} pattern(s) with strongest category "
                f"'{CATEGORY_LABELS.get(primary, primary)}' (score {primary_score:.1f})."
            ),
        ),
        matches,
    )


def matches_to_signals(matches: list[RuleMatch]) -> list[EvidenceSignal]:
    """Convert rule matches into structured evidence signals."""
    signals: list[EvidenceSignal] = []
    for match in matches:
        signals.append(
            EvidenceSignal(
                source="scam_pattern",
                signal=match.rule.id,
                severity=match.rule.severity,
                confidence=match.rule.confidence,
                description=f"[{CATEGORY_LABELS.get(match.rule.category, match.rule.category)}] {match.rule.description}",
                detail={
                    "rule_name": match.rule.name,
                    "category": match.rule.category,
                    "matched_keywords": match.matched_keywords,
                    "weight": match.rule.weight,
                },
            )
        )
    return signals