"""Scam-pattern detection package."""
from .engine import classify, matches_to_signals, match_rules  # noqa: F401
from .rules import CATEGORY_LABELS, RULES  # noqa: F401