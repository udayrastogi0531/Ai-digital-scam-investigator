"""Text normalization and string helpers."""
from __future__ import annotations

import re

_WHITESPACE = re.compile(r"[ \t]+")


def normalize_text(text: str | None) -> str:
    """Trim and collapse runs of spaces/tabs (keeps newlines)."""
    if not text:
        return ""
    return _WHITESPACE.sub(" ", text).strip()


def levenshtein(a: str, b: str, max_dist: int = 3) -> int:
    """Bounded Levenshtein distance (returns > max_dist when exceeding)."""
    a, b = a.lower(), b.lower()
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev = dp[0]
        dp[0] = i
        for j, cb in enumerate(b, 1):
            cur = dp[j]
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
            prev = cur
        if min(dp) > max_dist:
            return max_dist + 1
    return dp[-1]


def truncate(text: str, limit: int = 200) -> str:
    text = normalize_text(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def md5_hex(text: str) -> str:
    import hashlib

    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()  # noqa: S324 (fingerprint only)