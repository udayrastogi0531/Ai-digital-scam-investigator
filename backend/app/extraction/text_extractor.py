"""Regex-driven extraction of entities from raw message text.

This module is deliberately dependency-free and deterministic so it can be
unit-tested exhaustively.  It returns structured :class:`ExtractedEntities`.
"""
from __future__ import annotations

import re
from urllib.parse import unquote

from app.schemas.evidence import ExtractedEntities, ExtractedEntity
from app.utils.text import normalize_text

# --- URL detection ----------------------------------------------------------
# Matches http(s):// or www. prefixed tokens, stopping at common delimiters.
_URL_RE = re.compile(
    r"""(?i)\b(?:(?:https?|ftp)://|www\.)[^\s<>()\[\]{}\"'`\\]+""",
    re.UNICODE,
)

# Characters that may trail a URL but are usually punctuation.
_TRAILING_PUNCT = set(".,;:!?)]}>'\"")

# --- Email ------------------------------------------------------------------
_EMAIL_RE = re.compile(
    r"""(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"""
)

# --- Phone numbers ----------------------------------------------------------
# Covers the common shapes with separators: international (+44 20 7946 0958,
# +1-555-0100), parenthesized area codes ((555) 010-1234), 10-digit
# (555 010 1234) and short 7-digit numbers (555-0100).  Digit-count guards in
# ``extract_phones`` reject dates/years and random IDs.
_PHONE_RE = re.compile(
    r"""(?<![\d+])
    (?:
      \+\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{3,4})?   # +CC 555-0100 / +44 20 7946 0958
      |
      (?:\(\d{2,5}\)[\s.-]?|\d{2,5}[\s.-]?)?\d{3}[\s.-]?\d{4}   # (area) / area / plain 7-digit
      |
      \d{3}[\s.-]?\d{3}[\s.-]?\d{3,4}                         # 10-digit without area
    )
    (?!\d)""",
    re.VERBOSE,
)

# --- Monetary amounts -------------------------------------------------------
_CURRENCY_SYMBOLS = r"[$€£₹¥₩₦₱]"
_CURRENCY_CODES = r"(?:USD|EUR|GBP|INR|JPY|CNY|AUD|CAD|SGD|HKD|NGN|RUB|TRY|ZAR|BRL|MXN|KRW|PKR|BDT|VND|PHP|MYR|THB)"
_MONEY_RE = re.compile(
    rf"""(?i)
        (?:{_CURRENCY_SYMBOLS}\s?\d[\d,]*(?:\.\d{{1,2}})?)
        |
        (\d[\d,]*(?:\.\d{{1,2}})?\s*(?:{_CURRENCY_CODES}|dollars?|euros?|pounds?|rupees?|yen|yuan|bucks?))
        """,
    re.VERBOSE,
)

# --- Dates ------------------------------------------------------------------
_MONTHS = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*"
_DATE_RE = re.compile(
    rf"""(?i)
        \b\d{{1,2}}[/.-]\d{{1,2}}[/.-]\d{{2,4}}\b
        |
        \b\d{{1,2}}(?:st|nd|rd|th)?\s{_MONTHS}(?:\s\d{{4}})?\b
        |
        \b{_MONTHS}\s\d{{1,2}}(?:st|nd|rd|th)?,?\s\d{{4}}\b
        """,
    re.VERBOSE,
)

# --- Codes (OTP / PIN / verification codes) ---------------------------------
_CODE_TRIGGER = re.compile(r"(?i)\b(otp|one[- ]time(?: password| pin| code)?|verification code|security code|auth(?:entication)? code|pin|confirmation code|login code)\b")
_CODE_NUMBER = re.compile(r"(?<!\d)\d{4,8}(?!\d)")


def _clean_url_token(token: str) -> str:
    token = token.strip()
    # strip trailing punctuation and a dangling closing paren
    while token and token[-1] in _TRAILING_PUNCT:
        if token[-1] == ")" and token.count("(") < token.count(")"):
            token = token[:-1]
        elif token[-1] in ".,;:!?]}'\"'":
            token = token[:-1]
        else:
            break
    return token


def extract_urls(text: str) -> list[ExtractedEntity]:
    found: list[ExtractedEntity] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text):
        raw = _clean_url_token(match.group(0))
        if not raw or raw.lower().startswith(("www.",)):
            raw = "http://" + raw if raw else raw
        if raw in seen:
            continue
        seen.add(raw)
        found.append(
            ExtractedEntity(entity_type="url", value=raw, context="message text")
        )
    return found


def extract_emails(text: str) -> list[ExtractedEntity]:
    seen: set[str] = set()
    out: list[ExtractedEntity] = []
    for match in _EMAIL_RE.finditer(text):
        email = match.group(0).rstrip(".")
        if email.lower() in seen:
            continue
        seen.add(email.lower())
        out.append(ExtractedEntity(entity_type="email", value=email, context="message text"))
    return out


def extract_phones(text: str) -> list[ExtractedEntity]:
    seen: set[str] = set()
    out: list[ExtractedEntity] = []
    for match in _PHONE_RE.finditer(text):
        phone = match.group(0).strip()
        digits = re.sub(r"\D", "", phone)
        # avoid matching dates or years
        if len(digits) < 7 or len(digits) > 15:
            continue
        if phone in seen:
            continue
        seen.add(phone)
        out.append(
            ExtractedEntity(
                entity_type="phone",
                value=phone,
                context=text[max(0, match.start() - 40) : match.end() + 40].replace("\n", " "),
            )
        )
    return out


def extract_amounts(text: str) -> list[ExtractedEntity]:
    out: list[ExtractedEntity] = []
    seen: set[str] = set()
    for match in _MONEY_RE.finditer(text):
        amount = match.group(0).strip()
        if amount.lower() in seen:
            continue
        seen.add(amount.lower())
        out.append(
            ExtractedEntity(
                entity_type="amount",
                value=amount,
                context=text[max(0, match.start() - 40) : match.end() + 40].replace("\n", " "),
                metadata={"normalized": re.sub(r"[,\s]", "", amount)},
            )
        )
    return out


def extract_dates(text: str) -> list[ExtractedEntity]:
    out: list[ExtractedEntity] = []
    seen: set[str] = set()
    for match in _DATE_RE.finditer(text):
        value = match.group(0).strip()
        if value.lower() in seen:
            continue
        seen.add(value.lower())
        out.append(ExtractedEntity(entity_type="date", value=value, context="message text"))
    return out


def extract_codes(text: str) -> list[ExtractedEntity]:
    """Extract short numeric codes that appear near OTP/pin/code keywords."""
    out: list[ExtractedEntity] = []
    seen: set[str] = set()
    for trigger in _CODE_TRIGGER.finditer(text):
        window = text[max(0, trigger.start() - 25) : trigger.end() + 25]
        for num in _CODE_NUMBER.finditer(window):
            code = num.group(0)
            if code in seen:
                continue
            seen.add(code)
            out.append(
                ExtractedEntity(
                    entity_type="code",
                    value=code,
                    context=f"near '{trigger.group(0)}'",
                )
            )
    return out


def extract_all(text: str) -> ExtractedEntities:
    """Run every extractor and group results."""
    normalized = normalize_text(text)
    entities = ExtractedEntities()
    for url in extract_urls(normalized):
        entities.urls.append(url)
    for email in extract_emails(normalized):
        entities.emails.append(email)
    for phone in extract_phones(normalized):
        entities.phones.append(phone)
    for amount in extract_amounts(normalized):
        entities.amounts.append(amount)
    for date in extract_dates(normalized):
        entities.dates.append(date)
    for code in extract_codes(normalized):
        entities.other.append(code)
    return entities


def decode_obfuscated_url(text: str) -> str | None:
    """Best-effort recovery of URLs hidden by copy-paste tricks, e.g.

    ``hxxps://example[.]com`` or ``https :// example.com``.
    """
    candidate = text
    candidate = candidate.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    candidate = candidate.replace("hxxp://", "http://").replace("hxxps://", "https://")
    candidate = candidate.replace("http ://", "http://").replace("https ://", "https://")
    candidate = candidate.replace("http:// ", "http://").replace("https:// ", "https://")
    if "http" in candidate.lower() and ("http://" in candidate.lower() or "https://" in candidate.lower()):
        matches = _URL_RE.findall(candidate)
        if matches:
            return _clean_url_token(matches[0])
    return None


def unrotate_urls(urls: list[str]) -> list[str]:
    """Percent-decode and unescape URLs for analysis."""
    out = []
    for u in urls:
        try:
            out.append(unquote(u))
        except Exception:  # noqa: BLE001
            out.append(u)
    return out