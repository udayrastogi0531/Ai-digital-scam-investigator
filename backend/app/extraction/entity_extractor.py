"""Known-brand / organization extraction and lookalike-domain heuristics.

The knowledge base is small, curated and fictional-friendly: it only
contains widely known organizations.  Impersonation is *never* claimed
from the brand dictionary alone — it requires corroborating signals
(e.g. a URL whose host does not belong to the claimed brand).
"""
from __future__ import annotations

import re

from app.schemas.evidence import ExtractedEntities, ExtractedEntity
from app.utils.text import levenshtein, normalize_text

# name -> (category, official hostnames)
_KNOWN: dict[str, tuple[str, list[str]]] = {
    # Tech platforms
    "microsoft": ("company", ["microsoft.com"]),
    "apple": ("company", ["apple.com", "icloud.com"]),
    "amazon": ("company", ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"]),
    "google": ("company", ["google.com", "gmail.com", "youtube.com"]),
    "netflix": ("company", ["netflix.com"]),
    "paypal": ("company", ["paypal.com"]),
    "ebay": ("company", ["ebay.com"]),
    "facebook": ("company", ["facebook.com"]),
    "instagram": ("company", ["instagram.com"]),
    "linkedin": ("company", ["linkedin.com"]),
    "whatsapp": ("company", ["whatsapp.com"]),
    "telegram": ("company", ["telegram.org"]),
    "twitter": ("company", ["twitter.com", "x.com"]),
    "spotify": ("company", ["spotify.com"]),
    "adobe": ("company", ["adobe.com"]),
    "samsung": ("company", ["samsung.com"]),
    "sony": ("company", ["sony.com", "playstation.com"]),
    "nvidia": ("company", ["nvidia.com"]),
    "tesla": ("company", ["tesla.com"]),
    "uber": ("company", ["uber.com"]),
    "airbnb": ("company", ["airbnb.com"]),
    "shopify": ("company", ["shopify.com"]),
    "etsy": ("company", ["etsy.com"]),
    "alibaba": ("company", ["alibaba.com"]),
    "aliexpress": ("company", ["aliexpress.com"]),
    "coinbase": ("company", ["coinbase.com"]),
    "binance": ("company", ["binance.com"]),
    "kraken": ("company", ["kraken.com"]),
    "wise": ("company", ["wise.com"]),
    "stripe": ("company", ["stripe.com"]),
    "western union": ("company", ["westernunion.com"]),
    "moneygram": ("company", ["moneygram.com"]),
    "dhl": ("company", ["dhl.com"]),
    "fedex": ("company", ["fedex.com"]),
    "ups": ("company", ["ups.com"]),
    "usps": ("company", ["usps.com"]),
    "royal mail": ("company", ["royalmail.com"]),
    "australia post": ("company", ["auspost.com.au"]),
    "telstra": ("company", ["telstra.com.au"]),
    # Banks / financial
    "hsbc": ("bank", ["hsbc.com"]),
    "barclays": ("bank", ["barclays.co.uk", "barclays.com"]),
    "santander": ("bank", ["santander.com", "santander.co.uk"]),
    "chase": ("bank", ["chase.com"]),
    "wells fargo": ("bank", ["wellsfargo.com"]),
    "bank of america": ("bank", ["bankofamerica.com"]),
    "citi": ("bank", ["citi.com", "citibank.com"]),
    "citibank": ("bank", ["citi.com", "citibank.com"]),
    "deutsche bank": ("bank", ["db.com"]),
    "standard chartered": ("bank", ["sc.com"]),
    "natwest": ("bank", ["natwest.com"]),
    "lloyds": ("bank", ["lloydsbank.co.uk"]),
    "halifax": ("bank", ["halifax.co.uk"]),
    "nationwide": ("bank", ["nationwide.co.uk"]),
    "monzo": ("bank", ["monzo.com"]),
    "revolut": ("bank", ["revolut.com"]),
    "n26": ("bank", ["n26.com"]),
    "hdfc": ("bank", ["hdfcbank.com"]),
    "icici": ("bank", ["icicibank.com"]),
    "sbi": ("bank", ["onlinesbi.sbi"]),
    "axis bank": ("bank", ["axisbank.com"]),
    "commonwealth bank": ("bank", ["commbank.com.au"]),
    "anz": ("bank", ["anz.com"]),
    "westpac": ("bank", ["westpac.com.au"]),
    "nab": ("bank", ["nab.com.au"]),
    "bmo": ("bank", ["bmo.com"]),
    "td bank": ("bank", ["td.com"]),
    "rbc": ("bank", ["rbc.com"]),
    "scotiabank": ("bank", ["scotiabank.com"]),
    # Government / official
    "irs": ("government", ["irs.gov"]),
    "hmrc": ("government", ["hmrc.gov.uk"]),
    "ato": ("government", ["ato.gov.au"]),
    "social security": ("government", ["ssa.gov"]),
    "customs": ("government", []),
    "police": ("government", []),
    "interpol": ("government", ["interpol.int"]),
    "fbi": ("government", ["fbi.gov"]),
    "cra": ("government", ["canada.ca"]),
    "centrelink": ("government", ["servicesaustralia.gov.au"]),
    "passport office": ("government", ["gov.uk"]),
    "dvla": ("government", ["gov.uk"]),
    "ministry of finance": ("government", []),
}

# Aliases map to canonical keys
_ALIASES: dict[str, str] = {
    "ms": "microsoft",
    "microsooft": "microsoft",
    "appel": "apple",
    "amaz0n": "amazon",
    "paypa1": "paypal",
    "netfix": "netflix",
    "whats app": "whatsapp",
    "whatsapp": "whatsapp",
    "wapp": "whatsapp",
}

_WORD_RE = re.compile(r"[a-z0-9&.' ]+")

# Leetspeak / character-substitution normalisation (e.g. paypa1 -> paypal,
# amaz0n -> amazon, m1crosoft -> microsoft) used for hostname lookalikes.
_LEET = str.maketrans({"0": "o", "1": "l", "2": "z", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g"})

# Cyrillic / Greek homoglyphs that visually mimic Latin letters (e.g.
# "аррӏе" -> "apple").  Conservative: only near-identical lookalikes.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ӏ": "l", "ѕ": "s", "г": "r", "в": "b",
    "м": "m", "к": "k", "н": "h", "т": "m", "и": "u", "п": "n",
    "а": "a", "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "У": "Y", "Х": "X", "І": "I", "Ѕ": "S", "Г": "R", "В": "B",
})


def _decode_punycode_labels(hostname: str) -> str:
    """Decode IDNA punycode labels (``xn--…``) so homoglyph brand detection
    sees the real characters (e.g. ``xn--80ak6aa92e`` -> ``аррӏе``)."""
    try:
        import idna
    except ImportError:  # pragma: no cover - stdlib has no idna; installed normally
        return hostname
    labels: list[str] = []
    for label in hostname.split("."):
        if label.startswith("xn--"):
            try:
                label = idna.decode(label)
            except Exception:  # noqa: BLE001 - malformed punycode, keep as-is
                pass
        labels.append(label)
    return ".".join(labels)


def _single_word_brands() -> dict[str, str]:
    """canonical key -> brand label for every single-word known brand."""
    out: dict[str, str] = {}
    for key in _KNOWN:
        if " " not in key and len(key) >= 3:
            out[key] = key
    for alias, key in _ALIASES.items():
        if " " not in alias and len(alias) >= 3:
            out[alias] = key
    return out


def detect_brand_lookalike_host(hostname: str | None) -> dict | None:
    """Return ``{claimed_brand, hostname, normalized}`` when a hostname
    visually invokes a known brand but does not belong to its official
    domains — without requiring the brand to appear anywhere else.

    Returns ``None`` for official domains and unrelated hostnames.
    """
    host = (hostname or "").lower().rstrip(".")
    if not host:
        return None
    # Decode punycode first (xn--80ak6aa92e -> аррӏе), then normalise
    # leetspeak and homoglyphs (аррӏе -> apple) before token matching.
    decoded = _decode_punycode_labels(host)
    normalized = decoded.translate(_LEET).translate(_HOMOGLYPHS)
    for candidate, canonical in _single_word_brands().items():
        official = _KNOWN.get(canonical, (None, []))[1]
        if hostname_matches_official(host, official):
            continue
        tokens = re.split(r"[.\-]+", normalized)
        for token in tokens:
            matched = (
                token == candidate
                or (token.startswith(candidate) and len(token) <= len(candidate) + 6)
                or (token.endswith(candidate) and len(token) <= len(candidate) + 6)
            )
            if matched:
                return {
                    "claimed_brand": canonical,
                    "hostname": host,
                    "normalized": normalized,
                    "decoded": decoded if decoded != host else None,
                }
    return None


def _brand_key(name: str) -> str | None:
    lowered = normalize_text(name).lower()
    if lowered in _KNOWN:
        return lowered
    if lowered in _ALIASES:
        return _ALIASES[lowered]
    # fuzzy match: allow small typos against known brand names
    best, best_dist = None, 2
    for key in _KNOWN:
        dist = levenshtein(lowered, key, max_dist=2)
        if dist <= best_dist:
            best, best_dist = key, dist
    return best


def extract_known_entities(text: str) -> ExtractedEntities:
    """Find mentions of known organizations/brands in the text."""
    result = ExtractedEntities()
    normalized = normalize_text(text)
    lowered = normalized.lower()
    matched_keys: set[str] = set()
    for key in sorted(_KNOWN, key=len, reverse=True):
        if key in matched_keys:
            continue
        # word-boundary search
        if re.search(rf"(?i)\b{re.escape(key)}\b", normalized):
            category, _ = _KNOWN[key]
            entity = ExtractedEntity(
                entity_type=category,
                value=key.title() if category == "company" else key.upper() if len(key) <= 4 else key.title(),
                context="claimed organization in message",
                metadata={"canonical_key": key, "official_hostnames": _KNOWN[key][1]},
            )
            if category == "company":
                result.companies.append(entity)
            elif category == "bank":
                result.banks.append(entity)
            else:
                result.organizations.append(entity)
            matched_keys.add(key)
    # also detect obfuscated versions like "m!crosoft"
    for alias, key in _ALIASES.items():
        if key in matched_keys:
            continue
        if alias in lowered:
            category, hostnames = _KNOWN[key]
            result.companies.append(
                ExtractedEntity(
                    entity_type=category,
                    value=alias,
                    context="obfuscated brand name in message",
                    metadata={"canonical_key": key, "official_hostnames": hostnames},
                )
            )
            matched_keys.add(key)
    return result


def official_hostnames_for(key: str) -> list[str]:
    entry = _KNOWN.get(key)
    return list(entry[1]) if entry else []


def hostname_matches_official(hostname: str, official_hostnames: list[str]) -> bool:
    """True when the hostname belongs to the brand's official domains.

    Handles subdomains: ``login.microsoft.com`` matches ``microsoft.com``.
    """
    hostname = hostname.lower().rstrip(".")
    for official in official_hostnames:
        if hostname == official or hostname.endswith("." + official):
            return True
    return False


def brand_name_for_hostname(hostname: str) -> str | None:
    """Best-effort reverse lookup: which known brand does a hostname invoke?"""
    hostname = hostname.lower().rstrip(".")
    for key, (_, official) in _KNOWN.items():
        if hostname_matches_official(hostname, official):
            return key
    # lookalike: brand name appears inside host but not officially
    for key, (_, official) in _KNOWN.items():
        if key in hostname and not hostname_matches_official(hostname, official):
            return key
    return None