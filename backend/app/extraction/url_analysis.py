"""Deterministic URL analysis.

One URL in, one :class:`URLAnalysis` out.  Heuristics are deliberately
non-alarmist: no single heuristic labels a URL malicious; several signals
must accumulate before the risk score rises meaningfully.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlparse

from app.extraction.entity_extractor import detect_brand_lookalike_host
from app.schemas.analysis import URLAnalysis

# Common multi-label public suffixes (registrable domain = last suffix labels).
_PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "org.in", "net.in", "gov.in", "ac.in",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "org.cn", "net.cn", "gov.cn",
    "co.nz", "org.nz", "net.nz", "govt.nz",
    "co.za", "org.za", "net.za", "gov.za",
    "com.sg", "org.sg", "gov.sg",
    "com.my", "org.my", "net.my", "gov.my",
    "com.hk", "org.hk", "net.hk", "gov.hk",
    "com.tw", "org.tw", "net.tw", "gov.tw",
    "com.ae", "gov.ae",
    "com.tr", "org.tr", "net.tr", "gov.tr",
    "com.ph", "org.ph", "gov.ph",
    "com.pk", "org.pk", "net.pk", "gov.pk",
    "com.bd", "org.bd", "gov.bd",
    "com.vn", "org.vn", "net.vn", "gov.vn",
    "co.th", "or.th", "go.th", "ac.th",
    "com.ar", "com.mx", "com.co", "com.pe", "com.ec", "com.uy", "com.cl",
    "co.kr", "or.kr", "go.kr", "ac.kr",
}

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
    "lnkd.in", "short.link", "su.pr", "v.gd", "tny.im", "bc.vc", "soo.gd",
    "shorte.st", "adf.ly", "t.ly", "short.io", "bl.ink", "trib.al",
    "snip.ly", "1url.com", "tr.im", "x.co", "qr.ae", "surl.li", "gg.gg",
}

_SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "unlock", "suspend", "blocked",
    "refund", "invoice", "billing", "payment", "wallet", "bonus",
    "prize", "lottery", "reward", "gift", "claim", "win", "free",
    "bank", "paypal", "apple", "microsoft", "netflix", "amazon",
    "tracking", "delivery", "courier", "parcel", "shipment",
    "authenticate", "authorize", "webscr", "dispute", "limited",
    "recover", "restore", "password", "credential", "otp", "2fa",
    "invest", "bitcoin", "crypto", "trading", "forex", "mining",
]

_SUSPICIOUS_SYMBOLS = ["@", "%00", "%2f", "\\", ".."]



def _registrable_domain(hostname: str) -> str:
    labels = hostname.rstrip(".").split(".")
    if len(labels) <= 2:
        return hostname
    last_two = ".".join(labels[-2:])
    if last_two in _PUBLIC_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _tld(hostname: str) -> str:
    labels = hostname.rstrip(".").split(".")
    if len(labels) == 0:
        return ""
    if len(labels) >= 2 and ".".join(labels[-2:]) in _PUBLIC_SUFFIXES:
        return ".".join(labels[-2:])
    return labels[-1]


def analyze_url(raw_url: str) -> URLAnalysis:
    """Analyze a single URL and produce structured signals."""
    url = raw_url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    # strip trailing dot + userinfo
    hostname = hostname.rstrip(".")
    registrable = _registrable_domain(hostname) if hostname else ""
    tld = _tld(hostname) if hostname else ""

    signals: list[str] = []
    detail: dict = {}
    risk = 0.0

    def bump(amount: float, reason: str, max_total: float = 0.9) -> None:
        nonlocal risk
        risk = min(max_total, risk + amount)
        detail.setdefault("reasons", []).append(reason)

    # --- scheme / transport
    is_https = parsed.scheme == "https"
    if not is_https:
        signals.append("no_https")
        bump(0.05, "URL does not use HTTPS")

    # --- length
    url_length = len(url)
    if url_length > 100:
        bump(0.05, f"long URL ({url_length} chars)")
    if url_length > 200:
        bump(0.05, f"very long URL ({url_length} chars)")
    detail["url_length"] = url_length

    # --- host-based signals
    if hostname:
        if _IPV4_RE.match(hostname) or _is_ipv6(hostname):
            signals.append("ip_address_url")
            bump(0.35, "host is a raw IP address instead of a domain name")
        if "xn--" in hostname:
            signals.append("punycode")
            bump(0.15, "hostname contains punycode (xn--)")
        if "@" in hostname:
            signals.append("userinfo_at")
            bump(0.2, "URL contains userinfo '@' trick")
        labels = hostname.split(".")
        if len(labels) > 4:
            signals.append("excessive_subdomains")
            bump(0.1, f"excessive subdomains ({len(labels)} labels)")
        # hyphen-heavy host
        hyphen_count = hostname.count("-")
        if hyphen_count >= 4:
            signals.append("many_hyphens")
            bump(0.1, f"{hyphen_count} hyphens in hostname")
        # brand-lookalike detection (works without any text mention)
        lookalike = detect_brand_lookalike_host(hostname)
        if lookalike:
            claimed = lookalike["claimed_brand"]
            signals.append("brand_lookalike")
            bump(
                0.4,
                f"hostname resembles '{claimed}' but is not an official {claimed} domain",
                max_total=0.95,
            )
            detail["brand_lookalike"] = lookalike
            if claimed not in _SUSPICIOUS_KEYWORDS:
                hits = list(detail.get("keyword_hits") or [])
                if claimed not in hits:
                    hits.append(claimed)
                    detail["keyword_hits"] = hits

    # --- scheme/brand checks against registered domain
    if registrable:
        detail["registrable_domain"] = registrable

    # --- path
    path = parsed.path or "/"
    if len(path) > 60:
        signals.append("long_path")
        bump(0.05, "unusually long path")

    # --- query params
    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    sensitive_params = {"email", "password", "token", "key", "user", "login", "redirect", "url", "return", "next", "ref", "account", "otp"}
    leaked = [p for p in params if p.lower() in sensitive_params]
    if leaked:
        signals.append("sensitive_query_params")
        bump(0.15, f"query params may carry sensitive data: {', '.join(leaked)}")

    # --- keyword scan on full URL
    lowered = url.lower()
    hits = [kw for kw in _SUSPICIOUS_KEYWORDS if re.search(rf"(?<![a-z]){re.escape(kw)}(?![a-z])", lowered)]
    if hits:
        bump(min(0.25, 0.06 * len(hits)), f"suspicious keywords in URL: {', '.join(hits[:5])}")
        detail["keyword_hits"] = hits

    # --- symbols
    found_symbols = [s for s in _SUSPICIOUS_SYMBOLS if s in url]
    if found_symbols:
        signals.append("suspicious_symbols")
        bump(0.1, f"suspicious symbols: {', '.join(found_symbols)}")
        detail["suspicious_symbols"] = found_symbols

    # --- shortening
    is_shortened = hostname in _SHORTENER_DOMAINS or any(
        hostname.endswith("." + d) for d in _SHORTENER_DOMAINS
    )
    if is_shortened:
        signals.append("url_shortener")
        bump(0.2, "URL shortener used (hides final destination)")
        detail["shortener"] = hostname

    # --- numeric-heavy host
    digit_ratio = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    if hostname and digit_ratio > 0.4:
        bump(0.1, "hostname is numeric-heavy")

    # --- risky TLDs (commonly abused; informational only)
    risky_tlds = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "support", "rest", "stream", "download", "cam", "work", "country", "review", "loan", "date", "win", "bid", "racing", "accountant", "site"}
    if tld and tld.lower() in risky_tlds:
        signals.append("risky_tld")
        bump(0.1, f"TLD '{tld}' is commonly abused")

    # --- characters frequency
    special_chars = sum(c in "_-@%*&!" for c in url)
    detail["special_chars"] = special_chars

    return URLAnalysis(
        url=url,
        domain=registrable or hostname,
        hostname=hostname or None,
        tld=tld or None,
        path=path if path != "/" else None,
        query_params=params,
        scheme=parsed.scheme,
        is_https=is_https,
        url_length=url_length,
        has_ip_address="ip_address_url" in signals,
        has_punycode="punycode" in signals,
        is_shortened=is_shortened,
        suspicious_symbols=found_symbols,
        suspicious_keywords=hits,
        excessive_subdomains="excessive_subdomains" in signals,
        risk_score=round(min(1.0, risk), 3),
        signals=signals,
        detail=detail,
    )


def _is_ipv6(hostname: str) -> bool:
    # urlparse brackets IPv6 literals; check both forms
    cleaned = hostname.strip("[]")
    if ":" not in cleaned:
        return False
    try:
        ipaddress.IPv6Address(cleaned)
        return True
    except ValueError:
        return False