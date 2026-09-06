"""Linguistic scam-signal detection.

Deterministic keyword/phrase scoring producing a :class:`TextSignals`
object.  Scores are clamped ``0..1`` and derived from matched phrases, so
findings are reproducible and testable.

Request-vs-mention semantics
----------------------------
A word like ``OTP``, ``password`` or ``payment`` appearing in a message is
NOT by itself a request.  ``otp_request`` / ``credential_request`` /
``payment_request`` are only set when the message actually asks the
recipient to do something (a *requestive* verb such as "enter", "reply
with", "send us"), and requestive verbs negated by "never"/"do not" are
ignored.  This is what keeps legitimate security notices ("never share your
OTP"), 2FA code texts ("your code is 482913") and payment receipts
("payment of $14.99 was received") from being flagged as scam requests.

Two context flags are produced:

* ``protective_warning`` — the message advises the recipient NOT to share
  credentials (typical of genuine bank warnings).
* ``reassurance`` — the message says no action is needed / the alert may be
  ignored (typical of genuine device/login notifications).

Both are consumed by the pattern engine to suppress credential/account
alarm rules when nothing is actually being requested.
"""
from __future__ import annotations

import re

from app.schemas.analysis import TextSignals
from app.utils.text import normalize_text

# phrase groups --------------------------------------------------------------
_URGENCY = [
    "urgent", "immediately", "within 24 hours", "within 48 hours", "within the hour",
    "asap", "act now", "expires", "expire today", "closing soon", "offer ends",
    "deadline", "limited time", "final notice", "last warning", "right away",
    "do not delay", "at once", "before it's too late", "before the window closes",
    "immediate action", "respond immediately", "time sensitive", "final reminder",
    "will be withdrawn", "offer will be cancelled",
]
_FEAR_THREAT = [
    "suspend", "suspended", "blocked", "will be blocked", "deactivate", "deactivated",
    "closed", "terminated", "banned", "legal action", "lawsuit", "arrest", "warrant",
    "penalty", "fine", "freeze", "frozen", "fraudulent activity", "unusual activity",
    "unauthorized", "compromised", "breach", "permanently", "risk of",
    "account will be", "will be closed", "will be deleted", "criminal",
    "investigation", "court", "will be charged", "negative impact", "funds frozen",
    "returned to sender", "you will lose",
]
_REWARD = [
    "congratulations", "you have won", "winner", "prize", "lottery", "jackpot",
    "gift card", "free", "bonus", "cash reward", "selected", "exclusive offer",
    "claim your", "won a", "lucky", "winning", "double your money",
    "guaranteed returns", "guaranteed income",
]
_PRESSURE = [
    "limited", "only today", "hurry", "first come", "don't miss", "act fast",
    "last chance", "few spots", "guaranteed", "guarantees", "only a few", "register now",
    "don't wait", "while supplies last", "zero risk", "no risk", "risk free",
    "seats left", "spots left", "positions left", "slots left", "high demand",
    "act immediately", "don't miss out",
]
_AUTHORITY = [
    "official", "government", "police", "irs", "hmrc", "bank", "security team",
    "support team", "administrator", "department", "authority", "federal",
    "state bank", "reserve bank", "regulatory", "legal department", "court",
    "fraud department", "security alert", "alert", "kyc",
]

# --- payment: request phrases vs mere mentions ------------------------------
# Request phrases directly ask for money, a transfer, card details, or to
# purchase something.  Mention phrases only talk about payments/fees.
_PAYMENT_REQUEST = [
    "pay", "pay the", "pay us", "pay me", "payable", "make the payment",
    "send money", "send the", "send us", "send me", "send btc", "send usdt",
    "wire", "transfer", "bank transfer", "deposit now", "payment link",
    "to release", "to secure", "to confirm your seat", "confirm your seat",
    "purchase a", "buy a", "gift cards", "redemption code", "registration fee",
    "processing fee", "redelivery fee", "security deposit", "advance payment",
    "fund your account", "minimum investment", "western union", "moneygram",
    "bank details", "card details", "cvv", "money to",
]
_PAYMENT_MENTION = [
    "payment", "fee", "deposit", "refundable", "invoice", "salary", "advance",
    "refund", "overpaid", "renewal", "subscription fee",
]

_CREDENTIAL = [
    "password", "username", "login", "sign in", "credentials", "verify your identity",
    "confirm your account", "re-enter", "update your password", "log in",
    "account details", "sign-in", "2fa", "two-factor", "recovery phrase",
    "secret phrase", "security question", "complete verification",
    "verify your card", "account verification", "update your details",
    "verify your details", "login credentials", "reset your password",
]
_OTP = [
    "otp", "one time password", "one-time password", "one time code",
    "one-time code", "verification code", "security code", "share the code",
    "code sent to", "confirm the code", "enter the code", "sms code", "passcode",
]
_SENSITIVE = [
    "ssn", "social security", "passport", "id card", "aadhaar", "driver's license",
    "mother's maiden name", "date of birth", "full name", "home address",
    "bank account number", "routing number", "credit card", "cvv", "expiry",
    "identity document", "selfie", "bank statement",
]
_SUSPICIOUS_INSTRUCTIONS = [
    "install this app", "download apk", "enable unknown sources", "disable security",
    "turn off antivirus", "run this command", "remote access", "anydesk",
    "teamviewer", "screen share", "buy gift cards", "scan the qr code",
    "forward to", "share this with", "do not tell anyone", "keep it secret",
    "delete this message", "call this number", "on whatsapp",
]

# --- protective / reassurance context --------------------------------------
# Protective phrasing tells the recipient never to reveal credentials;
# reassurance says the alert may be ignored / no action is needed.
_PROTECTIVE = [
    "never share", "do not share", "don't share", "never ask", "do not ask",
    "never give", "do not give", "never disclose", "do not disclose",
    "never reveal", "do not reveal", "will never ask", "won't ask",
    "never request", "do not request", "never ask for",
]
_REASSURANCE = [
    "no action needed", "no action is needed", "no further action",
    "you can safely ignore", "if this wasn't you", "if this was you",
    "if you did not request", "if you didn't request", "ignore this message",
    "ignore this email", "no need to do anything",
]

# Requestive verbs: turn a mention of credentials/codes/payments into an
# actual request.  Matches negated by "never / do not / don't" right before
# the verb are ignored (e.g. "never share your OTP" is not a request).
_REQUESTIVE_PATTERNS = [
    r"\benter( your| the| it| a)?\b",
    r"\bre-enter\b",
    r"\btype( your| the| it)?\b",
    r"\bpaste\b",
    r"\binput\b",
    r"\bsend (us|me|them|it|the|your)\b",
    r"\bprovide( your| the| us| me)?\b",
    r"\breply with\b",
    r"\bshare( your| the| it| this)?\b",
    r"\bgive( us| me| your| the)?\b",
    r"\bhand over\b",
    r"\bsubmit( your| the| it)?\b",
    r"\btell me\b",
    r"\bconfirm( with| your| it| the)?\b",
    r"\bverify( with| by| your)?\b",
    r"\bsecure (your|the) account\b",
    r"\brequires? (a|an|you|your|the)\b",
    r"\brequired to\b",
]
_NEGATION_BEFORE = re.compile(r"(never|do not|don'?t|won'?t|should not|must not|will never)\s*$")

_PHRASE_GROUPS: dict[str, list[str]] = {
    "urgency": _URGENCY,
    "fear_threat": _FEAR_THREAT,
    "reward": _REWARD,
    "pressure": _PRESSURE,
    "authority": _AUTHORITY,
    "payment": _PAYMENT_REQUEST,
    "credential": _CREDENTIAL,
    "otp": _OTP,
    "sensitive": _SENSITIVE,
    "instructions": _SUSPICIOUS_INSTRUCTIONS,
}


def _find_phrases(text: str, phrases: list[str]) -> list[str]:
    lowered = text.lower()
    hits: list[str] = []
    for phrase in phrases:
        if re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", lowered):
            hits.append(phrase)
    return hits

# numeric/length variants that literals cannot express (e.g. "within 12 hours")
_REGEX_PATTERNS: dict[str, list[str]] = {
    "urgency": [
        r"within \d+ hours?",
        r"within \d+ days?",
        r"before \d{1,2}(:| )\d{2}",
        r"reply (within|by) \d+",
        r"(?:only|just) \d+ (?:hours?|days?|minutes?) (?:left|remaining|to)",
        r"\boffer (?:closes?|ends|expires) (?:at|tonight|soon|today|midnight)",
        r"\bcloses? (?:at|tonight|midnight|soon)",
    ],
    "pressure": [
        r"only \d+ (?:seats?|spots?|places?|positions?|slots?|vacancies?) (?:left|remain|remaining)",
        r"\d+ (?:seats?|spots?|places?|positions?) remaining",
        r"first \d+ (?:people|members|customers|callers)",
    ],
    "payment": [
        r"(?:pay|send|wire|transfer) (?:us|me|them|the )?\$?\s?\d+",
        r"\$\s?\d+ (?:fee|to (?:start|begin|activate|release|claim|confirm|secure|unlock))",
    ],
}


def _find_regex(text: str, patterns: list[str]) -> list[str]:
    lowered = text.lower()
    return [p for p in patterns if re.search(p, lowered)]


def _score(hits: list[str]) -> float:
    # 1 match -> 0.25, 2 -> 0.5, 3 -> 0.75, >=4 -> 1.0
    return min(1.0, 0.25 * len(hits))


def _has_requestive(text: str) -> bool:
    """True when a non-negated requestive verb is present."""
    lowered = text.lower()
    for pattern in _REQUESTIVE_PATTERNS:
        for match in re.finditer(pattern, lowered):
            before = lowered[max(0, match.start() - 24): match.start()]
            if _NEGATION_BEFORE.search(before):
                continue  # "never share your OTP" is advice, not a request
            return True
    return False


def analyze_text_signals(raw_text: str | None) -> TextSignals:
    """Produce structured linguistic signals from raw message text."""
    text = normalize_text(raw_text)
    signals = TextSignals()

    def group(name: str, phrases: list[str]) -> list[str]:
        hits = _find_phrases(text, phrases)
        hits.extend(p for p in _find_regex(text, _REGEX_PATTERNS.get(name, [])) if p not in hits)
        return hits

    urgency = group("urgency", _URGENCY)
    fear_threat = group("fear_threat", _FEAR_THREAT)
    reward = group("reward", _REWARD)
    pressure = group("pressure", _PRESSURE)
    authority = group("authority", _AUTHORITY)
    payment = group("payment", _PAYMENT_REQUEST)
    payment_mentions = group("payment", _PAYMENT_MENTION)
    credential = group("credential", _CREDENTIAL)
    otp = group("otp", _OTP)
    sensitive = group("sensitive", _SENSITIVE)
    instructions = group("instructions", _SUSPICIOUS_INSTRUCTIONS)

    protective = _find_phrases(text, _PROTECTIVE)
    reassurance = _find_phrases(text, _REASSURANCE)
    requestive = _has_requestive(text)

    signals.urgency_score = _score(urgency)
    signals.fear_threat_score = _score(fear_threat)
    signals.reward_score = _score(reward)
    signals.pressure_score = _score(pressure)

    signals.urgent_phrases = urgency
    signals.authority_phrases = authority
    signals.reward_phrases = reward
    signals.payment_phrases = [*payment, *payment_mentions]
    signals.credential_phrases = credential
    signals.threat_phrases = fear_threat

    signals.authority_impersonation = len(authority) > 0
    # Requests require requestive intent; mentions alone never count.
    signals.payment_request = bool(payment) or (bool(payment_mentions) and requestive)
    signals.credential_request = bool(credential) and requestive
    signals.otp_request = bool(otp) and requestive
    signals.sensitive_info_request = bool(sensitive) and requestive
    signals.suspicious_instructions = len(instructions) > 0
    signals.protective_warning = len(protective) > 0
    signals.reassurance = len(reassurance) > 0

    return signals