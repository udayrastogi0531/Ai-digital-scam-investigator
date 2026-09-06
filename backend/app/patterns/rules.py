"""Scam-pattern rule definitions.

Rules are declarative data, not hardcoded inside prompts.  Adding or
tuning a pattern is a data change, and every rule carries its own
severity, confidence and description so the risk engine can explain why
it fired.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CATEGORY_LABELS: dict[str, str] = {
    "phishing": "Phishing",
    "job_scam": "Job scam",
    "investment_scam": "Investment scam",
    "payment_scam": "Payment scam",
    "banking_scam": "Banking scam",
    "romance_scam": "Romance scam",
    "tech_support_scam": "Tech-support scam",
    "impersonation_scam": "Impersonation scam",
    "delivery_scam": "Delivery/package scam",
    "lottery_scam": "Lottery/prize scam",
    "account_takeover": "Account takeover attempt",
    "identity_theft": "Identity theft attempt",
    "advance_fee": "Advance-fee scam",
    "crypto_scam": "Cryptocurrency scam",
    "unknown": "Other / Unknown",
}

CATEGORY_IDS = list(CATEGORY_LABELS)


@dataclass(frozen=True)
class ScamRule:
    id: str
    category: str
    name: str
    description: str
    keywords: tuple[str, ...]
    required_entities: tuple[str, ...] = ()
    weight: float = 1.0
    severity: str = "medium"  # low | medium | high | critical
    confidence: float = 0.6


# fmt: off
RULES: list[ScamRule] = [
    # ------------------------------------------------------------ job scams
    ScamRule("job_unrealistic_income", "job_scam", "Unrealistic income",
             "Promises of high, effortless, guaranteed income",
             ("work from home", "earn up to", "guaranteed salary", "no experience needed",
              "make money online", "guaranteed income", "high salary", "easy money"), weight=1.0, severity="medium"),
    ScamRule("job_registration_fee", "job_scam", "Registration/training fee",
             "Asks for money before employment starts",
             ("registration fee", "registration deposit", "training fee", "security deposit",
              "refundable deposit", "startup fee", "joining fee", "administration fee",
              "processing fee"), weight=2.0, severity="high", confidence=0.75),
    ScamRule("job_guaranteed_selection", "job_scam", "Guaranteed selection",
             "Claims the job is guaranteed without an interview",
             ("guaranteed job", "you have been selected", "shortlisted for", "was shortlisted",
              "100% placement", "confirm your seat", "immediate start", "selected for"), weight=1.0, severity="medium"),
    ScamRule("job_offplatform_contact", "job_scam", "Off-platform contact only",
             "Forces communication through WhatsApp/Telegram instead of official channels",
             ("whatsapp only", "contact us on whatsapp", "message us on telegram",
              "add our whatsapp", "reply on whatsapp", "send your cv on whatsapp"), weight=1.5, severity="high", confidence=0.7),
    ScamRule("job_scarcity", "job_scam", "Artificial scarcity",
             "Few spots / limited seats to pressure quick action",
             ("only 10 seats", "spots left", "limited seats", "few openings", "last seats"), weight=0.8, severity="low"),
    # --------------------------------------------------------- banking scams
    ScamRule("bank_account_suspension", "banking_scam", "Account suspension threat",
             "Claims the account will be blocked/suspended to create fear",
             ("account will be", "will be suspended", "will be closed", "suspend", "blocked",
              "deactivated", "frozen", "limited access", "locked", "permanently closed"), weight=2.0, severity="high"),
    ScamRule("bank_card_blocked", "banking_scam", "Card blocking threat",
             "Threatens that the payment card will be blocked/frozen",
             ("card will be blocked", "card has been blocked", "card was blocked",
              "your card is blocked", "card blocked", "card will be frozen",
              "card has been frozen", "debit card blocked"), weight=2.0, severity="high", confidence=0.7),
    ScamRule("bank_otp_request", "banking_scam", "OTP request",
             "Asks the victim to share a one-time password",
             ("otp", "otp code", "one-time code", "one time code", "one-time password",
              "share the code", "verification code", "confirm the code", "enter the code"), weight=2.0, severity="critical", confidence=0.85),
    ScamRule("bank_login_verification", "banking_scam", "Login verification demand",
             "Demands login/account verification through a provided link",
             ("login verification", "complete verification", "verify your account",
              "account verification", "verify your card", "re-verify your identity"), weight=2.0, severity="high", confidence=0.7),
    ScamRule("bank_kyc_request", "banking_scam", "KYC / identity verification",
             "Asks to complete KYC or verify identity via a link",
             ("kyc", "know your customer", "update your details", "verify your account",
              "complete your kyc", "re-verify"), weight=2.0, severity="high"),
    ScamRule("bank_fake_refund", "banking_scam", "Fake refund",
             "Promises a refund that requires details or a fee",
             ("refund", "credit back", "refund of", "receive a refund"), weight=1.0, severity="medium"),
    # ------------------------------------------------------ investment scams
    ScamRule("invest_guaranteed_returns", "investment_scam", "Guaranteed returns",
             "Guarantees profit or claims risk-free investing",
             ("guaranteed returns", "no risk", "risk free", "zero risk", "guarantees",
              "guaranteed profit", "double your money", "passive income", "high returns",
              "huge profit", "guaranteed roi"), weight=2.0, severity="high", confidence=0.8),
    ScamRule("invest_time_limited", "investment_scam", "Time-limited opportunity",
             "Creates urgency with closing offers",
             ("limited time", "closing soon", "only today", "exclusive offer", "act now",
              "offer closes", "closing at", "offer ends", "expires soon"), weight=1.0, severity="medium"),
    ScamRule("invest_deposit_pressure", "investment_scam", "Deposit pressure",
             "Pressures to deposit or top up funds immediately",
             ("deposit", "deposit now", "invest now", "minimum investment", "fund your account",
              "initial deposit", "top up", "don't miss this", "send money to"), weight=2.0, severity="high"),
    ScamRule("invest_fake_advisor", "investment_scam", "Fake advisor/signal groups",
             "Claims personal advisors or trading signals that guarantee wins",
             ("your advisor", "personal manager", "investment expert", "portfolio manager",
              "signal group", "crypto signals", "trading signals", "winning trades"), weight=1.0, severity="medium"),
    # --------------------------------------------------------- payment scams
    ScamRule("payment_upfront_fee", "payment_scam", "Upfront payment request",
             "Asks for money before delivering a product/service",
             ("advance", "upfront", "before delivery", "shipping fee", "customs fee",
              "insurance fee", "handling fee", "clearance fee", "advance payment"), weight=2.0, severity="critical", confidence=0.8),
    ScamRule("payment_overpayment", "payment_scam", "Overpayment trick",
             "Claims accidental overpayment and asks to send the difference",
             ("overpaid", "send the difference", "excess payment", "accidental payment",
              "accidentally sent"), weight=2.0, severity="high", confidence=0.75),
    ScamRule("payment_gift_cards", "payment_scam", "Gift-card payment",
             "Asks for payment in gift cards",
             ("gift card", "itunes card", "google play card", "amazon card",
              "scratch the card", "redeem the code", "buy a card"), weight=2.5, severity="critical", confidence=0.9),
    # ------------------------------------------------------ romance scams
    ScamRule("romance_quick_affection", "romance_scam", "Rapid affection",
             "Extremely fast declarations of love",
             ("i love you", "my love", "sweetheart", "my darling", "marry me",
              "soulmate", "love at first sight"), weight=1.0, severity="medium"),
    ScamRule("romance_excuse_money", "romance_scam", "Money request with sob story",
             "Requests money for flights/visas/hospital from someone never met",
             ("money for the flight", "visa fees", "hospital bills", "can't afford",
              "help me with", "wire me", "western union", "moneygram"), weight=2.0, severity="high", confidence=0.75),
    ScamRule("romance_remote_deployment", "romance_scam", "Remote deployment story",
             "Claims to be deployed/abroad and unable to meet",
             ("military", "oil rig", "deployed", "overseas", "offshore", "peacekeeping"), weight=1.0, severity="medium"),
    # ------------------------------------------------- tech-support scams
    ScamRule("techsupport_virus_alert", "tech_support_scam", "Fake virus alert",
             "Claims infection and asks for remote access or payment",
             ("virus detected", "infected", "your computer", "your pc is", "error code",
              "windows support", "microsoft support"), weight=2.0, severity="high"),
    ScamRule("techsupport_remote_access", "tech_support_scam", "Remote access request",
             "Asks the victim to install remote access software",
             ("remote access", "anydesk", "teamviewer", "screen share", "install this app",
              "enable unknown sources", "download apk"), weight=2.5, severity="critical", confidence=0.9),
    ScamRule("techsupport_renewal", "tech_support_scam", "Subscription renewal scare",
             "Claims antivirus/OS subscription is expiring",
             ("subscription renewal", "renew your license", "subscription fee",
              "windows defender", "renewal fee"), weight=1.0, severity="medium"),
    # ------------------------------------------------------ delivery scams
    ScamRule("delivery_undeliverable", "delivery_scam", "Undeliverable package",
             "Claims a package couldn't be delivered",
             ("your package", "your parcel", "failed delivery", "address confirmation",
              "could not be delivered", "requires confirmation", "confirm your address",
              "address details", "returned to sender", "redelivery", "undeliverable",
              "delivery attempt"), weight=2.0, severity="high"),
    ScamRule("delivery_fee_request", "delivery_scam", "Delivery fee request",
             "Asks for payment to release the package",
             ("delivery fee", "customs", "claim your package", "shipping fee",
              "pay to receive", "release fee"), weight=2.0, severity="high", confidence=0.75),
    ScamRule("delivery_tracking_link", "delivery_scam", "Tracking link bait",
             "Sends a tracking link, often to a lookalike site",
             ("tracking number", "track your package", "track your order", "track here"), weight=1.0, severity="medium"),
    # --------------------------------------------------------- lottery scams
    ScamRule("lottery_you_won", "lottery_scam", "You won a prize",
             "Unsolicited prize/lottery win notification",
             ("you have won", "congratulations", "winner", "lottery", "jackpot",
              "winning ticket", "lucky number", "lucky draw", "won a"), weight=2.0, severity="high"),
    ScamRule("lottery_fee_to_release", "lottery_scam", "Fee to claim prize",
             "Asks for a fee or tax before releasing the prize",
             ("claim your prize", "processing fee to release", "pay the tax",
              "release your winnings", "claim fee"), weight=2.5, severity="critical", confidence=0.9),
    # ----------------------------------------------------- account takeover
    ScamRule("account_unusual_activity", "account_takeover", "Unusual activity alert",
             "Claims suspicious sign-in or activity on the account",
             ("unusual activity", "new device", "sign-in attempt", "login from",
              "unrecognized", "someone tried", "unauthorized access", "recently logged in"), weight=2.0, severity="high"),
    ScamRule("account_verify_identity", "account_takeover", "Identity verification demand",
             "Demands identity verification through a provided link",
             ("verify your identity", "confirm your account", "reset your password",
              "secure your account", "account verification"), weight=2.0, severity="high"),
    # ------------------------------------------------------- identity theft
    ScamRule("identity_documents", "identity_theft", "Document harvesting",
             "Requests copies of identity documents",
             ("passport number", "aadhaar", "driver's license", "id card", "selfie",
              "upload your id", "bank statement", "identity document"), weight=2.0, severity="critical", confidence=0.8),
    ScamRule("identity_personal_data", "identity_theft", "Personal data harvesting",
             "Requests sensitive personal identifiers",
             ("ssn", "social security", "date of birth", "mother's maiden name",
              "full name", "home address", "routing number"), weight=2.0, severity="high", confidence=0.75),
    # --------------------------------------------------------- advance fee
    ScamRule("advancefee_admin", "advance_fee", "Administrative fee",
             "Requests administrative/legal fees to proceed",
             ("administration fee", "legal fee", "transfer fee", "tax clearance",
              "unlock fee", "processing charge"), weight=2.0, severity="high", confidence=0.7),
    ScamRule("advancefee_inheritance", "advance_fee", "Inheritance/fortune",
             "Claims an inheritance or unclaimed fortune",
             ("inheritance", "unclaimed", "estate of", "left for you", "your share of"), weight=1.5, severity="medium"),
    # ---------------------------------------------------------- crypto scams
    ScamRule("crypto_wallet_drain", "crypto_scam", "Wallet key request",
             "Asks for wallet keys or seed phrases",
             ("private key", "seed phrase", "wallet address", "send btc", "send usdt",
              "recovery phrase", "import your wallet", "bc1", "btc to", "crypto address"), weight=2.5, severity="critical", confidence=0.9),
    ScamRule("crypto_double_invest", "crypto_scam", "Crypto investment lure",
             "Promises doubled crypto or free airdrops",
             ("double your bitcoin", "mining pool", "defi", "trading bot",
              "airdrop", "claim your tokens", "staking rewards", "crypto investment",
              "btc back", "usdt back", "mining account"), weight=1.5, severity="high"),
    # ------------------------------------------------------- general phishing
    ScamRule("phishing_generic", "phishing", "Generic phishing language",
             "Classic phishing wording: verify/confirm/update via link",
             ("verify your account", "confirm your account", "click the link",
              "click here", "log in to", "sign in to", "update your information",
              "urgent action required", "verify your email", "suspicious activity",
              "unauthorized transaction", "verify your details", "security alert",
              "account verification"), weight=2.0, severity="high"),
    ScamRule("phishing_impersonation", "impersonation_scam", "Authority impersonation",
             "Claims to be a government, bank or official body",
             ("official", "government", "police", "irs", "hmrc", "legal department",
              "warrant", "arrest", "from the bank", "your bank", "official notification"), weight=2.0, severity="high"),
    ScamRule("impersonation_executive", "impersonation_scam", "Executive / colleague impersonation",
             "A message claiming to be from an executive or colleague requests money or credentials",
             ("the ceo", "ceo", "executive team", "senior manager", "from the director",
              "from the boss", "company president", "vice president", "the cfo",
              "chief financial officer", "urgent favor", "the executive"), weight=2.5, severity="high", confidence=0.8),
]
# fmt: on