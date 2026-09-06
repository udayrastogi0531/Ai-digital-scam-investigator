"""Fictional demo cases.

Every domain, phone number, email and person in these cases is invented
(using the reserved fictional ``.example`` TLD and 555 exchange numbers).
They are sample evidence for exercising the product — never real data.
"""
from __future__ import annotations

DEMO_CASES: dict[str, dict] = {
    "banking_phishing": {
        "title": "Demo: Fake bank KYC message",
        "text": (
            "URGENT: Your SwiftBank account has been temporarily suspended due to unusual activity.\n"
            "Complete KYC verification within 24 hours to avoid permanent closure.\n"
            "Verify your account here: https://secure-login.example.com/swiftbank/verify\n"
            "Do not share this link. If you fail to verify, your funds will be frozen."
        ),
        "urls": [],
    },
    "job_scam": {
        "title": "Demo: Fake job offer",
        "text": (
            "Congratulations! You have been selected for a work-from-home position with GlobalFreight Co.\n"
            "Salary: $4,500/week, no experience needed, guaranteed income.\n"
            "To confirm your seat, pay a one-time registration fee of $49 via Western Union to our HR manager.\n"
            "Only 10 seats left! Contact us on WhatsApp at +1 (555) 019-2834 to secure your spot."
        ),
        "urls": [],
    },
    "investment_scam": {
        "title": "Demo: Fake investment opportunity",
        "text": (
            "Dear investor, our crypto trading bot guarantees 15% returns weekly with zero risk.\n"
            "Exclusive offer closing soon — minimum investment $500. Fund your account now to double your money in 30 days.\n"
            "Your personal portfolio manager is waiting: https://invest-now.example/trading-signals"
        ),
        "urls": [],
    },
    "delivery_scam": {
        "title": "Demo: Fake delivery fee",
        "text": (
            "Your package could not be delivered: address confirmation required.\n"
            "Reschedule delivery by paying the $2.99 redelivery fee: https://track-parcel.example/reschedule\n"
            "If unpaid within 24 hours your parcel will be returned to sender."
        ),
        "urls": [],
    },
    "lottery_scam": {
        "title": "Demo: Fake lottery win",
        "text": (
            "Congratulations! You have won $250,000 in the International Lucky Draw.\n"
            "To release your winnings, pay the $120 processing fee to claim your prize.\n"
            "Contact our claims agent today: claims@lottery-office.example.org or call +1 (555) 812-4490."
        ),
        "urls": [],
    },
    "tech_support": {
        "title": "Demo: Fake tech support",
        "text": (
            "Windows Support Alert: Your computer is infected with a virus.\n"
            "Call us immediately at +1 (555) 200-5511 or install this app for remote repair: https://support-download.example/repair.exe\n"
            "Your subscription will be renewed automatically ($299/year) unless you call within 1 hour."
        ),
        "urls": [],
    },
    "romance_scam": {
        "title": "Demo: Romance scam",
        "text": (
            "My darling, I love you so much. I am deployed overseas on an oil rig and cannot video call.\n"
            "My visa money is blocked; please send $850 via MoneyGram to help me come see you.\n"
            "Don't tell anyone, this is private. I will repay you when we meet."
        ),
        "urls": [],
    },
    "account_takeover": {
        "title": "Demo: Account takeover attempt",
        "text": (
            "Security alert: a new device signed in to your email from Russia.\n"
            "If this wasn't you, reset your password immediately: https://verify-account.example/login/secure\n"
            "Reply with your OTP to confirm your identity."
        ),
        "urls": [],
    },
    "crypto_scam": {
        "title": "Demo: Crypto wallet drain",
        "text": (
            "CoinPulse airdrop: claim your free 5,000 tokens before the snapshot ends!\n"
            "Import your wallet to claim: https://wallet-verify.example/airdrop\n"
            "Enter your recovery phrase to link your wallet. Hurry — only today!"
        ),
        "urls": [],
    },
    "benign_message": {
        "title": "Demo: Normal message (control case)",
        "text": (
            "Hey Sam, are we still on for lunch on Friday at 12:30? I'll book the usual place.\n"
            "Let me know if you'd rather go somewhere else. Cheers, Priya"
        ),
        "urls": [],
    },
    "suspicious_url": {
        "title": "Demo: Suspicious URL only",
        "text": (
            "Check this invoice I got from accounting: "
            "http://paypa1-login.example.com/webscr?cmd=_verify&email=user@example.org&return=https://paypal.com"
        ),
        "urls": [],
    },
}


def list_demo_cases() -> list[tuple[str, str]]:
    return [(slug, case["title"]) for slug, case in DEMO_CASES.items()]