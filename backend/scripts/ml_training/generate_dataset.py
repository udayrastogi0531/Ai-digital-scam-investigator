"""Synthetic dataset generator for the scam classifier.

Every message is fictional: domains use ``example``/``.test``-style hosts or
clearly fake names, phone numbers are reserved 555/000 ranges, and no real
person's data is used.  The generator intentionally mixes templates with
randomization so the model cannot just memorize phrasing.

Dataset honesty
---------------
This is a *stand-in* dataset so the training pipeline is fully exercised
offline.  For real-world deployment, retrain on a vetted, labelled corpus
(e.g. consumer-report repositories with permission, or an internal SOC
dataset) — the loader interface (``load_dataframe``) is CSV-shaped so a real
dataset drops in without code changes.
"""
from __future__ import annotations

import csv
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # backend/
DEFAULT_OUT = ROOT / "data" / "datasets" / "scam_messages.csv"

# --- randomizable building blocks (all fictional) --------------------------

SUSPICIOUS_HOSTS = [
    "secure-verify-account.example", "paypal-security-alert.example",
    "microsoft-account-verify.example", "login-check-bank.example",
    "delivery-tracking-info.example", "claim-your-prize.example",
    "bitcoin-invest-signal.example", "jobs-career-hiring.example",
    "netflix-billing-update.example", "apple-id-confirm.example",
    "amazon-order-support.example", "irs-refund-notice.example",
]
BENIGN_HOSTS = [
    "example.com", "news.example.org", "shop.example.net",
    "blog.example.io", "weather.example.com",
]
PHONES = ["+1-555-0100", "(555) 0132", "555-0167"]
AMOUNTS = ["$2,450", "$500", "$9,999", "€1,200", "$150"]
EMAILS = ["hr.hiring@example.test", "support@example.test", "admin@example.test"]
NAMES = ["Sarah Mitchell", "James Carter", "Aisha Khan", "Daniel Osei", "Maria Lopez"]
BANKS = ["National Trust Bank", "Global Savings Bank", "First Horizon Bank", "Metro Credit Union"]
PLATFORMS = ["PayPal", "Microsoft", "Apple", "Netflix", "Amazon", "eBay", "FedEx", "DHL"]
CRYPTO = ["Bitcoin", "Ethereum", "USDT"]

JOB = [
    "Congratulations! You have been selected for the {name} remote role. Guaranteed {amount}/month salary for {hrs} hours/week. Send a {fee} registration fee to reserve your position. Contact us only on WhatsApp.",
    "URGENT HIRING: {name} is hiring work-from-home staff. No experience needed, earn {amount} weekly! Register now by paying a small processing fee. Limited slots!",
    "You are shortlisted for {company} customer support. To complete onboarding, pay {amount} for your work ID and training kit. Reply FAST before the offer expires.",
]
BANKING = [
    "Dear customer, your {bank} account has been suspended due to unusual activity. Verify your identity within 24 hours or your account will be closed: {url}",
    "{bank} ALERT: Unauthorized login detected from a new device. Confirm your details immediately at {url} or your card will be blocked. Do not share your OTP with anyone — but confirm it here to secure your account.",
    "Your {bank} KYC update is due. Click {url} to complete verification and avoid account restriction. Enter your password and the one-time code sent to your phone.",
]
INVESTMENT = [
    "Join {name}'s elite trading group! Guaranteed returns of {pct}% daily with our automated {crypto} bot. Deposit now — offer ends soon! Minimum {amount}.",
    "We recovered {amount} of unclaimed {crypto} from your old wallet. Pay {fee} release fee to transfer it to your account today.",
    "Limited-time: double your {crypto} with our VIP investment plan. Funds locked for 72 hours. Send your deposit to the provided wallet address immediately.",
]
DELIVERY = [
    "Your package from {platform} is on hold. To reschedule delivery, pay a {amount} redelivery fee here: {url}",
    "{platform} courier could not deliver your parcel due to an incorrect address. Update your details and pay {amount} within 12 hours at {url}.",
    "Delivery attempt failed for your order. Claim your parcel by confirming your payment details at {url}. Fees apply.",
]
LOTTERY = [
    "Congratulations!! You won {amount} in the {company} international lottery. Claim your prize by paying {fee} processing fee to {email} within 48 hours.",
    "Your email was randomly selected for a {amount} prize draw. Send your personal details and a small handling fee to our agent to receive your winnings.",
]
TECH_SUPPORT = [
    "Warning: your computer has been infected! Call our certified technicians at {phone} immediately to remove the virus before your data is stolen.",
    "We detected unusual activity on your {platform} account. Our security team needs remote access to fix it. Download this tool and share the session code: {url}",
]
ROMANCE = [
    "Hello darling, I am a doctor on an offshore oil rig and cannot access my bank. I need {amount} for my visa to come meet you. Please wire it and I will repay you double. It must stay secret between us.",
    "I love you so much, but I am stuck at customs with no money for the fee. Send {amount} via gift cards and send me the codes, my love.",
]
ACCOUNT_TAKEOVER = [
    "We noticed you logged in from a new location. If this was not you, secure your {platform} account now by confirming your password at {url}. Otherwise your account will be locked permanently.",
    "Someone tried to change your password. Verify it is really you by entering the code we sent and your current password here: {url}",
]
CRYPTO_WALLET = [
    "Your {crypto} wallet needs re-verification to avoid suspension. Connect your wallet and approve the smart contract at {url} now.",
    "Drain-proof your {crypto}: new regulation requires address validation. Enter your seed phrase at {url} to keep your funds safe.",
]
ADVANCE_FEE = [
    "The {company} inheritance department has {amount} waiting for you as the next of kin of a deceased client. Send {fee} legal fee to {email} to begin the transfer.",
    "Your {amount} insurance payout is approved. Pay the {fee} stamp duty first and the money will be released within 24 hours.",
]

BENIGN = [
    "Hi {name}, just confirming our meeting tomorrow at 10am. The {company} report is attached — please review before we chat. Thanks!",
    "Your order from {company} has shipped and will arrive Friday. Track it here: {url}",
    "The {company} team is hosting a lunch next Tuesday. RSVP by Friday if you can make it.",
    "Reminder: your dentist appointment is on {date}. Reply CONFIRM to keep the slot or call {phone} to reschedule.",
    "{name} from accounting needs the Q3 budget file. You can send it by EOD whenever you have a moment.",
    "Thanks for subscribing to the {company} newsletter! You will receive one update each month. Unsubscribe anytime.",
]

SHORTENERS = ["bit.ly", "tinyurl.com", "is.gd", "t.co"]
RISKY_TLDS = ["tk", "xyz", "click", "top", "link", "support", "work", "review"]


def _maybe_url(scam: bool, rng: random.Random) -> str | None:
    if rng.random() < (0.85 if scam else 0.2):
        host = rng.choice(SUSPICIOUS_HOSTS if scam else BENIGN_HOSTS)
        if rng.random() < 0.3:
            host = rng.choice(SHORTENERS) + "/" + "".join(rng.choice("abcdefghjkmnpqrstuvwxyz0123456789") for _ in range(7))
        tld_host = host
        if not scam and rng.random() < 0.7:
            tld_host = f"www.{host}"
        scheme = "http" if rng.random() < 0.3 else "https"
        return f"{scheme}://{tld_host}/login?u={rng.randint(1000, 9999)}"
    return None


def _fill(template: str, rng: random.Random) -> str:
    ctx = {
        "name": rng.choice(NAMES),
        "company": rng.choice(["Acme Corp", "Zenith Ltd", "Nova Works", "Brightpath Co"]),
        "platform": rng.choice(PLATFORMS),
        "bank": rng.choice(BANKS),
        "crypto": rng.choice(CRYPTO),
        "amount": rng.choice(AMOUNTS),
        "fee": rng.choice(["$49", "$99", "$120", "$35", "£60"]),
        "pct": str(rng.randint(2, 20)),
        "hrs": str(rng.randint(4, 20)),
        "phone": rng.choice(PHONES),
        "email": rng.choice(EMAILS),
        "date": f"{rng.randint(1, 28)} {rng.choice(['May', 'June', 'July', 'Aug'])}",
        "url": "",
    }
    msg = template.format(**ctx)
    url = _maybe_url(True, rng)
    if url:
        msg = msg.replace("{url}", url)
    msg = re.sub(r"\{url\}", rng.choice(BENIGN_HOSTS), msg)
    if rng.random() < 0.5:
        msg = msg.upper()
    return msg


def _fill_benign(template: str, rng: random.Random) -> str:
    ctx = {
        "name": rng.choice(NAMES),
        "company": rng.choice(["Acme Corp", "Zenith Ltd", "Nova Works", "Brightpath Co"]),
        "platform": rng.choice(PLATFORMS),
        "phone": rng.choice(PHONES),
        "date": f"{rng.randint(1, 28)} {rng.choice(['May', 'June', 'July', 'Aug'])}",
        "url": "",
    }
    msg = template.format(**ctx)
    url = _maybe_url(False, rng)
    if url:
        msg = msg.replace("{url}", url)
    msg = re.sub(r"\{url\}", rng.choice(BENIGN_HOSTS), msg)
    return msg


def generate(n_per_category: int = 120, seed: int = 7) -> list[dict]:
    """Return a list of {text, label, category} rows."""
    rng = random.Random(seed)
    rows: list[dict] = []
    # Category keys must match the rule-engine taxonomy (app/patterns/rules.py
    # CATEGORY_LABELS) so the validated dataset loader accepts every row.
    categories = [
        ("job_scam", JOB), ("banking_scam", BANKING), ("investment_scam", INVESTMENT),
        ("delivery_scam", DELIVERY), ("lottery_scam", LOTTERY), ("tech_support_scam", TECH_SUPPORT),
        ("romance_scam", ROMANCE), ("account_takeover", ACCOUNT_TAKEOVER),
        ("crypto_scam", CRYPTO_WALLET), ("advance_fee", ADVANCE_FEE),
    ]
    for category, templates in categories:
        for _ in range(n_per_category):
            rows.append({
                "text": _fill(rng.choice(templates), rng),
                "label": "scam",
                "category": category,
            })
    # benign control set — include some noise that shares surface features
    for _ in range(int(n_per_category * 1.6)):
        rows.append({
            "text": _fill_benign(rng.choice(BENIGN), rng),
            "label": "benign",
            "category": "benign",
        })
    rng.shuffle(rows)
    return rows


def write_csv(rows: list[dict], out_path: Path = DEFAULT_OUT) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["text", "label", "category"])
        writer.writeheader()
        writer.writerows(rows)
    return out_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-category", type=int, default=120)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    dataset = generate(args.per_category, args.seed)
    path = write_csv(dataset, args.out)
    counts: dict[str, int] = {}
    for row in dataset:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    print(f"wrote {len(dataset)} rows -> {path}")
    print(f"label distribution: {counts}")
