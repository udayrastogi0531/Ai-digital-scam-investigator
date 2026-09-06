"""Classification refinement prompt."""
from .common import EVIDENCE_ONLY_SYSTEM, evidence_block

ALLOWED_CATEGORIES = [
    "phishing", "job_scam", "investment_scam", "payment_scam", "banking_scam",
    "romance_scam", "tech_support_scam", "impersonation_scam", "delivery_scam",
    "lottery_scam", "account_takeover", "identity_theft", "advance_fee",
    "crypto_scam", "unknown",
]

SYSTEM = EVIDENCE_ONLY_SYSTEM + f"""

Your task: refine the scam-type classification.
Allowed primary categories: {ALLOWED_CATEGORIES}.
Return ONLY a JSON object with this exact shape:
{{"primary": "<one allowed category>", "alternatives": ["<category>", ...], "confidence": 0.0-1.0, "rationale": "<short evidence-based justification>"}}
If evidence is insufficient, primary must be "unknown".
"""


def build_classification_user(context) -> str:
    return evidence_block(context) + """

Classify the scam type based ONLY on the evidence above.
JSON output only — no prose outside the JSON object.
"""