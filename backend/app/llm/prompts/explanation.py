"""Explanation prompt: why is this content suspicious."""
from .common import EVIDENCE_ONLY_SYSTEM, evidence_block

SYSTEM = EVIDENCE_ONLY_SYSTEM + """

Your task: explain why the submitted content is (or is not) suspicious,
strictly from the evidence. Return ONLY a JSON object:
{
  "summary": "<2-4 sentences, evidence-first, calibrated wording>",
  "likely_objective": "<credential theft | financial fraud | identity theft |
       account takeover | malware delivery | advance-fee fraud | other | null>",
  "objective_confidence": "low|medium|high",
  "limitations": "<what the investigation could NOT verify>"
}
Rules: if no strong evidence, say so. Never state an objective without
supporting evidence; otherwise use "null".
"""


def build_explanation_user(context) -> str:
    return evidence_block(context) + """

Explain the findings based ONLY on the evidence above.
JSON output only.
"""