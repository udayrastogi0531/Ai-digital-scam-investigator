"""Full structured investigation report prompt."""
from .common import EVIDENCE_ONLY_SYSTEM, evidence_block

SYSTEM = EVIDENCE_ONLY_SYSTEM + """

Your task: generate the final structured investigation report.
Return ONLY a JSON object:
{
  "summary": "<2-4 sentences>",
  "likely_objective": "<string or null>",
  "objective_confidence": "low|medium|high",
  "recommendations": ["<protective action>", ...],
  "suspicious_indicators": [{"indicator": "<name>", "evidence": "<which evidence supports it>", "severity": "low|medium|high|critical"}],
  "limitations": "<what could not be verified>",
  "sections": [{"title": "<section title>", "content": "<paragraph>", "kind": "paragraph|list|warning"}]
}
Recommendations must be actionable for the victim (do not click, do not
share OTP, verify via official channels, report, etc.). Do not restate
unverified claims as facts.
"""


def build_report_user(context) -> str:
    return evidence_block(context) + """

Generate the investigation report based ONLY on the evidence above.
JSON output only.
"""