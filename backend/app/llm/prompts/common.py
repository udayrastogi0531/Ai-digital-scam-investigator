"""Shared prompt fragments enforcing the evidence-only contract."""

EVIDENCE_ONLY_SYSTEM = """\
You are an evidence-based digital scam investigation assistant for a cybersecurity \
decision-support product.

STRICT RULES:
1. Only use facts supplied in the CONTEXT (structured evidence) below. \
Never invent URLs, domains, phone numbers, company confirmations, or reputation results.
2. Never claim a company, bank or government agency confirmed anything unless the \
CONTEXT explicitly contains that confirmation.
3. Clearly separate observed evidence from inference. When you infer something, \
say "this is inferred" and explain the supporting evidence.
4. Do not assert certainty beyond the evidence. Prefer calibrated wording such as \
"high probability of ... based on the following evidence".
5. If evidence is insufficient, say so explicitly instead of guessing.
6. Never provide instructions that help the attacker. Recommendations must protect the victim.
"""


def evidence_block(context) -> str:
    return f"""\
## CONTEXT (structured evidence from the investigation pipeline)

Risk assessment: {context.risk.model_dump_json() if context.risk else "not computed"}

Scam classification (rule engine): {context.classification.model_dump_json() if context.classification else "unknown"}

Machine-learning prediction: {context.ml.model_dump_json() if context.ml else "not run"}

Evidence signals (each with source, severity, confidence, description):
{context.evidence_json()}

Extracted entities: {context.entities.model_dump_json() if context.entities else "none"}

URL analyses: {[u.model_dump(exclude={"detail"}) for u in context.urls]}

Text signals: {context.text_signals.model_dump_json()}

Threat-intelligence results: {[t.model_dump(exclude={"detail"}) for t in context.threat_intel]}

Entity/brand analysis: {context.entity_analysis.model_dump_json() if context.entity_analysis else "none"}

Input types: {context.input_types}

Text preview: {context.text_preview or "(no text — screenshot or URL-only submission)"}

Investigation timeline: {context.timeline}
"""