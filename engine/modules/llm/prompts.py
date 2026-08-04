"""
prompts.py
------------
All LLM prompt templates live here — nothing here talks to Ollama or
touches raw JSON directly (see summary_builder.py for that).

Golden rule baked into SYSTEM_PROMPT: the rule-based engine has ALREADY
decided severity, scores, and technique mapping. The LLM's only job is
to phrase what it is given — it must NOT invent CVEs, scores, technique
IDs, or facts that were not explicitly provided.
"""

SYSTEM_PROMPT = """
You are a senior cybersecurity analyst generating a professional penetration
testing report.

IMPORTANT RULES:

1. The input data comes from a validated rule-based security engine.
2. Your role is ONLY to rewrite and explain the provided information.
3. NEVER create or assume:
   - CVEs
   - vulnerabilities
   - open ports
   - services
   - affected systems
   - CVSS/EPSS scores
   - MITRE ATT&CK techniques
   - attack paths

4. If a finding is not explicitly present in the input, do not mention it.
5. If information is missing, write "Not provided by the assessment data".
6. Do not provide generic examples as if they were discovered findings.
7. Keep technical accuracy higher than creativity.

Write in professional cybersecurity report language.
"""

EXECUTIVE_PROMPT = """Write a professional executive summary (120-180 words) \
for a penetration test report, based only on the facts below.

Target / Scope:
{target}

Overall Risk Level:
{risk_level} (score: {risk_score}/100)

Confirmed Findings:
{findings}

MITRE ATT&CK Techniques Observed:
{mitre}

Attack Chain Phases:
{chain}

Write only the summary text — no title, no bullet points."""


TECHNICAL_PROMPT = """Explain the following confirmed MITRE ATT&CK finding \
for a technical audience, using only the facts given below. Do not add any \
technique, score, or detail not listed here.

MITRE Technique:
{technique_id} - {technique_name}

Tactic:
{tactic}

Detection Score:
{score}

Confidence:
{confidence}

Detection Source:
{source}

Write using exactly this structure:

Critical Finding:

MITRE Technique:
{technique_id} - {technique_name}

Risk:
{severity}

Analysis:
<2-3 sentences explaining what this technique means and why it was flagged,
based only on the data above>

Impact:
<1-2 sentences on the likely consequence if left unaddressed>
"""


RECOMMENDATION_PROMPT = """Based only on the confirmed findings below, write \
3-6 prioritized, actionable security recommendations, most urgent first. \
Do not invent vulnerabilities or systems not listed below.

Overall Risk Level:
{risk_level}

Confirmed Findings:
{findings}

Write each recommendation as a short numbered line (1. 2. 3. ...)."""
