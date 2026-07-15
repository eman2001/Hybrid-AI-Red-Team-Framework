EXECUTIVE_PROMPT = """
You are a senior cybersecurity analyst.

Write a professional executive summary.

Target:
{target}

Risk Score:
{risk}

Critical Findings:
{findings}

MITRE Techniques:
{mitre}

Attack Chain:
{chain}

Return only the summary.
"""


ATTACK_PROMPT = """
Explain how the attacker progressed through the attack.

Attack Chain:
{chain}

Vulnerabilities:
{findings}

Return a chronological attack narrative.
"""


RECOMMENDATION_PROMPT = """
Generate security recommendations.

Risk:
{risk}

Findings:
{findings}

MITRE:
{mitre}

Provide recommendations ordered by priority.
"""
