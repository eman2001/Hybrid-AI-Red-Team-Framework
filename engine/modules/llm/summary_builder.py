"""
summary_builder.py
---------------------
Condenses the large, raw pipeline output (findings, mapped MITRE results,
risk_summary, attack_chain) into small, clean structures that are cheap
and safe to feed into an LLM prompt.

THIS IS THE RULE-BASED / LLM BOUNDARY:
No function in this file calls an LLM. Everything here only selects,
ranks, and trims data that has ALREADY been decided upstream by the
rule-based engine (severity, scores, technique mapping, etc). The LLM
never sees raw pipeline output — only what this file hands it.
"""

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_findings_summary(findings: list[dict], top_n: int = 8) -> list[dict]:
    """Pick the most important findings (already scored/ranked upstream)
    and strip them down to only the fields report writing needs."""
    if not findings:
        return []

    ranked = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "low")).lower(), 9),
            -_as_number(f.get("threat_score", f.get("risk_score", 0))),
        ),
    )

    summary = []
    for f in ranked[:top_n]:
        summary.append({
            "cve":         f.get("cve") or f.get("vulnerability", "N/A"),
            "severity":    f.get("severity", "unknown"),
            "host":        f.get("host", "unknown"),
            "port":        f.get("port", "-"),
            "cvss":        f.get("cvss_live", f.get("cvss", "-")),
            "in_kev":      bool(f.get("in_kev")),
            "remediation": f.get("remediation", ""),
        })
    return summary


def build_mitre_summary(mapped_results: list[dict], top_n: int = 8) -> list[dict]:
    """Flatten + rank MITRE technique layers already mapped by the rule
    engine / STIX / ML fusion — this file does not re-map anything."""
    if not mapped_results:
        return []

    techniques = []
    seen = set()

    for r in mapped_results:
        for layer in r.get("layers", []):
            tid = layer.get("technique_id") or layer.get("techniqueID", "")
            if not tid or tid in seen:
                continue
            seen.add(tid)
            techniques.append({
                "technique_id":   tid,
                "technique_name": layer.get("technique_name", ""),
                "tactic":         layer.get("tactic", "unknown"),
                "score":          layer.get("score", layer.get("confidence", 0)),
                "confidence":     layer.get("confidence", "N/A"),
                "source":         layer.get("source", "N/A"),
                "severity": layer.get("severity", "UNKNOWN"),
            })

    techniques.sort(key=lambda t: -_as_number(t.get("score", 0)))
    return techniques[:top_n]


def build_risk_summary(risk_summary: dict) -> dict:
    if not risk_summary:
        return {}

    scope = risk_summary.get("scope", "N/A")
    if isinstance(scope, list):
        scope = ", ".join(scope)

    return {
        "overall_risk":    risk_summary.get("overall_risk", risk_summary.get("risk_level", "UNKNOWN")),
        "risk_score":      risk_summary.get("risk_score", 0),
        "total_findings":  risk_summary.get("total_findings", 0),
        "high_risk_count": risk_summary.get("high_risk_count", 0),
        "kev_count":       risk_summary.get("kev_count", 0),
        "exploit_success": risk_summary.get("exploit_success", 0),
        "scope":           scope,
    }


def build_attack_chain_summary(attack_chain, top_n: int = 10) -> list[str]:
    if not attack_chain:
        return []

    if isinstance(attack_chain, dict):
        phases = attack_chain.get("phases", list(attack_chain.values()))
    else:
        phases = attack_chain

    lines = []
    for phase in phases[:top_n]:
        if isinstance(phase, dict):
            label = phase.get("phase", phase.get("name", "phase"))
            action = phase.get("technique_id", phase.get("action", ""))
            lines.append(f"{label}: {action}".strip(": "))
        else:
            lines.append(str(phase))
    return lines


def _as_number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
