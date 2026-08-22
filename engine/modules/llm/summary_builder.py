"""
summary_builder.py
---------------------
Condenses the large, raw pipeline output (findings, mapped MITRE results,
risk_summary, attack_chain, exploit_results) into small, clean structures
that are cheap and safe to feed into an LLM prompt.

THIS IS THE RULE-BASED / LLM BOUNDARY:
No function in this file calls an LLM. Everything here only selects,
ranks, and trims data that has ALREADY been decided upstream by the
rule-based engine (severity, scores, technique mapping, exploitation
results, etc). The LLM never sees raw pipeline output — only what this
file hands it.
"""

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def build_findings_summary(findings: list[dict], top_n: int = 8) -> list[dict]:
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
            "identifier": f.get("cve") or f.get("cwe_id") or "N/A",
            "finding": (
                f.get("vulnerability")
                or f.get("title")
                or f.get("edb_title")
                or "Unknown finding"
            ),
            "severity": str(f.get("severity", "unknown")).upper(),
            "host": f.get("host", "unknown"),
            "port": f.get("port", "-"),
            "cvss": f.get("cvss_live", f.get("cvss", "-")),
            "epss": f.get("epss", "N/A"),
            "in_kev": bool(f.get("in_kev", False)),
            "remediation": f.get("remediation", ""),
        })

    return summary


def build_mitre_summary(mapped_results: list[dict], top_n: int = 8) -> list[dict]:
    if not mapped_results:
        return []

    techniques = []
    seen = set()

    def add_technique(layer):
        if not isinstance(layer, dict):
            return

        tid = layer.get("technique_id") or layer.get("techniqueID") or ""
        if not tid or tid in seen:
            return

        seen.add(tid)
        confidence = layer.get("confidence", layer.get("score", 0))

        techniques.append({
            "technique_id": tid,
            "technique_name": layer.get("technique_name") or layer.get("name") or "",
            "tactic": layer.get("tactic", "unknown"),
            "score": layer.get("score", confidence),
            "confidence": confidence,
            "source": layer.get("source", "N/A"),
            "severity": layer.get("severity", "UNKNOWN"),
        })

    for result in mapped_results:
        if not isinstance(result, dict):
            continue

        primary = result.get("mitre")
        if isinstance(primary, dict):
            add_technique(primary)

        layers = result.get("layers", [])
        if isinstance(layers, list):
            for layer in layers:
                add_technique(layer)

        if result.get("technique_id") or result.get("techniqueID"):
            add_technique(result)

    techniques.sort(
        key=lambda item: -_as_number(item.get("confidence", item.get("score", 0)))
    )

    return techniques[:top_n]


def build_risk_summary(risk_summary: dict) -> dict:
    if not risk_summary:
        return {}

    scope = risk_summary.get("scope", "N/A")
    if isinstance(scope, list):
        scope = ", ".join(str(item) for item in scope)

    return {
        "scope": scope,
        "overall_risk": risk_summary.get(
            "overall_risk",
            risk_summary.get("risk_level", "UNKNOWN"),
        ),
        "risk_score": risk_summary.get("risk_score", 0),
        "total_findings": risk_summary.get("total_findings", 0),
        "high_risk_count": risk_summary.get("high_risk_count", 0),
        "kev_count": risk_summary.get("kev_count", 0),
        "exploit_success": risk_summary.get("exploit_success", 0),
    }


def build_attack_chain_summary(attack_chain, top_n: int = 10) -> list[str]:
    if not attack_chain:
        return []

    if isinstance(attack_chain, dict):
        if "phases" in attack_chain:
            phases = attack_chain.get("phases", [])
            if isinstance(phases, dict):
                phases = list(phases.values())
        else:
            phases = [
                value
                for value in attack_chain.values()
                if isinstance(value, dict)
            ]
    elif isinstance(attack_chain, list):
        phases = attack_chain
    else:
        return []

    lines = []

    for phase in phases[:top_n]:
        if not isinstance(phase, dict):
            lines.append(str(phase))
            continue

        label = (
            phase.get("phase_name")
            or phase.get("phase")
            or phase.get("name")
            or "Phase"
        )

        technique_ids = []
        techniques = phase.get("techniques", [])

        if isinstance(techniques, dict):
            techniques = list(techniques.values())

        if isinstance(techniques, list):
            for technique in techniques:
                if isinstance(technique, dict):
                    tid = (
                        technique.get("id")
                        or technique.get("technique_id")
                        or technique.get("techniqueID")
                    )
                    if tid:
                        technique_ids.append(str(tid))
                elif isinstance(technique, str):
                    technique_ids.append(technique)

        if not technique_ids:
            tid = phase.get("technique_id") or phase.get("techniqueID")
            if tid:
                technique_ids.append(str(tid))

        action = ", ".join(technique_ids)
        lines.append(f"{label}: {action}" if action else str(label))

    return lines


def build_exploitation_summary(exploit_results: list[dict]) -> dict:
    if not exploit_results:
        return {
            "attempts": 0,
            "successful": 0,
            "failed": 0,
            "success_rate": 0.0,
            "successful_examples": [],
        }

    def is_success(result: dict) -> bool:
        if result.get("success") is True:
            return True

        status = str(
            result.get("result")
            or result.get("status")
            or ""
        ).strip().lower()

        return status in {
            "success",
            "successful",
            "succeeded",
            "exploited",
        }

    valid_results = [r for r in exploit_results if isinstance(r, dict)]
    attempts = len(valid_results)
    successful_results = [r for r in valid_results if is_success(r)]
    successful = len(successful_results)
    failed = max(0, attempts - successful)
    success_rate = round((successful / attempts) * 100, 2) if attempts else 0.0

    examples = []
    for result in successful_results[:5]:
        examples.append({
            "host": result.get("host", "N/A"),
            "port": result.get("port", "N/A"),
            "method": (
                result.get("type")
                or result.get("exploit_type")
                or result.get("module")
                or result.get("exploit")
                or "N/A"
            ),
        })

    return {
        "attempts": attempts,
        "successful": successful,
        "failed": failed,
        "success_rate": success_rate,
        "successful_examples": examples,
    }


def _as_number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
