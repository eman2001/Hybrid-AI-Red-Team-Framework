"""
web_security/vuln_correlator.py
--------------------------------
Aggregation and scoring layer. Takes the `findings` lists already
produced by the individual checkers (InjectionChecker, XSSChecker,
BrokenAccessControlChecker, SecurityHeadersChecker, CORSChecker, ...)
-- each finding already a WebFinding.to_dict() -- and:

  1. Groups/correlates them (same host, related OWASP categories,
     compounding misconfigurations) so the report can say "these two
     findings together indicate X" instead of just listing rows.
  2. Computes a single 0-100 Threat Score for the target, weighted by
     severity, confidence, and confirmation status.

This module does NOT send any requests and does NOT know how any
finding was produced -- it only reads the dicts it's handed. It has
no dependency on http_utils, no target_url, nothing that talks to a
network.
"""

from collections import defaultdict
from typing import Dict, List

# Severity -> base point value used in the weighted score.
_RISK_WEIGHT = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   12,
    "LOW":      4,
}

# Status multiplier -- an unconfirmed/low-confidence finding shouldn't
# move the score as much as a confirmed one, even at the same
# nominal severity.
_STATUS_MULTIPLIER = {
    "CONFIRMED":     1.0,
    "VALIDATED":     0.8,
    "DETECTED":      0.5,
    "NOT_CONFIRMED": 0.0,   # should already be filtered out by checkers, but defend anyway
    "ERROR":         0.0,
    "SKIPPED":       0.0,
}

# Category pairs that, when BOTH present on the same host, indicate a
# compounding issue worse than either finding alone. Order-independent
# (checked both ways).
_COMPOUND_RULES = [
    {
        "categories": {"cors_misconfiguration", "security_headers"},
        "label": "Open CORS policy combined with missing security headers",
        "note": "A permissive CORS policy is more exploitable when baseline "
                "browser protections (CSP, X-Frame-Options, etc.) are also absent.",
        "bonus": 8,
    },
    {
        "categories": {"sql_injection", "idor"},
        "label": "Injection plus broken object-level authorization",
        "note": "SQL injection combined with IDOR suggests the application "
                "layer has no consistent input/ownership validation strategy, "
                "not just an isolated bug.",
        "bonus": 15,
    },
    {
        "categories": {"xss", "cors_misconfiguration"},
        "label": "Reflected XSS combined with permissive CORS",
        "note": "Reflected XSS is more dangerous when a permissive CORS policy "
                "also allows cross-origin exfiltration of any token XSS can read.",
        "bonus": 10,
    },
]


class VulnCorrelator:

    def __init__(self, check_results: List[dict]):
        """
        check_results: list of the dicts each checker's run_check()
        returns, e.g. [{"check_name": ..., "category": ..., "findings": [...]}, ...]
        """
        self._check_results = check_results
        self.findings: List[dict] = []
        for result in check_results:
            self.findings.extend(result.get("findings", []))

        self.correlations: List[dict] = []
        self.threat_score: float = 0.0
        self.score_breakdown: dict = {}

    # ── grouping ─────────────────────────────────────────────────────
    def group_by_host(self) -> Dict[str, List[dict]]:
        groups = defaultdict(list)
        for f in self.findings:
            host_key = f.get("host") or "unknown-host"
            groups[host_key].append(f)
        return dict(groups)

    def group_by_category(self) -> Dict[str, List[dict]]:
        groups = defaultdict(list)
        for f in self.findings:
            groups[f.get("check_type", "unknown")].append(f)
        return dict(groups)

    def group_by_owasp(self) -> Dict[str, List[dict]]:
        groups = defaultdict(list)
        for f in self.findings:
            groups[f.get("owasp_id", "unknown")].append(f)
        return dict(groups)

    # ── correlation ──────────────────────────────────────────────────
    def _find_compound_issues(self) -> List[dict]:
        by_host = self.group_by_host()
        hits = []
        for host, host_findings in by_host.items():
            present_categories = {f.get("check_type") for f in host_findings}
            for rule in _COMPOUND_RULES:
                if rule["categories"].issubset(present_categories):
                    hits.append({
                        "host": host,
                        "label": rule["label"],
                        "note": rule["note"],
                        "categories": sorted(rule["categories"]),
                        "bonus_points": rule["bonus"],
                    })
        return hits

    def correlate(self) -> List[dict]:
        """Populates and returns self.correlations. Call before/along with score()."""
        self.correlations = self._find_compound_issues()
        return self.correlations

    # ── scoring ──────────────────────────────────────────────────────
    def score(self) -> float:
        """
        Computes a 0-100 threat score. Not a simple sum-and-clamp --
        uses diminishing returns past the first few high-severity
        findings so that e.g. 20 LOW findings don't outrank 1 CONFIRMED
        CRITICAL, and one host with everything wrong doesn't blow past
        100 just because it has more findings than another.
        """
        if not self.findings:
            self.threat_score = 0.0
            self.score_breakdown = {"base_points": 0.0, "compound_bonus": 0.0, "raw_total": 0.0}
            return self.threat_score

        weighted_points = []
        for f in self.findings:
            risk = f.get("risk_level", "LOW")
            status = f.get("status", "DETECTED")
            confidence = f.get("confidence", 0.5)

            base = _RISK_WEIGHT.get(risk, _RISK_WEIGHT["LOW"])
            status_mult = _STATUS_MULTIPLIER.get(status, 0.5)
            points = base * status_mult * confidence
            weighted_points.append(points)

        # Diminishing returns: sort descending, apply a decay factor to
        # each subsequent finding's contribution so score growth flattens
        # rather than growing unbounded with finding count.
        weighted_points.sort(reverse=True)
        base_points = 0.0
        decay = 1.0
        for points in weighted_points:
            base_points += points * decay
            decay *= 0.85  # each additional finding contributes progressively less

        if not self.correlations:
            self.correlate()
        compound_bonus = sum(c["bonus_points"] for c in self.correlations)

        raw_total = base_points + compound_bonus
        self.threat_score = round(min(raw_total, 100.0), 1)
        self.score_breakdown = {
            "base_points": round(base_points, 1),
            "compound_bonus": compound_bonus,
            "raw_total": round(raw_total, 1),
            "finding_count": len(self.findings),
            "confirmed_count": sum(1 for f in self.findings if f.get("status") == "CONFIRMED"),
        }
        return self.threat_score

    @staticmethod
    def score_band(score: float) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"

    # ── report-ready summary ────────────────────────────────────────
    def summarize(self) -> dict:
        """One call to get everything a report generator needs."""
        self.correlate()
        score = self.score()
        by_owasp = self.group_by_owasp()

        return {
            "threat_score": score,
            "threat_band": self.score_band(score),
            "score_breakdown": self.score_breakdown,
            "total_findings": len(self.findings),
            "findings_by_owasp_category": {
                k: len(v) for k, v in by_owasp.items()
            },
            "compound_correlations": self.correlations,
            "checks_run": [r.get("check_name") for r in self._check_results],
        }
