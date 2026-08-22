"""
web_security/web_findings.py
-----------------------------
Shared data structures used across all OWASP checkers.
NVD API integration for live CWE → CVE enrichment.
Falls back to local table if NVD is offline.

NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0

CHANGE NOTE (this revision): added `variant`, `status`, `parameter`,
`baseline`, `probe`, and `validation` fields to WebFinding, plus
matching kwargs on build_finding(). All new fields are optional with
safe defaults ("" / None / {}), so every existing call site that
built a WebFinding or called build_finding() the old way keeps
working unchanged. These fields exist so checkers can express:
  - variant:   e.g. "ERROR_BASED" vs "BOOLEAN_DIFFERENTIAL" for the
               same vulnerability type, instead of overloading `title`.
  - status:    DETECTED | VALIDATED | CONFIRMED | NOT_CONFIRMED | ERROR
               -- so the report can distinguish confidence tiers instead
               of presenting every finding as an equally-certain "confirmed".
  - parameter: single affected parameter name (affected_params stays
               for the list form some checkers already use).
  - baseline / probe / validation: raw evidence dicts (e.g. a
               ResponseDiffer.as_evidence_dict() result) for
               reproducibility, separate from the human-readable
               `evidence` string list.
"""

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# ── NVD API ────────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── In-memory caches ───────────────────────────────────────────────────────
_nvd_cache:      Dict[str, List[dict]] = {}
_METADATA_CACHE: Optional[dict]        = None

# Valid values for the new `status` field. Checkers should use these
# constants rather than free-text strings so downstream reporting can
# rely on a closed set.
STATUS_DETECTED = "DETECTED"
STATUS_VALIDATED = "VALIDATED"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_NOT_CONFIRMED = "NOT_CONFIRMED"
STATUS_ERROR = "ERROR"
STATUS_SKIPPED = "SKIPPED"


# ── Metadata loader ────────────────────────────────────────────────────────
def load_metadata() -> dict:
    """
    Load vulnerability metadata from data/web_vulnerability_metadata.json.
    Result is cached after first load — zero I/O on subsequent calls.
    Raises FileNotFoundError if the JSON file is missing.
    """
    global _METADATA_CACHE

    if _METADATA_CACHE is not None:
        return _METADATA_CACHE

    metadata_file = (
        Path(__file__).resolve().parents[2]
        / "data"
        / "web_vulnerability_metadata.json"
    )

    with open(metadata_file, "r", encoding="utf-8") as f:
        _METADATA_CACHE = json.load(f)

    return _METADATA_CACHE


# ── NVD enrichment ─────────────────────────────────────────────────────────
def fetch_nvd_cves(cwe_id: str, max_results: int = 3) -> List[dict]:
    """
    Query NVD API for recent critical CVEs by CWE ID.
    Returns list of {cve_id, cvss, description} dicts.
    Falls back to empty list if offline or rate-limited.

    NVD endpoint:
        GET /rest/json/cves/2.0?cweId=CWE-89&resultsPerPage=3
    """
    if cwe_id in _nvd_cache:
        return _nvd_cache[cwe_id]

    try:
        url = (f"{NVD_API_BASE}"
               f"?cweId={cwe_id}"
               f"&resultsPerPage={max_results}"
               f"&sortBy=publishedDate&sortOrder=desc")
        req = urllib.request.Request(url, headers={"User-Agent": "RedTeamFramework/2.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())

        results = []
        for item in data.get("vulnerabilities", []):
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc   = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:120]
                    break
            cvss_score = 0.0
            metrics = cve.get("metrics", {})
            for m in metrics.get("cvssMetricV31", []):
                cvss_score = m.get("cvssData", {}).get("baseScore", 0.0)
                break
            if not cvss_score:
                for m in metrics.get("cvssMetricV30", []):
                    cvss_score = m.get("cvssData", {}).get("baseScore", 0.0)
                    break

            if cve_id:
                results.append({
                    "cve_id":      cve_id,
                    "cvss":        cvss_score,
                    "description": desc,
                })

        _nvd_cache[cwe_id] = results
        return results

    except Exception:
        _nvd_cache[cwe_id] = []
        return []


# ── WebFinding dataclass ───────────────────────────────────────────────────
@dataclass
class WebFinding:
    """
    Single OWASP finding produced by any checker.
    Mirrors the dict structure used by VulnCorrelator and ThreatScore.
    """
    check_type:      str
    owasp_id:        str
    owasp_name:      str
    mitre_technique: str
    risk_level:      str
    cvss_base:       float
    confidence:      float
    title:           str
    cwe_id:          str        = ""
    nvd_cves:        List[dict] = field(default_factory=list)
    evidence:        List[str]  = field(default_factory=list)
    affected_params: List[str]  = field(default_factory=list)
    remediation:     str        = ""
    host:            Optional[str] = None
    port:            Optional[int] = None
    service:         Optional[str] = None

    # ── additive fields (see CHANGE NOTE above) ─────────────────────────
    variant:         str            = ""
    status:          str            = STATUS_DETECTED
    parameter:       Optional[str]  = None
    baseline:        dict           = field(default_factory=dict)
    probe:           dict           = field(default_factory=dict)
    validation:      dict           = field(default_factory=dict)
    repeatable:      Optional[bool] = None

    def to_dict(self) -> dict:
        return {
            "check_type":      self.check_type,
            "owasp_id":        self.owasp_id,
            "owasp_name":      self.owasp_name,
            "mitre_technique": self.mitre_technique,
            "risk_level":      self.risk_level,
            "cvss_base":       self.cvss_base,
            "confidence":      self.confidence,
            "title":           self.title,
            "cwe_id":          self.cwe_id,
            "nvd_cves":        self.nvd_cves,
            "evidence":        self.evidence,
            "affected_params": self.affected_params,
            "remediation":     self.remediation,
            "host":            self.host,
            "port":            self.port,
            "service":         self.service,
            "variant":         self.variant,
            "status":          self.status,
            "parameter":       self.parameter,
            "baseline":        self.baseline,
            "probe":           self.probe,
            "validation":      self.validation,
            "repeatable":      self.repeatable,
        }


# ── Confidence model (requirement: confidence must be computed, not
#    an arbitrary constant) ──────────────────────────────────────────────
def compute_confidence(*, error_evidence: bool = False,
                        behavioral_evidence: bool = False,
                        repeatable: Optional[bool] = None,
                        validated: bool = False) -> float:
    """
    Combines independent evidence signals into a single 0..1 score.
    Callers pass booleans for whichever signals they actually gathered;
    unavailable signals should be left False rather than guessed.

        error_evidence       explicit DBMS/framework error signature, a
                              reflected/unescaped canary, etc.
        behavioral_evidence   a structural/timing/status diff between
                              baseline and probe (ResponseDiffer output)
        repeatable            same result observed on a second, independent
                              probe. None = not re-tested (no bonus, no penalty)
        validated              an additional, distinct validation step
                              succeeded (e.g. boolean true/false pair both
                              behaved as predicted)

    0.0-0.39 LOW, 0.40-0.69 MEDIUM, 0.70-0.89 HIGH, 0.90-1.00 VERY_HIGH
    """
    score = 0.0
    if error_evidence:
        score += 0.45
    if behavioral_evidence:
        score += 0.30
    if validated:
        score += 0.20
    if repeatable is True:
        score += 0.15
    elif repeatable is False:
        score -= 0.30  # contradicted on retest -- strong penalty
    return round(max(0.0, min(score, 1.0)), 2)


def confidence_band(confidence: float) -> str:
    if confidence >= 0.90:
        return "VERY_HIGH"
    if confidence >= 0.70:
        return "HIGH"
    if confidence >= 0.40:
        return "MEDIUM"
    return "LOW"


# ── Factory ────────────────────────────────────────────────────────────────
def build_finding(check_type: str, title: str, evidence: List[str],
                  confidence: float, host: str = None, port: int = None,
                  service: str = None, affected_params: List[str] = None,
                  remediation: str = "",
                  enrich_nvd: bool = True,
                  variant: str = "",
                  status: str = STATUS_DETECTED,
                  parameter: Optional[str] = None,
                  baseline: Optional[dict] = None,
                  probe: Optional[dict] = None,
                  validation: Optional[dict] = None,
                  repeatable: Optional[bool] = None,
                  cwe_override: Optional[str] = None) -> WebFinding:
    """
    Factory — enriches finding with OWASP/MITRE/CVSS/CWE metadata
    loaded from data/web_vulnerability_metadata.json.
    If enrich_nvd=True, fetches live CVE examples from NVD API.

    cwe_override: use when the checker has a more specific CWE than
    the metadata table's default for this check_type. If the checker
    isn't confident of a mapping, leave this None -- build_finding
    will fall back to the metadata table, and if that also has
    nothing suitable, cwe stays "" rather than a guessed ID.
    """
    metadata = load_metadata()

    meta = metadata.get(
        check_type,
        {
            "owasp":      "A05:2021",
            "owasp_name": "Security Misconfiguration",
            "mitre":      "T1190",
            "cvss":       5.0,
            "cwe":        "CWE-16",
        }
    )

    cvss  = float(meta["cvss"])
    owasp = meta["owasp"]
    cwe   = cwe_override or meta.get("cwe", "")

    if cvss >= 9.0:     risk = "CRITICAL"
    elif cvss >= 7.0:   risk = "HIGH"
    elif cvss >= 4.0:   risk = "MEDIUM"
    else:               risk = "LOW"

    nvd_cves = fetch_nvd_cves(cwe) if (enrich_nvd and cwe) else []
    if nvd_cves:
        evidence = evidence + [
            f"NVD reference ({cwe}): {c['cve_id']} — CVSS {c['cvss']}"
            for c in nvd_cves[:2]
        ]

    return WebFinding(
        check_type      = check_type,
        owasp_id        = owasp,
        owasp_name      = meta.get("owasp_name", "Unknown"),
        mitre_technique = meta.get("mitre", "T1190"),
        risk_level      = risk,
        cvss_base       = cvss,
        confidence      = round(min(confidence, 1.0), 2),
        title           = title,
        cwe_id          = cwe,
        nvd_cves        = nvd_cves,
        evidence        = evidence,
        affected_params = affected_params or [],
        remediation     = remediation,
        host            = host,
        port            = port,
        service         = service,
        variant         = variant,
        status          = status,
        parameter       = parameter,
        baseline        = baseline or {},
        probe           = probe or {},
        validation      = validation or {},
        repeatable      = repeatable,
    )
