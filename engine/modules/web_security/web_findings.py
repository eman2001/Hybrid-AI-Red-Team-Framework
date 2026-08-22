"""
web_security/web_findings.py
-----------------------------
Shared data structures used across all OWASP checkers.
NVD API integration for live CWE -> CVE enrichment.
Falls back to local metadata if NVD is offline.

CVSS preference for NVD enrichment:
    CVSS v4.0 -> v3.1 -> v3.0 -> v2.0

NVD API:
https://services.nvd.nist.gov/rest/json/cves/2.0
"""

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ── NVD API ────────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ── In-memory caches ───────────────────────────────────────────────────────
_nvd_cache: Dict[str, List[dict]] = {}
_METADATA_CACHE: Optional[dict] = None


# ── Metadata loader ────────────────────────────────────────────────────────
def load_metadata() -> dict:
    """
    Load vulnerability metadata from
    data/web_vulnerability_metadata.json.

    Result is cached after first load.
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

    with open(
        metadata_file,
        "r",
        encoding="utf-8",
    ) as f:
        _METADATA_CACHE = json.load(f)

    return _METADATA_CACHE


# ── NVD enrichment ─────────────────────────────────────────────────────────
def fetch_nvd_cves(
    cwe_id: str,
    max_results: int = 3,
) -> List[dict]:
    """
    Query the NVD API for recent CVEs associated with a CWE.

    CVSS preference:
        v4.0 -> v3.1 -> v3.0 -> v2.0

    Returns dictionaries containing:
        cve_id
        cvss
        cvss_version
        cvss_source
        description

    Returns an empty list if NVD is unavailable or rate-limited.

    Example endpoint:
        GET /rest/json/cves/2.0
            ?cweId=CWE-89
            &resultsPerPage=3
    """

    if cwe_id in _nvd_cache:
        return _nvd_cache[cwe_id]

    try:
        url = (
            f"{NVD_API_BASE}"
            f"?cweId={cwe_id}"
            f"&resultsPerPage={max_results}"
        )

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "RedTeamFramework/2.0"
            },
        )

        with urllib.request.urlopen(
            req,
            timeout=5,
        ) as r:
            data = json.loads(
                r.read()
            )

        results = []

        for item in data.get(
            "vulnerabilities",
            [],
        ):

            cve = item.get(
                "cve",
                {},
            )

            cve_id = cve.get(
                "id",
                "",
            )

            # ── English description ────────────────────────────────────
            desc = ""

            for d in cve.get(
                "descriptions",
                [],
            ):
                if d.get("lang") == "en":
                    desc = d.get(
                        "value",
                        "",
                    )[:120]
                    break

            # ── CVSS selection ─────────────────────────────────────────
            # Prefer newest available version:
            # v4.0 -> v3.1 -> v3.0 -> v2.0

            cvss_score = 0.0
            cvss_version = None

            metrics = cve.get(
                "metrics",
                {},
            )

            version_keys = (
                ("cvssMetricV40", "4.0"),
                ("cvssMetricV31", "3.1"),
                ("cvssMetricV30", "3.0"),
                ("cvssMetricV2", "2.0"),
            )

            for key, version in version_keys:

                entries = metrics.get(
                    key,
                    [],
                )

                for metric in entries:

                    cvss_data = metric.get(
                        "cvssData",
                        {},
                    )

                    score = cvss_data.get(
                        "baseScore"
                    )

                    if score is None:
                        continue

                    try:
                        cvss_score = float(
                            score
                        )

                    except (
                        TypeError,
                        ValueError,
                    ):
                        continue

                    cvss_version = version
                    break

                if cvss_score:
                    break

            # ── Build NVD CVE record ───────────────────────────────────
            if cve_id:

                results.append(
                    {
                        "cve_id": cve_id,
                        "cvss": cvss_score,
                        "cvss_version": cvss_version,
                        "cvss_source": "NVD",
                        "description": desc,
                    }
                )

        _nvd_cache[
            cwe_id
        ] = results

        return results

    except Exception:

        _nvd_cache[
            cwe_id
        ] = []

        return []


# ── WebFinding dataclass ───────────────────────────────────────────────────
@dataclass
class WebFinding:
    """
    Single OWASP finding produced by any checker.

    Mirrors the dictionary structure used by
    VulnCorrelator and ThreatScore.
    """

    check_type: str
    owasp_id: str
    owasp_name: str
    mitre_technique: str
    risk_level: str
    cvss_base: float
    confidence: float
    title: str

    cwe_id: str = ""

    nvd_cves: List[dict] = field(
        default_factory=list
    )

    evidence: List[str] = field(
        default_factory=list
    )

    affected_params: List[str] = field(
        default_factory=list
    )

    remediation: str = ""

    host: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "check_type":
                self.check_type,

            "owasp_id":
                self.owasp_id,

            "owasp_name":
                self.owasp_name,

            "mitre_technique":
                self.mitre_technique,

            "risk_level":
                self.risk_level,

            "cvss_base":
                self.cvss_base,

            "confidence":
                self.confidence,

            "title":
                self.title,

            "cwe_id":
                self.cwe_id,

            "nvd_cves":
                self.nvd_cves,

            "evidence":
                self.evidence,

            "affected_params":
                self.affected_params,

            "remediation":
                self.remediation,

            "host":
                self.host,

            "port":
                self.port,

            "service":
                self.service,
        }


# ── Factory ────────────────────────────────────────────────────────────────
def build_finding(
    check_type: str,
    title: str,
    evidence: List[str],
    confidence: float,
    host: str = None,
    port: int = None,
    service: str = None,
    affected_params: List[str] = None,
    remediation: str = "",
    enrich_nvd: bool = True,
) -> WebFinding:
    """
    Factory that enriches a finding with OWASP, MITRE,
    CVSS, and CWE metadata loaded from:

        data/web_vulnerability_metadata.json

    If enrich_nvd=True, live CVE references are also
    retrieved from NVD.

    The finding's primary cvss_base remains the value
    defined by the web vulnerability metadata because
    this score describes the detected finding itself.

    NVD CVSS values are kept separately under nvd_cves
    as supporting vulnerability references.
    """

    metadata = load_metadata()

    meta = metadata.get(
        check_type,
        {
            "owasp": "A05:2025",
            "owasp_name":
                "Security Misconfiguration",
            "mitre": "T1190",
            "cvss": 5.0,
            "cwe": "CWE-16",
        },
    )

    # This is the finding-level score supplied by
    # the framework metadata, not an NVD CVE score.
    cvss = float(
        meta["cvss"]
    )

    owasp = meta[
        "owasp"
    ]

    cwe = meta.get(
        "cwe",
        "",
    )

    # ── Finding risk band ─────────────────────────────────────────────────
    if cvss >= 9.0:
        risk = "CRITICAL"

    elif cvss >= 7.0:
        risk = "HIGH"

    elif cvss >= 4.0:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    # ── Live NVD enrichment ────────────────────────────────────────────────
    nvd_cves = (
        fetch_nvd_cves(cwe)
        if (
            enrich_nvd
            and cwe
        )
        else []
    )

    if nvd_cves:

        reference_evidence = []

        for cve_record in nvd_cves[:2]:

            cve_id = cve_record.get(
                "cve_id",
                "N/A",
            )

            cve_cvss = cve_record.get(
                "cvss",
                0.0,
            )

            cve_version = cve_record.get(
                "cvss_version"
            )

            if cve_version:

                reference_evidence.append(
                    f"NVD reference ({cwe}): "
                    f"{cve_id} — "
                    f"CVSS v{cve_version} "
                    f"{cve_cvss}"
                )

            else:

                reference_evidence.append(
                    f"NVD reference ({cwe}): "
                    f"{cve_id} — "
                    f"CVSS {cve_cvss}"
                )

        evidence = (
            evidence
            + reference_evidence
        )

    return WebFinding(
        check_type=check_type,

        owasp_id=owasp,

        owasp_name=meta.get(
            "owasp_name",
            "Unknown",
        ),

        mitre_technique=meta.get(
            "mitre",
            "T1190",
        ),

        risk_level=risk,

        cvss_base=cvss,

        confidence=round(
            min(
                confidence,
                1.0,
            ),
            2,
        ),

        title=title,

        cwe_id=cwe,

        nvd_cves=nvd_cves,

        evidence=evidence,

        affected_params=(
            affected_params
            or []
        ),

        remediation=remediation,

        host=host,

        port=port,

        service=service,
    )
