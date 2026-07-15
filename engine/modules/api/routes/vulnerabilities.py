"""
api/routes/vulnerabilities.py — Vulnerability Intelligence API
يقرأ من DB بدل DEMO_VULNS.
"""

from fastapi import APIRouter, HTTPException, Query
from engine.modules.api.schemas import VulnOut, VulnListResponse
from engine.database.repository import get_all_sessions, get_vulns_by_session

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


def _get_latest_vulns() -> list[dict]:
    sessions = get_all_sessions()
    if not sessions:
        return []
    return get_vulns_by_session(sessions[0]["id"])


def _to_vuln_out(v: dict) -> VulnOut:
    intel = v.get("intel", {})
    return VulnOut(
        host       = v.get("host", ""),
        port       = int(v.get("port", 0)),
        service    = v.get("service", ""),
        cve        = v.get("cve", ""),
        severity   = v.get("severity", "low"),
        cvss       = float(v.get("cvss_live", v.get("cvss", 0.0))),
        risk_score = float(v.get("risk_score", 0.0)),
        exploit    = v.get("exploit", ""),
        title      = v.get("title", v.get("vulnerability", "")),
        intel      = {
            "epss": float(v.get("epss", intel.get("epss", 0.0))),
            "kev":  bool(v.get("in_kev", intel.get("kev", False))),
        },
    )


@router.get("/", response_model=VulnListResponse)
async def list_vulnerabilities(
    severity: str | None = Query(None, description="Filter: critical|high|medium|low"),
    min_cvss: float      = Query(0.0,  description="Minimum CVSS score"),
):
    vulns = _get_latest_vulns()
    if not vulns:
        raise HTTPException(
            status_code=404,
            detail="No vulnerabilities in DB yet. Run a scan first.",
        )

    filtered = [
        v for v in vulns
        if (severity is None or v.get("severity") == severity)
        and float(v.get("cvss_live", v.get("cvss", 0.0))) >= min_cvss
    ]

    return VulnListResponse(
        total           = len(filtered),
        critical_count  = sum(1 for v in filtered if v.get("severity") == "critical"),
        high_count      = sum(1 for v in filtered if v.get("severity") == "high"),
        vulnerabilities = [_to_vuln_out(v) for v in filtered],
    )


@router.get("/critical", response_model=VulnListResponse)
async def critical_vulnerabilities():
    vulns = [v for v in _get_latest_vulns() if v.get("severity") == "critical"]
    return VulnListResponse(
        total=len(vulns), critical_count=len(vulns), high_count=0,
        vulnerabilities=[_to_vuln_out(v) for v in vulns],
    )


@router.get("/kev", response_model=VulnListResponse)
async def kev_vulnerabilities():
    vulns = _get_latest_vulns()
    kevs  = [
        v for v in vulns
        if v.get("in_kev") or v.get("intel", {}).get("kev")
    ]
    return VulnListResponse(
        total=len(kevs), critical_count=len(kevs), high_count=0,
        vulnerabilities=[_to_vuln_out(v) for v in kevs],
    )


@router.get("/{cve_id}", response_model=VulnOut)
async def get_by_cve(cve_id: str):
    from fastapi import HTTPException
    vulns = _get_latest_vulns()
    for v in vulns:
        if v.get("cve", "").lower() == cve_id.lower():
            return _to_vuln_out(v)
    raise HTTPException(status_code=404, detail="CVE not found")
