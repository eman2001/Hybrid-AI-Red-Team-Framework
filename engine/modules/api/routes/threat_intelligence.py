"""
api/routes/threat_intelligence.py — Threat Intelligence API
"""
from fastapi import APIRouter, HTTPException, Query
from engine.modules.api.schemas import ThreatIntelOut, ThreatSummaryResponse
from engine.modules.threat_intelligence.epss_engine import EpssEngine
from engine.modules.threat_intelligence.kev_engine  import KevEngine
from engine.modules.threat_intelligence.threat_score import ThreatScore

router = APIRouter(prefix="/api/threat-intelligence", tags=["Threat Intelligence"])

_epss   = EpssEngine()
_kev    = KevEngine()
_scorer = ThreatScore()

# Pre-computed demo findings (in production: pulled from DB after scan)
DEMO_FINDINGS = [
    {"cve":"CVE-2011-2523","cvss":10.0,"service":"ftp",   "vendor":"vsftpd project","product":"vsftpd","severity":"critical"},
    {"cve":"CVE-2007-2447","cvss":9.3, "service":"smb",   "vendor":"samba",         "product":"samba", "severity":"critical"},
    {"cve":"CVE-2017-0144","cvss":9.8, "service":"smb",   "vendor":"microsoft",     "product":"windows smb","severity":"critical"},
    {"cve":"CVE-2010-2075","cvss":9.8, "service":"irc",   "vendor":"unrealircd",    "product":"unrealircd","severity":"critical"},
    {"cve":"CVE-2008-0166","cvss":7.8, "service":"ssh",   "vendor":"debian",        "product":"openssl","severity":"high"},
    {"cve":"CVE-2009-2446","cvss":8.5, "service":"mysql", "vendor":"oracle",        "product":"mysql", "severity":"high"},
]


def _enrich(f: dict) -> ThreatIntelOut:
    cve   = f["cve"]
    epss  = _epss.score(cve)
    in_kev= _kev.is_kev(cve)
    f2    = {**f, "epss": epss, "in_kev": in_kev}
    score = _scorer.calculate(f2)
    tier  = _scorer.label(score)
    return ThreatIntelOut(
        cve       = cve,
        cvss      = f["cvss"],
        epss      = epss,
        kev       = in_kev,
        vendor    = f.get("vendor",""),
        product   = f.get("product",""),
        severity  = f.get("severity",""),
        score     = score,
        risk_tier = tier.lower(),
        priority  = "patch_immediately" if score >= 80 else ("patch_within_week" if score >= 50 else "monitor"),
    )


@router.get("/", response_model=ThreatSummaryResponse)
async def get_threat_intel():
    """Full threat intelligence enrichment for all findings."""
    enriched = [_enrich(f) for f in DEMO_FINDINGS]
    return ThreatSummaryResponse(
        total         = len(enriched),
        kev_count     = sum(1 for e in enriched if e.kev),
        ransomware    = 3,   # from KEV catalog
        imminent_epss = sum(1 for e in enriched if e.epss >= 0.9),
        avg_cvss      = round(sum(e.cvss for e in enriched) / len(enriched), 2),
        avg_epss      = round(sum(e.epss for e in enriched) / len(enriched), 3),
        findings      = enriched,
    )


@router.get("/kev", response_model=list[ThreatIntelOut])
async def kev_findings():
    """Return only KEV-confirmed findings — highest priority."""
    return [_enrich(f) for f in DEMO_FINDINGS if _kev.is_kev(f["cve"])]


@router.get("/epss/top", response_model=list[ThreatIntelOut])
async def top_epss(limit: int = Query(5, ge=1, le=20)):
    """Top N findings by EPSS exploitation probability."""
    enriched = sorted([_enrich(f) for f in DEMO_FINDINGS], key=lambda x: x.epss, reverse=True)
    return enriched[:limit]


@router.get("/{cve_id}", response_model=ThreatIntelOut)
async def get_cve_intel(cve_id: str):
    """Full threat intelligence for a specific CVE."""
    for f in DEMO_FINDINGS:
        if f["cve"].lower() == cve_id.lower():
            return _enrich(f)
    # Return estimated intel even for unknown CVEs
    estimated = {"cve": cve_id.upper(), "cvss": 7.5, "service": "unknown",
                 "vendor": "unknown", "product": "unknown", "severity": "high"}
    return _enrich(estimated)
