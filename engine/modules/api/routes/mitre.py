"""
api/routes/mitre.py — MITRE ATT&CK API
يقرأ من DB بدل DEMO_TECHNIQUES.
"""

from fastapi import APIRouter, HTTPException, Query
from engine.modules.api.schemas import (
    MitreResponse, TechniqueOut, TacticDistOut,
    HeatmapResponse, HeatmapTechniqueOut,
)
from engine.database.repository import get_all_sessions, get_mitre_by_session

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])

COLOR_MAP = {
    "rule_exact":   "#e03d3d",
    "rule_service": "#e07d00",
    "post_exploit": "#34d399",
    "stix":         "#c0882a",
    "ml":           "#3b82f6",
    "default":      "#6b7280",
}
SCORE_MAP = {
    "rule_exact": 100, "rule_service": 80,
    "post_exploit": 95, "stix": 65, "ml": 55,
}


def _get_latest_techniques() -> list[dict]:
    sessions = get_all_sessions()
    if not sessions:
        return []
    return get_mitre_by_session(sessions[0]["id"])


@router.get("/techniques", response_model=MitreResponse)
async def list_techniques():
    techniques = _get_latest_techniques()

    if not techniques:
        raise HTTPException(
            status_code=404,
            detail="No MITRE findings in DB yet. Run a scan first.",
        )

    techs = [TechniqueOut(**t) for t in techniques]

    by_tactic: dict[str, list] = {}
    for t in techniques:
        tac = t.get("tactic", "unknown")
        by_tactic.setdefault(tac, [])
        by_tactic[tac].append(t["technique_id"])

    dist = [
        TacticDistOut(tactic=tac, count=len(ids), techniques=ids)
        for tac, ids in by_tactic.items()
    ]

    return MitreResponse(
        total_techniques    = len(techs),
        tactics_covered     = len(by_tactic),
        techniques          = techs,
        tactic_distribution = dist,
    )


@router.get("/tactics")
async def list_tactics():
    techniques = _get_latest_techniques()
    by_tactic: dict[str, int] = {}
    for t in techniques:
        tac = t.get("tactic", "unknown")
        by_tactic[tac] = by_tactic.get(tac, 0) + 1
    return {"tactic_distribution": by_tactic, "total_tactics": len(by_tactic)}


@router.get("/heatmap", response_model=HeatmapResponse)
async def get_heatmap():
    techniques = _get_latest_techniques()

    heatmap_techs = [
        HeatmapTechniqueOut(
            techniqueID = t["technique_id"],
            score       = SCORE_MAP.get(t.get("source", ""), 50),
            color       = COLOR_MAP.get(t.get("source", ""), COLOR_MAP["default"]),
            comment     = (
                f"Source: {t.get('source','')} | "
                f"Confidence: {int(t.get('confidence', 0) * 100)}%"
            ),
        )
        for t in techniques
    ]

    return HeatmapResponse(
        name       = "Red Team AI — ATT&CK Layer",
        domain     = "enterprise-attack",
        techniques = heatmap_techs,
        legend     = [
            {"label": "Rule-based (0.85–0.95)",    "color": "#e03d3d"},
            {"label": "STIX semantic (0.60–0.75)", "color": "#c0882a"},
            {"label": "ML classifier (0.50–0.70)", "color": "#3b82f6"},
            {"label": "Post-exploitation",          "color": "#34d399"},
        ],
    )


@router.get("/chain")
async def get_chain():
    techniques = _get_latest_techniques()
    if not techniques:
        raise HTTPException(status_code=404, detail="No MITRE data. Run a scan first.")

    from engine.modules.mitre.chain_builder import ChainBuilder
    builder     = ChainBuilder()
    fake_mapped = [{"host": t.get("host", ""), "layers": [t], "mitre": t}
                   for t in techniques]
    chain = builder.build(fake_mapped)
