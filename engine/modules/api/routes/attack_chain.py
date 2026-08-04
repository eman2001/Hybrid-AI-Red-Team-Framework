"""
api/routes/attack_chain.py
--------------------------
Serves the real attack chain from the latest completed
assessment report.
"""

from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    HTTPException,
)

from engine.modules.api.current_report import (
    load_latest_report,
)

from engine.modules.api.schemas import (
    AttackChainResponse,
    ChainPhaseOut,
)


router = APIRouter(
    prefix="/api/attack-chain",
    tags=["Attack Chain"],
)


def _load_chain() -> dict:
    report = load_latest_report()

    chain = report.get(
        "attack_chain",
        {}
    )

    if not isinstance(chain, dict):
        return {}

    return chain


def _normalize_phase(
    phase: dict,
) -> dict:
    raw_techniques = phase.get(
        "techniques",
        []
    )

    techniques = []

    if isinstance(
        raw_techniques,
        list
    ):
        for technique in raw_techniques:
            if isinstance(
                technique,
                str
            ):
                techniques.append({
                    "id": technique,
                    "name": "",
                })

            elif isinstance(
                technique,
                dict
            ):
                techniques.append({
                    "id": (
                        technique.get("id")
                        or
                        technique.get(
                            "technique_id"
                        )
                        or
                        technique.get(
                            "techniqueID"
                        )
                        or
                        "N/A"
                    ),
                    "name": (
                        technique.get("name")
                        or
                        technique.get(
                            "technique_name"
                        )
                        or
                        ""
                    ),
                })

    hosts = phase.get(
        "hosts",
        []
    )

    if not isinstance(hosts, list):
        hosts = [str(hosts)]

    return {
        "phase_name": (
            phase.get("phase_name")
            or
            phase.get("name")
            or
            "Unknown Phase"
        ),
        "tactic": phase.get(
            "tactic",
            "unknown"
        ),
        "techniques": techniques,
        "hosts": hosts,
        "confidence": float(
            phase.get(
                "confidence",
                0
            )
        ),
        "source": phase.get(
            "source",
            "unknown"
        ),
    }


@router.get(
    "/",
    response_model=AttackChainResponse,
)
async def get_attack_chain():
    chain = _load_chain()

    if not chain:
        raise HTTPException(
            status_code=404,
            detail=(
                "No attack chain is available. "
                "Run a scan first."
            ),
        )

    normalized = {
        str(key): _normalize_phase(value)
        for key, value in chain.items()
        if isinstance(value, dict)
    }

    if not normalized:
        raise HTTPException(
            status_code=404,
            detail="No valid attack-chain phases found.",
        )

    total_techniques = sum(
        len(
            phase["techniques"]
        )
        for phase in normalized.values()
    )

    confidence_values = [
        phase["confidence"]
        for phase in normalized.values()
    ]

    average_confidence = (
        round(
            sum(confidence_values)
            /
            len(confidence_values),
            3,
        )
        if confidence_values
        else 0.0
    )

    phases = {
        key: ChainPhaseOut(**value)
        for key, value in normalized.items()
    }

    report = load_latest_report()

    return AttackChainResponse(
        generated=report.get(
            "generated_at",
            datetime.now(
                timezone.utc
            ).isoformat(),
        ),
        phase_count=len(phases),
        tech_count=total_techniques,
        avg_confidence=average_confidence,
        phases=phases,
    )


@router.get("/phases")
async def get_phases():
    chain = _load_chain()

    normalized = {
        str(key): _normalize_phase(value)
        for key, value in chain.items()
        if isinstance(value, dict)
    }

    return {
        "phases": normalized,
        "count": len(normalized),
    }


@router.get(
    "/phases/{phase_num}"
)
async def get_phase(
    phase_num: str,
):
    chain = _load_chain()

    if phase_num not in chain:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Phase {phase_num} not found."
            ),
        )

    return _normalize_phase(
        chain[phase_num]
    )


@router.get(
    "/export/navigator"
)
async def export_navigator():
    chain = _load_chain()

    mapped_results = []

    for phase in chain.values():
        if not isinstance(
            phase,
            dict
        ):
            continue

        normalized = _normalize_phase(
            phase
        )

        for technique in normalized[
            "techniques"
        ]:
            mapped_results.append({
                "host": (
                    normalized["hosts"][0]
                    if normalized["hosts"]
                    else ""
                ),
                "layers": [{
                    "technique_id":
                        technique["id"],
                    "technique_name":
                        technique["name"],
                    "tactic":
                        normalized["tactic"],
                    "confidence":
                        normalized[
                            "confidence"
                        ],
                    "source":
                        normalized["source"],
                }],
            })

    from engine.modules.mitre.heatmap_generator import (
        HeatmapGenerator,
    )

    generator = HeatmapGenerator()

    return generator.generate(
        mapped_results
    )
