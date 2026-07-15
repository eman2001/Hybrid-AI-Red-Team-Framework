"""
api/routes/attack_chain.py — Attack Chain API
"""
from fastapi import APIRouter
from engine.modules.api.schemas import AttackChainResponse, ChainPhaseOut

router = APIRouter(prefix="/api/attack-chain", tags=["Attack Chain"])

DEMO_CHAIN = {
    "1": {"phase_name":"Initial Access",       "tactic":"initial-access",       "techniques":[{"id":"T1190","name":"Exploit Public-Facing App"},{"id":"T1566","name":"Phishing"}],     "hosts":["192.168.1.100"],"confidence":0.95,"source":"rule_exact"},
    "2": {"phase_name":"Execution",            "tactic":"execution",            "techniques":[{"id":"T1059.004","name":"Unix Shell"}],                                                 "hosts":["192.168.1.100"],"confidence":0.90,"source":"rule_exact"},
    "3": {"phase_name":"Privilege Escalation", "tactic":"privilege-escalation", "techniques":[{"id":"T1068","name":"Exploitation for Priv. Escalation"}],                             "hosts":["192.168.1.100"],"confidence":0.93,"source":"post_exploit"},
    "4": {"phase_name":"Credential Access",    "tactic":"credential-access",    "techniques":[{"id":"T1003","name":"OS Credential Dumping"},{"id":"T1110","name":"Brute Force"}],    "hosts":["192.168.1.100"],"confidence":0.91,"source":"post_exploit"},
    "5": {"phase_name":"Discovery",            "tactic":"discovery",            "techniques":[{"id":"T1082","name":"System Info Discovery"},{"id":"T1016","name":"Network Config"},{"id":"T1057","name":"Process Discovery"}],"hosts":["192.168.1.100"],"confidence":0.94,"source":"post_exploit"},
    "6": {"phase_name":"Lateral Movement",     "tactic":"lateral-movement",     "techniques":[{"id":"T1210","name":"Exploitation of Remote Services"}],                               "hosts":["192.168.1.100"],"confidence":0.88,"source":"stix"},
    "7": {"phase_name":"Exfiltration",         "tactic":"exfiltration",         "techniques":[{"id":"T1041","name":"Exfiltration Over C2"}],                                          "hosts":["192.168.1.100"],"confidence":0.60,"source":"ml"},
}


@router.get("/", response_model=AttackChainResponse)
async def get_attack_chain():
    total_techs = sum(len(p["techniques"]) for p in DEMO_CHAIN.values())
    avg_conf    = round(sum(p["confidence"] for p in DEMO_CHAIN.values()) / len(DEMO_CHAIN), 3)
    phases      = {k: ChainPhaseOut(**v) for k, v in DEMO_CHAIN.items()}
    return AttackChainResponse(
        generated      = "2026-06-05T08:00:00",
        phase_count    = len(DEMO_CHAIN),
        tech_count     = total_techs,
        avg_confidence = avg_conf,
        phases         = phases,
    )


@router.get("/phases")
async def get_phases():
    return {"phases": DEMO_CHAIN, "count": len(DEMO_CHAIN)}


@router.get("/phases/{phase_num}")
async def get_phase(phase_num: str):
    if phase_num not in DEMO_CHAIN:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Phase {phase_num} not found.")
    return DEMO_CHAIN[phase_num]


@router.get("/export/navigator")
async def export_navigator():
    """Export ATT&CK Navigator compatible layer JSON."""
    from engine.modules.mitre.heatmap_generator import HeatmapGenerator
    gen = HeatmapGenerator()
    # Build fake mapped results from chain
    fake = []
    for phase in DEMO_CHAIN.values():
        for tech in phase["techniques"]:
            fake.append({"host":"192.168.1.100","layers":[{
                "technique_id": tech["id"], "technique_name": tech["name"],
                "tactic": phase["tactic"], "confidence": phase["confidence"],
                "source": phase["source"],
            }]})
    layer = gen.generate(fake)
    return layer
