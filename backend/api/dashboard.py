from fastapi import APIRouter
from backend.core.progress import get_progress
from engine.database.repository import (
    get_latest_session,
    get_vulns_by_session,
    get_mitre_by_session,
)


router = APIRouter(
    prefix="/api",
    tags=["Dashboard"]
)


# =========================
# Vulnerabilities
# =========================

@router.get("/vulnerabilities/")
def vulnerabilities():

    session = get_latest_session()

    if not session:
        return {
            "vulnerabilities": []
        }


    vulns = get_vulns_by_session(
        session["id"]
    )


    return {
        "vulnerabilities": vulns
    }



# =========================
# MITRE ATT&CK
# =========================

@router.get("/mitre/techniques")
def mitre():

    session = get_latest_session()

    if not session:
        return {
            "techniques": []
        }


    techniques = get_mitre_by_session(
        session["id"]
    )


    return {
        "techniques": techniques
    }



# =========================
# Attack Chain
# =========================

@router.get("/attack-chain/")
def chain():

    session = get_latest_session()


    if not session:
        return {
            "phases": [],
            "phase_count": 0
        }


    # حاليا attack_chain غير محفوظ في DB
    # سيتم ربطه لاحقا مع جدول attack_chain

    return {
        "phases": [],
        "phase_count": 0
    }

@router.get("/progress")
def progress():

    return get_progress()
