"""
api/routes/scan.py
Hybrid AI Red Team Scan API
Runs full pipeline with progress tracking.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException

from engine.modules.api.schemas import ScanRequest

from engine.main import run_pipeline

from backend.core.progress import (
    update,
    finish
)

from engine.database.repository import (
    save_session,
    update_session_status,
    get_all_sessions,
    get_session_by_id,
)


router = APIRouter(
    prefix="/api/scan",
    tags=["Scan"]
)



# ==========================================
# Background Pipeline Runner
# ==========================================

def execute_scan(
    session_id,
    target,
    lhost
):

 

    try:
   

        # البداية
        update(
            0,
            "Starting Scan",
            0
        )


        # تشغيل الـ Hybrid AI Pipeline
        result = run_pipeline(
            target,
            lhost
        )


        # انتهاء الفحص
        finish()


        update_session_status(
            session_id,
            "completed",
            100
        )


        return result



    except Exception as e:


        update(
            0,
            f"Failed: {str(e)}",
            0
        )


        update_session_status(
            session_id,
            "failed",
            0
        )



# ==========================================
# Start Scan
# ==========================================


@router.post("/run")
async def run_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks
):

    session_id = (
        f"SIM-{uuid.uuid4().hex[:6].upper()}"
    )


    timestamp = datetime.now().isoformat()



    # حفظ Session فارغة قبل بدء الفحص

    save_session(
        session_id,
        req.target,
        req.lhost,
        []
    )



    update_session_status(
        session_id,
        "running",
        0
    )



    # تشغيل الفحص بالخلفية

    background_tasks.add_task(
        execute_scan,
        session_id,
        req.target,
        req.lhost
    )



    return {

        "status": "running",

        "session_id": session_id,

        "target": req.target,

        "timestamp": timestamp

    }




# ==========================================
# Sessions
# ==========================================


@router.get("/sessions")
def sessions():

    data = get_all_sessions()


    return {

        "sessions": data,

        "count": len(data)

    }





@router.get("/sessions/{session_id}")
def session(
    session_id: str
):

    result = get_session_by_id(
        session_id
    )


    if not result:

        raise HTTPException(
            status_code=404,
            detail="Session not found"
        )


    return result
