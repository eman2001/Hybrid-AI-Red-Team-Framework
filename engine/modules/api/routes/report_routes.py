"""
engine/api/routes/report_routes.py
------------------------------------
Serves generated reports (PDF/JSON) to the frontend.

Reports are saved by ReportGenerator under:
    reports/{session_id}/attack_report_{timestamp}.pdf
    reports/{session_id}/attack_report_{timestamp}.json

This router does NOT generate reports — it only serves files that the
pipeline (main.py / run_pipeline) has already produced.
"""

import glob
import json
import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from engine.modules.api.current_report import (
    get_latest_session_id,
)
router = APIRouter(prefix="/api/report", tags=["Reports"])

REPORTS_DIR = "reports"


def _report_session_dirs():
    """All session folders under reports/, newest first."""
    if not os.path.isdir(REPORTS_DIR):
        return []
    dirs = [
        d for d in os.listdir(REPORTS_DIR)
        if os.path.isdir(os.path.join(REPORTS_DIR, d))
    ]
    dirs.sort(
        key=lambda d: os.path.getmtime(os.path.join(REPORTS_DIR, d)),
        reverse=True,
    )
    return dirs


def _latest_file(session_id: str, ext: str):
    """Newest file with the given extension inside a session folder."""
    # os.path.basename strips any '../' path traversal attempts
    safe_id = os.path.basename(session_id)
    pattern = os.path.join(REPORTS_DIR, safe_id, f"*.{ext}")
    matches = glob.glob(pattern)
    if not matches:
        return None
    matches.sort(key=os.path.getmtime, reverse=True)
    return matches[0]


# ----------------------------------------------------------------------
# GET /api/report/list  -> all past report sessions
# ----------------------------------------------------------------------
@router.get("/list")
async def list_reports():
    sessions = []
    for session_id in _report_session_dirs():
        pdf_path = _latest_file(session_id, "pdf")
        json_path = _latest_file(session_id, "json")
        sessions.append({
            "session_id": session_id,
            "has_pdf": pdf_path is not None,
            "has_json": json_path is not None,
            "generated_at": os.path.getmtime(os.path.join(REPORTS_DIR, session_id)),
        })
    return sessions


# ----------------------------------------------------------------------
# GET /api/report/latest -> id of the most recent session
# ----------------------------------------------------------------------
@router.get("/latest")
async def latest_report():
    session_id = get_latest_session_id()

    if not session_id:
        raise HTTPException(
            status_code=404,
            detail="No completed report found yet",
        )

    return {
        "session_id": session_id
    }

# ----------------------------------------------------------------------
# GET /api/report/{session_id}/pdf -> streams the PDF file
# ----------------------------------------------------------------------
@router.get("/{session_id}/pdf")
async def get_report_pdf(session_id: str):
    pdf_path = _latest_file(session_id, "pdf")
    if not pdf_path or not os.path.isfile(pdf_path):
        raise HTTPException(status_code=404, detail="PDF report not found")

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(pdf_path),
    )


# ----------------------------------------------------------------------
# GET /api/report/{session_id}/json -> raw JSON report data
# ----------------------------------------------------------------------
@router.get("/{session_id}/json")
async def get_report_json(session_id: str):
    json_path = _latest_file(session_id, "json")
    if not json_path or not os.path.isfile(json_path):
        raise HTTPException(status_code=404, detail="JSON report not found")

    with open(json_path, encoding="utf-8") as f:
        return JSONResponse(json.load(f))
