from fastapi import FastAPI

from backend.schemas.requests import ScanRequest
from backend.schemas.responses import ScanResponse

from backend.services.scan_service import start_scan
from backend.storage.sessions import get_session
from backend.services.report_service import generate_report

from engine.modules.api.routes.vulnerabilities import router as vuln_router
from engine.modules.api.routes.mitre import router as mitre_router
from engine.modules.api.routes.attack_chain import router as chain_router

from engine.config.database import init_db

app = FastAPI(
    title="Hybrid AI Penetration Testing",
    version="1.0"
)


@app.on_event("startup")
def startup_event():
    init_db()

app.include_router(vuln_router)
app.include_router(mitre_router)
app.include_router(chain_router)


# اختبار أن الـ API يعمل
@app.get("/")
def home():
    return {
        "message": "API is running"
    }



# تشغيل الفحص
@app.post("/scan", response_model=ScanResponse)
def start_scan_endpoint(request: ScanRequest):

    result = start_scan(
        request.target,
        request.lhost
    )

    return result



# جلب نتائج Session
@app.get("/scan/{session_id}")
def get_scan_result(session_id: str):

    result = get_session(session_id)

    if not result:
        return {
            "error": "Session not found"
        }

    return result



# تقرير الفحص
@app.get("/report/{session_id}")
def get_report(session_id: str):

    return generate_report(session_id)
