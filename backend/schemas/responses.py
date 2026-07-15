from pydantic import BaseModel


class ScanResponse(BaseModel):
    session_id: str
    target: str
    timestamp: str
    status: str
