from sqlalchemy import Column, String, Integer, DateTime, Float, JSON
from sqlalchemy.sql import func
from engine.config.database import Base

class ScanSession(Base):
    __tablename__ = "scan_sessions"
    id         = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    target     = Column(String)
    lhost      = Column(String, default="")
    live_hosts = Column(JSON, default=[])
    status     = Column(String, default="running")
    risk_score = Column(Float, default=0.0)
    result     = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
