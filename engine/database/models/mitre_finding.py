from sqlalchemy import Column, String, Integer, Float, DateTime, JSON
from sqlalchemy.sql import func
from engine.config.database import Base

class MitreFinding(Base):
    __tablename__ = "mitre_findings"
    id             = Column(Integer, primary_key=True, index=True)
    session_id     = Column(String, index=True)
    technique_id   = Column(String)
    technique_name = Column(String)
    tactic         = Column(String)
    confidence     = Column(Float)
    source         = Column(String)
    host           = Column(String)
    created_at     = Column(DateTime, server_default=func.now())
