from sqlalchemy import Column, String, Integer, DateTime, JSON
from sqlalchemy.sql import func
from engine.config.database import Base

class Report(Base):
    __tablename__ = "reports"
    id         = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    report_type= Column(String)
    file_path  = Column(String, nullable=True)
    summary    = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
