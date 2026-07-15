"""
database/models.py
-------------------
SQLAlchemy ORM models — 5 tables.
يُستورد من config/database.py عند init_db().
"""

import json
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, Float, Boolean,
    Text, DateTime, ForeignKey,
)
from engine.config.database import Base


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    target     = Column(String(256), nullable=False)
    lhost      = Column(String(64),  nullable=True, default="")
    live_hosts = Column(Text, default="[]")        # JSON list
    status     = Column(String(32),  default="running")
    risk_score = Column(Float,       default=0.0)
    created_at = Column(DateTime,    default=datetime.utcnow)
    updated_at = Column(DateTime,    default=datetime.utcnow,
                        onupdate=datetime.utcnow)

    def live_hosts_list(self) -> list:
        try:
            return json.loads(self.live_hosts or "[]")
        except Exception:
            return []


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    session_db_id = Column(Integer, ForeignKey("scan_sessions.id"),
                           nullable=False, index=True)
    host          = Column(String(64),  default="")
    port          = Column(Integer,     default=0)
    service       = Column(String(64),  default="")
    cve           = Column(String(32),  default="", index=True)
    severity      = Column(String(16),  default="low")
    cvss          = Column(Float,       default=0.0)
    risk_score    = Column(Float,       default=0.0)
    exploit_ref   = Column(String(256), default="")
    title         = Column(String(512), default="")
    epss          = Column(Float,       default=0.0)
    kev           = Column(Boolean,     default=False)
    raw_json      = Column(Text,        default="{}")
    created_at    = Column(DateTime,    default=datetime.utcnow)


class ExploitResult(Base):
    __tablename__ = "exploit_results"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    session_db_id = Column(Integer, ForeignKey("scan_sessions.id"),
                           nullable=False, index=True)
    host          = Column(String(64),  default="")
    port          = Column(Integer,     default=0)
    cve           = Column(String(32),  default="")
    module        = Column(String(256), default="")
    result        = Column(String(16),  default="FAILED")
    exploit_score = Column(Float,       default=0.0)
    payload       = Column(String(256), default="")
    exploit_path  = Column(Text,        default="[]")
    raw_json      = Column(Text,        default="{}")
    created_at    = Column(DateTime,    default=datetime.utcnow)


class MitreFinding(Base):
    __tablename__ = "mitre_findings"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    session_db_id  = Column(Integer, ForeignKey("scan_sessions.id"),
                            nullable=False, index=True)
    host           = Column(String(64),  default="")
    technique_id   = Column(String(16),  default="", index=True)
    technique_name = Column(String(256), default="")
    tactic         = Column(String(64),  default="")
    confidence     = Column(Float,       default=0.0)
    source         = Column(String(32),  default="")
    fused_score    = Column(Float,       default=0.0)
    raw_json       = Column(Text,        default="{}")
    created_at     = Column(DateTime,    default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    session_db_id = Column(Integer, ForeignKey("scan_sessions.id"),
                           nullable=False, index=True)
    report_file   = Column(String(512), default="")
    format_type   = Column(String(16),  default="json")
    size_bytes    = Column(Integer,     default=0)
