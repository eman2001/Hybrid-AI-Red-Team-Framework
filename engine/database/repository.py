"""
database/repository.py
-----------------------
Real SQLAlchemy repository.
يحل محل الـ dummy stubs — كل save_* تكتب فعلاً في الـ DB.
نفس الـ signatures القديمة حتى لا يتكسر main.py.
"""

import json
import os
from datetime import datetime

from engine.config.database import SessionLocal
from engine.database.models import (
    ScanSession, Vulnerability, ExploitResult, MitreFinding, Report,
)


def _db():
    return SessionLocal()


def save_session(session_id: str, target: str,
                 lhost: str, live_hosts: list) -> int:
    db = _db()
    try:
        row = ScanSession(
            session_id = session_id,
            target     = target,
            lhost      = lhost or "",
            live_hosts = json.dumps(live_hosts or []),
            status     = "running",
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        print(f"[DB] save_session → id={row.id}  session={session_id}")
        return row.id
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_session: {exc}")
        return -1
    finally:
        db.close()


def update_session_status(session_id: str,
                          status: str,
                          risk_score: float = 0.0) -> None:
    db = _db()
    try:
        row = (db.query(ScanSession)
                 .filter(ScanSession.session_id == session_id)
                 .first())
        if row:
            row.status     = status
            row.risk_score = risk_score
            row.updated_at = datetime.utcnow()
            db.commit()
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] update_session_status: {exc}")
    finally:
        db.close()


def save_vulnerabilities(db_id: int, vuln_findings: list) -> None:
    if not vuln_findings:
        return
    db = _db()
    try:
        rows = []
        for v in vuln_findings:
            intel = v.get("intel", {})
            rows.append(Vulnerability(
                session_id = db_id,
                host       = v.get("host", ""),
                port       = int(v.get("port", 0)),
                service    = v.get("service", ""),
                cve        = v.get("cve", ""),
                severity   = v.get("severity", "low"),
                cvss       = float(v.get("cvss_live", v.get("cvss", 0.0))),
                risk_score = float(v.get("risk_score", 0.0)),
                exploit    = v.get("exploit", ""),
                title      = v.get("title", v.get("vulnerability", "")),
                intel      = _safe(v.get("intel", {})),
            ))
        db.bulk_save_objects(rows)
        db.commit()
        print(f"[DB] save_vulnerabilities → {len(rows)} rows  session_id={db_id}")
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_vulnerabilities: {exc}")
    finally:
        db.close()


def _safe(v):
    """Convert numpy/int64 to native Python types for JSON."""
    import numpy as np
    if isinstance(v, (np.integer,)): return int(v)
    if isinstance(v, (np.floating,)): return float(v)
    if isinstance(v, dict): return {k: _safe(val) for k, val in v.items()}
    if isinstance(v, list): return [_safe(i) for i in v]
    return v

def save_exploit_results(db_id: int, exploit_results: list) -> None:
    if not exploit_results:
        return
    db = _db()
    try:
        rows = []
        for r in exploit_results:
            rows.append(ExploitResult(
                session_id = db_id,
                host       = r.get("host", ""),
                port       = int(r.get("port", 0)),
                exploit    = r.get("exploit", r.get("module", "")),
                success    = bool(r.get("success", False)),
                score      = float(r.get("selection_score", 0.0)),
                details    = _safe(r.get("details", {})),
            ))
        db.bulk_save_objects(rows)
        db.commit()
        print(f"[DB] save_exploit_results → {len(rows)} rows  session_id={db_id}")
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_exploit_results: {exc}")
    finally:
        db.close()


def save_mitre_findings(db_id: int, mapped_results: list) -> None:
    if not mapped_results:
        return
    db = _db()
    try:
        rows = []
        for m in mapped_results:
            primary = m.get("mitre") or m.get("primary") or {}
            if not primary:
                continue
            rows.append(MitreFinding(
                session_id     = db_id,
                host           = m.get("host", ""),
                technique_id   = primary.get("technique_id", ""),
                technique_name = primary.get("technique_name", ""),
                tactic         = primary.get("tactic", ""),
                confidence     = float(primary.get("confidence", 0.0)),
                source         = primary.get("source", ""),
            ))
        db.bulk_save_objects(rows)
        db.commit()
        print(f"[DB] save_mitre_findings → {len(rows)} rows  session_id={db_id}")
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_mitre_findings: {exc}")
    finally:
        db.close()


def save_report(db_id: int, report_file: str, format_type: str) -> None:
    db = _db()
    try:
        size = 0
        if report_file and os.path.exists(report_file):
            size = os.path.getsize(report_file)
        row = Report(
            session_id  = db_id,
            file_path   = report_file or "",
            report_type = format_type or "json",
        )
        db.add(row)
        db.commit()
        print(f"[DB] save_report → {report_file} ({format_type})  session_id={db_id}")
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_report: {exc}")
    finally:
        db.close()


def get_all_sessions() -> list[dict]:
    db = _db()
    try:
        rows = (db.query(ScanSession)
                  .order_by(ScanSession.created_at.desc())
                  .all())
        return [
            {
                "id":         r.id,
                "session_id": r.session_id,
                "target":     r.target,
                "lhost":      r.lhost,
                "live_hosts": r.live_hosts or [],
                "status":     r.status,
                "risk_score": r.risk_score,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    finally:
        db.close()


def get_session_by_id(session_id: str) -> dict | None:
    db = _db()
    try:
        row = (db.query(ScanSession)
                 .filter(ScanSession.session_id == session_id)
                 .first())
        if not row:
            return None
        return {
            "id":         row.id,
            "session_id": row.session_id,
            "target":     row.target,
            "lhost":      row.lhost,
            "live_hosts": row.live_hosts_list(),
            "status":     row.status,
            "risk_score": row.risk_score,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
    finally:
        db.close()


def get_vulns_by_session(db_id: int) -> list[dict]:
    db = _db()
    try:
        rows = (db.query(Vulnerability)
                  .filter(Vulnerability.session_id == db_id)
                  .all())
        return [{
            "host": r.host, "port": r.port, "service": r.service,
            "cve": r.cve, "cvss": r.cvss, "severity": r.severity,
            "risk_score": r.risk_score, "title": r.title,
            "exploit": r.exploit, "intel": r.intel or {},
        } for r in rows]
    finally:
        db.close()


def get_mitre_by_session(db_id: int) -> list[dict]:
    db = _db()
    try:
        rows = (db.query(MitreFinding)
                  .filter(MitreFinding.session_id == db_id)
                  .all())
        return [
            {
                "technique_id":   r.technique_id,
                "technique_name": r.technique_name,
                "tactic":         r.tactic,
                "confidence":     r.confidence,
                "source":         r.source,
                "fused_score":    getattr(r, "fused_score", None),
                "host":           r.host,
            }
            for r in rows
        ]
    finally:
        db.close()


def get_exploits_by_session(db_id: int) -> list[dict]:
    db = _db()
    try:
        rows = (db.query(ExploitResult)
                  .filter(ExploitResult.session_id == db_id)
                  .all())
        return [{
            "host": r.host, "port": r.port,
            "exploit": r.exploit, "success": r.success,
            "score": r.score, "details": r.details or {},
        } for r in rows]
    finally:
        db.close()


def get_latest_session() -> dict | None:
    db = _db()
    try:
        row = (db.query(ScanSession)
                 .order_by(ScanSession.created_at.desc())
                 .first())
        if not row:
            return None
        return {
            "id":         row.id,
            "session_id": row.session_id,
            "target":     row.target,
            "status":     row.status,
            "risk_score": row.risk_score,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
    finally:
        db.close()
        
