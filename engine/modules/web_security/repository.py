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


# ── helper ────────────────────────────────────────────────────────────────

def _db():
    return SessionLocal()


# ══════════════════════════════════════════════════════════════════════════
# Write functions  (نفس الـ signatures القديمة)
# ══════════════════════════════════════════════════════════════════════════

def save_session(session_id: str, target: str,
                 lhost: str, live_hosts: list) -> int:
    """يحفظ جلسة scan جديدة ويرجع الـ DB id."""
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
    """يحدّث status ورقم الخطر بعد انتهاء الـ pipeline."""
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
    """يحفظ قائمة الـ vulnerabilities مرتبطة بجلسة."""
    if not vuln_findings:
        return
    db = _db()
    try:
        rows = []
        for v in vuln_findings:
            intel = v.get("intel", {})
            rows.append(Vulnerability(
                session_db_id = db_id,
                host          = v.get("host", ""),
                port          = int(v.get("port", 0)),
                service       = v.get("service", ""),
                cve           = v.get("cve", ""),
                severity      = v.get("severity", "low"),
                cvss          = float(v.get("cvss_live", v.get("cvss", 0.0))),
                risk_score    = float(v.get("risk_score", 0.0)),
                exploit_ref   = v.get("exploit", ""),
                title         = v.get("title", v.get("vulnerability", "")),
                epss          = float(v.get("epss", intel.get("epss", 0.0))),
                kev           = bool(v.get("in_kev", intel.get("kev", False))),
                raw_json      = json.dumps(v),
            ))
        db.bulk_save_objects(rows)
        db.commit()
        print(f"[DB] save_vulnerabilities → {len(rows)} rows  session_db_id={db_id}")
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_vulnerabilities: {exc}")
    finally:
        db.close()


def save_exploit_results(db_id: int, exploit_results: list) -> None:
    """يحفظ نتائج الاستغلال."""
    if not exploit_results:
        return
    db = _db()
    try:
        rows = []
        for r in exploit_results:
            rows.append(ExploitResult(
                session_db_id = db_id,
                host          = r.get("host", ""),
                port          = int(r.get("port", 0)),
                cve           = r.get("cve", ""),
                module        = r.get("exploit", r.get("module", "")),
                result        = "SUCCESS" if r.get("success") else "FAILED",
                exploit_score = float(r.get("exploit_score",
                                            r.get("selection_score", 0.0))),
                payload       = r.get("payload", ""),
                exploit_path  = json.dumps(r.get("exploit_path", [])),
                raw_json      = json.dumps(r),
            ))
        db.bulk_save_objects(rows)
        db.commit()
        print(f"[DB] save_exploit_results → {len(rows)} rows  session_db_id={db_id}")
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_exploit_results: {exc}")
    finally:
        db.close()


def save_mitre_findings(db_id: int, mapped_results: list) -> None:
    """يحفظ نتائج MITRE ATT&CK mapping."""
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
                session_db_id  = db_id,
                host           = m.get("host", ""),
                technique_id   = primary.get("technique_id", ""),
                technique_name = primary.get("technique_name", ""),
                tactic         = primary.get("tactic", ""),
                confidence     = float(primary.get("confidence", 0.0)),
                source         = primary.get("source", ""),
                fused_score    = float(primary.get("fused_score", 0.0)),
                raw_json       = json.dumps(m),
            ))
        db.bulk_save_objects(rows)
        db.commit()
        print(f"[DB] save_mitre_findings → {len(rows)} rows  session_db_id={db_id}")
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_mitre_findings: {exc}")
    finally:
        db.close()


def save_report(db_id: int, report_file: str, format_type: str) -> None:
    """يسجّل ملف report مُنتج."""
    db = _db()
    try:
        size = 0
        if report_file and os.path.exists(report_file):
            size = os.path.getsize(report_file)
        row = Report(
            session_db_id = db_id,
            report_file   = report_file or "",
            format_type   = format_type or "json",
            size_bytes    = size,
        )
        db.add(row)
        db.commit()
        print(f"[DB] save_report → {report_file} ({format_type})  session_db_id={db_id}")
    except Exception as exc:
        db.rollback()
        print(f"[DB ERROR] save_report: {exc}")
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════════════
# Read helpers — مستخدمة من API routes
# ══════════════════════════════════════════════════════════════════════════

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
                "live_hosts": r.live_hosts_list(),
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
                  .filter(Vulnerability.session_db_id == db_id)
                  .all())
        return [json.loads(r.raw_json) for r in rows]
    finally:
        db.close()


def get_mitre_by_session(db_id: int) -> list[dict]:
    db = _db()
    try:
        rows = (db.query(MitreFinding)
                  .filter(MitreFinding.session_db_id == db_id)
                  .all())
        return [
            {
                "technique_id":   r.technique_id,
                "technique_name": r.technique_name,
                "tactic":         r.tactic,
                "confidence":     r.confidence,
                "source":         r.source,
                "fused_score":    r.fused_score,
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
                  .filter(ExploitResult.session_db_id == db_id)
                  .all())
        return [json.loads(r.raw_json) for r in rows]
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
