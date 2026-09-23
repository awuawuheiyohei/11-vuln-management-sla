"""
Vulnerability Management + SLA Tracking API
- Dashboard / Vulnerabilities / Assets / SLA / Exceptions / Scan upload / Audit
"""
import json
from datetime import date, datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Body, Query, UploadFile, File
from pydantic import BaseModel, Field

from ..models.db import get_conn, init_db, row_to_dict, rows_to_dicts, write_audit
from ..models.parsers import parse_scan
from ..models.risk_engine import (
    composite_score, determine_severity, evaluate_sla_status,
    SLA_DAYS, TIER_WEIGHTS, stats_summary,
)
from ..models.seed import seed_all, DEFAULT_ASSETS

router = APIRouter()


# ============================================
# Pydantic Schemas
# ============================================
class VulnerabilityCreate(BaseModel):
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = ""
    asset_id: str
    cvss_base: float = Field(0.0, ge=0.0, le=10.0)
    epss_score: float = Field(0.0, ge=0.0, le=1.0)
    is_cisa_kev: bool = False
    source: str = "MANUAL"
    remediation_advice: Optional[str] = ""


class ExceptionCreate(BaseModel):
    vuln_id: str
    requested_by: str
    justification: str
    compensating_controls: List[str] = []
    exception_until: str  # ISO date


class ExceptionDecision(BaseModel):
    approved: bool
    approved_by: str = "CISO"


# ============================================
# Dashboard
# ============================================
@router.get("/dashboard/summary")
async def dashboard_summary():
    init_db()
    conn = get_conn()
    n_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    n_vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    n_open = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status='OPEN'").fetchone()[0]
    by_sev = rows_to_dicts(conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM vulnerabilities WHERE status='OPEN' GROUP BY severity"
    ).fetchall())
    sla_breached = conn.execute(
        "SELECT COUNT(*) FROM sla_tracking WHERE status='BREACHED' AND severity IN ('CRITICAL','HIGH','MEDIUM','LOW')"
    ).fetchone()[0]
    # 但我们想过滤已 resolved 的，所以加 JOIN
    sla_breached = conn.execute(
        """SELECT COUNT(*) FROM sla_tracking s
           JOIN vulnerabilities v ON s.vuln_id = v.vuln_id
           WHERE s.status='BREACHED' AND v.status IN ('OPEN','IN_PROGRESS')"""
    ).fetchone()[0]
    sla_at_risk = conn.execute(
        """SELECT COUNT(*) FROM sla_tracking s
           JOIN vulnerabilities v ON s.vuln_id = v.vuln_id
           WHERE s.status='AT_RISK' AND v.status IN ('OPEN','IN_PROGRESS')"""
    ).fetchone()[0]
    n_exc_approved = conn.execute(
        "SELECT COUNT(*) FROM risk_exceptions WHERE status='APPROVED'"
    ).fetchone()[0]
    n_exc_pending = conn.execute(
        "SELECT COUNT(*) FROM risk_exceptions WHERE status='PENDING'"
    ).fetchone()[0]
    kev_count = conn.execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE is_cisa_kev=1 AND status IN ('OPEN','IN_PROGRESS')"
    ).fetchone()[0]
    by_source = rows_to_dicts(conn.execute(
        "SELECT source, COUNT(*) as cnt FROM vulnerabilities GROUP BY source"
    ).fetchall())
    by_team = rows_to_dicts(conn.execute(
        "SELECT assigned_team, COUNT(*) as cnt FROM vulnerabilities WHERE status='OPEN' GROUP BY assigned_team"
    ).fetchall())
    return {
        "assets": n_assets,
        "vulnerabilities": {"total": n_vulns, "open": n_open},
        "by_severity": by_sev,
        "by_source": by_source,
        "by_team": by_team,
        "sla": {"breached": sla_breached, "at_risk": sla_at_risk},
        "exceptions": {"approved": n_exc_approved, "pending": n_exc_pending},
        "kev_open": kev_count,
    }


# ============================================
# Vulnerabilities
# ============================================
@router.get("/vulnerabilities")
async def list_vulns(severity: Optional[str] = None, status: Optional[str] = None,
                     asset_id: Optional[str] = None, sla_status: Optional[str] = None,
                     limit: int = Query(100, ge=1, le=500)):
    init_db()
    conn = get_conn()
    sql = """SELECT v.*, s.status AS sla_status, s.days_remaining
             FROM vulnerabilities v
             LEFT JOIN sla_tracking s ON v.vuln_id = s.vuln_id
             WHERE 1=1"""
    params = []
    if severity:
        sql += " AND v.severity=?"
        params.append(severity)
    if status:
        sql += " AND v.status=?"
        params.append(status)
    if asset_id:
        sql += " AND v.asset_id=?"
        params.append(asset_id)
    if sla_status:
        sql += " AND s.status=?"
        params.append(sla_status)
    sql += " ORDER BY v.severity, v.due_date LIMIT ?"
    params.append(limit)
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    return {"count": len(rows), "items": rows}


@router.get("/vulnerabilities/{vuln_id}")
async def get_vuln(vuln_id: str):
    conn = get_conn()
    row = conn.execute(
        """SELECT v.*, s.status AS sla_status, s.days_remaining
           FROM vulnerabilities v LEFT JOIN sla_tracking s ON v.vuln_id = s.vuln_id
           WHERE v.vuln_id=?""", (vuln_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, f"Vulnerability not found: {vuln_id}")
    d = row_to_dict(row)
    # Join asset
    asset = conn.execute("SELECT * FROM assets WHERE asset_id=?", (d["asset_id"],)).fetchone()
    d["asset"] = row_to_dict(asset) if asset else None
    # Join exceptions
    excs = rows_to_dicts(conn.execute(
        "SELECT * FROM risk_exceptions WHERE vuln_id=? ORDER BY created_at DESC", (vuln_id,)
    ).fetchall())
    for e in excs:
        try:
            e["compensating_controls"] = json.loads(e["compensating_controls"]) if e["compensating_controls"] else []
        except Exception:
            e["compensating_controls"] = []
    d["exceptions"] = excs
    return d


@router.post("/vulnerabilities")
async def create_vuln(req: VulnerabilityCreate, actor: str = "scanner"):
    init_db()
    conn = get_conn()
    asset = conn.execute("SELECT * FROM assets WHERE asset_id=?", (req.asset_id,)).fetchone()
    if not asset:
        raise HTTPException(400, f"Asset not found: {req.asset_id}")
    a = row_to_dict(asset)
    tier = a["tier"]
    aw = a["criticality_weight"]
    severity = determine_severity(req.cvss_base, req.epss_score, req.is_cisa_kev, aw)
    score = composite_score(req.cvss_base, req.epss_score, aw)
    today = date.today()
    sla_days = SLA_DAYS[severity]
    due = today + timedelta(days=sla_days)

    # next vuln_id
    n = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    vuln_id = f"VUL-{n + 1:04d}"

    conn.execute(
        """INSERT INTO vulnerabilities
           (vuln_id, cve_id, title, description, asset_id, asset_tier, cvss_base, epss_score,
            is_cisa_kev, severity, composite_score, status, assigned_team, discovered_at, due_date,
            source, remediation_advice)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?)""",
        (vuln_id, req.cve_id, req.title, req.description, req.asset_id, tier,
         req.cvss_base, req.epss_score, int(req.is_cisa_kev), severity, score,
         a["owner_team"], today.isoformat(), due.isoformat(), req.source, req.remediation_advice)
    )
    # SLA
    sla = evaluate_sla_status(due, today)
    conn.execute(
        """INSERT INTO sla_tracking (sla_id, vuln_id, severity, sla_days, discovered_at, due_date, days_remaining, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (f"SLA-{vuln_id}", vuln_id, severity, sla_days, today.isoformat(), due.isoformat(),
         sla["days_remaining"], sla["status"])
    )
    write_audit(conn, actor=actor, action="create_vuln",
                entity_type="vulnerabilities", entity_id=vuln_id,
                details={"severity": severity, "score": score})
    conn.commit()
    return {"vuln_id": vuln_id, "severity": severity, "composite_score": score, "due_date": due.isoformat()}


@router.post("/vulnerabilities/{vuln_id}/resolve")
async def resolve_vuln(vuln_id: str, actor: str = "engineer"):
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM vulnerabilities WHERE vuln_id=?", (vuln_id,)).fetchone():
        raise HTTPException(404, f"Vuln not found: {vuln_id}")
    today = date.today().isoformat()
    conn.execute("UPDATE vulnerabilities SET status='RESOLVED', resolved_at=? WHERE vuln_id=?",
                 (today, vuln_id))
    conn.execute("UPDATE sla_tracking SET status='RESOLVED' WHERE vuln_id=?", (vuln_id,))
    write_audit(conn, actor=actor, action="resolve_vuln",
                entity_type="vulnerabilities", entity_id=vuln_id, details={})
    conn.commit()
    return {"vuln_id": vuln_id, "status": "RESOLVED"}


# ============================================
# Assets
# ============================================
@router.get("/assets")
async def list_assets(tier: Optional[str] = None):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM assets WHERE 1=1"
    params = []
    if tier:
        sql += " AND tier=?"
        params.append(tier)
    sql += " ORDER BY asset_id"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    # 加上 vuln count
    for r in rows:
        r["open_vuln_count"] = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE asset_id=? AND status IN ('OPEN','IN_PROGRESS')",
            (r["asset_id"],)
        ).fetchone()[0]
    return {"count": len(rows), "items": rows}


# ============================================
# SLA
# ============================================
@router.get("/sla/breaches")
async def sla_breaches(limit: int = Query(50, ge=1, le=200)):
    init_db()
    conn = get_conn()
    rows = rows_to_dicts(conn.execute(
        """SELECT s.*, v.title, v.cve_id, v.asset_id
           FROM sla_tracking s JOIN vulnerabilities v ON s.vuln_id = v.vuln_id
           WHERE s.status IN ('BREACHED','AT_RISK') AND v.status IN ('OPEN','IN_PROGRESS')
           ORDER BY s.days_remaining LIMIT ?""", (limit,)
    ).fetchall())
    return {"count": len(rows), "items": rows}


@router.post("/sla/reevaluate")
async def reevaluate_sla(actor: str = "system"):
    """重新评估所有 SLA 状态（daily 跑）"""
    init_db()
    conn = get_conn()
    today = date.today()
    vulns = rows_to_dicts(conn.execute(
        "SELECT vuln_id, severity, due_date FROM vulnerabilities WHERE status IN ('OPEN','IN_PROGRESS')"
    ).fetchall())
    updated = 0
    for v in vulns:
        due = date.fromisoformat(v["due_date"])
        new_sla = evaluate_sla_status(due, today)
        conn.execute(
            "UPDATE sla_tracking SET status=?, days_remaining=?, last_evaluated_at=datetime('now') WHERE vuln_id=?",
            (new_sla["status"], new_sla["days_remaining"], v["vuln_id"])
        )
        updated += 1
    write_audit(conn, actor=actor, action="reevaluate_sla",
                entity_type="sla_tracking", entity_id=None,
                details={"updated": updated})
    conn.commit()
    return {"updated": updated, "evaluated_at": today.isoformat()}


# ============================================
# Risk Exceptions
# ============================================
@router.get("/exceptions")
async def list_exceptions(status: Optional[str] = None):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM risk_exceptions WHERE 1=1"
    params = []
    if status:
        sql += " AND status=?"
        params.append(status)
    sql += " ORDER BY created_at DESC"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    for r in rows:
        try:
            r["compensating_controls"] = json.loads(r["compensating_controls"]) if r["compensating_controls"] else []
        except Exception:
            r["compensating_controls"] = []
    return {"count": len(rows), "items": rows}


@router.post("/exceptions")
async def create_exception(req: ExceptionCreate, actor: str = "requester"):
    init_db()
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM vulnerabilities WHERE vuln_id=?", (req.vuln_id,)).fetchone():
        raise HTTPException(400, f"Vulnerability not found: {req.vuln_id}")
    n = conn.execute("SELECT COUNT(*) FROM risk_exceptions").fetchone()[0]
    exc_id = f"EXC-{n + 1:04d}"
    conn.execute(
        """INSERT INTO risk_exceptions (exception_id, vuln_id, requested_by, justification,
           compensating_controls, exception_until, status) VALUES (?, ?, ?, ?, ?, ?, 'PENDING')""",
        (exc_id, req.vuln_id, req.requested_by, req.justification,
         json.dumps(req.compensating_controls, ensure_ascii=False), req.exception_until)
    )
    write_audit(conn, actor=actor, action="create_exception",
                entity_type="risk_exceptions", entity_id=exc_id,
                details={"vuln_id": req.vuln_id, "until": req.exception_until})
    conn.commit()
    return {"exception_id": exc_id, "status": "PENDING"}


@router.post("/exceptions/{exception_id}/decide")
async def decide_exception(exception_id: str, req: ExceptionDecision, actor: str = "ciso"):
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM risk_exceptions WHERE exception_id=?", (exception_id,)).fetchone():
        raise HTTPException(404, f"Exception not found: {exception_id}")
    today = date.today().isoformat()
    if req.approved:
        # 把 vuln 标为 RISK_ACCEPTED
        exc = conn.execute("SELECT vuln_id FROM risk_exceptions WHERE exception_id=?", (exception_id,)).fetchone()
        conn.execute("UPDATE vulnerabilities SET status='RISK_ACCEPTED' WHERE vuln_id=?",
                     (exc["vuln_id"],))
        conn.execute("""UPDATE risk_exceptions SET status='APPROVED', approved_by=?, decided_at=?
                       WHERE exception_id=?""", (req.approved_by, today, exception_id))
    else:
        conn.execute("""UPDATE risk_exceptions SET status='REJECTED', approved_by=?, decided_at=?
                       WHERE exception_id=?""", (req.approved_by, today, exception_id))
    write_audit(conn, actor=actor, action="decide_exception",
                entity_type="risk_exceptions", entity_id=exception_id,
                details={"approved": req.approved})
    conn.commit()
    return {"exception_id": exception_id, "approved": req.approved}


# ============================================
# Scan Upload
# ============================================
@router.post("/scan/upload")
async def upload_scan(source: str = Query("TRIVY", pattern="^(TRIVY|NESSUS|GENERIC)$"),
                      asset_id: str = Query(...), payload: dict = Body(...),
                      actor: str = "scanner"):
    """接收扫描器 JSON 输出，解析 + 归一化 + 入库"""
    init_db()
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM assets WHERE asset_id=?", (asset_id,)).fetchone():
        raise HTTPException(400, f"Asset not found: {asset_id}")
    asset = row_to_dict(conn.execute("SELECT * FROM assets WHERE asset_id=?", (asset_id,)).fetchone())
    aw = asset["criticality_weight"]
    tier = asset["tier"]

    parsed = parse_scan(source, payload, asset_id)
    inserted = 0
    skipped = 0
    new_vulns = []
    for p in parsed:
        severity = determine_severity(p["cvss_base"], p["epss_score"], p["is_cisa_kev"], aw)
        score = composite_score(p["cvss_base"], p["epss_score"], aw)
        cve_id = p["cve_id"]

        # 查重：(asset_id, cve_id) — 同 asset 同 CVE 不重复
        if cve_id and conn.execute(
            "SELECT 1 FROM vulnerabilities WHERE asset_id=? AND cve_id=? AND cve_id IS NOT NULL AND cve_id != ''",
            (asset_id, cve_id)
        ).fetchone():
            skipped += 1
            continue

        n = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        vuln_id = f"VUL-{n + 1:04d}"
        today = date.today()
        sla_days = SLA_DAYS[severity]
        due = today + timedelta(days=sla_days)
        conn.execute(
            """INSERT INTO vulnerabilities
               (vuln_id, cve_id, title, description, asset_id, asset_tier, cvss_base, epss_score,
                is_cisa_kev, severity, composite_score, status, assigned_team, discovered_at, due_date,
                source, remediation_advice, raw_payload_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?)""",
            (vuln_id, cve_id, p["title"], p["description"], asset_id, tier,
             p["cvss_base"], p["epss_score"], int(p["is_cisa_kev"]),
             severity, score, asset["owner_team"],
             today.isoformat(), due.isoformat(), p["source"], p["remediation_advice"],
             p["raw_payload_hash"])
        )
        sla = evaluate_sla_status(due, today)
        conn.execute(
            """INSERT INTO sla_tracking (sla_id, vuln_id, severity, sla_days, discovered_at, due_date, days_remaining, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (f"SLA-{vuln_id}", vuln_id, severity, sla_days, today.isoformat(), due.isoformat(),
             sla["days_remaining"], sla["status"])
        )
        new_vulns.append({"vuln_id": vuln_id, "severity": severity, "composite_score": score,
                          "cve_id": cve_id, "title": p["title"]})
        inserted += 1

    write_audit(conn, actor=actor, action="scan_upload",
                entity_type="vulnerabilities", entity_id=asset_id,
                details={"source": source, "parsed": len(parsed), "inserted": inserted, "skipped": skipped})
    conn.commit()
    return {
        "source": source,
        "parsed": len(parsed),
        "inserted": inserted,
        "skipped_dedup": skipped,
        "new_vulns": new_vulns,
    }


# ============================================
# Report Export (SOC 2 CC7.1 / PCI DSS Req 6)
# ============================================
@router.get("/report/soc2")
async def report_soc2():
    init_db()
    conn = get_conn()
    today = date.today().isoformat()
    open_v = conn.execute(
        """SELECT severity, COUNT(*) as cnt FROM vulnerabilities WHERE status IN ('OPEN','IN_PROGRESS')
           GROUP BY severity"""
    ).fetchall()
    breached = conn.execute(
        """SELECT COUNT(*) FROM sla_tracking s JOIN vulnerabilities v ON s.vuln_id = v.vuln_id
           WHERE s.status='BREACHED' AND v.status IN ('OPEN','IN_PROGRESS')"""
    ).fetchone()[0]
    by_team = rows_to_dicts(conn.execute(
        """SELECT assigned_team, severity, COUNT(*) as cnt FROM vulnerabilities
           WHERE status IN ('OPEN','IN_PROGRESS') GROUP BY assigned_team, severity"""
    ).fetchall())
    return {
        "report_date": today,
        "framework": "SOC 2 Type II - CC7.1",
        "open_by_severity": rows_to_dicts(open_v),
        "sla_breached_count": breached,
        "by_team_severity": by_team,
        "control_owner": "GRC Team",
    }


# ============================================
# Audit + Admin
# ============================================
@router.get("/audit")
async def list_audit(limit: int = Query(50, ge=1, le=500)):
    init_db()
    conn = get_conn()
    rows = rows_to_dicts(conn.execute(
        "SELECT * FROM audit_trail ORDER BY occurred_at DESC LIMIT ?", (limit,)).fetchall())
    return {"count": len(rows), "items": rows}


@router.post("/admin/seed")
async def admin_seed(actor: str = "grc-team"):
    init_db()
    stats = seed_all(verbose=False)
    conn = get_conn()
    write_audit(conn, actor=actor, action="reseed",
                entity_type="system", entity_id="all", details=stats)
    conn.commit()
    return {"status": "ok", "stats": stats}
