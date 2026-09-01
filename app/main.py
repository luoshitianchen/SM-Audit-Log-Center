#!/usr/bin/env python3
"""SM Audit Log Center —— 统一审计与日志中心：事件接入、SM3 完整性链、异常检测与合规报表。"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app import base

SERVICE = "sm-audit-log-center"
VERSION = "2.1.0"
NAME = "SM Audit Log Center"
DESCRIPTION = "统一审计与日志中心：事件接入、SM3 完整性链、异常检测与合规报表"
PORT = 8320
GENESIS = "0" * 64

# 已知服务白名单：用于检测"未登记/伪造服务"上报（可通过 SM_ALERT_KNOWN_SERVICES 覆盖）
DEFAULT_KNOWN_SERVICES = {
    "sm-api-gateway", "sm-iam", "sm-audit-log-center", "sm-observability", "sm-devsecops",
    "sm-workflow-approval", "sm-data-governance", "sm-service-desk", "sm-cmdb", "sm-agentops",
    "sm-config-kms", "sm-event-bus", "sm-object-storage", "sm-backup-dr", "sm-api-developer-portal",
    "sm-mdm", "sm-soc", "sm-notification-center", "sm-data-exchange", "sm-hr", "sm-crm",
    "sm-finance", "sm-procurement", "sm-legal-contract", "sm-release-center", "sm-erp",
    "sm-knowledge-bot", "sm-fusion-platform",
}
# 高频突发检测：同一 (service, actor) 在窗口内的写入条数阈值
RATE_BURST_WINDOW = int(os.getenv("SM_ALERT_RATE_BURST_WINDOW", "60"))
RATE_BURST_THRESHOLD = int(os.getenv("SM_ALERT_RATE_BURST_THRESHOLD", "60"))


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _known_services() -> set[str]:
    configured = os.getenv("SM_ALERT_KNOWN_SERVICES", "").strip()
    if configured:
        return {s.strip() for s in configured.split(",") if s.strip()}
    return set(DEFAULT_KNOWN_SERVICES)


def _init() -> None:
    with base.db_ctx() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE, service TEXT NOT NULL, action TEXT NOT NULL,
                actor TEXT NOT NULL, timestamp TEXT NOT NULL, request_id TEXT, trace_id TEXT,
                detail TEXT, integrity TEXT NOT NULL, prev_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_records_ts ON audit_records(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_records_service ON audit_records(service, action);
            CREATE TABLE IF NOT EXISTS audit_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL UNIQUE, rule TEXT NOT NULL, severity TEXT NOT NULL,
                service TEXT NOT NULL, actor TEXT NOT NULL, event_id TEXT, detail TEXT,
                detected_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_alerts_status ON audit_alerts(status, severity);
            CREATE INDEX IF NOT EXISTS idx_audit_alerts_ts ON audit_alerts(detected_at DESC);
            """
        )


def _raise_alert(rule: str, severity: str, service: str, actor: str, event_id: str, detail: str) -> None:
    with base.db_ctx() as conn:
        conn.execute(
            "INSERT INTO audit_alerts (alert_id, rule, severity, service, actor, event_id, detail, detected_at) VALUES (?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), rule, severity, service, actor, event_id, detail, _now()),
        )


def _detect(payload: "AuditEventIn") -> None:
    """接入时执行异常检测：未知服务 / 完整性不符 / 高频突发（事件重放在 ingest 内处理）。"""
    service = payload.service
    actor = payload.actor
    if service not in _known_services():
        _raise_alert("unknown_service", "high", service, actor, payload.event_id, f"未登记服务 {service} 上报审计事件，疑似伪造或未纳管服务")
        return
    if payload.integrity:
        recomputed = base.sm3_hex(json.dumps(payload.model_dump(exclude={"integrity"}), ensure_ascii=False, sort_keys=True).encode("utf-8"))
        if payload.integrity != recomputed:
            _raise_alert("integrity_mismatch", "high", service, actor, payload.event_id, "事件完整性摘要与重算结果不符，疑似篡改")
            return
    since = datetime.fromtimestamp(datetime.now(UTC).timestamp() - RATE_BURST_WINDOW, tz=UTC).isoformat()
    with base.db_ctx() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM audit_records WHERE service=? AND actor=? AND timestamp>=?",
            (service, actor, since),
        ).fetchone()[0]
    if count >= RATE_BURST_THRESHOLD:
        _raise_alert("rate_burst", "medium", service, actor, payload.event_id, f"服务 {service} 的操作者 {actor} 在 {RATE_BURST_WINDOW}s 内写入 {count} 条审计事件，疑似滥用或暴力操作")


app = base.create_app(
    service=SERVICE, name=NAME, description=DESCRIPTION, version=VERSION, port=PORT,
    dependencies=["sm-iam", "sm-event-bus", "sm-observability"],
    events=["audit.recorded", "audit.verified", "alert.raised"],
    overview_fn=lambda _r: {
        "summary": {
            "records": base.get_db().execute("SELECT COUNT(*) FROM audit_records").fetchone()[0],
            "services": base.get_db().execute("SELECT COUNT(DISTINCT service) FROM audit_records").fetchone()[0],
            "open_alerts": base.get_db().execute("SELECT COUNT(*) FROM audit_alerts WHERE status='open'").fetchone()[0],
        }
    },
)
_init()


class AuditEventIn(BaseModel):
    event_id: str = Field(min_length=8, max_length=64)
    service: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=120)
    actor: str = Field(min_length=1, max_length=120)
    timestamp: str = Field(min_length=10, max_length=40)
    request_id: str = Field(default="", max_length=64)
    trace_id: str = Field(default="", max_length=64)
    detail: str = Field(default="", max_length=4000)
    integrity: str = Field(default="", max_length=64)


def _chain_hash(event_id: str, integrity: str, prev_hash: str) -> str:
    return base.sm3_hex(f"{event_id}|{integrity}|{prev_hash}".encode())


@app.post("/api/audit/events", status_code=status.HTTP_201_CREATED)
def ingest_event(payload: AuditEventIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        if conn.execute("SELECT 1 FROM audit_records WHERE event_id=?", (payload.event_id,)).fetchone():
            _raise_alert("replay_duplicate", "medium", payload.service, payload.actor, payload.event_id, f"重复事件 event_id={payload.event_id}，疑似重放攻击")
            raise HTTPException(status.HTTP_409_CONFLICT, "事件已存在")
        last = conn.execute("SELECT prev_hash FROM audit_records ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = last["prev_hash"] if last else GENESIS
        integrity = payload.integrity or base.sm3_hex(json.dumps(payload.model_dump(exclude={"integrity"}), ensure_ascii=False, sort_keys=True).encode("utf-8"))
        chain = _chain_hash(payload.event_id, integrity, prev_hash)
        conn.execute(
            "INSERT INTO audit_records (event_id, service, action, actor, timestamp, request_id, trace_id, detail, integrity, prev_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (payload.event_id, payload.service, payload.action, payload.actor, payload.timestamp, payload.request_id, payload.trace_id, payload.detail, integrity, chain),
        )
    _detect(payload)
    return {"event_id": payload.event_id, "chain_hash": chain, "status": "recorded"}


@app.get("/api/audit/events")
def list_events(
    service: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    since: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100000),
) -> dict[str, Any]:
    clauses, params = [], []
    if service:
        clauses.append("service=?")
        params.append(service)
    if action:
        clauses.append("action=?")
        params.append(action)
    if actor:
        clauses.append("actor=?")
        params.append(actor)
    if since:
        clauses.append("timestamp>=?")
        params.append(since)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with base.db_ctx() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM audit_records{where}", params).fetchone()[0]
        rows = conn.execute(f"SELECT * FROM audit_records{where} ORDER BY id DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/audit/events/{event_id}")
def get_event(event_id: str) -> dict[str, Any]:
    with base.db_ctx() as conn:
        row = conn.execute("SELECT * FROM audit_records WHERE event_id=?", (event_id,)).fetchone()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "审计事件不存在")
    return dict(row)


@app.get("/api/audit/verify")
def verify_chain() -> dict[str, Any]:
    """校验审计完整性链：逐条重算链哈希并比对，发现篡改即失败。"""
    with base.db_ctx() as conn:
        rows = conn.execute("SELECT * FROM audit_records ORDER BY id ASC").fetchall()
    prev = GENESIS
    broken: list[dict[str, Any]] = []
    for row in rows:
        expected = _chain_hash(row["event_id"], row["integrity"], prev)
        if expected != row["prev_hash"]:
            broken.append({"event_id": row["event_id"], "id": row["id"], "expected": expected, "stored": row["prev_hash"]})
        prev = row["prev_hash"]
    return {"status": "ok" if not broken else "tampered", "records": len(rows), "tampered": broken}


@app.get("/api/audit/stats")
def stats() -> dict[str, Any]:
    with base.db_ctx() as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_records").fetchone()[0]
        services = [dict(r) for r in conn.execute("SELECT service, COUNT(*) AS count FROM audit_records GROUP BY service ORDER BY count DESC").fetchall()]
        top_actions = [dict(r) for r in conn.execute("SELECT action, COUNT(*) AS count FROM audit_records GROUP BY action ORDER BY count DESC LIMIT 10").fetchall()]
        open_alerts = conn.execute("SELECT COUNT(*) FROM audit_alerts WHERE status='open'").fetchone()[0]
    return {
        "total": total,
        "services": services,
        "top_actions": top_actions,
        "alerts": {"open": open_alerts},
        "chain": {"genesis": GENESIS[:16] + "...", "retention_days": 365},
    }


# --------------------------------------------------------------------------- #
# 异常检测与告警（安全运营）
# --------------------------------------------------------------------------- #
class AlertAckIn(BaseModel):
    note: str = Field(default="", max_length=500)


@app.get("/api/audit/alerts")
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    service: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100000),
) -> dict[str, Any]:
    clauses, params = [], []
    if status:
        clauses.append("status=?")
        params.append(status)
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if service:
        clauses.append("service=?")
        params.append(service)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with base.db_ctx() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM audit_alerts{where}", params).fetchone()[0]
        rows = conn.execute(f"SELECT * FROM audit_alerts{where} ORDER BY id DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/audit/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    with base.db_ctx() as conn:
        row = conn.execute("SELECT * FROM audit_alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "告警不存在")
    return dict(row)


@app.post("/api/audit/alerts/{alert_id}/ack")
def ack_alert(alert_id: str, request: Request, payload: AlertAckIn | None = None) -> dict[str, Any]:
    base.require_internal_token(request)
    note = payload.note if payload else ""
    with base.db_ctx() as conn:
        cur = conn.execute("UPDATE audit_alerts SET status='acknowledged', note=? WHERE alert_id=? AND status='open'", (note, alert_id))
        exists = conn.execute("SELECT alert_id FROM audit_alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if cur.rowcount == 0 and not exists:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "告警不存在")
    return {"alert_id": alert_id, "status": "acknowledged"}


@app.get("/api/audit/anomalies")
def anomalies() -> dict[str, Any]:
    """实时异常概览：未处置告警数、按规则/服务分布、最近告警。"""
    with base.db_ctx() as conn:
        open_count = conn.execute("SELECT COUNT(*) FROM audit_alerts WHERE status='open'").fetchone()[0]
        by_rule = [dict(r) for r in conn.execute("SELECT rule, severity, COUNT(*) AS count FROM audit_alerts GROUP BY rule, severity ORDER BY count DESC").fetchall()]
        by_service = [dict(r) for r in conn.execute("SELECT service, COUNT(*) AS count FROM audit_alerts GROUP BY service ORDER BY count DESC").fetchall()]
        recent = [dict(r) for r in conn.execute("SELECT alert_id, rule, severity, service, actor, detected_at, status FROM audit_alerts ORDER BY id DESC LIMIT 20").fetchall()]
    return {"open": open_count, "by_rule": by_rule, "by_service": by_service, "recent": recent}
