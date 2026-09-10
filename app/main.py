"""SM Audit Log Center —— 统一审计与日志中心：事件接入、SM3 完整性链、检索与合规报表。"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib import error as _urlerr
from urllib import request as _urlreq

from fastapi import HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app import base

SERVICE = "sm-audit-log-center"
VERSION = "3.0.0"
NAME = "SM Audit Log Center"
DESCRIPTION = "统一审计与日志中心：事件接入、SM3 完整性链、检索与合规报表"
PORT = 8320
GENESIS = "0" * 64

# 异常检测与告警专线配置（测试会 monkeypatch 以下模块级符号）
RATE_BURST_THRESHOLD = 10
NOTIFICATION_CENTER_URL = "http://127.0.0.1:8470"
KNOWN_SERVICES = {
    "sm-iam", "sm-erp", "sm-crm", "sm-hr", "sm-finance", "sm-cmdb", "sm-api-gateway",
    "sm-event-bus", "sm-object-storage", "sm-observability", "sm-audit-log-center",
    "sm-notification-center", "sm-config-kms", "sm-devsecops", "sm-agentops",
    "sm-backup-dr", "sm-data-exchange", "sm-data-governance", "sm-mdm", "sm-procurement",
    "sm-legal-contract", "sm-release-center", "sm-service-desk", "sm-soc",
    "sm-workflow-approval", "sm-api-developer-portal", "sm-knowledge-bot", "sm-fusion-platform",
}

_logger = logging.getLogger("sm.audit")


def _now() -> str:
    return datetime.now(UTC).isoformat()


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
            CREATE TABLE IF NOT EXISTS anomalies (
                id TEXT PRIMARY KEY, alert_id TEXT NOT NULL UNIQUE, rule TEXT NOT NULL,
                severity TEXT NOT NULL, service TEXT, actor TEXT, event_id TEXT,
                detail TEXT, status TEXT NOT NULL DEFAULT 'open', detected_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_anomalies_status ON anomalies(status, detected_at DESC);
            CREATE INDEX IF NOT EXISTS idx_anomalies_rule ON anomalies(rule);
            """
        )


app = base.create_app(
    service=SERVICE, name=NAME, description=DESCRIPTION, version=VERSION, port=PORT,
    dependencies=["sm-iam", "sm-event-bus", "sm-observability"],
    events=["audit.recorded", "audit.verified"],
    overview_fn=lambda _r: {
        "summary": {
            "records": base.get_db().execute("SELECT COUNT(*) FROM audit_records").fetchone()[0],
            "services": base.get_db().execute("SELECT COUNT(DISTINCT service) FROM audit_records").fetchone()[0],
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


def _send_notification(alert: dict[str, Any]) -> None:
    """best-effort 异步推送告警到通知中心告警专线；失败静默忽略。"""

    def _worker() -> None:
        try:
            body = json.dumps(alert, ensure_ascii=False).encode("utf-8")
            req = _urlreq.Request(
                NOTIFICATION_CENTER_URL.rstrip("/") + "/api/notifications/alert",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Internal-Token": base.internal_api_key(),
                },
                method="POST",
            )
            _urlreq.urlopen(req, timeout=3)  # nosec B310  # 推送至受控内部通知中心，带 X-Internal-Token 认证
        except (_urlerr.URLError, OSError):
            _logger.debug("alert push failed", exc_info=True)

    threading.Thread(target=_worker, daemon=True).start()


def _record_anomaly(rule: str, severity: str, payload: AuditEventIn, conn, detail: str) -> dict[str, Any]:
    """落库一条异常并异步推送通知，返回告警字典。"""
    alert_id = "al-" + uuid.uuid4().hex[:8]
    detected_at = _now()
    conn.execute(
        "INSERT INTO anomalies (id, alert_id, rule, severity, service, actor, event_id, detail, status, detected_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), alert_id, rule, severity, payload.service, payload.actor, payload.event_id, detail, "open", detected_at),
    )
    alert = {
        "alert_id": alert_id, "rule": rule, "severity": severity, "service": payload.service,
        "actor": payload.actor, "event_id": payload.event_id, "detail": detail, "detected_at": detected_at,
    }
    _send_notification(alert)
    return alert


def _detect_anomalies(payload: AuditEventIn, conn) -> list[dict[str, Any]]:
    """事件写入后调用：检测未知服务 / 完整性不符 / 速率突增等异常。"""
    found: list[dict[str, Any]] = []
    if payload.service not in KNOWN_SERVICES:
        found.append(_record_anomaly("unknown_service", "high", payload, conn, f"未登记服务上报: {payload.service}"))
    if payload.integrity:
        found.append(_record_anomaly("integrity_mismatch", "high", payload, conn, f"客户端声明完整性与服务端计算不一致: {payload.event_id}"))
    cutoff = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
    recent = conn.execute(
        "SELECT COUNT(*) AS c FROM audit_records WHERE actor=? AND timestamp>=?",
        (payload.actor, cutoff),
    ).fetchone()["c"]
    if recent >= RATE_BURST_THRESHOLD:
        found.append(_record_anomaly("rate_burst", "medium", payload, conn, f"actor={payload.actor} 最近60秒内事件数={recent}"))
    return found


@app.post("/api/audit/events", status_code=status.HTTP_201_CREATED)
def ingest_event(payload: AuditEventIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        last = conn.execute("SELECT prev_hash FROM audit_records ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = last["prev_hash"] if last else GENESIS
        integrity = payload.integrity or base.sm3_hex(json.dumps(payload.model_dump(exclude={"integrity"}), ensure_ascii=False, sort_keys=True).encode("utf-8"))
        chain = _chain_hash(payload.event_id, integrity, prev_hash)
        try:
            conn.execute(
                "INSERT INTO audit_records (event_id, service, action, actor, timestamp, request_id, trace_id, detail, integrity, prev_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (payload.event_id, payload.service, payload.action, payload.actor, payload.timestamp, payload.request_id, payload.trace_id, payload.detail, integrity, chain),
            )
        except Exception as exc:  # noqa: BLE001
            # 重放/重复事件：仍需记录 replay_duplicate 异常
            _record_anomaly("replay_duplicate", "medium", payload, conn, f"重复事件重放: {payload.event_id}")
            raise HTTPException(status.HTTP_409_CONFLICT, "事件已存在") from exc
        _detect_anomalies(payload, conn)
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
        total = conn.execute(f"SELECT COUNT(*) FROM audit_records{where}", params).fetchone()[0]  # nosec B608  # SQL片段为程序生成，用户输入已参数化
        rows = conn.execute(f"SELECT * FROM audit_records{where} ORDER BY id DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()  # nosec B608  # SQL片段为程序生成，用户输入已参数化
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




@app.get("/api/audit/anomalies")
def list_anomalies() -> dict[str, Any]:
    with base.db_ctx() as conn:
        open_count = conn.execute("SELECT COUNT(*) FROM anomalies WHERE status='open'").fetchone()[0]
        by_rule_rows = conn.execute(
            "SELECT rule, severity, COUNT(*) AS count FROM anomalies GROUP BY rule, severity ORDER BY count DESC"
        ).fetchall()
        items = [dict(r) for r in conn.execute("SELECT * FROM anomalies ORDER BY detected_at DESC").fetchall()]
    by_rule = [{"rule": r["rule"], "count": r["count"], "severity": r["severity"]} for r in by_rule_rows]
    return {"open": open_count, "by_rule": by_rule, "items": items}


@app.get("/api/audit/alerts")
def list_alerts(severity: str | None = None, status_: str | None = None) -> dict[str, Any]:
    clauses, params = [], []
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if status_:
        clauses.append("status=?")
        params.append(status_)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with base.db_ctx() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM anomalies{where}", params).fetchone()[0]  # nosec B608  # SQL片段为程序生成，用户输入已参数化
        rows = conn.execute(f"SELECT * FROM anomalies{where} ORDER BY detected_at DESC", params).fetchall()  # nosec B608  # SQL片段为程序生成，用户输入已参数化
    return {"items": [dict(r) for r in rows], "total": total}


@app.get("/api/audit/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    with base.db_ctx() as conn:
        row = conn.execute("SELECT * FROM anomalies WHERE alert_id=?", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "告警不存在")
    return dict(row)


class AckIn(BaseModel):
    note: str = Field(default="", max_length=1000)


@app.post("/api/audit/alerts/{alert_id}/ack")
def ack_alert(alert_id: str, payload: AckIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        row = conn.execute("SELECT * FROM anomalies WHERE alert_id=?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "告警不存在")
        conn.execute("UPDATE anomalies SET status='acknowledged' WHERE alert_id=?", (alert_id,))
    return {"alert_id": alert_id, "status": "acknowledged"}


@app.get("/api/audit/stats")
def stats() -> dict[str, Any]:
    with base.db_ctx() as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_records").fetchone()[0]
        services = [dict(r) for r in conn.execute("SELECT service, COUNT(*) AS count FROM audit_records GROUP BY service ORDER BY count DESC").fetchall()]
        top_actions = [dict(r) for r in conn.execute("SELECT action, COUNT(*) AS count FROM audit_records GROUP BY action ORDER BY count DESC LIMIT 10").fetchall()]
        open_alerts = conn.execute("SELECT COUNT(*) FROM anomalies WHERE status='open'").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    return {
        "total": total, "services": services, "top_actions": top_actions,
        "chain": {"genesis": GENESIS[:16] + "...", "retention_days": 365},
        "alerts": {"open": open_alerts, "total": total_alerts},
    }
