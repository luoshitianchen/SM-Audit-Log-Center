"""SM Audit Log Center —— 统一审计与日志中心：事件接入、SM3 完整性链、检索与合规报表。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app import base

SERVICE = "sm-audit-log-center"
VERSION = "2.0.0"
NAME = "SM Audit Log Center"
DESCRIPTION = "统一审计与日志中心：事件接入、SM3 完整性链、检索与合规报表"
PORT = 8320
GENESIS = "0" * 64


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
            raise HTTPException(status.HTTP_409_CONFLICT, "事件已存在") from exc
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
    return {"total": total, "services": services, "top_actions": top_actions, "chain": {"genesis": GENESIS[:16] + "...", "retention_days": 365}}
