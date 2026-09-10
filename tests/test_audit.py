"""审计事件查询端点测试。"""
from __future__ import annotations

import pytest

H = {"X-Internal-Token": "test-internal-key-12345"}
BAD = {"X-Internal-Token": "wrong"}


@pytest.mark.asyncio
async def test_query_audit_events_requires_token(client):
    """未携带内部令牌访问 /api/audit/events 被拒绝。"""
    resp = await client.get("/api/audit/events")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_query_audit_events_invalid_token(client):
    """错误内部令牌被拒绝。"""
    resp = await client.get("/api/audit/events", headers=BAD)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_query_audit_events_returns_recent(client):
    """写入业务项产生审计事件后，查询接口返回最近事件。"""
    create = await client.post("/api/items", json={"name": "审计查询项"}, headers=H)
    assert create.status_code == 201

    resp = await client.get("/api/audit/events", headers=H)
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "sm-audit-log-center"
    assert body["total"] >= 1
    assert len(body["events"]) >= 1
    latest = body["events"][0]
    assert {"event_id", "service", "action", "actor", "timestamp", "trace_id", "integrity"} <= latest.keys()
    assert latest["action"] == "resource.created"
