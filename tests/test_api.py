"""SM Audit Log Center 领域测试：事件接入、SM3 完整性链、检索与篡改检测。"""

import pytest
from fastapi.testclient import TestClient

from app import base
from app.main import VERSION, app


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(base, "internal_api_key", lambda: "TEST")
    base.reset_state()
    from app.main import _init as init_db
    init_db()
    with TestClient(app) as c:
        c.headers["X-Internal-Token"] = "TEST"
        yield c


def _ingest(client, action="auth.login", service="sm-erp", event_id=None):
    import uuid
    payload = {
        "event_id": event_id or str(uuid.uuid4()),
        "service": service,
        "action": action,
        "actor": "admin",
        "timestamp": "2026-08-31T00:00:00+00:00",
        "request_id": "req-1",
        "detail": "登录成功",
    }
    return client.post("/api/audit/events", json=payload)


def test_health_and_version(client):
    r = client.get("/health", headers={"X-Request-Id": "suite-test"})
    assert r.status_code == 200
    assert r.json()["version"] == VERSION


def test_ingest_and_chain(client):
    r1 = _ingest(client, action="auth.login")
    r2 = _ingest(client, action="employee.created")
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["chain_hash"] != r2.json()["chain_hash"]
    assert client.get("/api/audit/verify").json()["status"] == "ok"
    assert client.get("/api/audit/stats").json()["total"] == 2


def test_duplicate_event_rejected(client):
    event_id = "evt-dup-0001"
    assert _ingest(client, event_id=event_id).status_code == 201
    assert _ingest(client, event_id=event_id).status_code == 409


def test_search_filters(client):
    _ingest(client, action="auth.login", service="sm-erp")
    _ingest(client, action="order.created", service="sm-finance")
    by_service = client.get("/api/audit/events", params={"service": "sm-finance"}).json()
    assert by_service["total"] == 1
    by_action = client.get("/api/audit/events", params={"action": "auth.login"}).json()
    assert by_action["total"] == 1


def test_tamper_detection(client):
    _ingest(client, action="auth.login")
    # 篡改链上记录的 integrity 字段应导致校验失败
    with base.db_ctx() as conn:
        row = conn.execute("SELECT id, integrity FROM audit_records ORDER BY id ASC LIMIT 1").fetchone()
        conn.execute("UPDATE audit_records SET integrity=? WHERE id=?", ("f" * 64, row["id"]))
        conn.commit()
    verify = client.get("/api/audit/verify").json()
    assert verify["status"] == "tampered"
    assert len(verify["tampered"]) >= 1


def test_get_event(client):
    _ingest(client, event_id="evt-get-0001")
    assert client.get("/api/audit/events/evt-get-0001").json()["action"] == "auth.login"
    assert client.get("/api/audit/events/nope").status_code == 404


def test_manifest_and_crypto(client):
    assert client.get("/api/integration/manifest").json()["version"] == VERSION
    enc = client.post("/api/crypto/encrypt", json={"value": "x"}).json()["ciphertext"]
    assert client.post("/api/crypto/decrypt", json={"value": enc}).json()["plaintext"] == "x"


def test_write_requires_auth(client):
    del client.headers["X-Internal-Token"]
    assert _ingest(client).status_code == 401
