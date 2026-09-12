"""集成测试：审计事件写入后异步投递到通知中心告警链路。

验证 SM-Audit-Log-Center -> SM-Notification-Center POST /alerts/ingest：
  1. record_audit 写库后触发 _forward_audit；
  2. 实际发起 HTTP POST 到 {AUDIT_CENTER_URL}/alerts/ingest（而非旧 /api/audit/events）；
  3. 携带 X-Internal-Token 内部令牌；
  4. 请求体符合通知中心 AlertIngest 契约 (source/summary/severity/details)。
本地起一个真实 HTTP sink 捕获请求，避免跨仓库导入。
"""
from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.core.config import settings
from app.core.database import async_session, init_db
from app.services.audit import record_audit


class _Sink(BaseHTTPRequestHandler):
    """捕获所有 POST 请求的 sink 处理器。"""

    received: list[dict] = []  # class-level, 在每个测试前清空

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        _Sink.received.append({
            "method": self.command,
            "path": self.path,
            "token": self.headers.get("X-Internal-Token", ""),
            "content_type": self.headers.get("Content-Type", ""),
            "body": body.decode("utf-8"),
        })
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"accepted"}')

    def log_message(self, *args) -> None:  # 静默
        pass


@pytest.fixture()
def sink_server(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    host, port = server.server_address
    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    _Sink.received.clear()
    monkeypatch.setattr(settings, "AUDIT_CENTER_URL", f"http://{host}:{port}")
    yield f"http://{host}:{port}"
    server.shutdown()
    server.server_close()


def _wait_received(timeout: float = 3.0) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _Sink.received:
            return _Sink.received[0]
        time.sleep(0.05)
    return None


@pytest.mark.asyncio
async def test_record_audit_forwards_alert_to_notification_center(sink_server):
    """写入审计事件后，应真实 POST 到 /alerts/ingest 并符合 AlertIngest 契约。"""
    await init_db()
    async with async_session() as session:
        await record_audit(
            session, "resource.created", "internal", detail="id=item-1 name=链路验证",
        )

    req = _wait_received()
    assert req is not None, "审计事件未触发 HTTP 告警投递"

    # 1. 目标路径必须是通知中心告警接入端点（而非旧的 /api/audit/events）
    assert req["path"] == "/alerts/ingest", req["path"]

    # 2. 认证头一致
    assert req["token"] == settings.INTERNAL_API_KEY
    assert req["content_type"] == "application/json"

    # 3. 请求体符合 AlertIngest 契约
    payload = json.loads(req["body"])
    assert payload["source"] == "sm-audit-log-center"
    assert payload["summary"], "summary 必填且非空"
    assert payload["severity"] in ("critical", "warning", "info")
    assert "event_id" in payload["details"]
    assert "resource.created" in payload["summary"]


@pytest.mark.asyncio
async def test_no_forward_when_audit_url_empty(monkeypatch):
    """未配置 AUDIT_CENTER_URL 时静默不投递（回归保护）。"""
    monkeypatch.setattr(settings, "AUDIT_CENTER_URL", "")
    _Sink.received.clear()
    await init_db()
    async with async_session() as session:
        await record_audit(session, "resource.created", "internal", detail="不投递")
    time.sleep(0.3)  # 给 daemon 线程机会误发
    assert _Sink.received == []
