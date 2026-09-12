"""审计服务：本地写入 + 异步上报集中审计中心。"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import sm3_hex
from app.models.audit_event import AuditEvent
from app.repositories.audit import create_audit_event


async def record_audit(
    session: AsyncSession, action: str, actor: str,
    detail: str = "", request: Request | None = None,
) -> None:
    request_id = getattr(request.state, "request_id", "") if request else ""
    trace_id = getattr(request.state, "trace_id", "") if request else ""

    event_id = str(uuid.uuid4())
    event_timestamp = datetime.now(UTC).isoformat()
    event_payload = {
        "event_id": event_id, "service": settings.SERVICE_NAME,
        "action": action, "actor": actor, "timestamp": event_timestamp,
        "request_id": request_id[:64], "trace_id": trace_id[:64], "detail": detail,
    }
    canonical = json.dumps(event_payload, ensure_ascii=False, sort_keys=True)
    integrity = sm3_hex(canonical)

    event = AuditEvent(
        event_id=event_id, service=settings.SERVICE_NAME, action=action,
        actor=actor, request_id=request_id[:64], trace_id=trace_id[:64],
        detail=canonical, integrity=integrity,
    )
    await create_audit_event(session, event)

    if settings.AUDIT_CENTER_URL:
        _forward_audit({**event_payload, "integrity": integrity})


def _forward_audit(event: dict) -> None:
    """把审计事件异步投递到通知中心 POST /alerts/ingest。

    通知中心接收契约 (AlertIngest)：
      source   — 事件来源服务（必填，<=80）
      summary  — 告警摘要（必填，<=500）
      severity — critical / warning / info
      details  — 明细（含 event_id / 完整性摘要等追溯信息）
    认证：X-Internal-Token 需与通知中心 SM_INTERNAL_API_KEY 一致。
    """

    def _send() -> None:
        try:
            import urllib.request
            from urllib.parse import urlparse
            summary = f"{event.get('action', 'audit.event')} actor={event.get('actor', '')}"
            details = json.dumps(
                {
                    "event_id": event.get("event_id", ""),
                    "timestamp": event.get("timestamp", ""),
                    "request_id": event.get("request_id", ""),
                    "trace_id": event.get("trace_id", ""),
                    "integrity": event.get("integrity", ""),
                    "detail": event.get("detail", ""),
                },
                ensure_ascii=False,
            )[:2000]
            payload = {
                "source": str(event.get("service", settings.SERVICE_NAME))[:80],
                "summary": summary[:500],
                "severity": "warning",
                "details": details,
            }
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                f"{settings.AUDIT_CENTER_URL.rstrip('/')}/alerts/ingest",
                data=body,
                headers={"Content-Type": "application/json", "X-Internal-Token": settings.INTERNAL_API_KEY},
                method="POST",
            )
            parsed = urlparse(settings.AUDIT_CENTER_URL)
            if parsed.scheme not in ("http", "https"):
                return
            urllib.request.urlopen(req, timeout=2)  # nosec B310
        except Exception:
            pass

    threading.Thread(target=_send, daemon=True).start()
