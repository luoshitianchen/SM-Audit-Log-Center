"""审计事件查询路由：供内部服务按令牌拉取最近审计事件。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.security import internal_write_allowed
from app.repositories.audit import list_audit_events

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/events")
async def query_audit_events(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """返回最近 200 条审计事件，需内部令牌 (X-Internal-Token)。"""
    if not internal_write_allowed(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")

    events = await list_audit_events(session, limit=200)
    return {
        "service": settings.SERVICE_NAME,
        "total": len(events),
        "events": [
            {
                "event_id": e.event_id,
                "service": e.service,
                "action": e.action,
                "actor": e.actor,
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "trace_id": e.trace_id,
                "integrity": e.integrity,
            }
            for e in events
        ],
    }
