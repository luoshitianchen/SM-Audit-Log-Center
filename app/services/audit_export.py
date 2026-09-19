"""审计导出服务层：导出任务状态机管理。"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed
from app.models.audit_export import AuditExport
from app.repositories import audit_export as repo
from app.schemas.audit_governance import AuditExportCreate, AuditExportProgress
from app.services.audit import record_audit

# 状态机：pending -> running -> completed/failed；completed/failed 为终态
_TRANSITIONS = {
    "pending": {"running"},
    "running": {"completed", "failed"},
    "completed": set(),
    "failed": set(),
}


def _export_to_dict(e: AuditExport) -> dict:
    return {
        "id": e.id, "export_format": e.export_format, "query_filter": e.query_filter,
        "status": e.status, "file_uri": e.file_uri, "row_count": e.row_count,
        "requested_by": e.requested_by, "error": e.error,
        "created_at": e.created_at.isoformat() if e.created_at else "",
        "finished_at": e.finished_at.isoformat() if e.finished_at else None,
    }


class AuditExportService:
    @staticmethod
    async def list_exports(
        session: AsyncSession, limit: int, offset: int,
        status_filter: str | None, keyword: str | None,
    ) -> dict:
        items = await repo.list_exports(
            session, limit=limit, offset=offset, status=status_filter, keyword=keyword,
        )
        total = await repo.count_exports(session, status=status_filter, keyword=keyword)
        return {"total": total, "items": [_export_to_dict(e) for e in items]}

    @staticmethod
    async def get_export(session: AsyncSession, export_id: str) -> dict:
        export = await repo.get_export(session, export_id)
        if not export:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "导出任务不存在")
        return _export_to_dict(export)

    @staticmethod
    async def create_export(session: AsyncSession, payload: AuditExportCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        export = AuditExport(
            id=str(uuid.uuid4()),
            export_format=payload.export_format,
            query_filter=payload.query_filter,
            requested_by=payload.requested_by,
            status="pending",
        )
        export = await repo.create_export(session, export)
        await record_audit(session, "audit_export.created", "internal",
                           f"format={payload.export_format}", request)
        return _export_to_dict(export)

    @staticmethod
    async def progress_export(
        session: AsyncSession, export_id: str, payload: AuditExportProgress, request: Request,
    ) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        export = await repo.get_export(session, export_id)
        if not export:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "导出任务不存在")
        if payload.status not in _TRANSITIONS.get(export.status, set()):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"不允许从 {export.status} 迁移到 {payload.status}",
            )
        export.status = payload.status
        if payload.file_uri is not None:
            export.file_uri = payload.file_uri
        if payload.row_count is not None:
            export.row_count = payload.row_count
        if payload.error is not None:
            export.error = payload.error
        if payload.status in {"completed", "failed"}:
            export.finished_at = datetime.now(UTC)
        export = await repo.update_export(session, export)
        await record_audit(session, "audit_export.progressed", "internal",
                           f"id={export_id} status={payload.status}", request)
        return _export_to_dict(export)
