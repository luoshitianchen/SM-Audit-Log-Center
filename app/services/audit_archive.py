"""审计归档服务层：归档任务生命周期管理。"""
from __future__ import annotations

import uuid

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed
from app.models.audit_archive import AuditArchive
from app.repositories import audit_archive as repo
from app.schemas.audit_governance import AuditArchiveCreate, AuditArchiveFinish
from app.services.audit import record_audit


def _archive_to_dict(a: AuditArchive) -> dict:
    return {
        "id": a.id, "archive_name": a.archive_name, "period": a.period,
        "record_count": a.record_count, "storage_uri": a.storage_uri,
        "status": a.status, "note": a.note,
        "created_at": a.created_at.isoformat() if a.created_at else "",
        "updated_at": a.updated_at.isoformat() if a.updated_at else "",
    }


class AuditArchiveService:
    @staticmethod
    async def list_archives(
        session: AsyncSession, limit: int, offset: int,
        status_filter: str | None, period: str | None, keyword: str | None,
    ) -> dict:
        items = await repo.list_archives(
            session, limit=limit, offset=offset,
            status=status_filter, period=period, keyword=keyword,
        )
        total = await repo.count_archives(
            session, status=status_filter, period=period, keyword=keyword,
        )
        return {"total": total, "items": [_archive_to_dict(a) for a in items]}

    @staticmethod
    async def get_archive(session: AsyncSession, archive_id: str) -> dict:
        archive = await repo.get_archive(session, archive_id)
        if not archive:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "归档记录不存在")
        return _archive_to_dict(archive)

    @staticmethod
    async def create_archive(session: AsyncSession, payload: AuditArchiveCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        if await repo.get_archive_by_name(session, payload.archive_name):
            raise HTTPException(status.HTTP_409_CONFLICT, "归档名称已存在")
        archive = AuditArchive(
            id=str(uuid.uuid4()),
            archive_name=payload.archive_name,
            period=payload.period,
            record_count=payload.record_count,
            storage_uri=payload.storage_uri,
            status="in_progress",
            note=payload.note,
        )
        archive = await repo.create_archive(session, archive)
        await record_audit(session, "audit_archive.created", "internal",
                           f"name={payload.archive_name} period={payload.period}", request)
        return _archive_to_dict(archive)

    @staticmethod
    async def finish_archive(
        session: AsyncSession, archive_id: str, payload: AuditArchiveFinish, request: Request,
    ) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        archive = await repo.get_archive(session, archive_id)
        if not archive:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "归档记录不存在")
        if archive.status != "in_progress":
            raise HTTPException(status.HTTP_409_CONFLICT, "仅进行中的归档可回写状态")
        archive.status = payload.status
        if payload.record_count is not None:
            archive.record_count = payload.record_count
        if payload.storage_uri is not None:
            archive.storage_uri = payload.storage_uri
        archive = await repo.update_archive(session, archive)
        await record_audit(session, "audit_archive.finished", "internal",
                           f"id={archive_id} status={payload.status}", request)
        return _archive_to_dict(archive)
