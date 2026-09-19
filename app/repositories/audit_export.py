"""审计导出任务仓储层。"""
from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_export import AuditExport


async def get_export(session: AsyncSession, export_id: str) -> AuditExport | None:
    result = await session.execute(select(AuditExport).where(AuditExport.id == export_id))
    return result.scalar_one_or_none()


async def list_exports(
    session: AsyncSession, limit: int = 100, offset: int = 0,
    status: str | None = None, keyword: str | None = None,
) -> list[AuditExport]:
    stmt = select(AuditExport).order_by(AuditExport.created_at.desc())
    if status:
        stmt = stmt.where(AuditExport.status == status)
    if keyword:
        pattern = f"%{keyword}%"
        stmt = stmt.where(or_(
            AuditExport.requested_by.like(pattern),
            AuditExport.query_filter.like(pattern),
        ))
    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_exports(
    session: AsyncSession, status: str | None = None, keyword: str | None = None,
) -> int:
    stmt = select(func.count(AuditExport.id))
    if status:
        stmt = stmt.where(AuditExport.status == status)
    if keyword:
        pattern = f"%{keyword}%"
        stmt = stmt.where(or_(
            AuditExport.requested_by.like(pattern),
            AuditExport.query_filter.like(pattern),
        ))
    result = await session.execute(stmt)
    return int(result.scalar_one())


async def create_export(session: AsyncSession, export: AuditExport) -> AuditExport:
    session.add(export)
    await session.commit()
    await session.refresh(export)
    return export


async def update_export(session: AsyncSession, export: AuditExport) -> AuditExport:
    await session.commit()
    await session.refresh(export)
    return export
