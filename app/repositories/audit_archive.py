"""审计归档记录仓储层。"""
from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_archive import AuditArchive


async def get_archive(session: AsyncSession, archive_id: str) -> AuditArchive | None:
    result = await session.execute(select(AuditArchive).where(AuditArchive.id == archive_id))
    return result.scalar_one_or_none()


async def get_archive_by_name(session: AsyncSession, name: str) -> AuditArchive | None:
    result = await session.execute(select(AuditArchive).where(AuditArchive.archive_name == name))
    return result.scalar_one_or_none()


async def list_archives(
    session: AsyncSession, limit: int = 100, offset: int = 0,
    status: str | None = None, period: str | None = None, keyword: str | None = None,
) -> list[AuditArchive]:
    stmt = select(AuditArchive).order_by(AuditArchive.created_at.desc())
    if status:
        stmt = stmt.where(AuditArchive.status == status)
    if period:
        stmt = stmt.where(AuditArchive.period == period)
    if keyword:
        pattern = f"%{keyword}%"
        stmt = stmt.where(or_(
            AuditArchive.archive_name.like(pattern),
            AuditArchive.note.like(pattern),
        ))
    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_archives(
    session: AsyncSession, status: str | None = None,
    period: str | None = None, keyword: str | None = None,
) -> int:
    stmt = select(func.count(AuditArchive.id))
    if status:
        stmt = stmt.where(AuditArchive.status == status)
    if period:
        stmt = stmt.where(AuditArchive.period == period)
    if keyword:
        pattern = f"%{keyword}%"
        stmt = stmt.where(or_(
            AuditArchive.archive_name.like(pattern),
            AuditArchive.note.like(pattern),
        ))
    result = await session.execute(stmt)
    return int(result.scalar_one())


async def create_archive(session: AsyncSession, archive: AuditArchive) -> AuditArchive:
    session.add(archive)
    await session.commit()
    await session.refresh(archive)
    return archive


async def update_archive(session: AsyncSession, archive: AuditArchive) -> AuditArchive:
    await session.commit()
    await session.refresh(archive)
    return archive
