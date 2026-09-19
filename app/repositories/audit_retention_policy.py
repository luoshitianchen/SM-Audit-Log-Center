"""审计保留策略仓储层。"""
from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_retention_policy import AuditRetentionPolicy


async def get_policy(session: AsyncSession, policy_id: str) -> AuditRetentionPolicy | None:
    result = await session.execute(select(AuditRetentionPolicy).where(AuditRetentionPolicy.id == policy_id))
    return result.scalar_one_or_none()


async def get_policy_by_name(session: AsyncSession, name: str) -> AuditRetentionPolicy | None:
    result = await session.execute(select(AuditRetentionPolicy).where(AuditRetentionPolicy.name == name))
    return result.scalar_one_or_none()


async def list_policies(
    session: AsyncSession, limit: int = 100, offset: int = 0,
    enabled: bool | None = None, keyword: str | None = None,
) -> list[AuditRetentionPolicy]:
    stmt = select(AuditRetentionPolicy).order_by(AuditRetentionPolicy.created_at.desc())
    if enabled is not None:
        stmt = stmt.where(AuditRetentionPolicy.is_enabled == enabled)
    if keyword:
        pattern = f"%{keyword}%"
        stmt = stmt.where(or_(
            AuditRetentionPolicy.name.like(pattern),
            AuditRetentionPolicy.action_prefix.like(pattern),
            AuditRetentionPolicy.description.like(pattern),
        ))
    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_policies(
    session: AsyncSession, enabled: bool | None = None, keyword: str | None = None,
) -> int:
    stmt = select(func.count(AuditRetentionPolicy.id))
    if enabled is not None:
        stmt = stmt.where(AuditRetentionPolicy.is_enabled == enabled)
    if keyword:
        pattern = f"%{keyword}%"
        stmt = stmt.where(or_(
            AuditRetentionPolicy.name.like(pattern),
            AuditRetentionPolicy.action_prefix.like(pattern),
            AuditRetentionPolicy.description.like(pattern),
        ))
    result = await session.execute(stmt)
    return int(result.scalar_one())


async def create_policy(session: AsyncSession, policy: AuditRetentionPolicy) -> AuditRetentionPolicy:
    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    return policy


async def update_policy(session: AsyncSession, policy: AuditRetentionPolicy) -> AuditRetentionPolicy:
    await session.commit()
    await session.refresh(policy)
    return policy


async def delete_policy(session: AsyncSession, policy: AuditRetentionPolicy) -> None:
    await session.delete(policy)
    await session.commit()
