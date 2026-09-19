"""审计保留策略服务层：策略 CRUD 与启停。"""
from __future__ import annotations

import uuid

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed
from app.models.audit_retention_policy import AuditRetentionPolicy
from app.repositories import audit_retention_policy as repo
from app.schemas.audit_governance import RetentionPolicyCreate, RetentionPolicyUpdate
from app.services.audit import record_audit


def _policy_to_dict(p: AuditRetentionPolicy) -> dict:
    return {
        "id": p.id, "name": p.name, "action_prefix": p.action_prefix,
        "retention_days": p.retention_days, "is_enabled": p.is_enabled,
        "description": p.description,
        "created_at": p.created_at.isoformat() if p.created_at else "",
        "updated_at": p.updated_at.isoformat() if p.updated_at else "",
    }


class RetentionPolicyService:
    @staticmethod
    async def list_policies(
        session: AsyncSession, limit: int, offset: int,
        enabled: bool | None, keyword: str | None,
    ) -> dict:
        items = await repo.list_policies(
            session, limit=limit, offset=offset, enabled=enabled, keyword=keyword,
        )
        total = await repo.count_policies(session, enabled=enabled, keyword=keyword)
        return {"total": total, "items": [_policy_to_dict(p) for p in items]}

    @staticmethod
    async def get_policy(session: AsyncSession, policy_id: str) -> dict:
        policy = await repo.get_policy(session, policy_id)
        if not policy:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "保留策略不存在")
        return _policy_to_dict(policy)

    @staticmethod
    async def create_policy(session: AsyncSession, payload: RetentionPolicyCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        if await repo.get_policy_by_name(session, payload.name):
            raise HTTPException(status.HTTP_409_CONFLICT, "策略名称已存在")
        policy = AuditRetentionPolicy(
            id=str(uuid.uuid4()),
            name=payload.name,
            action_prefix=payload.action_prefix,
            retention_days=payload.retention_days,
            is_enabled=payload.is_enabled,
            description=payload.description,
        )
        policy = await repo.create_policy(session, policy)
        await record_audit(session, "retention_policy.created", "internal",
                           f"name={payload.name}", request)
        return _policy_to_dict(policy)

    @staticmethod
    async def update_policy(
        session: AsyncSession, policy_id: str, payload: RetentionPolicyUpdate, request: Request,
    ) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        policy = await repo.get_policy(session, policy_id)
        if not policy:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "保留策略不存在")
        if payload.action_prefix is not None:
            policy.action_prefix = payload.action_prefix
        if payload.retention_days is not None:
            policy.retention_days = payload.retention_days
        if payload.is_enabled is not None:
            policy.is_enabled = payload.is_enabled
        if payload.description is not None:
            policy.description = payload.description
        policy = await repo.update_policy(session, policy)
        await record_audit(session, "retention_policy.updated", "internal", f"id={policy_id}", request)
        return _policy_to_dict(policy)

    @staticmethod
    async def delete_policy(session: AsyncSession, policy_id: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        policy = await repo.get_policy(session, policy_id)
        if not policy:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "保留策略不存在")
        await repo.delete_policy(session, policy)
        await record_audit(session, "retention_policy.deleted", "internal", f"id={policy_id}", request)
        return {"deleted": True, "id": policy_id}
