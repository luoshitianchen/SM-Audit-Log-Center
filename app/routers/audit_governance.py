"""审计归档/导出/保留策略路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.schemas.audit_governance import (
    AuditArchiveCreate,
    AuditArchiveFinish,
    AuditExportCreate,
    AuditExportProgress,
    RetentionPolicyCreate,
    RetentionPolicyUpdate,
)
from app.services.audit_archive import AuditArchiveService
from app.services.audit_export import AuditExportService
from app.services.retention_policy import RetentionPolicyService

router = APIRouter(prefix="/api/audit", tags=["audit-governance"])


# ── 归档 ──
@router.get("/archives")
async def list_archives(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    period: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await AuditArchiveService.list_archives(
        session, limit=limit, offset=offset,
        status_filter=status_filter, period=period, keyword=keyword,
    )


@router.post("/archives", status_code=status.HTTP_201_CREATED)
async def create_archive(
    payload: AuditArchiveCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await AuditArchiveService.create_archive(session, payload, request)


@router.get("/archives/{archive_id}")
async def get_archive(
    archive_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await AuditArchiveService.get_archive(session, archive_id)


@router.post("/archives/{archive_id}/finish")
async def finish_archive(
    archive_id: str, payload: AuditArchiveFinish, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await AuditArchiveService.finish_archive(session, archive_id, payload, request)


# ── 导出 ──
@router.get("/exports")
async def list_exports(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    keyword: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await AuditExportService.list_exports(
        session, limit=limit, offset=offset,
        status_filter=status_filter, keyword=keyword,
    )


@router.post("/exports", status_code=status.HTTP_201_CREATED)
async def create_export(
    payload: AuditExportCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await AuditExportService.create_export(session, payload, request)


@router.get("/exports/{export_id}")
async def get_export(
    export_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await AuditExportService.get_export(session, export_id)


@router.patch("/exports/{export_id}/progress")
async def progress_export(
    export_id: str, payload: AuditExportProgress, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await AuditExportService.progress_export(session, export_id, payload, request)


# ── 保留策略 ──
@router.get("/retention-policies")
async def list_policies(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    enabled: bool | None = Query(default=None),
    keyword: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RetentionPolicyService.list_policies(
        session, limit=limit, offset=offset, enabled=enabled, keyword=keyword,
    )


@router.post("/retention-policies", status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: RetentionPolicyCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RetentionPolicyService.create_policy(session, payload, request)


@router.get("/retention-policies/{policy_id}")
async def get_policy(
    policy_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RetentionPolicyService.get_policy(session, policy_id)


@router.patch("/retention-policies/{policy_id}")
async def update_policy(
    policy_id: str, payload: RetentionPolicyUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RetentionPolicyService.update_policy(session, policy_id, payload, request)


@router.delete("/retention-policies/{policy_id}")
async def delete_policy(
    policy_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RetentionPolicyService.delete_policy(session, policy_id, request)
