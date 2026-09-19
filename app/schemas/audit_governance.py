"""审计归档/导出/保留策略 Pydantic 模型。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# ── 归档 ──
class AuditArchiveCreate(BaseModel):
    archive_name: str = Field(min_length=2, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    period: str = Field(min_length=7, max_length=16, pattern=r"^\d{4}-\d{2}$")
    record_count: int = Field(default=0, ge=0, le=10000000)
    storage_uri: str = Field(default="", max_length=512)
    note: str = Field(default="", max_length=1000)


class AuditArchiveFinish(BaseModel):
    """归档完成/失败回写。"""
    status: Literal["completed", "failed"]
    record_count: int | None = Field(default=None, ge=0, le=10000000)
    storage_uri: str | None = Field(default=None, max_length=512)


class AuditArchiveResponse(BaseModel):
    id: str
    archive_name: str
    period: str
    record_count: int
    storage_uri: str
    status: str
    note: str
    created_at: str
    updated_at: str


# ── 导出 ──
class AuditExportCreate(BaseModel):
    export_format: Literal["csv", "json"] = "csv"
    query_filter: str = Field(default="", max_length=1000)
    requested_by: str = Field(default="internal", max_length=128)


class AuditExportProgress(BaseModel):
    """导出任务状态推进。"""
    status: Literal["running", "completed", "failed"]
    file_uri: str | None = Field(default=None, max_length=512)
    row_count: int | None = Field(default=None, ge=0, le=10000000)
    error: str | None = Field(default=None, max_length=1000)


class AuditExportResponse(BaseModel):
    id: str
    export_format: str
    query_filter: str
    status: str
    file_uri: str
    row_count: int
    requested_by: str
    error: str
    created_at: str
    finished_at: str | None = None


# ── 保留策略 ──
class RetentionPolicyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    action_prefix: str = Field(default="", max_length=128)
    retention_days: int = Field(default=365, ge=1, le=3650)
    is_enabled: bool = True
    description: str = Field(default="", max_length=1000)


class RetentionPolicyUpdate(BaseModel):
    action_prefix: str | None = Field(default=None, max_length=128)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    is_enabled: bool | None = None
    description: str | None = Field(default=None, max_length=1000)


class RetentionPolicyResponse(BaseModel):
    id: str
    name: str
    action_prefix: str
    retention_days: int
    is_enabled: bool
    description: str
    created_at: str
    updated_at: str


class AuditListResponse(BaseModel):
    total: int
    items: list[BaseModel]
