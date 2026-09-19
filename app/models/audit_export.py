"""审计导出任务模型：异步把审计事件导出为文件。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models.base import Base


class AuditExport(Base):
    """审计导出任务：状态机 pending -> running -> completed/failed。"""

    __tablename__ = "audit_exports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # 导出格式：csv / json
    export_format: Mapped[str] = mapped_column(String(16), nullable=False, default="csv")
    query_filter: Mapped[str] = mapped_column(Text, default="")
    # 任务状态：pending / running / completed / failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    file_uri: Mapped[str] = mapped_column(String(512), default="")
    row_count: Mapped[int] = mapped_column(default=0)
    requested_by: Mapped[str] = mapped_column(String(128), default="internal")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
