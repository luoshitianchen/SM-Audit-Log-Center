"""审计归档记录模型：描述一次审计数据冷归档任务。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models.base import Base


class AuditArchive(Base):
    """审计归档记录：按周期把热数据导出到冷存储。"""

    __tablename__ = "audit_archives"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    archive_name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    # 归档周期，形如 2026-09
    period: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    storage_uri: Mapped[str] = mapped_column(String(512), default="")
    # 归档状态：in_progress / completed / failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="in_progress", index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
