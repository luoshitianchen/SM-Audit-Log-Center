"""审计保留策略模型：按事件类型控制数据保留天数。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models.base import Base


class AuditRetentionPolicy(Base):
    """审计保留策略：按名称唯一，控制某类事件的保留天数。"""

    __tablename__ = "audit_retention_policies"
    __table_args__ = (UniqueConstraint("name", name="uq_retention_policy_name"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    # 命中该策略的事件动作前缀，如 user.
    action_prefix: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
