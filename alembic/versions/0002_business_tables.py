"""新增业务表（审计归档 / 导出 / 保留策略）

Revision ID: 0002_business_tables
Revises: 0001_initial
Create Date: 2026-09-23
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# 本迁移由 autogenerate 生成，手动调整 revision 标识为 0002_business_tables
revision: str = '0002_business_tables'
down_revision: Union[str, None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### 自动生成开始：创建审计业务表 ###
    # 审计归档表：按周期归档历史审计日志
    op.create_table('audit_archives',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('archive_name', sa.String(length=128), nullable=False),
    sa.Column('period', sa.String(length=16), nullable=False),
    sa.Column('record_count', sa.Integer(), nullable=False),
    sa.Column('storage_uri', sa.String(length=512), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('note', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_archives_archive_name'), 'audit_archives', ['archive_name'], unique=True)
    op.create_index(op.f('ix_audit_archives_period'), 'audit_archives', ['period'], unique=False)
    op.create_index(op.f('ix_audit_archives_status'), 'audit_archives', ['status'], unique=False)
    # 审计导出表：记录按需导出审计日志的任务
    op.create_table('audit_exports',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('export_format', sa.String(length=16), nullable=False),
    sa.Column('query_filter', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('file_uri', sa.String(length=512), nullable=False),
    sa.Column('row_count', sa.Integer(), nullable=False),
    sa.Column('requested_by', sa.String(length=128), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_exports_status'), 'audit_exports', ['status'], unique=False)
    # 审计保留策略表：按动作前缀配置保留天数
    op.create_table('audit_retention_policies',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('action_prefix', sa.String(length=128), nullable=False),
    sa.Column('retention_days', sa.Integer(), nullable=False),
    sa.Column('is_enabled', sa.Boolean(), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name', name='uq_retention_policy_name')
    )
    op.create_index(op.f('ix_audit_retention_policies_name'), 'audit_retention_policies', ['name'], unique=False)
    # ### 自动生成结束 ###


def downgrade() -> None:
    # ### 自动生成开始：回滚业务表 ###
    op.drop_index(op.f('ix_audit_retention_policies_name'), table_name='audit_retention_policies')
    op.drop_table('audit_retention_policies')
    op.drop_index(op.f('ix_audit_exports_status'), table_name='audit_exports')
    op.drop_table('audit_exports')
    op.drop_index(op.f('ix_audit_archives_status'), table_name='audit_archives')
    op.drop_index(op.f('ix_audit_archives_period'), table_name='audit_archives')
    op.drop_index(op.f('ix_audit_archives_archive_name'), table_name='audit_archives')
    op.drop_table('audit_archives')
    # ### 自动生成结束 ###
