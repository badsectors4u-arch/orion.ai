"""Initial core schema for Users, Targets, Scans, Vulnerabilities, and Knowledgebase.

Revision ID: 0001
Revises: 
Create Date: 2026-10-31 20:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True, index=True),
        sa.Column('username', sa.String(length=64), nullable=True, unique=True, index=True),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('plan', sa.String(length=20), nullable=False, server_default='free'),
        sa.Column('scans_today', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_scan_reset', sa.Date(), nullable=False),
        sa.Column('ai_provider', sa.String(length=50), nullable=True),
        sa.Column('ai_api_key', sa.String(length=255), nullable=True),
        sa.Column('ai_base_url', sa.String(length=255), nullable=True),
        sa.Column('ai_model', sa.String(length=100), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

    # Targets table
    op.create_table(
        'targets',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('url', sa.String(length=500), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

    # Scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('target_id', sa.String(length=36), sa.ForeignKey('targets.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('target_url', sa.String(length=500), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('scan_type', sa.String(length=20), nullable=False, server_default='full'),
        sa.Column('plan', sa.String(length=20), nullable=False, server_default='advanced'),
        sa.Column('ai_hunter_duration', sa.Integer(), nullable=False, server_default='300'),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_tool', sa.String(length=50), nullable=True),
        sa.Column('raw_results', sa.JSON(), nullable=True),
        sa.Column('ai_analysis', sa.JSON(), nullable=True),
        sa.Column('attack_graph', sa.JSON(), nullable=True),
        sa.Column('attack_chains', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )

    # Vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('service', sa.String(length=100), nullable=False, server_default='http'),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('cve_id', sa.String(length=64), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('remediation_steps', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

    # Knowledgebase Articles table
    op.create_table(
        'knowledgebase_articles',
        sa.Column('id', sa.String(length=100), primary_key=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('cwe_id', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('vulnerable_code', sa.Text(), nullable=True),
        sa.Column('remediation_code', sa.Text(), nullable=True),
        sa.Column('references', sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('knowledgebase_articles')
    op.drop_table('vulnerabilities')
    op.drop_table('scans')
    op.drop_table('targets')
    op.drop_table('users')

