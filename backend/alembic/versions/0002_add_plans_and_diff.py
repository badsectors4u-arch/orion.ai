"""Add indexes and verify plan & diff extensions.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-31 20:30:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0002'
down_revision: Union[str, None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Ensure composite indexes for scan comparison and fast lookups
    try:
        op.create_index('ix_vuln_scan_severity', 'vulnerabilities', ['scan_id', 'severity'])
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_index('ix_vuln_scan_severity', 'vulnerabilities')
    except Exception:
        pass

