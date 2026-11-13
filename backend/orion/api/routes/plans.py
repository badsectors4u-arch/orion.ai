"""
Orion Security Platform — Subscription Plans & Quota Routes.

Endpoints:
  GET  /api/plans/quota   — Query daily scan quota and remaining balance
  POST /api/plans/upgrade — Upgrade user subscription tier (Free -> Pro / Enterprise)
"""
from __future__ import annotations

from datetime import date
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from orion.api.deps import get_current_user, get_db
from orion.models.database import User
from orion.models.schemas import PlanUpgradeRequest, PlanUpgradeResponse, QuotaResponse

router = APIRouter(prefix="/api/plans", tags=["Plans & Subscriptions"])


@router.get("/quota", response_model=QuotaResponse)
def get_user_quota(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns the user's active subscription plan and scan usage limits:
    - Free tier: 3 scans per day (resets daily at 00:00 UTC).
    - Pro / Enterprise: Unlimited scans (limit = -1).
    """
    # Check if a new day has arrived and reset count
    today = date.today()
    if current_user.last_scan_reset < today:
        current_user.scans_today = 0
        current_user.last_scan_reset = today
        db.commit()
        db.refresh(current_user)

    plan = current_user.plan.lower()
    if plan == "free":
        daily_limit = 3
        scans_remaining = max(0, daily_limit - current_user.scans_today)
    else:
        daily_limit = -1  # Unlimited
        scans_remaining = -1

    return QuotaResponse(
        plan=current_user.plan,
        scans_today=current_user.scans_today,
        daily_limit=daily_limit,
        scans_remaining=scans_remaining,
    )


@router.post("/upgrade", response_model=PlanUpgradeResponse)
def upgrade_plan(
    payload: PlanUpgradeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Directly upgrades the user's subscription tier.
    Unlocks unlimited scans, deep AI hunting (10-15 mins), and full remediation code.
    """
    current_user.plan = payload.plan
    db.commit()
    db.refresh(current_user)

    return PlanUpgradeResponse(
        success=True,
        new_plan=current_user.plan,
        message=f"Subscription successfully upgraded to {payload.plan.upper()}. Enjoy unlimited security scanning!",
    )

