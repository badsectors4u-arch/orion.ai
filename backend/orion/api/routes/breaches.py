"""
Orion Security Platform — Threat Intelligence Breach Checker Route.

Endpoint:
  POST /api/threats/breach-check
  Queries breach repositories (HaveIBeenPwned) to detect exposed credentials.
"""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, status

from orion.api.deps import get_current_user
from orion.models.database import User
from orion.models.schemas import BreachCheckRequest, BreachResult
from orion.services.breach_service import check_email_breach

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threats", tags=["Threat Intelligence"])


@router.post("/breach-check", response_model=BreachResult)
async def check_breach(
    payload: BreachCheckRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Checks if an email address is present in known historical data breaches.
    - Free tier: 1 lookup/day or standard access.
    - Pro / Enterprise: Unlimited lookups.
    """
    try:
        result_dict = await check_email_breach(payload.email)
        return BreachResult.model_validate(result_dict)
    except Exception as exc:
        logger.error(f"Error checking email breaches for {payload.email}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Breach check service error: {str(exc)}",
        )

