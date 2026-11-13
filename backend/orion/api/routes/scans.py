"""
Orion Security Platform — Scan Management Routes.

Endpoints:
  POST   /api/scans          — Launch a new vulnerability scan (Quota checked)
  GET    /api/scans          — List all scans for the authenticated user
  GET    /api/scans/{id}     — Retrieve comprehensive scan details, vulnerabilities, and graph
  DELETE /api/scans/{id}     — Delete scan session and cascading records
"""
from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from orion.api.deps import check_daily_quota, get_current_user, get_db
from orion.models.database import Scan, Target, User, Vulnerability
from orion.models.schemas import ScanCreate, ScanDetailResponse, ScanResponse, VulnerabilityResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["Scans"])


def _normalize_url(raw: str) -> str:
    """Ensures URL has a proper scheme."""
    cleaned = raw.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def launch_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(check_daily_quota),
    db: Session = Depends(get_db),
):
    """
    Initiates a new vulnerability scan.
    - Enforces Free Tier quota (max 3 scans/day).
    - Automatically finds or registers the target URL.
    - Dispatches execution to Celery queue (with async background fallback).
    """
    target_url = _normalize_url(payload.target_url)
    parsed = urlparse(target_url)
    domain = parsed.hostname or target_url

    # Find existing target or register new one
    target = (
        db.query(Target)
        .filter(Target.user_id == current_user.id, Target.url == target_url)
        .first()
    )
    if not target:
        target = Target(user_id=current_user.id, url=target_url, domain=domain)
        db.add(target)
        db.commit()
        db.refresh(target)

    # Determine scanning plan & AI budget
    effective_plan = payload.plan or current_user.plan or "advanced"
    ai_duration = payload.ai_hunter_duration if payload.ai_hunter_duration is not None else 300

    scan = Scan(
        target_id=target.id,
        user_id=current_user.id,
        target_url=target_url,
        status="pending",
        scan_type=payload.scan_type,
        plan=effective_plan,
        ai_hunter_duration=ai_duration,
        progress=0,
        current_tool="queued",
    )
    db.add(scan)

    # Increment daily usage count for free users
    if current_user.plan == "free":
        current_user.scans_today += 1

    db.commit()
    db.refresh(scan)

    # Dispatch to Celery background worker with fallback to FastAPI background task
    scan_id_str = str(scan.id)
    celery_dispatched = False
    try:
        from orion.tasks.scan_tasks import run_scan_task
        run_scan_task.delay(scan_id_str)
        celery_dispatched = True
        logger.info(f"[Scan {scan_id_str}] Successfully dispatched to Celery worker queue.")
    except Exception as exc:
        logger.warning(
            f"[Scan {scan_id_str}] Celery dispatch unavailable ({exc}). Using FastAPI BackgroundTasks."
        )

    if not celery_dispatched:
        from orion.tasks.scan_tasks import execute_scan_task_sync
        background_tasks.add_task(execute_scan_task_sync, scan_id_str)

    return ScanResponse.model_validate(scan)


@router.get("", response_model=List[ScanResponse])
def list_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves all scans initiated by the authenticated user, ordered newest first."""
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return [ScanResponse.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan_detail(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns full scan results, including 4-section vulnerability reports,
    attack graph topology, and AI attack planner chains.
    """
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan session not found or access denied.",
        )

    # Serialize vulnerabilities
    vuln_items = [VulnerabilityResponse.model_validate(v) for v in scan.vulnerabilities]

    return ScanDetailResponse(
        id=str(scan.id),
        target_url=scan.target_url,
        status=scan.status,
        scan_type=scan.scan_type,
        plan=scan.plan,
        progress=scan.progress,
        current_tool=scan.current_tool,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        vulnerabilities=vuln_items,
        attack_graph=scan.attack_graph or {},
        attack_chains=scan.attack_chains or [],
        ai_analysis=scan.ai_analysis or {},
    )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Deletes a scan session and cascades deletion to all vulnerabilities found."""
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan session not found or access denied.",
        )

    db.delete(scan)
    db.commit()
    return None

