"""
Orion Security Platform — Target Management Routes.

Endpoints:
  POST   /api/targets      — Register a new scan target
  GET    /api/targets      — List all targets owned by the current user
  DELETE /api/targets/{id} — Remove a target and its associated scan records
"""
from __future__ import annotations

from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from orion.api.deps import get_current_user, get_db
from orion.models.database import Target, User
from orion.models.schemas import TargetCreate, TargetResponse

router = APIRouter(prefix="/api/targets", tags=["Targets"])


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Registers a new scan target associated with the authenticated user."""
    raw_url = payload.url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"https://{raw_url}"

    parsed = urlparse(raw_url)
    domain = parsed.hostname or raw_url

    target = Target(
        user_id=current_user.id,
        url=raw_url,
        domain=domain,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return TargetResponse.model_validate(target)


@router.get("", response_model=list[TargetResponse])
def list_targets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves all targets registered by the authenticated user."""
    targets = (
        db.query(Target)
        .filter(Target.user_id == current_user.id)
        .order_by(Target.created_at.desc())
        .all()
    )
    return [TargetResponse.model_validate(t) for t in targets]


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Deletes a target and its cascading history. Only the owner can delete their target."""
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    db.delete(target)
    db.commit()
    return None

