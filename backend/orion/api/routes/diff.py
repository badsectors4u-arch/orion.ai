"""
Orion Security Platform — Scan Comparison (Diff) Route.

Endpoint:
  GET /api/scans/compare?scan_a={id}&scan_b={id}
  Calculates resolved, new, and persistent vulnerabilities between two historical scans
  and produces a quantitative security score improvement metric.
"""
from __future__ import annotations

from typing import Dict, List, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from orion.api.deps import get_current_user
from orion.models.database import Scan, User, Vulnerability, get_db
from orion.models.schemas import ScanDiffResult, VulnerabilityItem

router = APIRouter(prefix="/api/scans", tags=["Scan Comparison"])


def _vulnerability_key(v: Vulnerability) -> Tuple[str, int, str]:
    """Generates a stable comparison fingerprint for a vulnerability."""
    return (
        v.title.strip().lower(),
        v.port or 0,
        (v.service or "http").strip().lower(),
    )


def _to_item(v: Vulnerability) -> VulnerabilityItem:
    return VulnerabilityItem(
        id=str(v.id),
        title=v.title,
        severity=v.severity,  # type: ignore
        service=v.service,
        port=v.port,
        cve_id=v.cve_id,
        cvss_score=v.cvss_score,
        description=v.description,
        remediation_steps=v.remediation_steps or [],
    )


@router.get("/compare", response_model=ScanDiffResult)
def compare_scans(
    scan_a: str = Query(..., description="Baseline historical scan ID (Scan A)"),
    scan_b: str = Query(..., description="Target or follow-up scan ID (Scan B)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Compares two completed scans against the same target:
    - Resolved: Vulnerabilities present in Scan A but remediated in Scan B.
    - New: Vulnerabilities introduced in Scan B not present in Scan A.
    - Persistent: Vulnerabilities still open across both scans.
    - Improvement Score: Net percentage change in security posture.
    """
    if scan_a == scan_b:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot compare a scan with itself. Please select two distinct scans.",
        )

    # 1. Fetch both scans and verify ownership
    scan_1 = (
        db.query(Scan)
        .filter(Scan.id == scan_a, Scan.user_id == current_user.id)
        .first()
    )
    scan_2 = (
        db.query(Scan)
        .filter(Scan.id == scan_b, Scan.user_id == current_user.id)
        .first()
    )

    if not scan_1:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline scan '{scan_a}' not found or access denied.",
        )
    if not scan_2:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Comparison scan '{scan_b}' not found or access denied.",
        )

    # 2. Both scans should be completed
    if scan_1.status != "completed" or scan_2.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Both scans must be in 'completed' status to perform a diff comparison.",
        )

    # 3. Both scans should target the same host
    if scan_1.target_url.strip().lower() != scan_2.target_url.strip().lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot compare scans of different targets ('{scan_1.target_url}' vs '{scan_2.target_url}').",
        )

    # 4. Map vulnerabilities by composite key
    map_a: Dict[Tuple[str, int, str], Vulnerability] = {
        _vulnerability_key(v): v for v in scan_1.vulnerabilities
    }
    map_b: Dict[Tuple[str, int, str], Vulnerability] = {
        _vulnerability_key(v): v for v in scan_2.vulnerabilities
    }

    resolved_keys = set(map_a.keys()) - set(map_b.keys())
    new_keys = set(map_b.keys()) - set(map_a.keys())
    persistent_keys = set(map_a.keys()) & set(map_b.keys())

    resolved_items = [_to_item(map_a[k]) for k in resolved_keys]
    new_items = [_to_item(map_b[k]) for k in new_keys]
    persistent_items = [_to_item(map_b[k]) for k in persistent_keys]

    # 5. Security score improvement formula:
    # ((resolved - new) / max(all_a, 1)) * 100
    total_a = len(scan_1.vulnerabilities)
    denominator = max(total_a, 1)
    net_improvement = ((len(resolved_items) - len(new_items)) / denominator) * 100.0
    # Round to 1 decimal place
    security_score_improvement = round(net_improvement, 1)

    return ScanDiffResult(
        scan_a_id=str(scan_1.id),
        scan_b_id=str(scan_2.id),
        target_url=scan_1.target_url,
        resolved_vulnerabilities=resolved_items,
        new_vulnerabilities=new_items,
        persistent_vulnerabilities=persistent_items,
        security_score_improvement=security_score_improvement,
    )

