"""
Orion Security Platform — Executive PDF Export Route.

Endpoint:
  GET /api/scans/{scan_id}/pdf
  Generates and streams an executive-ready security penetration test assessment report
  complete with branded color coding, risk metrics, and 4-section vulnerability dossiers.
"""
from __future__ import annotations

import io
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from orion.api.deps import get_current_user
from orion.models.database import Scan, User, get_db
from orion.services.pdf_generator import generate_pdf_report

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["Report Export"])


@router.get("/{scan_id}/pdf")
async def export_scan_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Exports a completed or running scan as a high-fidelity executive PDF assessment report.
    Includes CVSS scores, remediation code, attack chains, and executive risk metrics.
    """
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan session '{scan_id}' not found or access denied.",
        )

    # Format findings dictionary for Member 3's PDF engine
    vuln_list = []
    for v in scan.vulnerabilities:
        vuln_list.append({
            "id": str(v.id),
            "title": v.title,
            "severity": v.severity,
            "service": v.service,
            "port": v.port,
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
            "description": v.description,
            "remediation_steps": v.remediation_steps or [],
        })

    scan_dict: Dict[str, Any] = {
        "id": str(scan.id),
        "target_url": scan.target_url,
        "status": scan.status,
        "scan_type": scan.scan_type,
        "plan": scan.plan,
        "risk_score": scan.risk_score,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "ai_analysis": scan.ai_analysis or {},
        "vulnerabilities": vuln_list,
        "attack_graph": scan.attack_graph or {},
    }

    try:
        pdf_bytes = await generate_pdf_report(scan_dict, scan.target_url)
        filename = f"orion_report_{str(scan.id)[:8]}.pdf"

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    except Exception as exc:
        logger.error(f"Error generating PDF report for scan {scan_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate assessment PDF: {str(exc)}",
        )

