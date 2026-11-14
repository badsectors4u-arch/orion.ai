"""
Orion Security Platform — AI Security Copilot & Chatbot Route.

Endpoint:
  POST /api/ai/chat
  Interactive AI Security Analyst answering vulnerability inquiries, remediation strategies,
  and attack vectors grounded in real-time scan context.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from orion.ai.analyst import chat, get_sanitizer
from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.api.deps import get_current_user
from orion.models.database import Scan, User, get_db
from orion.models.schemas import ChatRequest, ChatResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["AI Security Copilot"])


def _build_scan_context(scan: Scan) -> Dict[str, Any]:
    """Serializes scan findings and targets into an LLM-digestible context window."""
    vulns_summary = []
    for v in scan.vulnerabilities[:15]:  # Include top 15 findings to avoid context overflow
        vulns_summary.append({
            "title": v.title,
            "severity": v.severity,
            "service": v.service,
            "port": v.port,
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
        })

    return {
        "target": scan.target_url,
        "scan_id": str(scan.id),
        "scan_type": scan.scan_type,
        "risk_score": scan.risk_score,
        "total_vulnerabilities": len(scan.vulnerabilities),
        "vulnerabilities": vulns_summary,
    }


@router.post("/chat", response_model=ChatResponse)
async def security_copilot_chat(
    payload: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Submits a user inquiry to the Orion AI Security Copilot.
    - Grounded in active scan findings when scan_id is provided.
    - Uses user-configured AI provider (BYOK / OpenRouter / Ollama) or default system adapter.
    - Provides structured remediation advice, bullet takeaways, and authoritative references.
    """
    scan_context: Dict[str, Any] = {}
    scan_id_key = payload.scan_id or "default"

    if payload.scan_id:
        scan = (
            db.query(Scan)
            .filter(Scan.id == payload.scan_id, Scan.user_id == current_user.id)
            .first()
        )
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan session '{payload.scan_id}' not found or access denied.",
            )
        scan_context = _build_scan_context(scan)

    # Prepare user-specific AI adapter if custom settings configured
    adapter: Optional[UniversalAIAdapter] = None
    if current_user.ai_provider:
        adapter = UniversalAIAdapter({
            "provider": current_user.ai_provider,
            "api_key": current_user.ai_api_key,
            "base_url": current_user.ai_base_url,
            "model": current_user.ai_model,
        })

    sanitizer = get_sanitizer(scan_id_key)

    try:
        reply = await chat(
            user_message=payload.message,
            scan_context=scan_context,
            sanitizer=sanitizer,
            history=payload.history,
            ai_adapter=adapter,
        )

        return ChatResponse(
            answer=reply.answer,
            key_points=reply.key_points,
            severity=reply.severity,
            suggestions=reply.suggestions,
            references=reply.references,
        )
    except Exception as exc:
        logger.error(f"Error executing AI security copilot chat: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI Copilot failed to process message: {str(exc)}",
        )

