"""
Orion Security Platform — Celery Background Scan Tasks.

Orchestrates multi-phase security scanning workflows:
1. Loads scan target and user subscription quota.
2. Configures AI adapter (BYOK, OpenRouter, or Local Ollama).
3. Executes Member 3's core ScanOrchestrator pipeline (Nmap, Katana, Nuclei, AIDeepHunter, GhostAnalyst).
4. Persists 4-section vulnerability findings, attack graphs, and attack chains to PostgreSQL/SQLite.
5. Broadcasts real-time completion events across Redis Pub/Sub channel 'scan:{scan_id}'.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from orion.models.database import Scan, SessionLocal, User, Vulnerability
from orion.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


async def execute_scan_async(scan_id: str) -> None:
    """
    Core asynchronous scanning worker logic.
    Can be called by Celery workers or directly via FastAPI BackgroundTasks.
    """
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"[Scan {scan_id}] Scan session not found in database.")
            return

        user = db.query(User).filter(User.id == scan.user_id).first()

        # 1. Update status to running
        scan.status = "running"
        scan.progress = 5
        scan.current_tool = "orchestrator_init"
        db.commit()
        db.refresh(scan)

        # 2. Extract user settings and AI configuration
        user_plan = getattr(user, "plan", "advanced") if user else "advanced"
        ai_duration = getattr(scan, "ai_hunter_duration", 300) or 300

        ai_config: Dict[str, Any] = {}
        if user and getattr(user, "ai_provider", None):
            ai_config = {
                "provider": user.ai_provider,
                "api_key": getattr(user, "ai_api_key", None),
                "base_url": getattr(user, "ai_base_url", None),
                "model": getattr(user, "ai_model", None),
            }

        # 3. Connect Redis client for real-time progress publication
        redis_client = None
        try:
            import redis.asyncio as aioredis  # type: ignore
            redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
            await redis_client.ping()
        except Exception as redis_exc:
            logger.warning(f"[Scan {scan_id}] Redis unavailable for Pub/Sub ({redis_exc}). Proceeding.")
            redis_client = None

        # 4. Instantiate Member 3's central ScanOrchestrator
        from orion.core.orchestrator import ScanOrchestrator
        orchestrator = ScanOrchestrator(ai_config=ai_config)

        logger.info(
            f"[Scan {scan_id}] Starting pipeline for {scan.target_url} "
            f"(Plan: {user_plan}, AI Hunter Budget: {ai_duration}s)..."
        )

        scan_result = await orchestrator.run_full_scan(
            target_url=scan.target_url,
            scan_type=scan.scan_type or "full",
            scan_id=str(scan.id),
            redis_client=redis_client,
            allow_private=False,
            plan=user_plan,
            ai_hunter_duration=ai_duration,
        )

        # 5. Extract results & graphs
        risk_score = getattr(scan_result, "risk_score", 0.0)
        attack_graph = getattr(scan_result, "attack_graph", {})
        attack_chains = getattr(scan_result, "attack_chains", [])
        ai_analysis = getattr(scan_result, "ai_analysis", {})
        raw_results = (
            scan_result.model_dump()
            if hasattr(scan_result, "model_dump")
            else (scan_result if isinstance(scan_result, dict) else {})
        )

        # 6. Update scan metadata
        scan.status = "completed"
        scan.progress = 100
        scan.current_tool = "completed"
        scan.completed_at = datetime.utcnow()
        scan.risk_score = risk_score
        scan.attack_graph = attack_graph
        scan.attack_chains = attack_chains
        scan.ai_analysis = ai_analysis
        scan.raw_results = raw_results

        # 7. Persist vulnerabilities
        raw_vulns = getattr(scan_result, "vulnerabilities", [])
        for v in raw_vulns:
            # Handle Pydantic model or dict
            v_title = getattr(v, "title", None) or (v.get("title") if isinstance(v, dict) else "Unknown")
            v_severity = getattr(v, "severity", None) or (v.get("severity") if isinstance(v, dict) else "info")
            v_service = getattr(v, "service", None) or (v.get("service") if isinstance(v, dict) else "http")
            v_port = getattr(v, "port", None) or (v.get("port") if isinstance(v, dict) else None)
            v_cve = getattr(v, "cve_id", None) or (v.get("cve_id") if isinstance(v, dict) else None)
            v_cvss = getattr(v, "cvss_score", None) or (v.get("cvss_score") if isinstance(v, dict) else None)
            v_desc = getattr(v, "description", None) or (v.get("description") if isinstance(v, dict) else "")
            v_remed = getattr(v, "remediation_steps", None) or (v.get("remediation_steps") if isinstance(v, dict) else [])

            vuln_record = Vulnerability(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                title=str(v_title),
                severity=str(v_severity).lower(),
                service=str(v_service),
                port=int(v_port) if v_port is not None else None,
                cve_id=str(v_cve) if v_cve else None,
                cvss_score=float(v_cvss) if v_cvss is not None else None,
                description=str(v_desc),
                remediation_steps=v_remed if isinstance(v_remed, list) else [str(v_remed)],
            )
            db.add(vuln_record)

        db.commit()
        logger.info(f"[Scan {scan_id}] Successfully finished. Recorded {len(raw_vulns)} findings.")

        # 8. Broadcast completion message via Redis
        if redis_client:
            try:
                await redis_client.publish(
                    f"scan:{scan_id}",
                    json.dumps({
                        "type": "completed",
                        "scan_id": scan_id,
                        "percentage": 100,
                        "risk_score": risk_score,
                        "message": "Security scan completed successfully.",
                    }),
                )
            except Exception as pub_exc:
                logger.warning(f"[Scan {scan_id}] Redis PubSub publish error: {pub_exc}")

    except Exception as exc:
        logger.exception(f"[Scan {scan_id}] Unhandled failure during pipeline execution: {exc}")
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.progress = 0
                scan.current_tool = "error"
                db.commit()
        except Exception:
            pass

        # Try to publish error message via Redis
        try:
            if redis_client:
                await redis_client.publish(
                    f"scan:{scan_id}",
                    json.dumps({
                        "type": "error",
                        "scan_id": scan_id,
                        "message": f"Scan failed: {str(exc)}",
                    }),
                )
        except Exception:
            pass
    finally:
        if redis_client:
            try:
                await redis_client.close()
            except Exception:
                pass
        db.close()


def execute_scan_task_sync(scan_id: str) -> None:
    """Synchronous entry point that runs the async task in a clean event loop."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(execute_scan_async(scan_id))
        else:
            loop.run_until_complete(execute_scan_async(scan_id))
    except RuntimeError:
        asyncio.run(execute_scan_async(scan_id))


@celery_app.task(name="run_scan_task")
def run_scan_task(scan_id: str) -> str:
    """Celery task binding for distributed workers."""
    logger.info(f"[Celery] Worker starting task run_scan_task for scan: {scan_id}")
    execute_scan_task_sync(scan_id)
    return f"Completed scan {scan_id}"
