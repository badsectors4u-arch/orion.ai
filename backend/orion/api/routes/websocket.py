"""
Orion Security Platform — Real-Time WebSocket Channel.

Endpoint:
  WS /api/ws/scans/{scan_id}
  Subscribes to Redis Pub/Sub channel 'scan:{scan_id}' and broadcasts live progress,
  tool switches, and completion events directly to connected frontend clients.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from orion.models.database import Scan, SessionLocal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ws", tags=["WebSocket"])

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


async def _poll_db_fallback(websocket: WebSocket, scan_id: str):
    """
    Fallback loop: If Redis is unavailable, polls the DB every second
    to stream progress updates to the frontend without breaking.
    """
    last_progress = -1
    last_status = ""

    while True:
        await asyncio.sleep(1.0)
        db: Session = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                await websocket.send_text(
                    json.dumps({"type": "error", "message": f"Scan {scan_id} not found."})
                )
                break

            if scan.progress != last_progress or scan.status != last_status:
                last_progress = scan.progress
                last_status = scan.status

                if scan.status == "completed":
                    await websocket.send_text(
                        json.dumps({
                            "type": "completed",
                            "scan_id": scan_id,
                            "percentage": 100,
                            "message": "Vulnerability scan completed successfully.",
                            "risk_score": scan.risk_score,
                        })
                    )
                    break
                elif scan.status == "failed":
                    await websocket.send_text(
                        json.dumps({
                            "type": "error",
                            "scan_id": scan_id,
                            "message": "Scan failed during execution.",
                        })
                    )
                    break
                else:
                    await websocket.send_text(
                        json.dumps({
                            "type": "progress",
                            "scan_id": scan_id,
                            "percentage": scan.progress,
                            "current_tool": scan.current_tool or "active",
                            "message": f"Running {scan.current_tool or 'analysis'}...",
                        })
                    )
        finally:
            db.close()


@router.websocket("/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """
    WebSocket connection streaming live scan progress updates.
    Connects to Redis PubSub if available, or seamlessly uses the DB poller fallback.
    """
    await websocket.accept()
    logger.info(f"[WS] Client connected for scan_id: {scan_id}")

    # 1. Verify scan existence
    db: Session = SessionLocal()
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
    finally:
        db.close()

    if not scan:
        await websocket.send_text(
            json.dumps({"type": "error", "message": f"Scan '{scan_id}' not found."})
        )
        await websocket.close()
        return

    # If scan is already completed, send immediate finished event
    if scan.status == "completed":
        await websocket.send_text(
            json.dumps({
                "type": "completed",
                "scan_id": scan_id,
                "percentage": 100,
                "message": "Scan is already completed.",
                "risk_score": scan.risk_score,
            })
        )
        await websocket.close()
        return

    # 2. Try Redis PubSub connection
    redis_client = None
    pubsub = None
    try:
        import redis.asyncio as aioredis  # type: ignore

        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        # Test ping
        await asyncio.wait_for(redis_client.ping(), timeout=1.0)
        pubsub = redis_client.pubsub()
        channel_name = f"scan:{scan_id}"
        await pubsub.subscribe(channel_name)
        logger.info(f"[WS] Subscribed to Redis channel: {channel_name}")

        while True:
            # Receive message from Redis channel
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message.get("type") == "message":
                data = message.get("data")
                if isinstance(data, str):
                    await websocket.send_text(data)
                    try:
                        parsed = json.loads(data)
                        if parsed.get("type") in ("completed", "error"):
                            break
                    except Exception:
                        pass
            await asyncio.sleep(0.1)

    except (WebSocketDisconnect, asyncio.CancelledError):
        logger.info(f"[WS] Client disconnected from scan_id: {scan_id}")
    except Exception as exc:
        logger.warning(
            f"[WS] Redis PubSub unavailable ({exc}). Falling back to database polling mode."
        )
        try:
            await _poll_db_fallback(websocket, scan_id)
        except (WebSocketDisconnect, asyncio.CancelledError):
            logger.info(f"[WS] Client disconnected during fallback polling.")
        except Exception as e:
            logger.error(f"[WS] Error during fallback polling: {e}")
    finally:
        if pubsub:
            try:
                await pubsub.unsubscribe(f"scan:{scan_id}")
                await pubsub.close()
            except Exception:
                pass
        if redis_client:
            try:
                await redis_client.close()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass

