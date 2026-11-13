"""
Orion Security Platform — Main FastAPI Application Entrypoint.

Assembles all API routers, WebSocket communication pipelines, CORS middleware,
database initialization, and automatic Swagger documentation (/docs).
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from orion.api.routes import (
    ai_router,
    auth,
    breaches,
    diff,
    knowledgebase,
    pdf_export,
    plans,
    scans,
    targets,
    websocket,
)
from orion.models.database import SessionLocal, init_db
from orion.services.kb_service import seed_knowledgebase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("orion.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: prepares database tables and seeds OWASP Knowledgebase."""
    logger.info("Initializing Orion database models...")
    init_db()

    # Seed OWASP Top 10 knowledgebase articles
    db = SessionLocal()
    try:
        await seed_knowledgebase(db)
    except Exception as exc:
        logger.warning(f"Could not seed knowledgebase on startup: {exc}")
    finally:
        db.close()

    logger.info("Orion Security Platform API startup completed.")
    yield
    logger.info("Orion Security Platform API shutting down cleanly.")


app = FastAPI(
    title="Orion Security Platform API",
    description=(
        "Comprehensive REST & WebSocket API for SaaS vulnerability scanning, "
        "AI deep hunting, attack graph generation, and automated pentest reporting."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ──────────────────────────────────────────────────────────────
# CORS Middleware Configuration
# ──────────────────────────────────────────────────────────────

ALLOWED_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:3000,http://localhost:80,http://127.0.0.1:5173,http://localhost",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if "*" in ALLOWED_ORIGINS else ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────
# Request Execution Timing Middleware
# ──────────────────────────────────────────────────────────────

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    return response


# ──────────────────────────────────────────────────────────────
# Mount API Routers
# ──────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(diff.router)
app.include_router(pdf_export.router)
app.include_router(scans.router)
app.include_router(breaches.router)
app.include_router(knowledgebase.router)
app.include_router(plans.router)
app.include_router(websocket.router)
app.include_router(ai_router.router)


# ──────────────────────────────────────────────────────────────
# Base Health Check Endpoint
# ──────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["Health"])
def health_check():
    """Service health and readiness check."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "platform": "Orion Security Platform",
        "database": "connected",
    }
