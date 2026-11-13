"""
Orion Security Platform — Celery Worker Application Configuration.

Connects Celery to Redis message broker and results backend.
Enables asynchronous and distributed vulnerability scanning workflows.
"""
from __future__ import annotations

import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

try:
    from celery import Celery

    celery_app = Celery(
        "orion_tasks",
        broker=REDIS_URL,
        backend=REDIS_URL,
        include=["orion.tasks.scan_tasks"],
    )

    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_time_limit=1800,       # 30 minutes hard timeout
        task_soft_time_limit=1500,  # 25 minutes soft timeout
        worker_prefetch_multiplier=1,
    )
except ImportError:
    # Graceful fallback when running in lightweight environments without Celery installed
    class _DummyCelery:
        def task(self, *args, **kwargs):
            def decorator(fn):
                def delay(*d_args, **d_kwargs):
                    return fn(*d_args, **d_kwargs)
                fn.delay = delay
                return fn
            return decorator

    celery_app = _DummyCelery()  # type: ignore
