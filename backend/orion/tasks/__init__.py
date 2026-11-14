"""
Orion Security Platform — Celery Background Tasks Package.
"""
from orion.tasks.celery_app import celery_app
from orion.tasks.scan_tasks import run_scan_task

__all__ = ["celery_app", "run_scan_task"]

