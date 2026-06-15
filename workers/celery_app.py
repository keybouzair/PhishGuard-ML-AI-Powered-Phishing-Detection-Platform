"""Celery app with graceful fallback when Celery is unavailable."""

from __future__ import annotations

import os

try:
    from celery import Celery  # type: ignore
except Exception:  # pragma: no cover
    Celery = None


if Celery is not None:
    celery_app = Celery(
        "phishing_workers",
        broker=os.environ.get("CELERY_BROKER_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/0")),
        backend=os.environ.get("CELERY_RESULT_BACKEND", os.environ.get("REDIS_URL", "redis://localhost:6379/1")),
    )
else:
    celery_app = None
