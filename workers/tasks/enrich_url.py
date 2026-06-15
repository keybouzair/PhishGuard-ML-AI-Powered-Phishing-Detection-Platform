"""Async enrichment task for WHOIS/SSL/network metrics."""

from __future__ import annotations

from services.cache_service import cache_service
from services.enrichment_service import compute_domain_metrics
from workers.celery_app import celery_app


def _run_enrichment(url: str):
    metrics = compute_domain_metrics(url)
    cache_service.set(f"enrich:{url}", metrics, ttl_seconds=3600)
    return metrics


if celery_app is not None:

    @celery_app.task(name="enrich_url_async")
    def enrich_url_async(url: str):
        return _run_enrichment(url)

else:

    def enrich_url_async(url: str):
        return _run_enrichment(url)


def enqueue_url_enrichment(url: str):
    """Queue enrichment async when Celery exists, else compute synchronously."""
    if celery_app is not None and hasattr(enrich_url_async, "delay"):
        enrich_url_async.delay(url)
        return {"queued": True}
    # No worker configured: skip blocking computation in request path.
    return {"queued": False}
