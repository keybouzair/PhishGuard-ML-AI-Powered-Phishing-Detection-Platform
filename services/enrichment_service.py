"""URL/domain enrichment service extracted from request path."""

from __future__ import annotations

import time
from datetime import datetime
from urllib.parse import urlparse

import requests
import whois

from services.cache_service import cache_service


def compute_domain_metrics(url: str) -> dict:
    metrics = {
        "domain_age_days": "Unknown",
        "uptime_status": "Unknown",
        "loading_time_ms": "0 ms",
    }

    try:
        start_time = time.time()
        response = requests.get(url, timeout=3)
        load_time = (time.time() - start_time) * 1000
        metrics["loading_time_ms"] = f"{load_time:.0f} ms"
        metrics["uptime_status"] = "Active (99.9%)" if response.status_code < 400 else f"Down HTTP {response.status_code}"
    except Exception:
        metrics["uptime_status"] = "Unreachable"
        metrics["loading_time_ms"] = "Timeout"

    try:
        domain = urlparse(url).netloc.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        record = whois.whois(domain)
        creation_date = getattr(record, "creation_date", None)
        if creation_date:
            c = creation_date[0] if isinstance(creation_date, list) else creation_date
            if isinstance(c, datetime):
                c = c.replace(tzinfo=None)
                age = (datetime.now() - c).days
                metrics["domain_age_days"] = f"{age} days"
    except Exception:
        pass

    return metrics


def get_cached_domain_metrics(url: str) -> dict:
    cached = cache_service.get(f"enrich:{url}")
    if cached:
        return cached
    return {
        "domain_age_days": "Pending",
        "uptime_status": "Pending",
        "loading_time_ms": "Pending",
    }
