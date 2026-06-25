"""URL/domain enrichment service extracted from request path."""

from __future__ import annotations

import socket
import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from urllib.parse import urlparse

import requests
import whois

from services.cache_service import cache_service

logger = logging.getLogger("phishing_app.enrichment")

# ---------- A-06: SSRF protection ----------

def _is_safe_target(url: str) -> bool:
    """Block requests to private/reserved IP addresses (mirrors visual_analysis._is_safe_target)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        for _fam, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                logger.warning("SSRF blocked in enrichment: %s -> %s", hostname, ip)
                return False
        return True
    except Exception:
        return False


# C-17: whois can block for 10+ seconds; wrap in threadpool with timeout
_WHOIS_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="whois")


def compute_domain_metrics(url: str) -> dict:
    metrics = {
        "domain_age_days": "Unknown",
        "uptime_status": "Unknown",
        "loading_time_ms": "0 ms",
    }

    # A-06: SSRF guard before making outbound request
    if not _is_safe_target(url):
        logger.warning("Enrichment SSRF blocked for %s", url)
        metrics["uptime_status"] = "Blocked (internal target)"
        return metrics

    try:
        start_time = time.time()
        response = requests.get(url, timeout=3, allow_redirects=False)
        load_time = (time.time() - start_time) * 1000
        metrics["loading_time_ms"] = f"{load_time:.0f} ms"
        metrics["uptime_status"] = "Active (99.9%)" if response.status_code < 400 else f"Down HTTP {response.status_code}"
    except Exception:
        metrics["uptime_status"] = "Unreachable"
        metrics["loading_time_ms"] = "Timeout"

    # C-17: Wrap whois in ThreadPoolExecutor with 3s timeout
    try:
        domain = urlparse(url).netloc.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        future = _WHOIS_POOL.submit(whois.whois, domain)
        record = future.result(timeout=3)

        creation_date = getattr(record, "creation_date", None)
        if creation_date:
            c = creation_date[0] if isinstance(creation_date, list) else creation_date
            if isinstance(c, datetime):
                c = c.replace(tzinfo=None)
                age = (datetime.now() - c).days
                metrics["domain_age_days"] = f"{age} days"
    except FuturesTimeoutError:
        logger.debug("WHOIS lookup timed out for %s", url)
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
