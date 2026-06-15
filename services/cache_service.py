"""Cache service with Redis backend and safe in-memory fallback."""

from __future__ import annotations

import json
import os
import time
from typing import Any

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None


class CacheService:
    def __init__(self):
        self._redis = None
        self._mem: dict[str, tuple[float, Any]] = {}

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        if redis is not None:
            try:
                self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
            except Exception:
                self._redis = None

    def get(self, key: str):
        if self._redis is not None:
            try:
                value = self._redis.get(key)
                return json.loads(value) if value else None
            except Exception:
                return None

        row = self._mem.get(key)
        if not row:
            return None
        expires_at, value = row
        if time.time() > expires_at:
            self._mem.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any, ttl_seconds: int = 900):
        if self._redis is not None:
            try:
                self._redis.setex(key, ttl_seconds, json.dumps(value))
                return
            except Exception:
                pass

        self._mem[key] = (time.time() + ttl_seconds, value)


cache_service = CacheService()
