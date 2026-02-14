from __future__ import annotations

import asyncio
import hashlib
import hmac
import time


def verify_github_signature(
    secret: str,
    payload: bytes,
    signature_header: str | None,
) -> bool:
    if not secret:
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = (
        "sha256="
        + hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
    )
    return hmac.compare_digest(expected, signature_header.strip())


def fallback_delivery_id(event_name: str, payload: bytes) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    return f"{event_name}:{digest[:24]}"


class DeliveryDeduplicator:
    def __init__(self, ttl_seconds: int = 900, max_entries: int = 10000) -> None:
        self.ttl_seconds = max(int(ttl_seconds), 60)
        self.max_entries = max(int(max_entries), 1000)
        self._items: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def seen_before(self, key: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            self._cleanup(now)
            if key in self._items:
                return True
            self._items[key] = now + self.ttl_seconds
            if len(self._items) > self.max_entries:
                self._evict_to_limit()
            return False

    def reconfigure(self, ttl_seconds: int, max_entries: int) -> None:
        self.ttl_seconds = max(int(ttl_seconds), 60)
        self.max_entries = max(int(max_entries), 1000)

    def _cleanup(self, now: float) -> None:
        expired = [k for k, expires_at in self._items.items() if expires_at <= now]
        for key in expired:
            self._items.pop(key, None)

    def _evict_to_limit(self) -> None:
        overflow = len(self._items) - self.max_entries
        if overflow <= 0:
            return
        keys_by_expiry = sorted(self._items.items(), key=lambda kv: kv[1])
        for key, _ in keys_by_expiry[:overflow]:
            self._items.pop(key, None)
