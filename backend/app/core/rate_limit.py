"""
In-process sliding-window rate limiter.

FRD ref: FRD-AUTH-04 — login endpoint must throttle repeated failed/rapid
attempts per client identity (username + source IP) to blunt brute-force
and credential-stuffing attacks.

This is intentionally dependency-free (no Redis requirement) so it works
identically in tests and in a single-process dev server. For a
horizontally-scaled production deployment, swap the in-memory store for a
Redis-backed counter (INCR + EXPIRE) behind the same `RateLimiter`
interface — the call sites in api/v1/auth.py would not need to change.
"""

import threading
import time
from collections import defaultdict, deque


class RateLimitExceeded(Exception):
    def __init__(self, retry_after_seconds: float):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Rate limit exceeded, retry after {retry_after_seconds:.0f}s")


class RateLimiter:
    """Sliding-window limiter: at most `max_attempts` events per `window_seconds` per key."""

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, *, now: float | None = None) -> None:
        """Record an attempt for `key`; raise RateLimitExceeded if over budget."""
        now = now if now is not None else time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            cutoff = now - self.window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_attempts:
                retry_after = self.window_seconds - (now - bucket[0])
                raise RateLimitExceeded(max(retry_after, 0.0))
            bucket.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def reset_all(self) -> None:
        """Test helper: clear all tracked keys so limiter state doesn't leak between tests."""
        with self._lock:
            self._hits.clear()
