"""
rate_limiter.py — Adaptive Rate Limiter

Responsibilities:
  - Token-bucket rate limiting with burst capacity
  - Adaptive back-off when server signals overload (429, 503, slow responses)
  - Per-host rate limiting to avoid hammering specific targets
  - Jitter to avoid thundering herd on burst scenarios
  - Thread-safe and async-safe

Production considerations:
  - asyncio.Lock ensures no race conditions in concurrent detectors
  - Exponential back-off with configurable ceiling
  - Response-time monitoring: automatically throttles if avg latency spikes
  - Separate limits can be set per host (e.g. stricter for main app, looser for CDN)
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

logger = logging.getLogger(__name__)

# Default jitter range as a fraction of the base delay
JITTER_FRACTION = 0.2

# If average response time (ms) exceeds this, halve the rate
LATENCY_THROTTLE_THRESHOLD_MS = 3000

# Sliding window size for latency tracking
LATENCY_WINDOW_SIZE = 20


@dataclass
class RateLimiterStats:
    total_requests: int = 0
    throttled_requests: int = 0
    back_off_events: int = 0
    total_wait_ms: float = 0.0

    @property
    def avg_wait_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_wait_ms / self.total_requests


class AdaptiveRateLimiter:
    """
    Token-bucket rate limiter with adaptive back-off.

    Adapts in three ways:
      1. HTTP 429/503 → exponential back-off (doubles each time, max ceiling)
      2. Slow responses → reduces rate automatically
      3. Successful fast responses → gradually recovers toward configured rate

    Usage:
        limiter = AdaptiveRateLimiter(requests_per_second=5, burst_capacity=10)
        await limiter.acquire()   # call before every HTTP request
        limiter.report_response(status_code=200, elapsed_ms=250)  # call after
    """

    def __init__(
        self,
        requests_per_second: float = 5.0,
        burst_capacity: int = 10,
        min_rps: float = 0.5,
        max_rps: float = 50.0,
        back_off_base_seconds: float = 2.0,
        back_off_max_seconds: float = 60.0,
        jitter: bool = True,
        unthrottled: bool = False,
    ) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")

        self.unthrottled = unthrottled

        self._configured_rps = requests_per_second
        self._current_rps = requests_per_second
        self._min_rps = min_rps
        self._max_rps = max_rps
        self._burst_capacity = burst_capacity
        self._back_off_base = back_off_base_seconds
        self._back_off_max = back_off_max_seconds
        self._jitter = jitter

        # Token bucket state
        self._tokens: float = float(burst_capacity)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

        # Back-off state
        self._back_off_level: int = 0       # 0 = no back-off
        self._back_off_until: float = 0.0

        # Latency tracking (sliding window)
        self._latency_window: Deque[float] = deque(maxlen=LATENCY_WINDOW_SIZE)

        self.stats = RateLimiterStats()

    # ── Public API ─────────────────────────────────────────────────────────────

    async def acquire(self, host: Optional[str] = None) -> float:
        """
        Block until a token is available.
        Returns the actual wait time in seconds.
        """
        if self.unthrottled:
            self.stats.total_requests += 1
            return 0.0

        total_wait = 0.0
        async with self._lock:
            now = time.monotonic()
            
            # 1. Back-off logic
            wait_from_backoff = 0.0
            if now < self._back_off_until:
                wait_from_backoff = self._back_off_until - now

            # 2. Token bucket logic
            # Refill tokens since last update
            elapsed = now - self._last_refill
            refill = elapsed * self._current_rps
            self._tokens = min(float(self._burst_capacity), self._tokens + refill)
            self._last_refill = now

            # Consume token
            wait_from_tokens = 0.0
            if self._tokens < 1.0:
                # Need to wait for token generation
                deficit = 1.0 - self._tokens
                wait_from_tokens = deficit / self._current_rps
                self._tokens = 0.0
            else:
                self._tokens -= 1.0

            # 3. Final wait calculation
            total_wait = max(wait_from_backoff, wait_from_tokens)
            if self._jitter and total_wait > 0.01:
                total_wait += random.uniform(0, total_wait * JITTER_FRACTION)

            if total_wait > 0:
                self.stats.throttled_requests += 1
                self.stats.total_wait_ms += total_wait * 1000

        # CRITICAL: Do NOT hold the lock during asyncio.sleep
        if total_wait > 0:
            await asyncio.sleep(total_wait)

        self.stats.total_requests += 1
        return total_wait

    def report_response(
        self, status_code: int, elapsed_ms: float, host: Optional[str] = None
    ) -> None:
        """
        Report the result of an HTTP request.
        Triggers back-off on 429/503; adapts rate on latency.
        Must be called without holding the lock (non-async).
        """
        if self.unthrottled:
            return
            
        self._latency_window.append(elapsed_ms)

        if status_code == 429:
            self._trigger_back_off(reason="HTTP 429 Too Many Requests")
        elif status_code == 503:
            self._trigger_back_off(reason="HTTP 503 Service Unavailable")
        elif status_code < 400 and self._back_off_level > 0:
            # Successful response — gradually recover
            self._recover()
            self._adapt_latency()
        else:
            self._adapt_latency()

    def set_rate(self, requests_per_second: float) -> None:
        """Override the configured rate (e.g. from CLI flag)."""
        self._configured_rps = max(self._min_rps, min(self._max_rps, requests_per_second))
        self._current_rps = self._configured_rps
        logger.info("Rate limiter: rate set to %.1f rps", self._current_rps)

    def reset_back_off(self) -> None:
        """Manually clear any active back-off."""
        self._back_off_level = 0
        self._back_off_until = 0.0
        self._current_rps = self._configured_rps

    @property
    def current_rps(self) -> float:
        return self._current_rps

    @property
    def is_backing_off(self) -> bool:
        return time.monotonic() < self._back_off_until

    # ── Internal ───────────────────────────────────────────────────────────────

    def _trigger_back_off(self, reason: str) -> None:
        self._back_off_level += 1
        delay = min(
            self._back_off_base * (2 ** (self._back_off_level - 1)),
            self._back_off_max,
        )
        if self._jitter:
            delay += random.uniform(0, delay * JITTER_FRACTION)

        self._back_off_until = time.monotonic() + delay
        # Also reduce rate to half
        self._current_rps = max(self._min_rps, self._current_rps / 2)
        self.stats.back_off_events += 1

        logger.warning(
            "Rate limiter back-off triggered (%s). Level=%d, delay=%.1fs, new_rps=%.2f",
            reason, self._back_off_level, delay, self._current_rps,
        )

    def _recover(self) -> None:
        """Gradually restore rate after successful responses."""
        if self._back_off_level == 0:
            return
        self._back_off_level = max(0, self._back_off_level - 1)
        recovery = min(
            self._current_rps * 1.25,
            self._configured_rps,
        )
        self._current_rps = recovery
        if self._back_off_level == 0:
            logger.info(
                "Rate limiter: back-off cleared, rps restored to %.2f", self._current_rps
            )

    def _adapt_latency(self) -> None:
        """Throttle if average response latency is too high."""
        if len(self._latency_window) < 5:
            return

        avg_latency = sum(self._latency_window) / len(self._latency_window)

        if avg_latency > LATENCY_THROTTLE_THRESHOLD_MS:
            new_rps = max(self._min_rps, self._current_rps * 0.75)
            if new_rps < self._current_rps:
                self._current_rps = new_rps
                logger.info(
                    "Rate limiter: high latency (avg %.0fms), reduced to %.2f rps",
                    avg_latency, self._current_rps,
                )


# ── Per-host rate limiter manager ─────────────────────────────────────────────

class HostRateLimiterManager:
    """
    Maintains separate AdaptiveRateLimiter instances per hostname.
    Useful when scanning multi-domain targets where different hosts
    have different capacity.

    Usage:
        manager = HostRateLimiterManager(default_rps=5)
        await manager.acquire("api.example.com")
        manager.report("api.example.com", status_code=200, elapsed_ms=100)
    """

    def __init__(
        self,
        default_rps: float = 5.0,
        default_burst: int = 10,
    ) -> None:
        self._default_rps = default_rps
        self._default_burst = default_burst
        self._limiters: Dict[str, AdaptiveRateLimiter] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> float:
        limiter = await self._get_or_create(host)
        return await limiter.acquire()

    def report(self, host: str, status_code: int, elapsed_ms: float) -> None:
        if host in self._limiters:
            self._limiters[host].report_response(status_code, elapsed_ms)

    def set_host_rate(self, host: str, rps: float) -> None:
        if host in self._limiters:
            self._limiters[host].set_rate(rps)

    def get_stats(self, host: str) -> Optional[RateLimiterStats]:
        limiter = self._limiters.get(host)
        return limiter.stats if limiter else None

    async def _get_or_create(self, host: str) -> AdaptiveRateLimiter:
        async with self._lock:
            if host not in self._limiters:
                self._limiters[host] = AdaptiveRateLimiter(
                    requests_per_second=self._default_rps,
                    burst_capacity=self._default_burst,
                )
                logger.debug("Created rate limiter for host: %s", host)
            return self._limiters[host]