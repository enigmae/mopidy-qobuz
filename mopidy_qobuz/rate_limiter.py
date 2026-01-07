# -*- coding: utf-8 -*-
"""
Simple Per-Endpoint Rate Limiter for Qobuz API

Enforces max 2 calls/second for specific endpoints to achieve
Qobuz API certification compliance.

Only throttles the endpoints that violate the 2 calls/sec limit:
- album/get
- track/get
- artist/get

Search endpoints are not throttled (already compliant).
"""

import logging
import time
from collections import deque
from threading import Lock

logger = logging.getLogger(__name__)


class SimpleRateLimiter:
    """
    Simple per-endpoint rate limiter.

    Enforces max 2 calls per second for specified endpoints.
    Uses sliding window with deque for efficient operations.
    """

    def __init__(self, max_calls=2, window=1.0):
        """
        Initialize rate limiter.

        Args:
            max_calls: Maximum calls allowed per window (default: 2)
            window: Time window in seconds (default: 1.0)
        """
        self.max_calls = max_calls
        self.window = window

        # Track calls per endpoint: {endpoint: deque([timestamp, ...])}
        self.call_times = {}
        self.lock = Lock()

        # Only throttle these endpoints (the ones with violations)
        self.throttled_endpoints = {
            'album/get',
            'track/get',
            'artist/get'
        }

        logger.info(f"[RATE LIMITER] Initialized (max {max_calls} calls/{window}s)")
        logger.info(f"[RATE LIMITER] Throttling endpoints: {', '.join(sorted(self.throttled_endpoints))}")

    def wait_if_needed(self, endpoint):
        """
        Wait if endpoint would exceed rate limit.

        Args:
            endpoint: API endpoint (e.g., "track/get")

        Returns:
            float: Time waited in seconds (0 if no wait needed)
        """
        # Only throttle specific endpoints
        if endpoint not in self.throttled_endpoints:
            return 0.0

        with self.lock:
            now = time.time()

            # Initialize endpoint tracking if needed
            if endpoint not in self.call_times:
                self.call_times[endpoint] = deque()

            # Remove calls outside the time window
            while (self.call_times[endpoint] and
                   self.call_times[endpoint][0] < now - self.window):
                self.call_times[endpoint].popleft()

            # Check if we're at the rate limit
            if len(self.call_times[endpoint]) >= self.max_calls:
                # Calculate how long to wait
                oldest_call = self.call_times[endpoint][0]
                wait_time = self.window - (now - oldest_call)

                if wait_time > 0:
                    logger.debug(f"[RATE LIMITER] {endpoint} - waiting {wait_time:.2f}s")
                    time.sleep(wait_time)
                    now = time.time()

                    # Clean up old calls again after sleeping
                    while (self.call_times[endpoint] and
                           self.call_times[endpoint][0] < now - self.window):
                        self.call_times[endpoint].popleft()

                    # Record this call
                    self.call_times[endpoint].append(now)
                    return wait_time

            # Record this call
            self.call_times[endpoint].append(now)
            return 0.0

    def get_stats(self):
        """
        Get rate limiter statistics.

        Returns:
            dict: Statistics for each throttled endpoint
        """
        with self.lock:
            stats = {}
            now = time.time()

            for endpoint in self.throttled_endpoints:
                if endpoint in self.call_times:
                    # Clean old calls
                    while (self.call_times[endpoint] and
                           self.call_times[endpoint][0] < now - self.window):
                        self.call_times[endpoint].popleft()

                    recent_calls = len(self.call_times[endpoint])
                else:
                    recent_calls = 0

                stats[endpoint] = {
                    'recent_calls': recent_calls,
                    'rate': recent_calls / self.window,
                    'headroom': max(0, self.max_calls - recent_calls)
                }

            return stats


# Global rate limiter instance (initialized when client is created)
_rate_limiter = None


def get_rate_limiter():
    """Get the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = SimpleRateLimiter(max_calls=2, window=1.0)
    return _rate_limiter
