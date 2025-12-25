# -*- coding: utf-8 -*-
"""
Qobuz API Response Cache with LRU eviction

Implements size-limited caching for albums, tracks, artists, and artwork URLs.
- Max 300 items per cache type
- 8-hour TTL per item
- LRU eviction when cache is full
- Thread-safe operations
"""

import logging
import time
from collections import OrderedDict
from threading import Lock

logger = logging.getLogger(__name__)

# Cache configuration
CACHE_TTL = 8 * 60 * 60  # 8 hours in seconds
MAX_CACHE_SIZE = 300  # Maximum items per cache type


class LRUCache:
    """
    Thread-safe LRU cache with TTL and size limit.

    Features:
    - Automatic eviction of least recently used items when full
    - Time-based expiration (8 hour TTL)
    - Thread-safe operations
    - Efficient O(1) lookups and updates
    """

    def __init__(self, max_size=MAX_CACHE_SIZE, ttl=CACHE_TTL, name="Cache"):
        self.max_size = max_size
        self.ttl = ttl
        self.name = name
        self.cache = OrderedDict()  # {key: (value, expiry_time)}
        self.lock = Lock()

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

        logger.info(f"[CACHE] Initialized {name} (max_size={max_size}, ttl={ttl}s)")

    def get(self, key):
        """
        Get value from cache if present and not expired.
        Returns None if not found or expired.
        """
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                logger.debug(f"[CACHE MISS] {self.name}: {key}")
                return None

            value, expiry = self.cache[key]
            current_time = time.time()

            # Check if expired
            if current_time > expiry:
                logger.debug(f"[CACHE EXPIRED] {self.name}: {key}")
                del self.cache[key]
                self.misses += 1
                return None

            # Move to end (most recently used)
            self.cache.move_to_end(key)
            self.hits += 1
            logger.debug(f"[CACHE HIT] {self.name}: {key}")
            return value

    def put(self, key, value):
        """
        Add or update value in cache.
        Evicts LRU item if cache is full.
        """
        with self.lock:
            current_time = time.time()
            expiry = current_time + self.ttl

            # If key exists, update it
            if key in self.cache:
                self.cache[key] = (value, expiry)
                self.cache.move_to_end(key)
                logger.debug(f"[CACHE UPDATE] {self.name}: {key}")
                return

            # Check if cache is full
            if len(self.cache) >= self.max_size:
                # Evict least recently used (first item)
                evicted_key, _ = self.cache.popitem(last=False)
                self.evictions += 1
                logger.debug(
                    f"[CACHE EVICT] {self.name}: {evicted_key} "
                    f"(size={len(self.cache)}/{self.max_size})"
                )

            # Add new item
            self.cache[key] = (value, expiry)
            logger.debug(
                f"[CACHE ADD] {self.name}: {key} "
                f"(size={len(self.cache)}/{self.max_size})"
            )

    def clear(self):
        """Clear all cached items"""
        with self.lock:
            self.cache.clear()
            logger.info(f"[CACHE CLEAR] {self.name}: All items removed")

    def get_stats(self):
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

            return {
                "name": self.name,
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": f"{hit_rate:.1f}%",
                "total_requests": total_requests,
            }

    def log_stats(self):
        """Log cache statistics"""
        stats = self.get_stats()
        logger.info(
            f"[CACHE STATS] {stats['name']}: "
            f"size={stats['size']}/{stats['max_size']}, "
            f"hits={stats['hits']}, "
            f"misses={stats['misses']}, "
            f"evictions={stats['evictions']}, "
            f"hit_rate={stats['hit_rate']}"
        )


# Global cache instances
album_cache = LRUCache(max_size=300, ttl=CACHE_TTL, name="Album")
track_cache = LRUCache(max_size=300, ttl=CACHE_TTL, name="Track")
artist_cache = LRUCache(max_size=300, ttl=CACHE_TTL, name="Artist")
artwork_cache = LRUCache(max_size=300, ttl=CACHE_TTL, name="Artwork")


def get_all_stats():
    """Get statistics for all caches"""
    return {
        "album": album_cache.get_stats(),
        "track": track_cache.get_stats(),
        "artist": artist_cache.get_stats(),
        "artwork": artwork_cache.get_stats(),
    }


def log_all_stats():
    """Log statistics for all caches"""
    logger.info("[CACHE STATS] ===== Cache Statistics =====")
    album_cache.log_stats()
    track_cache.log_stats()
    artist_cache.log_stats()
    artwork_cache.log_stats()

    # Calculate totals
    stats = get_all_stats()
    total_items = sum(s["size"] for s in stats.values())
    total_hits = sum(s["hits"] for s in stats.values())
    total_misses = sum(s["misses"] for s in stats.values())
    total_requests = total_hits + total_misses
    overall_hit_rate = (total_hits / total_requests * 100) if total_requests > 0 else 0

    logger.info(
        f"[CACHE STATS] OVERALL: "
        f"items={total_items}/1200, "
        f"hits={total_hits}, "
        f"misses={total_misses}, "
        f"hit_rate={overall_hit_rate:.1f}%"
    )


def clear_all_caches():
    """Clear all caches"""
    album_cache.clear()
    track_cache.clear()
    artist_cache.clear()
    artwork_cache.clear()
    logger.info("[CACHE] All caches cleared")
