# -*- coding: utf-8 -*-
"""
Qobuz API Response Cache with LRU eviction

Implements size-limited caching for albums, tracks, artists, and artwork URLs.
- Max 300 items per cache type
- 8-hour TTL per item
- LRU eviction when cache is full
- Thread-safe operations
"""

import json
import logging
import time
from collections import OrderedDict
from pathlib import Path
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


class PlaylistArtworkDiskCache:
    """Disk-persisted cache for derived playlist artwork, keyed by
    playlist URI and invalidated by the playlist's own `updated_at`
    timestamp -- unlike LRUCache above, this survives a Mopidy restart.

    Without this, a playlist's artwork has to be re-derived on every
    restart even when nothing changed upstream: when the API doesn't
    provide a ready-made mosaic, deriving it means fetching a page of
    tracks (see `QobuzLibraryProvider._get_playlist_images`). Values are
    plain JSON-serializable dicts (`{"uri":..., "width":..., "height":...}`
    per image), not `models.Image` objects -- the caller reconstructs
    those on read.
    """

    def __init__(self, cache_dir):
        self._path = Path(cache_dir) / "playlist_artwork.json"
        self._lock = Lock()
        self._data = self._load()

    def _load(self):
        try:
            with open(self._path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _persist(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._path.with_suffix(".json.tmp")
            with open(tmp_path, "w") as f:
                json.dump(self._data, f)
            tmp_path.replace(self._path)
        except OSError:
            logger.exception("Failed to persist playlist artwork cache to disk")

    def get(self, uri, updated_at):
        with self._lock:
            entry = self._data.get(uri)
        if entry is None or entry.get("updated_at") != updated_at:
            return None
        return entry.get("images")

    def put(self, uri, updated_at, images):
        with self._lock:
            self._data[uri] = {"updated_at": updated_at, "images": images}
            self._persist()

    def prune(self, live_uris):
        """Drop cached artwork for playlists no longer in the snapshot, so the
        file doesn't grow unbounded with orphans as playlists come and go
        (mirrors PlaylistTracksDiskCache.prune)."""
        live = set(live_uris)
        with self._lock:
            stale = [uri for uri in self._data if uri not in live]
            for uri in stale:
                del self._data[uri]
            if stale:
                self._persist()


class PlaylistTracksDiskCache:
    """Disk-persisted cache of a playlist's fully-loaded track list, keyed
    by playlist URI and invalidated by the playlist's own `updated_at`
    timestamp -- like PlaylistArtworkDiskCache, it survives a Mopidy
    restart.

    Without this, every Mopidy restart (e.g. the whole process restarts
    when a streaming credential is added) drops the in-memory track lists,
    so opening any playlist re-pages the entire track list from Qobuz
    again. Values are the RAW Qobuz track item dicts (plain JSON), NOT
    Track objects -- the caller reconstructs `Track(client, raw)` on read.
    Skips playlists whose `updated_at` is None (nothing reliable to
    invalidate on), mirroring the artwork cache.
    """

    def __init__(self, cache_dir):
        self._path = Path(cache_dir) / "playlist_tracks.json"
        self._lock = Lock()
        self._data = self._load()

    def _load(self):
        try:
            with open(self._path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _persist(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._path.with_suffix(".json.tmp")
            with open(tmp_path, "w") as f:
                json.dump(self._data, f)
            tmp_path.replace(self._path)
        except OSError:
            logger.exception("Failed to persist playlist tracks cache to disk")

    def get(self, uri, updated_at):
        if updated_at is None:
            return None
        with self._lock:
            entry = self._data.get(uri)
        if entry is None or entry.get("updated_at") != updated_at:
            return None
        return entry.get("tracks")

    def put(self, uri, updated_at, tracks):
        if updated_at is None:
            return
        with self._lock:
            self._data[uri] = {"updated_at": updated_at, "tracks": tracks}
            self._persist()

    def prune(self, live_uris):
        """Drop cached entries for playlists no longer in the snapshot so
        the file doesn't grow unbounded as playlists come and go."""
        live = set(live_uris)
        with self._lock:
            stale = [uri for uri in self._data if uri not in live]
            for uri in stale:
                del self._data[uri]
            if stale:
                self._persist()


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
