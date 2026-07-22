# -*- coding: utf-8 -*-
import logging
import threading
import time

from mopidy import backend

from mopidy_qobuz.cache import LRUCache
from mopidy_qobuz.client import Playlist
from mopidy_qobuz.client import User
from mopidy_qobuz.translators import to_playlist
from mopidy_qobuz.translators import to_playlist_ref
from mopidy_qobuz.translators import to_track_ref

logger = logging.getLogger(__name__)

# Page size used when paging through playlist/getUserPlaylists
PLAYLIST_PAGE_SIZE = 100

# Fallback when playlist_cache_ttl is not configured (see ext.conf)
DEFAULT_CACHE_TTL = 300

# Cache key holding the full user playlist snapshot ({uri: Playlist})
_LIST_KEY = "__user_playlists__"


class PeriodicThread(threading.Thread):
    """Minimal stdlib-only periodic-task thread.

    Runs `target` every `period` seconds until `stop()` is called. Uses a
    single Event.wait() per cycle (interruptible sleep) so stop() takes
    effect within one `period` at most.
    """

    def __init__(self, target, period, name=None, daemon=True):
        super().__init__(name=name, daemon=daemon)
        self._target = target
        self._period = period
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.wait(self._period):
            try:
                self._target()
            except Exception:
                logger.exception("PeriodicThread target raised an exception")

    def stop(self):
        self._stop_event.set()


class QobuzPlaylistsProvider(backend.PlaylistsProvider):
    def __init__(self, backend):
        self._backend = backend

        config = backend._config["qobuz"]
        ttl = config.get("playlist_cache_ttl") or DEFAULT_CACHE_TTL
        # The user playlist snapshot ({uri: Playlist}) lives outside the TTL
        # cache so unchanged playlists keep their already-loaded tracks
        # across refreshes; the TTL cache acts as the freshness timer and
        # holds non-user playlists fetched via from_id (featured, shared)
        self._snapshot = {}
        self._playlists = LRUCache(max_size=300, ttl=ttl, name="Playlist")
        self._refresh_thread = None

    def start_periodic_refresh(self):
        """Kick off an eager initial load, then start the periodic refresh thread.

        Called by backend on_start (only once authenticated). The eager load
        runs in its own thread so it never blocks on_start()/backend startup --
        playlists just show up warm by the time the app asks for them instead
        of on-demand on first access.
        """
        threading.Thread(
            target=self._eager_initial_refresh,
            name="qobuz-playlist-initial-refresh",
            daemon=True,
        ).start()

        refresh_secs = self._backend._config["qobuz"].get("playlist_cache_refresh_secs")
        if not refresh_secs or refresh_secs <= 0:
            logger.info("Playlist periodic refresh disabled (playlist_cache_refresh_secs not set or <= 0)")
            return

        self._refresh_thread = PeriodicThread(
            target=self._periodic_refresh,
            period=refresh_secs,
            name="qobuz-playlist-refresh",
            daemon=True,
        )
        self._refresh_thread.start()
        logger.info("Started playlist periodic refresh thread (every %s seconds)", refresh_secs)

    def stop_periodic_refresh(self):
        """Stop the periodic refresh thread. Called by backend on_stop."""
        if self._refresh_thread:
            logger.info("Stopping playlist periodic refresh thread...")
            self._refresh_thread.stop()
            self._refresh_thread.join(timeout=5)
            if self._refresh_thread.is_alive():
                logger.warning("Playlist refresh thread did not stop cleanly")
            else:
                logger.info("Playlist periodic refresh thread stopped")
            self._refresh_thread = None

    def _eager_initial_refresh(self):
        """One-shot warm-up load, run once right after startup."""
        try:
            _start = time.time()
            logger.info("[SYNC_TIMING] qobuz eager initial playlist load begin t=%s", _start)
            self.refresh()
            logger.info(
                "[SYNC_TIMING] qobuz eager initial playlist load complete duration=%.2fs",
                time.time() - _start,
            )
        except Exception:
            logger.exception("Error during eager initial playlist load")

    def _periodic_refresh(self):
        try:
            logger.debug("Periodic Qobuz playlist refresh starting...")
            self.refresh()
            logger.debug("Periodic Qobuz playlist refresh complete")
        except Exception:
            logger.exception("Error in periodic Qobuz playlist refresh")

    def as_list(self):
        return [
            to_playlist_ref(playlist) for playlist in self._list_snapshot().values()
        ]

    def get_items(self, uri):
        playlist = self._get_playlist(uri)

        if playlist is not None:
            return [to_track_ref(track, False) for track in playlist.tracks]

        return playlist

    def lookup(self, uri):
        playlist = self._get_playlist(uri)

        if playlist is not None:
            return to_playlist(playlist)

        return playlist

    def refresh(self):
        _sync_timing_start = time.time()
        was_cold = not self._snapshot
        logger.info(
            "[SYNC_TIMING] qobuz refresh begin t=%s was_cold=%s",
            _sync_timing_start,
            was_cold,
        )
        logger.info("Refreshing Qobuz playlists")

        user = User(self._backend._client)
        playlists = user.get_playlists(limit=PLAYLIST_PAGE_SIZE)
        logger.info(
            "[SYNC_TIMING] qobuz get_playlists duration=%.2fs count=%d",
            time.time() - _sync_timing_start,
            len(playlists),
        )

        snapshot = {}

        for playlist in playlists:
            cached = self._snapshot.get(playlist.uri)
            if cached is not None and not _is_newer(playlist, cached):
                # Unchanged upstream: keep the cached copy so already
                # loaded tracks are reused
                snapshot[playlist.uri] = cached
            else:
                snapshot[playlist.uri] = playlist

        # Replacing the snapshot implicitly prunes playlists that
        # disappeared upstream. Unchanged entries are the same objects as
        # before, so dict equality doubles as an identity-based change check
        changed = snapshot != self._snapshot
        self._snapshot = snapshot
        self._playlists.put(_LIST_KEY, True)

        if changed:
            # Only notify clients when something actually changed;
            # unconditional events make every TTL-triggered refresh fan out
            # into a full re-fetch by every client
            backend.BackendListener.send("playlists_loaded")
        logger.info(
            "Qobuz playlists refreshed (%d playlists, changed=%s)",
            len(snapshot),
            changed,
        )
        logger.info(
            "[SYNC_TIMING] qobuz refresh complete duration=%.2fs was_cold=%s count=%d",
            time.time() - _sync_timing_start,
            was_cold,
            len(snapshot),
        )

    def create(self, name):
        # Apparently possible with Qobuz API. TODO.
        pass

    def delete(self, uri):
        # Apparently possible with Qobuz API. TODO.
        pass

    def save(self, playlist):
        # Apparently possible with Qobuz API. TODO.
        pass

    def _list_snapshot(self):
        if self._playlists.get(_LIST_KEY) is None:
            # Snapshot empty or stale: do a live (paged) fetch
            self.refresh()

        return self._snapshot

    def _get_playlist(self, uri):
        if uri is None or not uri.startswith("qobuz:playlist"):
            return None

        # Check the snapshot and the per-URI cache BEFORE the list
        # freshness check, so a single-playlist lookup never blocks on (or
        # fails with) a full user-list refresh after TTL expiry. Serving a
        # slightly-stale user playlist is fine: track staleness is governed
        # by the updated_at reconciliation in refresh()
        playlist = self._snapshot.get(uri) or self._playlists.get(uri)
        if playlist is not None:
            return playlist

        # Unknown URI: refresh the user list if stale (catches playlists
        # created upstream since the last refresh) and re-check
        playlist = self._list_snapshot().get(uri)
        if playlist is not None:
            return playlist

        # Not one of the user's own playlists (featured, shared, ...):
        # fall back to a direct fetch and cache the result
        playlist = Playlist.from_id(self._backend._client, uri.split(":")[-1])
        self._playlists.put(uri, playlist)
        return playlist


def _is_newer(upstream, cached):
    """True when the upstream copy is newer than the cached one.

    Compares updated_at timestamps when both sides have one. The real API
    may omit updated_at; in that case fall back to detectable-change
    heuristics (name, track count) so unchanged playlists keep their
    cached copy -- and already-loaded tracks -- across refreshes.
    """
    if upstream.updated_at is not None and cached.updated_at is not None:
        return upstream.updated_at > cached.updated_at

    return (
        upstream.name != cached.name
        or upstream.tracks_count != cached.tracks_count
    )
