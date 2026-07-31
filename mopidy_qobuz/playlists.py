# -*- coding: utf-8 -*-
import logging
import threading
import time

from mopidy import backend

from mopidy_qobuz import Extension
from mopidy_qobuz.cache import LRUCache
from mopidy_qobuz.cache import PlaylistTracksDiskCache
from mopidy_qobuz.client import Playlist
from mopidy_qobuz.client import Track
from mopidy_qobuz.client import User
from mopidy_qobuz.translators import to_playlist
from mopidy_qobuz.translators import to_playlist_ref
from mopidy_qobuz.translators import to_track_ref

logger = logging.getLogger(__name__)

# Page size used when paging through playlist/getUserPlaylists
PLAYLIST_PAGE_SIZE = 100

# Tracks returned immediately on the first open of a not-yet-loaded playlist.
# The remainder is paged in by a background backfill thread, so a large
# playlist's first screen paints after ONE playlist/get page instead of
# blocking on ceil(tracks_count / 500) sequential pages.
FIRST_SLICE_SIZE = 50

# On a cold start (empty disk cache), warm the first page of this many
# playlists so opening one feels instant -- matches mopidy-tidal's eager
# prefetch. Cheap: one playlist/get page each. Playlists already hydrated
# from disk are skipped.
EAGER_PREFETCH_COUNT = 5

# Fallback when playlist_cache_ttl is not configured (see ext.conf)
DEFAULT_CACHE_TTL = 300

# Cache key holding the full user playlist snapshot ({uri: Playlist})
_LIST_KEY = "__user_playlists__"

# Pause between playlists during the throttled full-catalog track+artwork
# prefetch pass -- mirrors mopidy-tidal's equivalent constant. Forcing
# Playlist.tracks to resolve pages through the whole playlist regardless
# of size, so for a library of 50-100 playlists this pass deliberately
# paces itself rather than firing everything back-to-back.
EAGER_FULL_CATALOG_PREFETCH_DELAY_SECS = 0.75


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
        # Disk-persisted per-playlist track lists (keyed by uri + updated_at)
        # that survive a Mopidy restart, so opening a previously-loaded
        # playlist after the process restarts (e.g. when a credential is
        # added) does NOT re-page every track from Qobuz. Written when a full
        # backfill completes; hydrated back into playlist objects in refresh().
        self._tracks_disk = PlaylistTracksDiskCache(
            Extension.get_cache_dir(backend._config)
        )
        # URIs whose remaining tracks are being backfilled, so a second open
        # doesn't spawn a duplicate backfill thread.
        self._backfilling = set()
        self._backfill_lock = threading.Lock()

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
        """One-shot warm-up load, run once right after startup.

        `refresh()` populates the playlist list, but Qobuz `Playlist`
        objects load their tracks lazily -- nothing here has actually
        fetched a single track yet. Kick off a throttled background pass
        that forces every playlist's tracks (and artwork) to resolve, so
        the whole library is warm on disk and opening any playlist is
        instant instead of triggering an on-demand fetch on first touch.
        """
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
            return

        # The full-catalog track+artwork prefetch storm is intentionally NOT
        # started. It forced every playlist's full tracks on every boot
        # (hundreds/thousands of calls over minutes -- the "stuck after adding
        # Tidal"). It is superseded by (a) the on-disk track cache hydrated in
        # refresh(), so unchanged playlists come back warm across restarts for
        # free, and (b) first-slice-on-open + background backfill, which makes a
        # cold open fast without pre-warming the whole library.
        # (_throttled_full_catalog_prefetch is kept for reference / opt-in.)

        # Warm the first page of the first few playlists so opening one feels
        # instant on a cold start (empty disk cache). Cheap -- one playlist/get
        # page each; the full track list still backfills lazily on actual open.
        try:
            _pf = time.time()
            warmed = 0
            for uri in list(self._snapshot.keys())[:EAGER_PREFETCH_COUNT]:
                pl = self._snapshot.get(uri)
                if pl is not None and pl._tracks is None:
                    pl.first_tracks_page(FIRST_SLICE_SIZE)
                    warmed += 1
            logger.info(
                "[SYNC_TIMING] qobuz eager first-page prefetch complete "
                "duration=%.2fs warmed=%d",
                time.time() - _pf,
                warmed,
            )
        except Exception:
            logger.exception("Error during qobuz eager first-page prefetch")

    def _throttled_full_catalog_prefetch(self):
        """Background pass: force every playlist's tracks + artwork to
        resolve, one playlist at a time with a pause between each (see
        EAGER_FULL_CATALOG_PREFETCH_DELAY_SECS) so this can't dominate the
        connection or trip rate limiting during startup."""
        uris = list(self._snapshot.keys())
        _start = time.time()
        logger.info(
            "[SYNC_TIMING] qobuz full-catalog prefetch begin count=%d", len(uris)
        )
        for uri in uris:
            try:
                playlist = self._snapshot.get(uri)
                if playlist is not None:
                    _ = playlist.tracks  # force the lazy property to resolve
                self._backend.library.get_images([uri])
            except Exception:
                logger.exception("Error during full-catalog prefetch for %s", uri)
            time.sleep(EAGER_FULL_CATALOG_PREFETCH_DELAY_SECS)
        logger.info(
            "[SYNC_TIMING] qobuz full-catalog prefetch complete duration=%.2fs count=%d",
            time.time() - _start,
            len(uris),
        )

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
        if playlist is None:
            return None
        tracks, _partial = self._tracks_for_open(playlist)
        return [to_track_ref(track, False) for track in tracks]

    def lookup(self, uri):
        playlist = self._get_playlist(uri)
        if playlist is None:
            return None
        tracks, partial = self._tracks_for_open(playlist)
        return to_playlist(playlist, tracks=tracks, partial=partial)

    def _tracks_for_open(self, playlist):
        """Return (tracks_to_expose_now, is_partial).

        Fast path: a fully-loaded playlist (in memory, or hydrated from the
        on-disk cache in refresh()) returns its complete track list. Cold
        path: return only the first page immediately and spawn a background
        thread to page in the rest, so a big playlist's first screen paints
        after one API call instead of ceil(tracks_count / 500) blocking calls.
        """
        if playlist._tracks is not None:
            return playlist._tracks, False

        first = playlist.first_tracks_page(FIRST_SLICE_SIZE)
        total = playlist.tracks_count
        if total is None or total > len(first):
            # More tracks upstream (or count unknown): serve the slice now and
            # fill in the rest in the background.
            self._schedule_backfill(playlist)
            return first, True
        # The first page already is the whole playlist: pin it as the full
        # track list and persist it so it comes back warm after a restart
        # (no re-fetch), same as a backfilled big playlist.
        playlist._tracks = list(first)
        self._tracks_disk.put(
            playlist.uri, playlist.updated_at, [track._raw for track in first]
        )
        return first, False

    def _schedule_backfill(self, playlist):
        uri = playlist.uri
        with self._backfill_lock:
            if uri in self._backfilling:
                return
            self._backfilling.add(uri)
        threading.Thread(
            target=self._backfill,
            args=(playlist,),
            name="qobuz-playlist-backfill",
            daemon=True,
        ).start()

    def _backfill(self, playlist):
        """Page in the full track list, persist it to disk, and tell clients
        the complete list is ready (they re-query / reopen to get it)."""
        uri = playlist.uri
        try:
            _start = time.time()
            tracks = playlist.tracks  # forces the full paged load
            self._tracks_disk.put(
                uri, playlist.updated_at, [track._raw for track in tracks]
            )
            logger.info(
                "[SYNC_TIMING] qobuz backfill complete uri=%s tracks=%d duration=%.2fs",
                uri,
                len(tracks),
                time.time() - _start,
            )
            # The only unconditional send in this provider: fires once per
            # user-initiated open, not on every TTL refresh (refresh()'s event
            # stays change-gated), so it can't fan out into a re-fetch storm.
            backend.BackendListener.send("playlists_loaded")
        except Exception:
            logger.exception("Error backfilling tracks for %s", uri)
        finally:
            with self._backfill_lock:
                self._backfilling.discard(uri)

    def _hydrate_tracks_from_disk(self, playlist):
        """Pre-load a fresh playlist object's tracks from the on-disk cache
        when its upstream updated_at matches, so opening it after a restart is
        instant instead of re-paging from Qobuz. Returns True if it hydrated."""
        if playlist._tracks is not None or playlist.updated_at is None:
            return False
        cached = self._tracks_disk.get(playlist.uri, playlist.updated_at)
        if not cached:
            return False
        try:
            client = self._backend._client
            playlist._tracks = [Track(client, raw) for raw in cached]
            logger.info(
                "[SYNC_TIMING] qobuz hydrated %d tracks from disk for %s",
                len(cached), playlist.uri,
            )
            return True
        except Exception:
            logger.exception(
                "Failed to hydrate tracks from disk for %s", playlist.uri
            )
            playlist._tracks = None
            return False

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
        hydrated = 0

        for playlist in playlists:
            cached = self._snapshot.get(playlist.uri)
            if cached is not None and not _is_newer(playlist, cached):
                # Unchanged upstream: keep the cached copy so already
                # loaded tracks are reused
                snapshot[playlist.uri] = cached
            else:
                # New or changed upstream (or the first refresh after a
                # restart, when the in-memory snapshot is empty): hydrate the
                # full track list from disk when the upstream updated_at still
                # matches, so a previously-opened playlist opens instantly
                # instead of re-paging. A changed updated_at won't match the
                # disk key, so stale tracks are never served.
                if self._hydrate_tracks_from_disk(playlist):
                    hydrated += 1
                snapshot[playlist.uri] = playlist

        # Replacing the snapshot implicitly prunes playlists that
        # disappeared upstream. Unchanged entries are the same objects as
        # before, so dict equality doubles as an identity-based change check
        changed = snapshot != self._snapshot
        self._snapshot = snapshot
        # Keep the on-disk tracks cache from growing without bound as
        # playlists come and go.
        self._tracks_disk.prune(snapshot.keys())
        self._playlists.put(_LIST_KEY, True)
        logger.info(
            "[SYNC_TIMING] qobuz refresh hydrated %d/%d playlists from disk cache",
            hydrated, len(playlists),
        )

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
