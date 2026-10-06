# -*- coding: utf-8 -*-
"""Provider-backed playlist/track lookups (the play-path speedup).

Covers the paths that make playing a big playlist fast:
  * QobuzPlaylistsProvider.full_tracks -- complete list from memory /
    disk / in-flight backfill, with exactly ONE blocking page-through
    ever happening cold.
  * QobuzPlaylistsProvider.loaded_track_index -- batched track-URI
    resolution from already-held tracks.
  * QobuzLibraryProvider.lookup/browse -- delegation to the provider
    instead of throwaway Playlist.from_id() re-pages and per-track
    track/get calls.
"""
import threading
import time

import pytest
from mopidy import models

from mopidy_qobuz import library as library_mod
from mopidy_qobuz.client import Track
from mopidy_qobuz.library import QobuzLibraryProvider
from mopidy_qobuz.playlists import QobuzPlaylistsProvider


def raw_track(i):
    return {
        "id": i,
        "title": "Song %d" % i,
        "duration": 200,
        "streamable": True,
        "media_number": 1,
        "track_number": i,
        "performer": {"id": 9, "name": "Artist"},
        "album": {
            "id": "al1",
            "title": "Album A",
            "streamable": True,
            "tracks_count": 10,
            "release_date_original": "2020-01-01",
            "artist": {"id": 9, "name": "Artist"},
        },
    }


class FakeApiPlaylist:
    """Duck-typed stand-in for client.Playlist: counts full page-throughs."""

    def __init__(self, uri="qobuz:playlist:pl1", updated_at=1000, n_tracks=4):
        self.uri = uri
        self.updated_at = updated_at
        self.tracks_count = n_tracks
        self._all_raw = [raw_track(i) for i in range(n_tracks)]
        self._tracks = None
        self._first_tracks_page = None
        self.full_loads = 0

    @property
    def tracks(self):
        if self._tracks is None:
            self.full_loads += 1
            self._tracks = [Track(None, raw) for raw in self._all_raw]
        return self._tracks

    def first_tracks_page(self, limit=50):
        if self._tracks is not None:
            return self._tracks[:limit]
        if self._first_tracks_page is None:
            self._first_tracks_page = [
                Track(None, raw) for raw in self._all_raw[:limit]
            ]
        return self._first_tracks_page


class BackendStub:
    def __init__(self, config, playlists=None):
        self._config = config
        self._client = None
        self.playlists = playlists


@pytest.fixture
def config(tmp_path):
    return {
        "core": {"cache_dir": str(tmp_path)},
        "qobuz": {"playlist_cache_ttl": 300},
    }


@pytest.fixture
def provider(config):
    return QobuzPlaylistsProvider(BackendStub(config))


# ---------------------------------------------------------------------------
# QobuzPlaylistsProvider.full_tracks
# ---------------------------------------------------------------------------


def test_full_tracks_reuses_loaded_tracks(provider):
    pl = FakeApiPlaylist()
    loaded = [Track(None, raw_track(i)) for i in range(3)]
    pl._tracks = loaded

    assert provider.full_tracks(pl) is loaded
    assert pl.full_loads == 0


def test_full_tracks_hydrates_from_disk(provider):
    pl = FakeApiPlaylist(n_tracks=5)
    provider._tracks_disk.put(
        pl.uri, pl.updated_at, [raw_track(i) for i in range(5)]
    )

    tracks = provider.full_tracks(pl)

    assert pl.full_loads == 0
    assert len(tracks) == 5
    assert tracks[0].uri == "qobuz:track:0"


def test_full_tracks_cold_loads_once_and_persists(provider):
    pl = FakeApiPlaylist(n_tracks=4)

    first = provider.full_tracks(pl)
    second = provider.full_tracks(pl)

    assert first is second
    assert pl.full_loads == 1
    # Persisted: a fresh object for the same (uri, updated_at) hydrates
    assert provider._tracks_disk.get(pl.uri, pl.updated_at)


def test_full_tracks_waits_for_inflight_backfill(provider):
    pl = FakeApiPlaylist(n_tracks=3)
    backfilled = [Track(None, raw_track(i)) for i in range(3)]
    with provider._backfill_lock:
        provider._backfilling.add(pl.uri)

    def finish_backfill():
        time.sleep(0.3)
        pl._tracks = backfilled
        with provider._backfill_lock:
            provider._backfilling.discard(pl.uri)

    threading.Thread(target=finish_backfill, daemon=True).start()

    tracks = provider.full_tracks(pl, backfill_wait_secs=5.0)

    assert tracks is backfilled
    assert pl.full_loads == 0


# ---------------------------------------------------------------------------
# QobuzPlaylistsProvider.loaded_track_index
# ---------------------------------------------------------------------------


def test_loaded_track_index_covers_full_and_first_page(provider):
    full = FakeApiPlaylist(uri="qobuz:playlist:full", n_tracks=2)
    full._tracks = [Track(None, raw_track(i)) for i in (1, 2)]
    sliced = FakeApiPlaylist(uri="qobuz:playlist:sliced", n_tracks=2)
    sliced._first_tracks_page = [Track(None, raw_track(i)) for i in (2, 3)]
    unloaded = FakeApiPlaylist(uri="qobuz:playlist:unloaded")
    provider._snapshot = {
        pl.uri: pl for pl in (full, sliced, unloaded)
    }

    index = provider.loaded_track_index()

    assert set(index) == {
        "qobuz:track:1", "qobuz:track:2", "qobuz:track:3",
    }
    assert unloaded.full_loads == 0


# ---------------------------------------------------------------------------
# QobuzLibraryProvider delegation
# ---------------------------------------------------------------------------


class StubPlaylistsProvider:
    def __init__(self, playlist=None, index=None, items=None):
        self.playlist = playlist
        self.index = index or {}
        self.items = items
        self.full_tracks_calls = 0

    def _get_playlist(self, uri):
        return self.playlist

    def full_tracks(self, playlist):
        self.full_tracks_calls += 1
        return playlist.tracks

    def loaded_track_index(self):
        return self.index

    def get_items(self, uri):
        if self.items is None:
            raise RuntimeError("boom")
        return self.items


@pytest.fixture
def library(config):
    def make(playlists_provider):
        backend = BackendStub(config, playlists=playlists_provider)
        return QobuzLibraryProvider(backend)

    return make


def test_lookup_playlist_goes_through_provider(library, monkeypatch):
    pl = FakeApiPlaylist(n_tracks=3)
    stub = StubPlaylistsProvider(playlist=pl)
    lib = library(stub)
    monkeypatch.setattr(
        library_mod.Playlist, "from_id",
        classmethod(lambda *a, **k: pytest.fail("direct from_id used")),
    )

    tracks = lib.lookup("qobuz:playlist:pl1")

    assert stub.full_tracks_calls == 1
    assert [t.uri for t in tracks] == [
        "qobuz:track:0", "qobuz:track:1", "qobuz:track:2",
    ]


def test_lookup_playlist_falls_back_without_provider_hit(library, monkeypatch):
    stub = StubPlaylistsProvider(playlist=None)
    lib = library(stub)
    fallback = FakeApiPlaylist(n_tracks=2)
    monkeypatch.setattr(
        library_mod.Playlist, "from_id",
        classmethod(lambda cls, client, id: fallback),
    )

    tracks = lib.lookup("qobuz:playlist:pl1")

    assert fallback.full_loads == 1
    assert len(tracks) == 2


def test_lookup_tracks_resolved_from_index(library, monkeypatch):
    index = {
        "qobuz:track:%d" % i: Track(None, raw_track(i)) for i in range(4)
    }
    lib = library(StubPlaylistsProvider(index=index))
    monkeypatch.setattr(
        library_mod.Track, "from_id",
        classmethod(lambda *a, **k: pytest.fail("track/get used")),
    )

    tracks = lib.lookup(list(index))

    assert len(tracks) == 4
    assert {t.uri for t in tracks} == set(index)


def test_lookup_track_miss_falls_back_to_api(library, monkeypatch):
    lib = library(StubPlaylistsProvider(index={}))
    monkeypatch.setattr(
        library_mod.Track, "from_id",
        classmethod(lambda cls, client, id: Track(None, raw_track(7))),
    )

    tracks = lib.lookup("qobuz:track:7")

    assert [t.uri for t in tracks] == ["qobuz:track:7"]


def test_browse_playlist_uses_provider_items(library):
    refs = [models.Ref.track(uri="qobuz:track:1", name="Song 1")]
    lib = library(StubPlaylistsProvider(items=refs))

    assert lib.browse("qobuz:playlist:pl1") == refs


def test_browse_playlist_falls_back_when_provider_fails(library, monkeypatch):
    sentinel = [models.Ref.track(uri="qobuz:track:9", name="fallback")]
    lib = library(StubPlaylistsProvider(items=None))  # get_items raises
    monkeypatch.setattr(
        library_mod, "browse", lambda uri, client, config: sentinel
    )

    assert lib.browse("qobuz:playlist:pl1") == sentinel
