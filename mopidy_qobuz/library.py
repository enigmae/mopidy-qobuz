# -*- coding: utf-8 -*-

import logging
import urllib.parse

from mopidy import backend
from mopidy import models

from mopidy_qobuz import Extension
from mopidy_qobuz import translators
from mopidy_qobuz.browse import browse
from mopidy_qobuz.browse import ROOT_DIR
from mopidy_qobuz.cache import PlaylistArtworkDiskCache
from mopidy_qobuz.client import Album
from mopidy_qobuz.client import Artist
from mopidy_qobuz.client import Playlist
from mopidy_qobuz.client import Track

logger = logging.getLogger(__name__)

# Up to 4 distinct covers per playlist so clients can composite a 2x2
# mosaic from the returned images
PLAYLIST_MOSAIC_SIZE = 4

# Qobuz playlist payloads carry ready-made cover mosaics in several
# square sizes; prefer the largest variant that is populated
_PLAYLIST_IMAGE_FIELDS = (
    ("images300", 300),
    ("images150", 150),
    ("images", 50),
)


class QobuzLibraryProvider(backend.LibraryProvider):
    root_directory = ROOT_DIR

    def __init__(self, backend):
        self._backend = backend
        self._config = backend._config["qobuz"]
        self._artwork_cache = PlaylistArtworkDiskCache(
            Extension.get_cache_dir(backend._config)
        )

    def get_distinct(self, field, query=None):
        logger.info("Browsing distinct %s with query %r", field, query)
        return []

    def browse(self, uri):
        # fixme
        if not uri or not uri.startswith("qobuz"):
            return []

        if uri.startswith("qobuz:playlist:"):
            # Serve playlist contents through the playlists provider so its
            # snapshot / disk cache / first-slice machinery is reused instead
            # of re-paging the whole playlist on every browse.
            refs = self._browse_playlist_fast(uri)
            if refs is not None:
                return refs

        return browse(uri, self._backend._client, self._config)

    def _browse_playlist_fast(self, uri):
        """Track refs for a playlist via the playlists provider's caches.

        Returns None when the provider can't serve the URI so the caller
        falls back to the direct (slow) browse path.
        """
        provider = getattr(self._backend, "playlists", None)
        if provider is None:
            return None
        try:
            return provider.get_items(uri)
        except Exception:
            logger.exception("Provider-backed browse failed for %s", uri)
            return None

    def lookup(self, uris=None):
        if not uris:
            return []

        # Why are strings passed here?
        if isinstance(uris, str):
            uris = [uris]

        client = self._backend._client
        tracks = []
        # Built lazily, at most once per lookup call: queueing a whole
        # playlist arrives as ONE lookup with hundreds of track URIs, so
        # resolve them from tracks already held by the playlists provider
        # instead of one rate-limited track/get call each.
        track_index = None
        for uri in uris:
            if not uri.startswith("qobuz:"):
                continue

            type = uri.split(":")[1]
            id = uri.split(":")[-1]

            # TODO: add artist support
            if type == "album":
                # Request album with embedded tracks to avoid individual track/get calls
                album = Album.from_id(client, id, extra="tracks")
                tracks.extend([translators.to_track(track) for track in album.tracks])

            elif type == "artist":
                artist = Artist.from_id(client, id)
                tracks.extend([translators.to_track(track) for track in artist.tracks])

            elif type == "playlist":
                tracks.extend(self._playlist_tracks(uri, id))

            elif type == "track":
                if track_index is None:
                    track_index = self._loaded_track_index()
                known = track_index.get(uri)
                if known is not None:
                    tracks.append(translators.to_track(known))
                else:
                    tracks.append(translators.to_track(Track.from_id(client, id)))

            else:
                logger.debug("Ignoring non-supported type: %s", type)

        return _filter_none(tracks)

    def _playlist_tracks(self, uri, playlist_id):
        """Complete translated track list for a playlist.

        Goes through the playlists provider (memory snapshot, on-disk track
        cache, in-flight backfill reuse) so repeated plays never re-page the
        whole playlist from the API -- the pre-existing direct
        Playlist.from_id() path built a throwaway object and re-fetched
        every page on every single call. Falls back to that direct path
        only when the provider can't serve the URI.
        """
        provider = getattr(self._backend, "playlists", None)
        if provider is not None:
            try:
                playlist = provider._get_playlist(uri)
                if playlist is not None:
                    return [
                        translators.to_track(track)
                        for track in provider.full_tracks(playlist)
                    ]
            except Exception:
                logger.exception("Provider-backed playlist lookup failed for %s", uri)

        playlist = Playlist.from_id(self._backend._client, playlist_id)
        return [translators.to_track(track) for track in playlist.tracks]

    def _loaded_track_index(self):
        """{track uri: client Track} from the playlists provider, or an
        empty dict when the provider is unavailable."""
        provider = getattr(self._backend, "playlists", None)
        if provider is None:
            return {}
        try:
            return provider.loaded_track_index()
        except Exception:
            logger.exception("Could not build the loaded-track index")
            return {}

    def search(self, query, uris=None, exact=False):
        if not query:
            logger.debug("Ignoring falsy query: %s", query)
            return None

        tracks = list()
        albums = list()
        artists = list()

        if "uri" in query:
            uri = query["uri"][0]
            if uri.startswith("qobuz:album:"):
                tracks = self.lookup(uri)
            else:
                return None
        else:
            # For qobuz API, which is smart enough
            query = " ".join(" ".join(value) for value in query.values()).strip()
            if not query:
                logger.debug("Query is empty: %s", query)
                return None

            uri = f"qobuz:search:{urllib.parse.quote(query)}"
            logger.debug("Generated uri: %s", uri)

            albums = self._search(translators.to_album, Album, "search_album_count", query)
            artists = self._search(
                translators.to_artist, Artist, "search_artist_count", query
            )
            tracks = self._search(translators.to_track, Track, "search_track_count", query)

            # Background fetch: Prefetch full artist data for better caching
            # This populates the cache with complete artist info (including images)
            # so clicking on an artist is instant
            self._prefetch_artists(artists)

        return models.SearchResult(
            uri=uri,
            albums=albums,
            artists=artists,
            tracks=tracks,
        )

    def _prefetch_artists(self, artists):
        """
        Background fetch full artist data to populate cache.
        This makes artist pages load instantly when clicked.
        """
        if not artists:
            return

        client = self._backend._client

        # Fetch artist data in background (non-blocking)
        def fetch_artist_data():
            for artist in artists[:10]:  # Limit to top 10 to avoid excessive calls
                try:
                    # Extract artist ID from URI (format: qobuz:artist:123456)
                    artist_id = artist.uri.split(":")[-1]
                    # Fetch full artist data - will populate cache
                    Artist.from_id(client, artist_id)
                    logger.debug(f"Prefetched artist data for: {artist.name}")
                except Exception as e:
                    logger.debug(f"Failed to prefetch artist {artist.name}: {e}")

        # Use thread pool executor from client for background fetch
        client._http_executor.submit(fetch_artist_data)

    def get_images(self, uris):
        logger.info("Looking for images: %s", uris)
        if not uris:
            return {}

        client = self._backend._client
        images = {}

        for uri in uris:
            type = uri.split(":")[1]
            id = uri.split(":")[-1]

            if type not in ("album", "track", "artist", "playlist"):
                continue

            if type == "playlist":
                # Playlists get multiple images (a content-derived
                # mosaic) instead of the single image built below
                images[uri] = self._get_playlist_images(uri)
                continue

            image = None
            if type == "album":
                # For image lookup, we don't need tracks
                album = Album.from_id(client, id)
                image = album.image()
            elif type == "track":
                track = Track.from_id(client, id)
                image = track.album.image()
            elif type == "artist":
                # Fetch artist and get image
                artist = Artist.from_id(client, id)
                image = artist.image()

            if image is not None:
                images[uri] = [models.Image(uri=image, width=600, height=600)]
            else:
                images[uri] = ()

        logger.info("Returning images: %s", images)
        return images

    def _get_playlist_images(self, uri):
        """Return up to PLAYLIST_MOSAIC_SIZE images for a playlist URI.

        Freshness: within a single process lifetime, results don't need
        re-deriving on every call -- the provider's refresh() swaps
        snapshot entries whose upstream updated_at changed, so artwork
        follows playlist edits without any invalidation logic here. But
        that in-memory reuse doesn't survive a restart, and deriving
        artwork the API doesn't hand us a ready-made mosaic for means
        fetching a page of tracks. So results are additionally persisted
        to `self._artwork_cache` (disk, keyed by uri + updated_at) --
        skipped when updated_at is unavailable, since there's nothing
        reliable to invalidate on.
        """
        playlist = self._backend.playlists._get_playlist(uri)
        if playlist is None:
            return ()

        updated_at = getattr(playlist, "updated_at", None)
        if updated_at is not None:
            cached = self._artwork_cache.get(uri, updated_at)
            if cached is not None:
                return [models.Image(**image) for image in cached]

        images = self._derive_playlist_images(playlist)
        if updated_at is not None:
            self._artwork_cache.put(
                uri,
                updated_at,
                [
                    {"uri": img.uri, "width": img.width, "height": img.height}
                    for img in images
                ],
            )
        return images

    @staticmethod
    def _derive_playlist_images(playlist):
        # Prefer the service-provided mosaic from the list payload
        for field, size in _PLAYLIST_IMAGE_FIELDS:
            urls = _distinct_urls(getattr(playlist, field, None) or [])
            if urls:
                return [
                    models.Image(uri=url, width=size, height=size)
                    for url in urls
                ]

        # No service images: derive distinct album covers from the
        # current tracks. Only the first tracks page is used (already
        # loaded tracks are reused, otherwise it is fetched once per
        # playlist object) so artwork never pages through a huge list
        urls = _distinct_urls(
            track.album.image() for track in playlist.first_tracks_page()
        )
        return [models.Image(uri=url, width=600, height=600) for url in urls]

    def _search(self, item_translator, item_cls, config_key, query):
        config_value = self._config[config_key]

        if not config_value:
            return []

        items = [
            item_translator(item)
            for item in item_cls.from_search(self._backend._client, query, config_value)
        ]
        return _filter_none(items)


def _filter_none(items):
    # Translator return None if something fails
    return [item for item in items if item is not None]


def _distinct_urls(urls, limit=PLAYLIST_MOSAIC_SIZE):
    # First `limit` distinct non-empty URLs, original order preserved
    distinct = []
    for url in urls:
        if url and url not in distinct:
            distinct.append(url)
            if len(distinct) == limit:
                break

    return distinct
