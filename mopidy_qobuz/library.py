# -*- coding: utf-8 -*-

import logging
import urllib.parse

from mopidy import backend
from mopidy import models

from mopidy_qobuz import translators
from mopidy_qobuz.browse import browse
from mopidy_qobuz.browse import ROOT_DIR
from mopidy_qobuz.client import Album
from mopidy_qobuz.client import Artist
from mopidy_qobuz.client import Playlist
from mopidy_qobuz.client import Track

logger = logging.getLogger(__name__)


class QobuzLibraryProvider(backend.LibraryProvider):
    root_directory = ROOT_DIR

    def __init__(self, backend):
        self._backend = backend
        self._config = backend._config["qobuz"]

    def get_distinct(self, field, query=None):
        logger.info("Browsing distinct %s with query %r", field, query)
        return []

    def browse(self, uri):
        # fixme
        if not uri or not uri.startswith("qobuz"):
            return []

        return browse(uri, self._backend._client, self._config)

    def lookup(self, uris=None):
        if not uris:
            return []

        # Why are strings passed here?
        if isinstance(uris, str):
            uris = [uris]

        client = self._backend._client
        tracks = []
        for uri in uris:
            if not uri.startswith("qobuz:"):
                continue

            type = uri.split(":")[1]
            id = uri.split(":")[-1]

            # TODO: add artist and playlist support
            if type == "album":
                # Request album with embedded tracks to avoid individual track/get calls
                album = Album.from_id(client, id, extra="tracks")
                tracks.extend([translators.to_track(track) for track in album.tracks])

            elif type == "artist":
                artist = Artist.from_id(client, id)
                tracks.extend([translators.to_track(track) for track in artist.tracks])

            elif type == "playlist":
                playlist = Playlist.from_id(client, id)
                tracks.extend(
                    [translators.to_track(track) for track in playlist.tracks]
                )

            elif type == "track":
                tracks.append(translators.to_track(Track.from_id(client, id)))

            else:
                logger.debug("Ignoring non-supported type: %s", type)

        return _filter_none(tracks)

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

            if type not in ("album", "track", "artist"):
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
