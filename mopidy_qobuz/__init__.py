# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import logging
import os
import pathlib
import sys

from mopidy import config
from mopidy import ext

__version__ = "0.2.0"  # v0.2.0: OAuth implementation with automatic token refresh


logger = logging.getLogger(__name__)

file_dir = os.path.dirname(__file__)
sys.path.append(file_dir)


class Extension(ext.Extension):
    dist_name = "Mopidy-Qobuz"
    ext_name = "qobuz"
    version = __version__

    def get_default_config(self):
        return config.read(pathlib.Path(__file__).parent / "ext.conf")

    def get_config_schema(self):
        schema = super().get_config_schema()

        # OAuth configuration
        schema["auth_method"] = config.String(optional=True, choices=["password", "oauth"])
        schema["client_id"] = config.String(optional=True)
        schema["client_secret"] = config.Secret(optional=True)

        # OAuth tokens (passed via command-line)
        schema["access_token"] = config.Secret(optional=True)
        schema["refresh_token"] = config.Secret(optional=True)
        schema["token_expires_in"] = config.Integer(optional=True)

        # Legacy password auth (kept for backward compatibility)
        schema["username"] = config.String(optional=True)
        schema["password"] = config.Secret(optional=True)
        schema["app_id"] = config.String(optional=True)
        schema["secret"] = config.Secret(optional=True)

        # Common settings
        schema["quality"] = config.Integer(choices=[5, 6, 7, 27])
        schema["search_artist_count"] = config.Integer()
        schema["search_track_count"] = config.Integer()
        schema["search_album_count"] = config.Integer()

        # Playlist settings
        schema["playlist_track_limit"] = config.Integer(optional=True)
        schema["playlist_cache_ttl"] = config.Integer(optional=True)

        # Playback reporting
        schema["enable_playback_reporting"] = config.Boolean(optional=True)

        # Token refresh settings
        schema["token_refresh_enabled"] = config.Boolean(optional=True)
        schema["token_refresh_check_interval"] = config.Integer(optional=True)
        schema["token_refresh_threshold"] = config.Float(optional=True)

        # Source identification (auto-detects from CLI if not set)
        schema["source_id"] = config.String(optional=True)

        # Debug logging
        schema["auth_logging_enabled"] = config.Boolean(optional=True)

        # OAuth client credentials (for token refresh)
        schema["client_id"] = config.String(optional=True)
        schema["client_secret"] = config.Secret(optional=True)

        # DEPRECATED (keep for backward compatibility but mark as such)
        schema["credential_api_url"] = config.String(optional=True)  # DEPRECATED
        schema["credential_api_auth_user"] = config.String(optional=True)  # DEPRECATED
        schema["credential_api_auth_pass"] = config.Secret(optional=True)  # DEPRECATED

        schema["custom_libraries"] = config.Path(optional=True)

        return schema

    def setup(self, registry):
        from .backend import QobuzBackend

        registry.add("backend", QobuzBackend)
