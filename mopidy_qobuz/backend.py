# -*- coding: utf-8 -*-

EXTENSION_VERSION = "NEW QOBUZ EXTENSION v2025.01.20.1 - Search result caching"

import logging
import time
import uuid

from mopidy import backend
from mopidy import core
import pykka

from mopidy_qobuz import client as qclient
from mopidy_qobuz import library
from mopidy_qobuz import playback
from mopidy_qobuz import playlists
from mopidy_qobuz.credential_client import CredentialClient

logger = logging.getLogger(__name__)


class QobuzPlaybackReporter(pykka.ThreadingActor, core.CoreListener):
    """
    Listens to Mopidy playback events and reports to Qobuz API with segment tracking.

    Each track can have multiple segments due to pause/resume/seek events.
    All segments share the same track_context_uuid but are reported separately.
    """
    def __init__(self, qobuz_backend):
        super().__init__()
        self._backend = qobuz_backend
        self._current_track_id = None
        self._current_segment_start = None
        self._track_context_uuid = None
        self._format_id = None
        self._segment_count = 0
        self._blob = None  # Blob from track/getFileUrl for reporting

        logger.info(f"[{EXTENSION_VERSION}] Qobuz Playback Reporter initialized")

    def _get_current_timestamp(self):
        """Get current Unix timestamp"""
        return int(time.time())

    def _start_new_segment(self):
        """Start tracking a new playback segment"""
        self._current_segment_start = self._get_current_timestamp()
        self._segment_count += 1

        logger.info(f"[{EXTENSION_VERSION}] Starting segment #{self._segment_count} at timestamp {self._current_segment_start}")

    def _end_current_segment(self):
        """End and report the current playback segment"""
        if not self._current_segment_start:
            logger.debug(f"[{EXTENSION_VERSION}] No active segment to end")
            return

        if not self._current_track_id:
            logger.warning(f"[{EXTENSION_VERSION}] Cannot end segment - no track ID")
            return

        try:
            # Calculate segment duration
            segment_end = self._get_current_timestamp()
            duration = segment_end - self._current_segment_start

            logger.info("=" * 70)
            logger.info(f"[{EXTENSION_VERSION}] Ending segment #{self._segment_count}")
            logger.info(f"[{EXTENSION_VERSION}] Track ID: {self._current_track_id}")
            logger.info(f"[{EXTENSION_VERSION}] Track Context UUID: {self._track_context_uuid}")
            logger.info(f"[{EXTENSION_VERSION}] Segment start: {self._current_segment_start}")
            logger.info(f"[{EXTENSION_VERSION}] Segment end: {segment_end}")
            logger.info(f"[{EXTENSION_VERSION}] Duration: {duration}s")
            logger.info(f"[{EXTENSION_VERSION}] Format ID: {self._format_id}")
            logger.info(f"[{EXTENSION_VERSION}] Blob: {self._blob[:50]}..." if self._blob else f"[{EXTENSION_VERSION}] Blob: <empty>")

            # Report this segment to Qobuz using JSON endpoint
            self._backend._client.report_streaming_end_json(
                track_id=self._current_track_id,
                duration=duration,
                date=self._current_segment_start,
                format_id=self._format_id,
                online=True,
                local=False,
                track_context_uuid=self._track_context_uuid,
                blob=self._blob
            )

            logger.info(f"[{EXTENSION_VERSION}] ✓ Segment #{self._segment_count} reported successfully (JSON endpoint)")
            logger.info("=" * 70)

            # Clear segment start (but keep track context for next segment)
            self._current_segment_start = None

        except Exception as e:
            logger.error(f"[{EXTENSION_VERSION}] Failed to report segment: {e}", exc_info=True)

    def track_playback_started(self, tl_track):
        """Called when Mopidy starts playing a track"""
        if not self._backend.playback._enable_reporting:
            logger.debug(f"[{EXTENSION_VERSION}] Reporting disabled - skipping track_playback_started")
            return

        if tl_track and tl_track.track and tl_track.track.uri:
            uri = tl_track.track.uri
            if not uri.startswith("qobuz:track:"):
                logger.debug(f"[{EXTENSION_VERSION}] Skipping non-Qobuz track: {uri}")
                return

            try:
                track_id = uri.split(":")[-1]

                # Generate new track context UUID for this track
                self._track_context_uuid = str(uuid.uuid4())
                self._current_track_id = track_id
                self._segment_count = 0

                # Get format_id from playback provider
                self._format_id = self._backend.playback._format_id

                # Extract blob from cached DownloadableTrack
                self._blob = ""  # Default to empty
                if track_id in self._backend.playback._tracks:
                    downloadable = self._backend.playback._tracks[track_id]
                    if hasattr(downloadable, 'blob'):
                        self._blob = downloadable.blob or ""
                        if self._blob:
                            logger.info(f"[{EXTENSION_VERSION}] ✓ Extracted blob from DownloadableTrack: {self._blob[:30]}...")
                        else:
                            logger.warning(f"[{EXTENSION_VERSION}] ⚠ Blob is empty in DownloadableTrack")
                    else:
                        logger.warning(f"[{EXTENSION_VERSION}] ⚠ DownloadableTrack has no blob attribute")
                else:
                    logger.warning(f"[{EXTENSION_VERSION}] ⚠ Track {track_id} not found in playback cache")

                logger.info("=" * 70)
                logger.info(f"[{EXTENSION_VERSION}] Track playback started")
                logger.info(f"[{EXTENSION_VERSION}] Track ID: {track_id}")
                logger.info(f"[{EXTENSION_VERSION}] Track Context UUID: {self._track_context_uuid}")
                logger.info(f"[{EXTENSION_VERSION}] Format ID: {self._format_id}")
                logger.info(f"[{EXTENSION_VERSION}] Blob: {self._blob[:50]}..." if self._blob else f"[{EXTENSION_VERSION}] Blob: <empty>")

                # Report streaming start to Qobuz
                self._backend._client.report_streaming_start(
                    track_id,
                    self._format_id,
                    intent="streaming",
                    sample=False
                )
                logger.info(f"[{EXTENSION_VERSION}] ✓ Streaming start reported")

                # Start first segment
                self._start_new_segment()
                logger.info("=" * 70)

            except Exception as e:
                logger.error(f"[{EXTENSION_VERSION}] Failed to handle track_playback_started: {e}", exc_info=True)

    def track_playback_paused(self, tl_track, time_position):
        """Called when playback is paused - end current segment"""
        if not self._backend.playback._enable_reporting:
            return

        logger.info(f"[{EXTENSION_VERSION}] Playback paused - ending segment")
        self._end_current_segment()

    def track_playback_resumed(self, tl_track, time_position):
        """Called when playback is resumed - start new segment"""
        if not self._backend.playback._enable_reporting:
            return

        logger.info(f"[{EXTENSION_VERSION}] Playback resumed - starting new segment")
        self._start_new_segment()

    def seeked(self, time_position):
        """Called when user seeks in track - split into segments"""
        if not self._backend.playback._enable_reporting:
            return

        if not self._current_track_id:
            return

        logger.info(f"[{EXTENSION_VERSION}] Seek event at position {time_position}ms - splitting segment")

        # End current segment
        self._end_current_segment()

        # Start new segment immediately
        self._start_new_segment()

    def track_playback_ended(self, tl_track, time_position):
        """Called when Mopidy ends playing a track - end final segment"""
        if not self._backend.playback._enable_reporting:
            logger.debug(f"[{EXTENSION_VERSION}] Reporting disabled - skipping track_playback_ended")
            return

        if self._current_track_id:
            try:
                logger.info(f"[{EXTENSION_VERSION}] Track playback ended - ending final segment")

                # End the final segment
                self._end_current_segment()

                # Clear track state
                logger.info(f"[{EXTENSION_VERSION}] Total segments reported for this track: {self._segment_count}")
                self._current_track_id = None
                self._track_context_uuid = None
                self._format_id = None
                self._segment_count = 0
                self._blob = None

            except Exception as e:
                logger.error(f"[{EXTENSION_VERSION}] Failed to handle track_playback_ended: {e}", exc_info=True)


class QobuzBackend(pykka.ThreadingActor, backend.Backend):
    def __init__(self, config, audio):
        super().__init__()
        self._config = config
        self._audio = audio
        self._client = None
        self._playback_reporter = None
        self._token_refresh_thread = None
        self._token_refresh_running = False
        self._credential_client = None
        self.playlists = playlists.QobuzPlaylistsProvider(self)
        self.library = library.QobuzLibraryProvider(self)
        self.playback = playback.QobuzPlaybackProvider(audio, self)
        self.uri_schemes = ["qobuz"]

    def ping(self):
        return True

    def on_start(self):
        from mopidy_qobuz import __version__
        logger.info("=" * 80)
        logger.info("[QOBUZ BACKEND] Starting Qobuz backend v%s with OAuth support", __version__)
        config = self._config["qobuz"]

        # Log configuration (sanitized)
        logger.info("[QOBUZ BACKEND] Configuration:")
        logger.info(f"  - enabled: {config.get('enabled', False)}")
        logger.info(f"  - quality: {config.get('quality', 'N/A')}")
        logger.info(f"  - auth_method: {config.get('auth_method', 'password')}")
        logger.info(f"  - app_id: {(config.get('app_id') or 'N/A')[:20]}...")
        logger.info(f"  - secret: {'***' if config.get('secret') else 'N/A'}")
        logger.info(f"  - username: {'***' if config.get('username') else 'None'}")
        logger.info(f"  - password: {'***' if config.get('password') else 'None'}")
        logger.info(f"  - access_token: {'***' if config.get('access_token') else 'None'}")
        logger.info(f"  - refresh_token: {'***' if config.get('refresh_token') else 'None'}")
        logger.info(f"  - search_album_count: {config.get('search_album_count', 10)}")
        logger.info(f"  - search_track_count: {config.get('search_track_count', 10)}")
        logger.info(f"  - search_artist_count: {config.get('search_artist_count', 0)}")

        # Playlist settings
        playlist_limit = config.get('playlist_track_limit', 100)
        playlist_ttl = config.get('playlist_cache_ttl', 300)
        logger.info("[QOBUZ BACKEND] Playlist Settings:")
        logger.info(f"  - playlist_track_limit: {playlist_limit} tracks")
        logger.info(f"  - playlist_cache_ttl: {playlist_ttl}s ({playlist_ttl/60:.1f} minutes)")

        # Playback reporting
        reporting_enabled = config.get('enable_playback_reporting', False)
        logger.info("[QOBUZ BACKEND] Playback Reporting:")
        logger.info(f"  - enable_playback_reporting: {reporting_enabled} {'✓ ENABLED' if reporting_enabled else '✗ DISABLED'}")

        # Always initialize client with app_id and secret (required for API calls)
        app_id = config.get("app_id") or config.get("client_id", "PLACEHOLDER")
        secret = config.get("secret") or config.get("client_secret", "PLACEHOLDER")

        logger.info("[QOBUZ BACKEND] Initializing Qobuz client...")
        # Pass entire config dict to client for API monitoring configuration
        self._client = qclient.Client(app_id, secret, config=config)
        logger.info("[QOBUZ BACKEND] ✓ Qobuz client initialized")

        # Initialize credential client for socket communication
        self._credential_client = CredentialClient(
            config=config,
            socket_address=("localhost", 13579),
            auth_logging_enabled=config.get("auth_logging_enabled", False)
        )
        logger.info("[QOBUZ BACKEND] ✓ Credential client initialized for socket communication")

        # Register token refresh callback for automatic retry on expiry
        self._client._backend_refresh_callback = lambda: self._perform_token_refresh()
        logger.info("[QOBUZ BACKEND] ✓ Token refresh callback registered for automatic retry")

        # Check if OAuth tokens are provided via configuration
        access_token = (config.get("access_token") or "").strip()
        refresh_token = (config.get("refresh_token") or "").strip()
        expires_in = config.get("token_expires_in", 86400)

        if access_token:
            try:
                logger.info("[QOBUZ BACKEND] OAuth tokens found in configuration")
                logger.info(f"[QOBUZ BACKEND] Access token length: {len(access_token)}")
                logger.info(f"[QOBUZ BACKEND] Refresh token length: {len(refresh_token) if refresh_token else 0}")
                logger.info(f"[QOBUZ BACKEND] Token expires in: {expires_in}s")

                self._client.set_oauth_tokens(access_token, refresh_token, expires_in)
                logger.info(
                    "[QOBUZ BACKEND] ✓ OAuth authentication successful | Quality: %s",
                    config["quality"],
                )

                # Check if token is already expired
                if self._client._is_token_expired():
                    logger.warning("[QOBUZ BACKEND] ⚠ OAuth token is ALREADY EXPIRED at startup!")
                    if self._credential_client:
                        self._credential_client.send_status('Token expired - please re-authenticate')
                else:
                    # Token is valid, clear status
                    if self._credential_client:
                        self._credential_client.send_status(None)

            except Exception as e:
                logger.error(f"[QOBUZ BACKEND] ✗ OAuth authentication failed: {e}")
                logger.info("[QOBUZ BACKEND] Falling back to password authentication if available")
                if self._credential_client:
                    self._credential_client.send_status(f'OAuth setup failed: {str(e)[:100]}')

        # Try legacy password authentication if credentials are provided and OAuth failed
        if not access_token or not self._client._using_oauth:
            username = (config.get("username") or "").strip()
            password = (config.get("password") or "").strip()

            if username and password:
                try:
                    logger.info("[QOBUZ BACKEND] Attempting legacy password authentication...")
                    self._client.login(username, password)
                    logger.info(
                        "[QOBUZ BACKEND] ✓ Legacy auth successful | Quality: %s | Membership: %s",
                        config["quality"],
                        self._client.membership.upper() if self._client.membership else "UNKNOWN",
                    )
                except Exception as e:
                    logger.warning(f"[QOBUZ BACKEND] ✗ Legacy authentication failed: {e}")
                    logger.info("[QOBUZ BACKEND] No valid authentication method available")
            else:
                logger.info("[QOBUZ BACKEND] No username/password configured")
                logger.info("[QOBUZ BACKEND] Backend will not be able to authenticate")

        # Check if we have valid authentication - if not, disable the scheme
        # This prevents Qobuz from appearing in URI schemes without valid credentials
        if not self._client._using_oauth and not getattr(self._client, '_logged_in', False):
            logger.warning("[QOBUZ BACKEND] ⚠ No valid credentials - disabling Qobuz scheme")
            logger.warning("[QOBUZ BACKEND] Qobuz will not appear in available sources until authenticated")
            self.uri_schemes = []

        # Start playback reporter if enabled
        reporting_enabled = config.get('enable_playback_reporting', False)
        if reporting_enabled:
            try:
                logger.info("[QOBUZ BACKEND] Starting playback reporter...")
                self._playback_reporter = QobuzPlaybackReporter.start(self).proxy()
                logger.info("[QOBUZ BACKEND] ✓ Playback reporter started and listening for events")
            except Exception as e:
                logger.error(f"[QOBUZ BACKEND] ✗ Failed to start playback reporter: {e}", exc_info=True)
        else:
            logger.info("[QOBUZ BACKEND] Playback reporter not started (reporting disabled)")

        # Start token refresh service if OAuth is enabled
        if self._client._using_oauth:
            refresh_enabled = config.get("token_refresh_enabled", True)
            if refresh_enabled:
                try:
                    self._start_token_refresh_thread()
                except Exception as e:
                    logger.error(f"[QOBUZ BACKEND] ✗ Failed to start token refresh service: {e}", exc_info=True)
            else:
                logger.info("[QOBUZ BACKEND] Token refresh disabled in config")
        else:
            logger.info("[QOBUZ BACKEND] Not using OAuth - token refresh not applicable")

        logger.info("[QOBUZ BACKEND] Backend initialization complete")
        logger.info("=" * 80)

    def on_stop(self):
        # Stop token refresh thread
        self._stop_token_refresh_thread()

        # Stop playback reporter if running
        if self._playback_reporter:
            logger.info("[QOBUZ BACKEND] Stopping playback reporter...")
            try:
                self._playback_reporter.stop()
                logger.info("[QOBUZ BACKEND] ✓ Playback reporter stopped")
            except Exception as e:
                logger.error(f"[QOBUZ BACKEND] Error stopping playback reporter: {e}")

        # Shutdown client executor to clean up background threads
        if self._client:
            logger.info("[QOBUZ BACKEND] Shutting down client...")
            try:
                self._client.shutdown()
                logger.info("[QOBUZ BACKEND] ✓ Client shut down successfully")
            except Exception as e:
                logger.error(f"[QOBUZ BACKEND] Error shutting down client: {e}")
        # TODO: implement logout

    def test_credential_file_update(self):
        """
        Test method to verify credential file update and auto-detection (JSON-RPC method)

        Returns current tokens to trigger file update without actually refreshing.
        This tests the auto-detection logic.
        """
        if not self._client._using_oauth:
            return {"success": False, "message": "Not using OAuth"}

        try:
            # Use current tokens to test file update
            test_tokens = {
                'access_token': self._client._oauth_access_token,
                'refresh_token': self._client._oauth_refresh_token,
                'expires_in': 1382400,
                'token_type': 'bearer'
            }

            success = self._update_credential_file(test_tokens)
            return {
                "success": success,
                "message": "Credential file update test completed - check logs for auto-detection"
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

    def set_oauth_credentials(self, access_token, refresh_token, expires_in=86400):
        """
        Inject OAuth credentials from external system (JSON-RPC method)

        This method is called via Mopidy JSON-RPC after OAuth flow completes
        in an external OAuth proxy.

        Args:
            access_token: OAuth access token from Qobuz
            refresh_token: OAuth refresh token for renewal
            expires_in: Token validity in seconds (default 86400 = 24h)

        Returns:
            bool: True if successful, False otherwise

        Example JSON-RPC call:
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "qobuz.set_oauth_credentials",
                "params": {
                    "access_token": "abc123...",
                    "refresh_token": "def456...",
                    "expires_in": 86400
                }
            }
        """
        logger.info("=" * 80)
        logger.info("[QOBUZ BACKEND] JSON-RPC call: qobuz.set_oauth_credentials")
        logger.info(f"[QOBUZ BACKEND] Access token length: {len(access_token) if access_token else 0}")
        logger.info(f"[QOBUZ BACKEND] Refresh token length: {len(refresh_token) if refresh_token else 0}")
        logger.info(f"[QOBUZ BACKEND] Expires in: {expires_in}s")

        if not self._client:
            logger.error("[QOBUZ BACKEND] ✗ Cannot set OAuth credentials: Qobuz client not initialized")
            logger.error("[QOBUZ BACKEND] This should not happen - client is initialized in on_start()")
            logger.info("=" * 80)
            return False

        try:
            logger.info("[QOBUZ BACKEND] Calling client.set_oauth_tokens()...")
            self._client.set_oauth_tokens(access_token, refresh_token, expires_in)
            logger.info("[QOBUZ BACKEND] ✓ OAuth credentials injected successfully via JSON-RPC")
            logger.info("[QOBUZ BACKEND] Qobuz search and playback should now work with OAuth")

            # Update credential status
            if self._client._is_token_expired():
                logger.warning("[QOBUZ BACKEND] ⚠ Injected token is already expired!")
                if self._credential_client:
                    self._credential_client.send_status('Token expired - please re-authenticate')
            else:
                if self._credential_client:
                    self._credential_client.send_status(None)

            logger.info("=" * 80)
            return True
        except Exception as e:
            logger.error(f"[QOBUZ BACKEND] ✗ Failed to set OAuth credentials: {e}", exc_info=True)

            # Send error status
            if self._credential_client:
                self._credential_client.send_status(f'Credential injection failed: {str(e)[:100]}')

            logger.info("=" * 80)
            return False

    def _start_token_refresh_thread(self):
        """Start background thread for token refresh"""
        import threading

        logger.info("=" * 80)
        logger.info("[QOBUZ TOKEN REFRESH] Starting token refresh service")

        config = self._config["qobuz"]
        refresh_interval = config.get("token_refresh_check_interval", 86400)  # Default: 24 hours
        refresh_threshold = config.get("token_refresh_threshold", 0.5)  # Default: 50%
        source_id = config.get("source_id")

        logger.info(f"[QOBUZ TOKEN REFRESH] Check interval: {refresh_interval}s ({refresh_interval/3600:.1f} hours)")
        logger.info(f"[QOBUZ TOKEN REFRESH] Refresh threshold: {refresh_threshold * 100:.0f}% of token lifetime")
        logger.info(f"[QOBUZ TOKEN REFRESH] Source ID for credential updates: {source_id or 'NOT SET'}")

        self._token_refresh_running = True
        self._token_refresh_thread = threading.Thread(
            target=self._token_refresh_loop,
            daemon=True,
            name="qobuz-token-refresh"
        )
        self._token_refresh_thread.start()

        logger.info("[QOBUZ TOKEN REFRESH] ✓ Token refresh service started")
        logger.info("=" * 80)

    def _stop_token_refresh_thread(self):
        """Stop background token refresh thread"""
        if self._token_refresh_thread:
            logger.info("[QOBUZ TOKEN REFRESH] Stopping token refresh service...")
            self._token_refresh_running = False

            # Wait up to 5 seconds for thread to finish
            self._token_refresh_thread.join(timeout=5)

            if self._token_refresh_thread.is_alive():
                logger.warning("[QOBUZ TOKEN REFRESH] Token refresh thread did not stop cleanly")
            else:
                logger.info("[QOBUZ TOKEN REFRESH] ✓ Token refresh service stopped")

    def _token_refresh_loop(self):
        """Main loop - check and refresh token periodically"""
        import time

        config = self._config["qobuz"]
        refresh_interval = config.get("token_refresh_check_interval", 86400)

        while self._token_refresh_running:
            try:
                logger.debug("[QOBUZ TOKEN REFRESH] Checking if token needs refresh...")
                self._check_and_refresh_token()
            except Exception as e:
                logger.error(f"[QOBUZ TOKEN REFRESH] Error in refresh loop: {e}", exc_info=True)

            # Sleep in 60-second chunks to allow clean shutdown
            for _ in range(refresh_interval // 60):
                if not self._token_refresh_running:
                    break
                time.sleep(60)

            # Sleep remaining seconds
            if self._token_refresh_running:
                remaining = refresh_interval % 60
                if remaining > 0:
                    time.sleep(remaining)

    def _check_and_refresh_token(self):
        """Check if token needs refresh and refresh if needed"""
        import time

        if not self._client._using_oauth:
            logger.debug("[QOBUZ TOKEN REFRESH] Not using OAuth, skipping refresh check")
            return

        # Check if token is expired
        if self._client._is_token_expired():
            logger.warning("[QOBUZ TOKEN REFRESH] Token is ALREADY EXPIRED! Refreshing immediately...")
            self._perform_token_refresh()
            return

        # Calculate time until expiration
        now = time.time()
        expires_at = self._client._oauth_expires_at
        time_until_expiry = expires_at - now

        # Get original token lifetime
        if not hasattr(self._client, '_oauth_original_lifetime'):
            # First time - assume current expires_in is close to original
            self._client._oauth_original_lifetime = time_until_expiry

        original_lifetime = self._client._oauth_original_lifetime
        config = self._config["qobuz"]
        threshold = config.get("token_refresh_threshold", 0.5)
        threshold_time = original_lifetime * threshold

        logger.debug(f"[QOBUZ TOKEN REFRESH] Token status:")
        logger.debug(f"  - Expires in: {time_until_expiry:.0f}s ({time_until_expiry/86400:.1f} days)")
        logger.debug(f"  - Original lifetime: {original_lifetime:.0f}s ({original_lifetime/86400:.1f} days)")
        logger.debug(f"  - Refresh threshold: {threshold_time:.0f}s ({threshold_time/86400:.1f} days)")
        logger.debug(f"  - Needs refresh: {time_until_expiry < threshold_time}")

        if time_until_expiry < threshold_time:
            logger.info("=" * 80)
            logger.info("[QOBUZ TOKEN REFRESH] Token needs refresh!")
            logger.info(f"[QOBUZ TOKEN REFRESH] Time until expiry: {time_until_expiry:.0f}s ({time_until_expiry/86400:.1f} days)")
            logger.info(f"[QOBUZ TOKEN REFRESH] Threshold: {threshold_time:.0f}s ({threshold_time/86400:.1f} days)")
            self._perform_token_refresh()
            logger.info("=" * 80)
        else:
            logger.debug("[QOBUZ TOKEN REFRESH] Token still fresh, no refresh needed")

    def _perform_token_refresh(self):
        """Actually refresh the token via Qobuz API"""
        import requests
        import time

        try:
            logger.info("[QOBUZ TOKEN REFRESH] Calling Qobuz token refresh API...")

            refresh_token = self._client._oauth_refresh_token
            config = self._config["qobuz"]
            client_id = config.get("client_id")
            client_secret = config.get("client_secret")

            if not refresh_token:
                logger.error("[QOBUZ TOKEN REFRESH] ✗ No refresh token available!")
                return False

            if not client_id or not client_secret:
                logger.error("[QOBUZ TOKEN REFRESH] ✗ Missing client_id or client_secret in config!")
                logger.error("[QOBUZ TOKEN REFRESH] Cannot refresh without OAuth credentials")
                return False

            # Call Qobuz token refresh endpoint
            response = requests.post(
                'https://www.qobuz.com/api.json/0.2/oauth2/token',
                data={
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token,
                    'client_id': client_id,
                    'client_secret': client_secret,
                },
                timeout=10,
            )

            if response.status_code == 200:
                new_tokens = response.json()

                logger.info("[QOBUZ TOKEN REFRESH] ✓ Token refresh successful!")
                logger.info(f"[QOBUZ TOKEN REFRESH] New access_token: {new_tokens.get('access_token', '')[:30]}...")
                logger.info(f"[QOBUZ TOKEN REFRESH] New refresh_token: {new_tokens.get('refresh_token', '')[:30]}...")
                logger.info(f"[QOBUZ TOKEN REFRESH] Expires in: {new_tokens.get('expires_in')}s ({new_tokens.get('expires_in', 0) / 86400:.1f} days)")

                # Update self (no restart needed)
                self._update_self_with_new_tokens(new_tokens)

                # Persist to RPI client via socket
                if self._credential_client:
                    class TokenSession:
                        def __init__(token_self, data, refresh_token_fallback):
                            token_self.access_token = data['access_token']
                            token_self.refresh_token = data.get('refresh_token', refresh_token_fallback)
                            token_self.token_type = data.get('token_type', 'Bearer')
                            token_self.expires_in = data.get('expires_in', 86400)

                    session = TokenSession(new_tokens, self._client._oauth_refresh_token if self._client else '')
                    self._credential_client.persist_token(session)
                    self._credential_client.send_status(None)  # Clear error

                return True
            else:
                logger.error(f"[QOBUZ TOKEN REFRESH] ✗ Token refresh failed: HTTP {response.status_code}")
                logger.error(f"[QOBUZ TOKEN REFRESH] Response: {response.text[:200]}")

                # Send error status and crash
                if self._credential_client:
                    self._credential_client.send_status("Token refresh failed. Please re-authenticate.")

                # Kill Mopidy process
                logger.error("Fatal: Token refresh failed. Exiting Mopidy...")
                import os
                os._exit(1)

        except Exception as e:
            logger.error(f"[QOBUZ TOKEN REFRESH] ✗ Exception during token refresh: {e}", exc_info=True)

            # Send error status and crash
            if self._credential_client:
                self._credential_client.send_status(f"Token refresh error: {str(e)[:100]}")

            # Kill Mopidy process
            logger.error("Fatal: Token refresh exception. Exiting Mopidy...")
            import os
            os._exit(1)

    def _update_self_with_new_tokens(self, new_tokens):
        """Update our own client with new tokens (no restart needed)"""
        try:
            access_token = new_tokens['access_token']
            refresh_token = new_tokens.get('refresh_token', self._client._oauth_refresh_token)
            expires_in = new_tokens.get('expires_in', 1382400)

            logger.info("[QOBUZ TOKEN REFRESH] Updating self with new tokens...")

            # Update client
            self._client.set_oauth_tokens(access_token, refresh_token, expires_in)

            # Track original lifetime for threshold calculations
            self._client._oauth_original_lifetime = expires_in

            logger.info("[QOBUZ TOKEN REFRESH] ✓ Self updated successfully")
            logger.info("[QOBUZ TOKEN REFRESH] Mopidy will continue running with new tokens (no restart needed)")

        except Exception as e:
            logger.error(f"[QOBUZ TOKEN REFRESH] ✗ Failed to update self: {e}", exc_info=True)

