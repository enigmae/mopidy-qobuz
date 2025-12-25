# License: GPL
# Author : Vitiko <vhnz98@gmail.com>
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import requests

# Import caching module
from mopidy_qobuz.cache import album_cache, track_cache, artist_cache, artwork_cache

# Import rate limiter
from mopidy_qobuz.rate_limiter import get_rate_limiter

# Client version
CLIENT_VERSION = "0.3.0"

# Extension update marker - helps identify updated code in logs
EXTENSION_VERSION = "NEW QOBUZ EXTENSION v2025.01.20.1 - Search result caching"


class QobuzException(Exception):
    pass


class TrackUrlNotFoundError(QobuzException):
    pass


class AuthenticationError(QobuzException):
    pass


class IneligibleError(QobuzException):
    pass


class InvalidAppIdError(QobuzException):
    pass


class InvalidAppSecretError(QobuzException):
    pass


class BadRequestError(QobuzException):
    pass


class NotFoundError(QobuzException):
    pass


class InvalidQuality(QobuzException):
    pass


logger = logging.getLogger(__name__)

BASE_URL = "https://www.qobuz.com/api.json/0.2"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36."


class Client:
    def __init__(self, app_id=None, secret=None, user_agent=None, session=None, config=None):
        self.secret = str(secret)
        self.app_id = str(app_id)
        self._session = session or requests.Session()
        self._session.headers.update(
            {"User-Agent": user_agent or USER_AGENT, "X-App-Id": self.app_id}
        )
        self._label = None
        self._logged_in = False
        self._config = config or {}

        # OAuth support
        self._oauth_access_token = None
        self._oauth_refresh_token = None
        self._oauth_expires_at = None
        self._using_oauth = False

        # Thread pool for async HTTP calls (fire-and-forget reporting)
        self._http_executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="qobuz-http"
        )

        # Log initialization with version marker
        logger.info(f"[{EXTENSION_VERSION}] Qobuz Client initialized")
        logger.info(f"[{EXTENSION_VERSION}] Client version: {CLIENT_VERSION}")
        logger.info(f"[{EXTENSION_VERSION}] App ID: {app_id[:20]}..." if app_id else f"[{EXTENSION_VERSION}] App ID: None")

    def login(self, email: str, password: str, force=False):
        if not self._logged_in or force:
            self._auth(email, password)
        else:
            logger.info("Already logged in")

    def _auth(self, email, pwd):
        params = {
            "email": email,
            "password": pwd,
            "app_id": self.app_id,
        }
        response = self._session.get(f"{BASE_URL}/user/login", params=params)

        if response.status_code == 401:
            raise AuthenticationError(_get_message(response))

        if response.status_code == 400:
            raise InvalidAppIdError(_get_message(response))

        response = response.json()

        try:
            subscription = response["user"]["credential"]["parameters"]
        except (KeyError, TypeError):
            subscription = None

        if subscription:
            self._label = response["user"]["credential"]["parameters"]["short_label"]

        self._uat = response["user_auth_token"]
        self._session.headers.update({"X-User-Auth-Token": self._uat})

        logger.info("Logged: OK // Qobuz membership: %s", self._label)

    def get(self, endpoint: str, params: dict, raise_for_status=True):
        # Start timing for detailed logging
        start_time = time.time()

        # Enable verbose logging if configured
        verbose = self._config.get("verbose_logging", False)
        # Detailed API logging can be enabled via config (currently disabled)
        detailed = False

        # Check if OAuth token is expired and attempt auto-refresh
        if self._using_oauth and self._is_token_expired():
            logger.warning(f"[{EXTENSION_VERSION}] OAuth token is EXPIRED! Attempting automatic refresh...")

            # Trigger refresh via backend's perform_token_refresh if available
            if hasattr(self, '_backend_refresh_callback') and self._backend_refresh_callback:
                try:
                    success = self._backend_refresh_callback()
                    if success:
                        logger.info(f"[{EXTENSION_VERSION}] ✓ Token auto-refreshed successfully")
                    else:
                        logger.error(f"[{EXTENSION_VERSION}] ✗ Token auto-refresh failed - API call will likely fail")
                except Exception as e:
                    logger.error(f"[{EXTENSION_VERSION}] ✗ Exception during token auto-refresh: {e}")
            else:
                logger.error(f"[{EXTENSION_VERSION}] No refresh callback available - API call may fail")

        # Apply rate limiting for specific endpoints (album/get, track/get, artist/get)
        rate_limiter = get_rate_limiter()
        wait_time = rate_limiter.wait_if_needed(endpoint)
        if wait_time > 0:
            logger.debug(f"[RATE LIMITER] {endpoint} - waited {wait_time:.2f}s for rate limit")

        # Log API call details with version marker
        auth_info = self._get_auth_info()

        # API Monitor detailed logging
        if detailed:
            logger.info(f"[API CALL] >>> GET {endpoint}")
            logger.info(f"[API CALL]     Params: {params}")
            logger.info(f"[API CALL]     Auth: {auth_info}")

        if verbose:
            logger.info(f"[{EXTENSION_VERSION}] GET {BASE_URL}/{endpoint}")
            logger.info(f"[{EXTENSION_VERSION}] Auth: {auth_info}")
            logger.info(f"[{EXTENSION_VERSION}] Parameters: {params}")
        else:
            # Log at INFO level for API call tracking
            logger.info(f"[API] >>> GET {endpoint} | Params: {params}")
            logger.debug(f"[{EXTENSION_VERSION}] GET {endpoint} | Auth: {auth_info}")
            logger.debug(f"[{EXTENSION_VERSION}] Parameters: {params}")

        # Log headers being sent (sanitized)
        headers_log = {k: (v[:20] + "..." if k == "Authorization" else v)
                      for k, v in self._session.headers.items()}
        if verbose:
            logger.info(f"[{EXTENSION_VERSION}] Request headers: {headers_log}")
        else:
            logger.debug(f"[{EXTENSION_VERSION}] Headers: {headers_log}")

        # Add timeout to prevent indefinite waits
        # Use tuple (connect_timeout, read_timeout) to timeout both connection AND data transfer
        response = self._session.get(f"{BASE_URL}/{endpoint}", params=params, timeout=(3.0, 5.0))

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Log response at INFO level for tracking
        logger.info(f"[API] <<< {response.status_code} {endpoint} ({duration_ms:.0f}ms)")

        # API Monitor detailed logging
        if detailed:
            logger.info(f"[API CALL] <<< {response.status_code} {endpoint} ({duration_ms:.1f}ms)")
            if response.status_code >= 400:
                logger.error(f"[API CALL]     Error: {response.text[:200]}")
            else:
                try:
                    response_preview = str(response.json())[:500]
                    logger.info(f"[API CALL]     Response: {response_preview}...")
                except:
                    pass

        # Log response with version marker - INFO/ERROR for visibility
        if response.status_code != 200:
            logger.error(f"[{EXTENSION_VERSION}] GET {endpoint} FAILED: {response.status_code}")
            logger.error(f"[{EXTENSION_VERSION}] Error response: {response.text[:200]}")
        else:
            if verbose:
                logger.info(f"[{EXTENSION_VERSION}] Response: {response.status_code} OK | Endpoint: {endpoint}")
                try:
                    response_preview = str(response.json())[:200]
                    logger.info(f"[{EXTENSION_VERSION}] Response preview: {response_preview}...")
                except:
                    pass
            else:
                logger.debug(f"[{EXTENSION_VERSION}] Response: {response.status_code} | Endpoint: {endpoint}")

        return _handle_response(response, raise_for_status)

    def post(self, endpoint: str, data: dict, raise_for_status=True):
        # Start timing for detailed logging
        start_time = time.time()

        # Enable verbose logging if configured
        verbose = self._config.get("verbose_logging", False)
        # Detailed API logging can be enabled via config (currently disabled)
        detailed = False

        # Check if OAuth token is expired and attempt auto-refresh
        if self._using_oauth and self._is_token_expired():
            logger.warning(f"[{EXTENSION_VERSION}] OAuth token is EXPIRED! Attempting automatic refresh...")

            # Trigger refresh via backend's perform_token_refresh if available
            if hasattr(self, '_backend_refresh_callback') and self._backend_refresh_callback:
                try:
                    success = self._backend_refresh_callback()
                    if success:
                        logger.info(f"[{EXTENSION_VERSION}] ✓ Token auto-refreshed successfully")
                    else:
                        logger.error(f"[{EXTENSION_VERSION}] ✗ Token auto-refresh failed - API call will likely fail")
                except Exception as e:
                    logger.error(f"[{EXTENSION_VERSION}] ✗ Exception during token auto-refresh: {e}")
            else:
                logger.error(f"[{EXTENSION_VERSION}] No refresh callback available - API call may fail")

        # Apply rate limiting for specific endpoints (album/get, track/get, artist/get)
        rate_limiter = get_rate_limiter()
        wait_time = rate_limiter.wait_if_needed(endpoint)
        if wait_time > 0:
            logger.debug(f"[RATE LIMITER] {endpoint} - waited {wait_time:.2f}s for rate limit")

        # Log API call details with version marker
        auth_info = self._get_auth_info()

        # API Monitor detailed logging
        if detailed:
            logger.info(f"[API CALL] >>> POST {endpoint}")
            logger.info(f"[API CALL]     Data: {data}")
            logger.info(f"[API CALL]     Auth: {auth_info}")

        if verbose:
            logger.info(f"[{EXTENSION_VERSION}] POST {BASE_URL}/{endpoint}")
            logger.info(f"[{EXTENSION_VERSION}] Auth: {auth_info}")
            logger.info(f"[{EXTENSION_VERSION}] Data: {data}")
        else:
            # Log at INFO level for API call tracking
            logger.info(f"[API] >>> POST {endpoint}")
            logger.debug(f"[{EXTENSION_VERSION}] POST {endpoint} | Auth: {auth_info}")
            logger.debug(f"[{EXTENSION_VERSION}] Data: {data}")

        # Log headers being sent (sanitized)
        headers_log = {k: (v[:20] + "..." if k == "Authorization" else v)
                      for k, v in self._session.headers.items()}
        if verbose:
            logger.info(f"[{EXTENSION_VERSION}] Request headers: {headers_log}")
        else:
            logger.debug(f"[{EXTENSION_VERSION}] Headers: {headers_log}")

        # Add timeout to prevent indefinite waits
        # Use tuple (connect_timeout, read_timeout) to timeout both connection AND data transfer
        response = self._session.post(f"{BASE_URL}/{endpoint}", data=data, timeout=(3.0, 5.0))

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Log response at INFO level for tracking
        logger.info(f"[API] <<< {response.status_code} {endpoint} ({duration_ms:.0f}ms)")

        # API Monitor detailed logging
        if detailed:
            logger.info(f"[API CALL] <<< {response.status_code} {endpoint} ({duration_ms:.1f}ms)")
            if response.status_code >= 400:
                logger.error(f"[API CALL]     Error: {response.text[:200]}")
            else:
                try:
                    response_preview = str(response.json())[:500]
                    logger.info(f"[API CALL]     Response: {response_preview}...")
                except:
                    pass

        # Log response with version marker - INFO/ERROR for visibility
        if response.status_code in [200, 201]:
            if verbose:
                logger.info(f"[{EXTENSION_VERSION}] Response: {response.status_code} OK | Endpoint: {endpoint}")
                try:
                    response_preview = str(response.json())[:200]
                    logger.info(f"[{EXTENSION_VERSION}] Response preview: {response_preview}...")
                except:
                    pass
            else:
                logger.debug(f"[{EXTENSION_VERSION}] Response: {response.status_code} | Endpoint: {endpoint}")
        else:
            logger.error(f"[{EXTENSION_VERSION}] POST {endpoint} FAILED: {response.status_code}")
            logger.error(f"[{EXTENSION_VERSION}] Error response: {response.text[:200]}")

        return _handle_response(response, raise_for_status)

    def _get_auth_info(self):
        """Get current authentication method info for logging"""
        if self._using_oauth:
            expires_in = int(self._oauth_expires_at - time.time()) if self._oauth_expires_at else 0
            return f"OAuth (expires in {expires_in}s)"
        elif "X-User-Auth-Token" in self._session.headers:
            return "Legacy (X-User-Auth-Token)"
        else:
            return "None (UNAUTHENTICATED)"

    @property
    def membership(self):
        return self._label

    def raise_for_secret(self):
        DownloadableTrack.from_id(self, "156914988", 5)

    def set_oauth_tokens(self, access_token, refresh_token, expires_in=86400):
        """
        Set OAuth tokens for authentication (injected externally)

        Args:
            access_token: OAuth access token from Qobuz
            refresh_token: OAuth refresh token for token renewal
            expires_in: Token validity in seconds (default 24h)
        """
        logger.info("=" * 70)
        logger.info(f"[{EXTENSION_VERSION}] Setting OAuth tokens for Qobuz authentication")
        logger.info(f"[{EXTENSION_VERSION}] Access token: {access_token[:30]}...")
        logger.info(f"[{EXTENSION_VERSION}] Refresh token: {refresh_token[:30] if refresh_token else 'None'}...")
        logger.info(f"[{EXTENSION_VERSION}] Expires in: {expires_in} seconds ({expires_in/3600:.1f} hours)")

        self._oauth_access_token = access_token
        self._oauth_refresh_token = refresh_token
        self._oauth_expires_at = time.time() + expires_in
        self._using_oauth = True
        self._logged_in = True  # Mark as logged in via OAuth

        # Remove legacy auth header if present
        if "X-User-Auth-Token" in self._session.headers:
            logger.info(f"[{EXTENSION_VERSION}] Removing legacy X-User-Auth-Token header")
            del self._session.headers["X-User-Auth-Token"]

        # Set OAuth Bearer token
        self._session.headers.update({
            "Authorization": f"Bearer {access_token}"
        })

        # Log current headers (sanitized)
        headers_log = {k: (v[:30] + "..." if k == "Authorization" else v)
                      for k, v in self._session.headers.items()}
        logger.info(f"[{EXTENSION_VERSION}] Session headers after OAuth setup: {headers_log}")

        # Verify OAuth setup with test API call
        logger.info(f"[{EXTENSION_VERSION}] Verifying OAuth authentication with test API call...")
        try:
            # Try to get user info to verify the token works
            test_response = self.get("user/login", {}, raise_for_status=False)
            if test_response.status_code == 200:
                logger.info(f"[{EXTENSION_VERSION}] ✓ OAuth token verification SUCCESSFUL")
                try:
                    user_data = test_response.json()
                    if "user" in user_data:
                        logger.info(f"[{EXTENSION_VERSION}] User authenticated: {user_data.get('user', {}).get('login', 'Unknown')}")
                        subscription = user_data.get("user", {}).get("credential", {}).get("parameters", {})
                        if subscription:
                            self._label = subscription.get("short_label", "Unknown")
                            logger.info(f"[{EXTENSION_VERSION}] Qobuz subscription: {self._label}")
                except Exception as e:
                    logger.warning(f"[{EXTENSION_VERSION}] Could not parse user data: {e}")
            else:
                logger.warning(f"[{EXTENSION_VERSION}] ⚠ OAuth token verification returned status {test_response.status_code}")
                logger.warning(f"[{EXTENSION_VERSION}] This may indicate an invalid or expired token")
        except Exception as e:
            logger.warning(f"[{EXTENSION_VERSION}] ⚠ OAuth verification test failed: {e}")
            logger.warning(f"[{EXTENSION_VERSION}] Token may still work for other API calls")

        logger.info(f"[{EXTENSION_VERSION}] ✓ OAuth authentication setup complete")
        logger.info("=" * 70)

    def _is_token_expired(self):
        """Check if OAuth token is expired"""
        if not self._using_oauth or self._oauth_expires_at is None:
            return False
        return time.time() >= self._oauth_expires_at

    def _refresh_oauth_token(self):
        """
        Refresh OAuth access token using refresh token

        Note: This requires the Qobuz OAuth token endpoint which may need
        client_id and client_secret. In the proxy architecture, token refresh
        should be handled by external system, not here. This is a placeholder.
        """
        if not self._oauth_refresh_token:
            logger.error("Cannot refresh token: no refresh token available")
            return False

        logger.warning("OAuth token refresh not implemented - tokens should be refreshed by external system")
        # In the proxy architecture, external system should refresh tokens and re-inject them
        # via set_oauth_tokens() when they expire
        return False

    def report_streaming_start(self, track_id, format_id=6, user_id=None, date=None, online=True, local=False, intent="streaming", sample=False):
        """
        Fire-and-forget - Report streaming start to Qobuz API in background thread.
        Returns immediately without blocking.

        Args:
            track_id: The track ID being played
            format_id: Audio format/quality ID (default: 6 = CD quality)
            user_id: Optional user ID for OAuth (if available)
            date: Unix timestamp of playback start (default: current time)
            online: Whether this is online streaming (default: True)
            local: Whether this is local playback (default: False)

        Returns:
            None - Fire-and-forget, HTTP call happens in background
        """
        def _report_async():
            try:
                # Build complete parameter set as per Qobuz API requirements
                current_time = int(time.time())
                params = {
                    "track_id": str(track_id),
                    "format_id": str(format_id),
                    "date": str(date if date is not None else current_time),
                    "online": "true" if online else "false",
                    "local": "true" if local else "false",
                    "intent": intent,
                    "sample": "true" if sample else "false"
                }
                if user_id:
                    params["user_id"] = str(user_id)

                logger.info("=" * 70)
                logger.info(f"[{EXTENSION_VERSION}] reportStreamingStart (async)")
                logger.info(f"[{EXTENSION_VERSION}]   - track_id: {track_id}")
                logger.info(f"[{EXTENSION_VERSION}]   - format_id: {format_id}")
                logger.info(f"[{EXTENSION_VERSION}]   - date: {params['date']}")
                logger.info(f"[{EXTENSION_VERSION}]   - online: {params['online']}")
                logger.info(f"[{EXTENSION_VERSION}]   - local: {params['local']}")
                logger.info(f"[{EXTENSION_VERSION}]   - intent: {intent}")
                logger.info(f"[{EXTENSION_VERSION}]   - sample: {sample}")
                logger.info(f"[{EXTENSION_VERSION}]   - user_id: {user_id or 'N/A'}")
                logger.info(f"[{EXTENSION_VERSION}]   - full payload: {params}")

                response = self.post("track/reportStreamingStart", params, raise_for_status=False)

                # HTTP 200 and 201 are both success
                if response.status_code in [200, 201]:
                    logger.info(f"[{EXTENSION_VERSION}] ✓ Streaming start reported (HTTP {response.status_code})")
                    try:
                        response_data = response.json()
                        logger.debug(f"[{EXTENSION_VERSION}] Response data: {response_data}")
                    except:
                        pass
                else:
                    logger.warning(f"[{EXTENSION_VERSION}] ✗ Streaming start FAILED with status {response.status_code}")
                    logger.warning(f"[{EXTENSION_VERSION}] Error response: {response.text[:200]}")

                logger.info("=" * 70)

            except Exception as e:
                logger.warning(f"[{EXTENSION_VERSION}] Background reporting failed: {e}")
                import traceback
                logger.debug(f"[{EXTENSION_VERSION}] Traceback: {traceback.format_exc()}")

        # Submit to thread pool and return immediately (fire-and-forget)
        self._http_executor.submit(_report_async)
        logger.debug(f"[{EXTENSION_VERSION}] Queued reportStreamingStart for track {track_id}")

    def _generate_request_signature(self, endpoint, params):
        """
        Generate request signature for signed Qobuz API endpoints.

        Args:
            endpoint: API endpoint (e.g., "track/reportStreamingEndJson")
            params: Dictionary of request parameters

        Returns:
            Tuple of (request_ts, request_sig)
        """
        unix = int(time.time())

        # Build signature string: endpoint + sorted params + timestamp + secret
        # Sort parameters alphabetically as per Qobuz API requirements
        sorted_params = sorted(params.items())
        param_string = "".join(f"{k}{v}" for k, v in sorted_params)

        sig_string = f"{endpoint}{param_string}{unix}{self.secret}"
        sig_hashed = hashlib.md5(sig_string.encode("utf-8")).hexdigest()

        return unix, sig_hashed

    def report_streaming_end_json(self, track_id, duration=None, user_id=None, format_id=6,
                                  date=None, online=True, local=False, track_context_uuid=None,
                                  blob=None):
        """
        Fire-and-forget - Report streaming end to Qobuz API using modern JSON endpoint.
        Returns immediately without blocking.

        This is the modern replacement for the deprecated reportStreamingEnd endpoint.
        Uses JSON body format with ISO 8601 timestamps and proper request signing.

        Args:
            track_id: The track ID that finished playing
            duration: Playback duration in seconds (optional but recommended)
            user_id: Optional user ID for OAuth (if available)
            format_id: Audio format/quality ID (default: 6 = CD quality)
            date: Unix timestamp of playback start (default: current time)
            online: Whether this was online streaming (default: True)
            local: Whether this was local playback (default: False)
            track_context_uuid: Optional tracking UUID from Qobuz
            blob: The blob from track/getFileUrl response (required by Qobuz)

        Returns:
            None - Fire-and-forget, HTTP call happens in background
        """
        def _report_async():
            try:
                import uuid

                # Get current time for timestamp
                current_time = int(time.time())
                start_timestamp = date if date is not None else current_time

                # Convert Unix timestamp to ISO 8601 format with timezone (UTC)
                start_datetime = datetime.datetime.fromtimestamp(start_timestamp, tz=datetime.timezone.utc)
                # Format as ISO 8601 with timezone: YYYY-MM-DDTHH:MM:SS+00:00
                start_iso = start_datetime.strftime("%Y-%m-%dT%H:%M:%S+00:00")

                # Build JSON body as per Qobuz API docs
                json_body = {
                    "renderer_context": {
                        "software_version": "Mopidy-Qobuz"
                    },
                    "events": [{
                        "duration": int(duration) if duration is not None else 0,
                        "start_stream": start_iso,
                        "blob": blob or "",  # Use provided blob or empty string
                        "track_context_uuid": track_context_uuid or str(uuid.uuid4()),
                        "online": online,
                        "local": local
                    }]
                }

                # Generate request signature for the endpoint
                endpoint = "track/reportStreamingEndJson"
                params = {
                    "track_id": str(track_id),
                    "format_id": str(format_id)
                }
                if user_id:
                    params["user_id"] = str(user_id)

                request_ts, request_sig = self._generate_request_signature(endpoint, params)
                params["request_ts"] = request_ts
                params["request_sig"] = request_sig

                logger.info("=" * 70)
                logger.info(f"[{EXTENSION_VERSION}] reportStreamingEndJson (async - MODERN JSON)")
                logger.info(f"[{EXTENSION_VERSION}]   - track_id: {track_id}")
                logger.info(f"[{EXTENSION_VERSION}]   - duration: {duration:.1f}s" if duration else f"[{EXTENSION_VERSION}]   - duration: 0s")
                logger.info(f"[{EXTENSION_VERSION}]   - format_id: {format_id}")
                logger.info(f"[{EXTENSION_VERSION}]   - start_stream: {start_iso}")
                logger.info(f"[{EXTENSION_VERSION}]   - online: {online}")
                logger.info(f"[{EXTENSION_VERSION}]   - local: {local}")
                logger.info(f"[{EXTENSION_VERSION}]   - track_context_uuid: {json_body['events'][0]['track_context_uuid']}")

                # Configurable full JSON payload logging
                enable_payload_logging = self._config.get('enable_payload_logging', False) if self._config else False
                if enable_payload_logging:
                    logger.info(f"[{EXTENSION_VERSION}]   - FULL JSON PAYLOAD:")
                    logger.info(f"[{EXTENSION_VERSION}] {json.dumps(json_body, indent=2)}")
                else:
                    logger.info(f"[{EXTENSION_VERSION}]   - JSON body: {json.dumps(json_body, indent=2)}")

                # Make POST request with JSON content type
                headers = {
                    "Content-Type": "application/json"
                }
                url = f"{BASE_URL}/{endpoint}"

                # Add signature to URL params
                url_with_params = f"{url}?{'&'.join(f'{k}={v}' for k, v in params.items())}"

                logger.info(f"[{EXTENSION_VERSION}]   - Request URL: {url_with_params}")

                response = self._session.post(
                    url_with_params,
                    json=json_body,
                    headers=headers,
                    timeout=5.0
                )

                # HTTP 200 and 201 are both success
                if response.status_code in [200, 201]:
                    logger.info(f"[{EXTENSION_VERSION}] ✓ Streaming end reported via JSON (HTTP {response.status_code})")
                    try:
                        response_data = response.json()
                        logger.debug(f"[{EXTENSION_VERSION}] Response data: {response_data}")
                    except:
                        pass
                else:
                    logger.warning(f"[{EXTENSION_VERSION}] ✗ Streaming end JSON FAILED with status {response.status_code}")
                    logger.warning(f"[{EXTENSION_VERSION}] Error response: {response.text[:200]}")

                logger.info("=" * 70)

            except Exception as e:
                logger.warning(f"[{EXTENSION_VERSION}] Background JSON reporting failed: {e}")
                import traceback
                logger.debug(f"[{EXTENSION_VERSION}] Traceback: {traceback.format_exc()}")

        # Submit to thread pool and return immediately (fire-and-forget)
        self._http_executor.submit(_report_async)
        logger.debug(f"[{EXTENSION_VERSION}] Queued reportStreamingEndJson for track {track_id}")

    def report_streaming_end(self, track_id, duration=None, user_id=None, format_id=6, date=None, online=True, local=False):
        """
        Fire-and-forget - Report streaming end to Qobuz API in background thread.
        Returns immediately without blocking.

        NOTE: This uses the deprecated reportStreamingEnd endpoint.
        Consider using report_streaming_end_json() for the modern JSON endpoint.

        Args:
            track_id: The track ID that finished playing
            duration: Playback duration in seconds (optional but recommended)
            user_id: Optional user ID for OAuth (if available)
            format_id: Audio format/quality ID (default: 6 = CD quality)
            date: Unix timestamp of playback end (default: current time)
            online: Whether this was online streaming (default: True)
            local: Whether this was local playback (default: False)

        Returns:
            None - Fire-and-forget, HTTP call happens in background
        """
        def _report_async():
            try:
                # Build complete parameter set as per Qobuz API requirements
                current_time = int(time.time())
                params = {
                    "track_id": str(track_id),
                    "format_id": str(format_id),
                    "date": str(date if date is not None else current_time),
                    "online": "true" if online else "false",
                    "local": "true" if local else "false",
                }
                if duration is not None:
                    params["duration"] = str(int(duration))
                if user_id:
                    params["user_id"] = str(user_id)

                logger.info("=" * 70)
                logger.info(f"[{EXTENSION_VERSION}] reportStreamingEnd (async - DEPRECATED)")
                logger.info(f"[{EXTENSION_VERSION}]   - track_id: {track_id}")
                logger.info(f"[{EXTENSION_VERSION}]   - duration: {duration:.1f}s" if duration else f"[{EXTENSION_VERSION}]   - duration: N/A")
                logger.info(f"[{EXTENSION_VERSION}]   - format_id: {format_id}")
                logger.info(f"[{EXTENSION_VERSION}]   - date: {params['date']}")
                logger.info(f"[{EXTENSION_VERSION}]   - online: {params['online']}")
                logger.info(f"[{EXTENSION_VERSION}]   - local: {params['local']}")
                logger.info(f"[{EXTENSION_VERSION}]   - user_id: {user_id or 'N/A'}")
                logger.info(f"[{EXTENSION_VERSION}]   - full payload: {params}")

                response = self.post("track/reportStreamingEnd", params, raise_for_status=False)

                # HTTP 200 and 201 are both success
                if response.status_code in [200, 201]:
                    logger.info(f"[{EXTENSION_VERSION}] ✓ Streaming end reported (HTTP {response.status_code})")
                    try:
                        response_data = response.json()
                        logger.debug(f"[{EXTENSION_VERSION}] Response data: {response_data}")
                    except:
                        pass
                else:
                    logger.warning(f"[{EXTENSION_VERSION}] ✗ Streaming end FAILED with status {response.status_code}")
                    logger.warning(f"[{EXTENSION_VERSION}] Error response: {response.text[:200]}")

                logger.info("=" * 70)

            except Exception as e:
                logger.warning(f"[{EXTENSION_VERSION}] Background reporting failed: {e}")
                import traceback
                logger.debug(f"[{EXTENSION_VERSION}] Traceback: {traceback.format_exc()}")

        # Submit to thread pool and return immediately (fire-and-forget)
        self._http_executor.submit(_report_async)
        logger.debug(f"[{EXTENSION_VERSION}] Queued reportStreamingEnd for track {track_id}")

    def shutdown(self):
        """
        Shutdown executor gracefully.
        Called when Mopidy backend is stopping.
        """
        if hasattr(self, '_http_executor'):
            logger.info(f"[{EXTENSION_VERSION}] Shutting down HTTP thread pool executor...")
            self._http_executor.shutdown(wait=False)
            logger.info(f"[{EXTENSION_VERSION}] ✓ HTTP thread pool executor shut down")


_exception_codes = {400: BadRequestError, 401: AuthenticationError, 404: NotFoundError}


def _handle_response(response, raise_for_status):
    if response.status_code == 200 or not raise_for_status:
        return response

    try:
        raise _exception_codes[response.status_code](_get_message(response))
    except KeyError:
        # Ok?
        raise BadRequestError(f"Not implemented status code: {response.json()}")


def _get_message(response):
    try:
        return response.json()["message"] or "No message"
    except (KeyError, json.JSONDecodeError):
        return "No message"


class DownloadableTrack:
    def __init__(self, client: Client, data: dict):
        self._data = data
        self.id = data["track_id"]
        self.url = data.get("url")
        self.duration = data.get("duration")
        self.bit_depth = data.get("bit_depth", 16)
        self.sampling_rate = data.get("sampling_rate", 44.1)
        self.restrictions = data.get("restrictions", [])
        self.blob = data.get("blob", "")  # Blob from track/getFileUrl for reporting

        try:
            self.etsp = datetime.datetime.fromtimestamp(
                int(urllib.parse.parse_qs(self.url)["etsp"][0])
            )
        except (KeyError, IndexError):
            self.etsp = None

        self._client = client
        self._size = None

    def __hash__(self) -> int:
        return hash(self.id)

    def is_expired(self):
        if self.etsp is None:
            logger.debug("Track doesn't have etsp data")
            return True

        return datetime.datetime.now() > self.etsp

    @classmethod
    def from_id(cls, client: Client, id, format_id=6, intent="stream"):
        """
        raises InvalidQuality, TrackUrlNotFoundError, InvalidAppSecretError
        """
        unix = int(time.time())  # Must be integer for Qobuz API

        try:
            valid = int(format_id) in (5, 6, 7, 27)
        except ValueError:
            valid = False

        if not valid:
            raise InvalidQuality("Invalid quality id: choose between 5, 6, 7 or 27")

        # Build signature string as per Qobuz API docs (alphabetical parameter order)
        r_sig = f"trackgetFileUrlformat_id{format_id}intent{intent}track_id{id}{unix}{client.secret}"
        r_sig_hashed = hashlib.md5(r_sig.encode("utf-8")).hexdigest()

        params = {
            "request_ts": unix,
            "request_sig": r_sig_hashed,
            "track_id": id,
            "format_id": format_id,
            "intent": intent,
        }

        response = client.get("track/getFileUrl", params, raise_for_status=False)
        response_dict = response.json()

        if response.status_code == 400 and "Invalid Request" in response_dict.get(
            "message", ""
        ):
            raise InvalidAppSecretError(f"Invalid app secret: {client.secret}")

        if response.status_code != 200 or not response_dict.get("url"):
            raise TrackUrlNotFoundError(response_dict)

        return cls(client, response_dict)

    @property
    def was_fallback(self):
        try:
            return any(
                restriction["code"] == "FormatRestrictedByFormatAvailability"
                for restriction in self.restrictions
            )
        except (KeyError, IndexError):
            return False

    @property
    def demo(self):
        return "sample" in self._data or not self._data.get("sampling_rate")

    @property
    def size(self):
        if self.url is None:
            return 0

        if self._size is None:
            response = self._client._session.head(self.url, allow_redirects=True)
            self._size = response.headers.get("Content-Length", 0)

        return self._size

    @property
    def extension(self):
        if "flac" in self._data.get("mime_type", "n/a"):
            return "FLAC"

        return "MP3"

    def __repr__(self):
        return f"<DownloadableTrack {self.id}@{self.extension} [{self.bit_depth}/{self.sampling_rate}]>"


class _WithMetadata:
    _endpoint = "album/get"
    _param = "album_id"

    def __init__(self, client: Client, data: dict):
        try:
            self.id = data["id"]
        except KeyError:
            raise ValueError("Can't construct without ID")

        self._client = client
        self._metadata = data.get("metadata")

    def _get_metadata(self):
        logger.debug("Getting metadata for ID: %s", id)
        if self._metadata is None:
            self._metadata = self._client.get(
                self._endpoint, params={self._param: self.id}
            ).json()
            return self._metadata

        logger.debug("Metadata already loaded")
        return self._metadata

    @classmethod
    def from_id(cls, client, id, **extra_params):
        """
        Fetch object by ID with optional extra parameters.
        For Album: pass extra="tracks" to get embedded track list.
        """
        params = {cls._param: id}
        params.update(extra_params)
        response = client.get(cls._endpoint, params=params).json()
        return cls(client, response)


# This class should be removed
class _BigWithMetadata(_WithMetadata):
    _endpoint = "artist/get"
    _param = "artist_id"
    _key = "albums_count"
    _extra = "albums"

    def __init__(self, client: Client, data):
        super().__init__(client, data)
        self._metadata = None

    def _get_metadata(self):
        return self._multi_meta(self._key, self._extra)

    def _multi_meta(self, key, extra):
        total = 1
        offset = 0
        while total > 0:
            j = self._client.get(
                self._endpoint,
                {
                    self._param: self.id,
                    "offset": offset,
                    # "type": None,
                    "extra": extra,
                },
            ).json()

            if offset == 0:
                yield j
                try:
                    total = j[key] - 500
                except (KeyError, IndexError) as error:
                    logger.debug(
                        "%s raised trying to fetch metadata: %s", type(error), error
                    )
                    break
            else:
                yield j
                total -= 500

            offset += 500


class Track(_WithMetadata):
    _endpoint = "track/get"
    _param = "track_id"

    def __init__(self, client: Client, data: dict, album=None, artist=None):
        super().__init__(client, data)

        # Ignored keys (for now): release_date_download, release_date_stream,
        # purchasable, purchasable_at previewable, sampleable, articles, performers

        self.title = data.get("title")
        self.copyright = data.get("copyright")
        self.work = data.get("work")
        self.audio_info = data.get("audio_info")
        self.duration = data.get("duration", 0)
        self.release_date_original = data.get("release_date_original")
        self.purchasable = data.get("purchasable", False)
        self.work = data.get("work")
        self.version = data.get("version")
        self.media_number = data.get("media_number", 1)
        self.track_number = data.get("track_number", 1)
        self.parental_warning = data.get("parental_warning", False)
        self.maximum_sampling_rate = data.get("maximum_sampling_rate")
        self.maximum_channel_count = data.get("maximum_channel_count")
        self.streamable = data.get("streamable", False)
        self.hires_streamable = data.get("hires_streamable", False)

        self.album = album or Album(client, data.get("album", {}))

        performer = data.get("performer")
        if artist is not None:
            self.artist = artist
        elif performer is not None:
            self.artist = Artist(client, performer)
        else:
            self.artist = self.album.artist

        self.composer = data.get("composer")
        if self.composer is not None:
            self.composer = Artist(client, self.composer)

    @property
    def uri(self):
        return f"qobuz:track:{self.id}"

    @classmethod
    def from_id(cls, client, id):
        """
        Fetch track by ID with caching.
        Cache stores Track objects for 8 hours, max 300 tracks.
        """
        # Check cache first
        cache_key = str(id)
        cached_track = track_cache.get(cache_key)
        if cached_track is not None:
            return cached_track

        # Cache miss - fetch from API
        response = client.get(cls._endpoint, params={cls._param: id}).json()
        track = cls(client, response)

        # Store in cache
        track_cache.put(cache_key, track)

        return track

    @classmethod
    def from_search(cls, client, query, limit=10):
        """
        Search for tracks and cache results to avoid redundant API calls.
        When get_images() is called after search, it will use cached data.
        """
        tracks_data = client.get("track/search", {"query": query, "limit": limit}).json()
        try:
            tracks = []
            for item in tracks_data["tracks"]["items"]:
                track = cls(client, item)
                # Cache track so get_images() doesn't need to fetch again
                track_cache.put(str(track.id), track)
                logger.debug(f"Cached track from search: {track.id}")
                tracks.append(track)
            return tracks
        except (IndexError, KeyError):
            return []

    def get_downloadable(self, format_id=6, intent="stream"):
        """
        :param format_id:
        :param intent:
        raises InvalidQuality, TrackUrlNotFoundError
        """
        return DownloadableTrack.from_id(self._client, self.id, format_id, intent)

    def __hash__(self):
        return hash(self.uri)

    def __repr__(self):
        return f"<Track {self.id}: {self.track_number}. {self.title}>"


class _WithImageMixin:
    _image: dict

    def image(self, key="large"):
        """
        Get image URL with caching.
        Cache stores image URLs for 8 hours, max 300 URLs.

        :param key: small, thumbnail, or large
        """
        # Create cache key from object ID and image size
        cache_key = f"{self.id}:{key}"

        # Check cache first
        cached_url = artwork_cache.get(cache_key)
        if cached_url is not None:
            return cached_url

        # Cache miss - get from image dict
        try:
            url = self._image[key]
            # Store in cache if found
            if url:
                artwork_cache.put(cache_key, url)
            return url
        except (TypeError, KeyError):
            return None


class Album(_WithMetadata, _WithImageMixin):
    def __init__(self, client: Client, data: dict):
        super().__init__(client, data)

        self.title = data.get("title", "Unknown")
        self.released_at = data.get("released_at")
        self._image = data.get("image", {})
        self.media_count = data.get("media_count")
        self.version = data.get("version")
        self.upc = data.get("upc")
        self.duration = data.get("duration")
        self.tracks_count = data.get("tracks_count", 1)
        self.release_date_original = data.get("release_date_original")
        self.release_type = data.get("release_type")
        self.parental_warning = data.get("parental_warning", False)
        self.hires_streamable = data.get("hires_streamable", False)
        self.streamable = data.get("streamable", self.hires_streamable)
        self.artist = Artist(client, data.get("artist"))

        self._tracks = data.get("tracks", {}).get("items")
        if self._tracks is not None:
            self._tracks = [
                Track(self._client, track, album=self) for track in self._tracks
            ]

        self.label = data.get("label")
        if self.label is not None:
            self.label = Label(client, self.label)

    @property
    def tracks(self):
        if self._tracks is None:
            self._tracks = [
                Track(self._client, track, album=self)
                for track in self._get_metadata()["tracks"]["items"]
            ]

        return self._tracks

    @property
    def uri(self):
        return f"qobuz:album:{self.id}"

    @classmethod
    def from_id(cls, client, id, **extra_params):
        """
        Fetch album by ID with caching.
        Cache stores Album objects for 8 hours, max 300 albums.
        """
        # Check cache first
        cache_key = str(id)
        cached_album = album_cache.get(cache_key)
        if cached_album is not None:
            return cached_album

        # Cache miss - fetch from API
        params = {cls._param: id}
        params.update(extra_params)
        response = client.get(cls._endpoint, params=params).json()
        album = cls(client, response)

        # Store in cache
        album_cache.put(cache_key, album)

        return album

    @classmethod
    def from_search(cls, client, query, limit=10):
        """
        Search for albums and cache results to avoid redundant API calls.
        When get_images() is called after search, it will use cached data.
        """
        albums_data = client.get(
            "album/search", {"query": query, "limit": limit, "extra": "release_type"}
        ).json()
        try:
            albums = []
            for item in albums_data["albums"]["items"]:
                album = cls(client, item)
                # Cache album so get_images() doesn't need to fetch again
                album_cache.put(str(album.id), album)
                logger.debug(f"Cached album from search: {album.id}")
                albums.append(album)
            return albums
        except (IndexError, KeyError):
            return []

    def __hash__(self):
        return hash(self.uri)

    def __repr__(self):
        return f"<Album {self.id}: {self.title} ({self.release_date_original})>"


class Artist(_BigWithMetadata, _WithImageMixin):
    def __init__(self, client: Client, data, albums=None, tracks=None):
        super().__init__(client, data)

        self.name = data.get("name", "Unknown")
        self.albums_as_primary_artist_count = data.get("albums_as_primary_artist_count")
        self.albums_as_primary_composer_count = data.get(
            "albums_as_primary_composer_count"
        )
        self.picture = data.get("picture")
        self.albums_count = data.get("albums_count")
        self.slug = data.get("slug")

        # Artist images can come from either "image" or "picture" field
        # Search results typically use "picture", full artist data uses "image"
        self._image = data.get("image")
        if self._image is None and self.picture is not None:
            # Convert picture URL to image dict format for consistency
            self._image = {
                "small": self.picture,
                "thumbnail": self.picture,
                "large": self.picture
            }

        self.similar_artist_ids = data.get("similar_artist_ids")
        self.information = data.get("information")
        self.biography = data.get("biography")
        self._albums = albums
        self._tracks = tracks

    @property
    def albums(self):
        if self._albums is None:
            self._albums = []
            for iterable in self._get_metadata():
                try:
                    self._albums.extend(
                        Album(self._client, data)
                        for data in iterable["albums"]["items"]
                    )
                except KeyError as error:
                    logger.debug("Unexpected KeyError fetching data: %s", error)

        return self._albums

    @property
    def tracks(self):
        if self._tracks is None:
            self._tracks = []
            # TODO: Sort by popularity
            for iterable in self._multi_meta("tracks_count", "tracks_appears_on"):
                try:
                    self._tracks.extend(
                        Track(self._client, data)
                        for data in iterable["tracks_appears_on"]["items"]
                    )
                except KeyError as error:
                    logger.debug("Unexpected KeyError fetching data: %s", error)

        return self._tracks

    @property
    def uri(self):
        return f"qobuz:artist:{self.id}"

    @classmethod
    def from_id(cls, client, id, **extra_params):
        """
        Fetch artist by ID with caching.
        Cache stores Artist objects for 8 hours, max 300 artists.
        """
        # Check cache first
        cache_key = str(id)
        cached_artist = artist_cache.get(cache_key)
        if cached_artist is not None:
            return cached_artist

        # Cache miss - fetch from API
        params = {cls._param: id}
        params.update(extra_params)
        response = client.get(cls._endpoint, params=params).json()
        artist = cls(client, response)

        # Store in cache
        artist_cache.put(cache_key, artist)

        return artist

    @classmethod
    def from_search(cls, client, query, limit=10):
        """
        Search for artists and cache results to avoid redundant API calls.
        When get_images() is called after search, it will use cached data.
        """
        artists_data = client.get("artist/search", {"query": query, "limit": limit}).json()
        try:
            artists = []
            for item in artists_data["artists"]["items"]:
                artist = cls(client, item)
                # Cache artist so get_images() doesn't need to fetch again
                artist_cache.put(str(artist.id), artist)
                logger.debug(f"Cached artist from search: {artist.id}")
                artists.append(artist)
            return artists
        except (IndexError, KeyError):
            return []

    def __hash__(self):
        return hash(self.uri)

    def __repr__(self):
        return f"<Artist {self.id}: {self.name}>"


class Playlist(_BigWithMetadata):
    _endpoint = "playlist/get"
    _param = "playlist_id"
    _key = "tracks_count"
    _extra = "tracks"

    def __init__(self, client, data: dict):
        super().__init__(client, data)

        self.id = data.get("id")
        self.name = data.get("name", "Unknown")
        self.tracks_count = data.get("tracks_count")
        self.duration = data.get("duration")
        self._tracks = None
        self._deleted = False

    @classmethod
    def create(
        cls, client, name, description=None, is_public=True, is_collaborative=False
    ):
        data = {
            "name": name,
            "description": description or "",
            "is_public": "true" if is_public else "false",
            "is_collaborative": "false" if not is_collaborative else "true",
        }
        response = client.post("playlist/create", data)
        # TODO: improve error handling
        response.raise_for_status()

        playlist_dict = response.json()
        if not playlist_dict.get("id"):
            raise IneligibleError

        return cls.from_id(client, playlist_dict["id"])

    def delete(self):
        response = self._client.post("playlist/delete", {"playlist_id": str(self.id)})
        self._deleted = True
        return response.json()

    @property
    def tracks(self):
        if self._tracks is None:
            self._tracks = []
            # TODO: Sort by popularity
            for iterable in self._multi_meta("tracks_count", "tracks"):
                try:
                    self._tracks.extend(
                        Track(self._client, data)
                        for data in iterable["tracks"]["items"]
                    )
                except KeyError as error:
                    logger.debug("Unexpected KeyError fetching data: %s", error)

        return self._tracks

    def subscribe(self):
        response = self._client.post(
            "playlist/subscribe", {"playlist_id": str(self.id)}
        )
        return response.json()

    def delete_tracks(self, tracks):
        data = {
            "playlist_id": str(self.id),
            "playlist_track_ids": ",".join([str(item.id) for item in tracks]),
        }
        response = self._client.post("playlist/addTracks", data)
        return response.json()

    def add_tracks(self, tracks, no_duplicate=True):
        data = {
            "playlist_id": str(self.id),
            "track_ids": ",".join([str(item.id) for item in tracks]),
            "no_duplicate": "true" if no_duplicate else "false",
        }
        response = self._client.post("playlist/addTracks", data)
        return response.json()

    def refresh(self):
        self._tracks = None

    @property
    def uri(self):
        return f"qobuz:playlist:{self.id}"

    def __hash__(self):
        return hash(self.uri)

    def __repr__(self):
        return f"<Playlist {self.id}: {self.name} ({self.tracks_count} tracks)>"


class Label(_BigWithMetadata):
    _endpoint = "label/get"
    _param = "label_id"
    _key = "albums_count"
    _extra = "albums"

    def __init__(self, client, data: dict):
        super().__init__(client, data)

        self.id = data.get("id")
        self.name = data.get("name", "Unknown")

    def __repr__(self):
        return f"<Label {self.id}: {self.name}>"


class User:
    def __init__(self, client: Client):
        self._client = client

    def get_playlists(self, limit=10):
        response = self._client.get(
            "playlist/getUserPlaylists", {"limit": limit}
        ).json()
        try:
            return [
                Playlist(self._client, data) for data in response["playlists"]["items"]
            ]
        except (KeyError, TypeError):
            return []

    def get_favorites(self, type="albums", offset=0, limit=10):
        # TODO: serialize more types
        response = self._client.get(
            "favorite/getUserFavorites",
            {"type": type, "offset": offset, "limit": limit},
        ).json()

        try:
            return [Album(self._client, data) for data in response["albums"]["items"]]
        except KeyError:
            return []

    def get_favorites_artists(self, type="artists", offset=0, limit=400):
        # TODO: serialize more types
        response = self._client.get(
            "favorite/getUserFavorites",
            {"type": type, "offset": offset, "limit": limit},
        ).json()

        try:
            return [Artist(self._client, data) for data in response["artists"]["items"]]
        except KeyError:
            return []

    def modify_favorites(self, method="create", albums=None, artists=None, tracks=None):
        data = {
            "artist_ids": _to_str_list(artists),
            "album_ids": _to_str_list(albums),
            "track_ids": _to_str_list(tracks),
        }
        response = self._client.post(f"favorite/{method}", data)
        return response.json()


def _to_str_list(items):
    if items is None:
        return ""

    return ",".join([item.id for item in items])


class Focus(_WithMetadata):
    _endpoint = "focus/get"
    _param = "focus_id"

    def __init__(self, client, data, id=None, name=None):
        try:
            super().__init__(client, {"id": id or data["id"]})
        except KeyError:
            raise ValueError("Can't construct without ID")

        self.name = name or data.get("title", "Unknown")
        self.title = self.name  # Consistency with API
        self._containers = None
        self._albums = None
        self._playlists = None

    @property
    def albums(self):
        if self._albums is None:
            self._albums = self._get_albums()

        return self._albums

    @property
    def playlists(self):
        if self._playlists is None:
            self._playlists = self._get_playlists()

        return self._playlists

    @classmethod
    def from_id(cls, client, id):
        logger.debug("Calling from ID: %s", id)
        response = client.get(cls._endpoint, params={cls._param: id}).json()
        return cls(client, response, id=id)

    def _get_albums(self):
        containers = self._get_containers()

        albums = []
        for key in containers.keys():
            if (
                "album" not in containers[key].get("type", "n/a").lower()
            ):  # avoid KeyError
                continue

            try:
                items = containers[key]["albums"]["items"]
            except KeyError:
                logger.debug("No albums found in %s container", containers[key])
                continue

            for data in items:
                # 'streamable' key is missing here. Can we blatantly assume
                # that is streamable?
                data.update({"streamable": True})
                albums.append(Album(self._client, data))

        return albums

    def _get_playlists(self):
        containers = self._get_containers()

        playlists = []
        for key in containers.keys():
            if (
                "playlist" not in containers[key].get("type", "n/a").lower()
            ):  # avoid KeyError
                continue

            try:
                playlists.append(Playlist(self._client, containers[key]["playlist"]))
            except KeyError:
                logger.debug("No playlists found in %s container", containers[key])
                continue

        return playlists

    def _get_containers(self):
        if self._containers is None:
            try:
                self._containers = self._get_metadata()["containers"]
            except KeyError:
                logger.debug("No containers found in %s", self)
                self._containers = {}

        return self._containers

    def __repr__(self):
        return f"<Focus {self.id}: {self.name}>"


class Featured:
    def __init__(self, client: Client):
        self._client = client

    def get_playlists(
        self, tags=None, genre_ids=None, limit=25, offset=0, type="editor-picks"
    ):
        response = self._client.get(
            "playlist/getFeatured",
            {
                "type": type,
                "tags": tags,
                "limit": limit,
                "offset": offset,
                "genre_ids": genre_ids,
            },
        ).json()

        try:
            return [
                Playlist(self._client, data) for data in response["playlists"]["items"]
            ]
        except TypeError:
            return []

    def get_albums(self, offset=0, limit=25, genre_ids=None, type="press-awards"):
        response = self._client.get(
            "album/getFeatured",
            {
                "type": type,
                "offset": offset,
                "limit": limit,
                "genre_ids": genre_ids,
            },
        ).json()

        try:
            return [Album(self._client, data) for data in response["albums"]["items"]]
        except TypeError:
            return []

    def get_focus(self, offset=0, limit=30, genre_ids=None, type=None):
        response = self._client.get(
            "focus/list",
            {
                "type": type,
                "offset": offset,
                "limit": limit,
                "genre_ids": genre_ids,
            },
        ).json()
        try:
            return [Focus(self._client, data) for data in response["focus"]["items"]]
        except TypeError:
            return []
