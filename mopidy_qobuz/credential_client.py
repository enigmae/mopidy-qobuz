"""Credential client for communicating with the RPI client via socket.

This module handles:
- Socket communication with the RPI client
- Source ID auto-detection from CLI arguments
- Token persistence via socket commands
- Credential status updates
- Error notifications
"""

from __future__ import unicode_literals

import json
import logging
import socket
import sys
import time
from typing import Optional

logger = logging.getLogger(__name__)


class CredentialClient:
    """Client for updating credentials via socket communication with RPI client.

    This client communicates with the RPI client running on localhost:13579
    to persist Qobuz credentials and update credential status in the UI.

    Args:
        config: Mopidy Qobuz configuration dictionary
        socket_address: Tuple of (host, port) for socket connection
        auth_logging_enabled: Whether to enable detailed auth logging
    """

    def __init__(
        self,
        config: dict,
        socket_address: tuple = ("localhost", 13579),
        auth_logging_enabled: bool = False
    ):
        self._config = config
        self._socket_address = socket_address
        self._auth_logging_enabled = auth_logging_enabled
        self._cached_source_id: Optional[str] = None

    def persist_token(self, session) -> bool:
        """Persist refreshed token to credential service.

        Args:
            session: Active Qobuz session with token data

        Returns:
            True if token was successfully persisted, False otherwise
        """
        if not session:
            logger.warning("[CREDENTIAL CLIENT] No active session available to persist token")
            return False

        token_data = {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "token_type": session.token_type,
            "created_at": int(time.time()),
        }

        # Add expires_in if available
        if hasattr(session, "expires_in") and session.expires_in:
            token_data["expires_in"] = session.expires_in
            token_data["expires_at"] = int(time.time()) + session.expires_in

        token_json = json.dumps(token_data)
        if self._update_credential_token(token_json):
            logger.info("[CREDENTIAL CLIENT] ✓ Token persisted via credential service")
            return True

        logger.warning("[CREDENTIAL CLIENT] Failed to persist token via credential service")
        return False

    def send_status(self, error_message: Optional[str]) -> bool:
        """Send credential status update.

        Args:
            error_message: Error message to send, or None for success status

        Returns:
            True if status was successfully sent, False otherwise
        """
        source_id = self._get_or_detect_source_id()
        if not source_id:
            logger.warning(
                "[CREDENTIAL CLIENT] Cannot send credential status - source_id unknown"
            )
            return False

        source_expr = json.dumps(source_id)
        if error_message is None or error_message == "":
            message_expr = "None"
        else:
            message_expr = json.dumps(error_message)

        command = f"update_credential_message({source_expr}, 'qobuz', {message_expr})"
        return self._send_command(command)

    def notify_error(self, detail: str) -> bool:
        """Notify user of authentication error.

        Args:
            detail: Detailed error message for logging

        Returns:
            True if notification was sent successfully, False otherwise
        """
        msg = "Authentication error. Please update your login in the app."
        return self.send_status(msg)

    def crash_on_unrecoverable_error(self, error_msg: str):
        """Log and crash the extension on unrecoverable error.

        This causes Qobuz backend to stop, which the poller will detect
        via missing 'qobuz' scheme.

        Args:
            error_msg: Error message describing the unrecoverable error

        Raises:
            RuntimeError: Always raised to crash the backend
        """
        logger.error("=" * 80)
        logger.error("[CREDENTIAL CLIENT] UNRECOVERABLE ERROR - %s", error_msg)
        logger.error("=" * 80)
        self.notify_error(error_msg)
        raise RuntimeError(f"[QOBUZ] Crashed: {error_msg}")

    def _get_or_detect_source_id(self) -> Optional[str]:
        """Get source ID from config or auto-detect from CLI arguments.

        Source ID format: DEVICEID-ZONE-INPUTID (e.g., 09AD9B-2D1-I21)

        Returns:
            Source ID string if found, None otherwise
        """
        # Check config first
        configured = self._config.get("source_id")
        if configured:
            return configured

        # Return cached value if available
        if self._cached_source_id:
            return self._cached_source_id

        # Try to detect from CLI arguments
        for arg in sys.argv:
            if arg.startswith("-oqobuz/source_id="):
                detected = arg.split("=", 1)[1]
                if detected:
                    logger.info(
                        "[CREDENTIAL CLIENT] Auto-detected source_id from CLI: %s", detected
                    )
                    self._cached_source_id = detected
                    return detected

        logger.warning("[CREDENTIAL CLIENT] No source_id configured or detected")
        logger.warning(
            "[CREDENTIAL CLIENT] Please set 'source_id' in mopidy.conf or pass -oqobuz/source_id=DEVICE-ZONE-INPUT"
        )
        return None

    def _update_credential_token(self, token_json: str) -> bool:
        """Send token update command to RPI client.

        Args:
            token_json: JSON string containing token data

        Returns:
            True if command was sent successfully, False otherwise
        """
        source_id = self._get_or_detect_source_id()
        if not source_id:
            logger.warning(
                "[CREDENTIAL CLIENT] Cannot update credential token - source_id unknown"
            )
            return False

        source_expr = json.dumps(source_id)
        token_expr = json.dumps(token_json)
        command = f"update_credential_token({source_expr}, 'qobuz', {token_expr})"
        return self._send_command(command)

    def _send_command(self, command: str) -> bool:
        """Send command to RPI client via socket.

        Args:
            command: Python command string to execute on RPI client

        Returns:
            True if command was sent successfully, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect(self._socket_address)
                sock.sendall(command.encode("utf-8"))
                sock.sendall(b"\n")
            return True
        except Exception as exc:
            logger.error(
                "[CREDENTIAL CLIENT] Failed to send command '%s': %s",
                command,
                exc,
            )
            return False
