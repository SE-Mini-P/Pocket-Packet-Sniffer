"""Error handling and exception definitions for the Packet Processing Layer.

Adheres to SADS 3.4:
- Malformed or unparsable frames are flagged and skipped rather than halting the pipeline,
  preserving throughput for well-formed traffic.
- Unhandled exceptions are caught and sanitized to prevent crash cascades.
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("pps.processing")


class PacketProcessingError(Exception):
    """Base exception for all packet processing and dissection errors."""
    pass


class TruncatedPacketError(PacketProcessingError):
    """Raised when packet bytes are shorter than the expected header length."""
    pass


class MalformedPacketError(PacketProcessingError):
    """Raised when packet headers contain invalid, corrupt, or inconsistent field values."""
    pass


class UnsupportedProtocolError(PacketProcessingError):
    """Raised when an unhandled link type or network protocol is encountered."""
    pass


class ParsingAnomalyLog:
    """In-memory collector for parsing anomalies and weird frame events (SADS 3.4 weird.log)."""

    def __init__(self, max_entries: int = 1000) -> None:
        self.max_entries = max_entries
        self._entries: list[Dict[str, Any]] = []

    def log_anomaly(self, reason: str, raw_length: int, details: Optional[str] = None) -> None:
        entry = {
            "reason": reason,
            "raw_length": raw_length,
            "details": details or "",
        }
        self._entries.append(entry)
        if len(self._entries) > self.max_entries:
            self._entries.pop(0)
        logger.warning("Packet processing anomaly: %s (length=%d, details=%s)", reason, raw_length, details)

    def get_entries(self) -> list[Dict[str, Any]]:
        return list(self._entries)

    def clear(self) -> None:
        self._entries.clear()


# Global anomaly log instance for the processing pipeline
anomaly_log = ParsingAnomalyLog()
