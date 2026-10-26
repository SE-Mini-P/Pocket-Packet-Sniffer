"""Unified Capture Service coordinator for Pocket Packet Sniffer.

Implements requirements:
- FR-7: Start and stop capture sessions from UI/API.
- FR-4: BPF capture filter application.
- NFR-REL-1: Integration with CaptureBuffer ring buffer.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from .buffer import CaptureBuffer
from .interfaces import STANDARD_INTERFACES, CaptureInterface


class CaptureService:
    """Manages active capture sessions and pushes packets to the bounded buffer."""

    def __init__(self, buffer_size: int = 10000) -> None:
        self.buffer = CaptureBuffer(maxsize=buffer_size)
        self._interface: CaptureInterface = STANDARD_INTERFACES["wlan0"]
        self._status = "idle"  # idle | capturing | stopped | error
        self._started_at: Optional[str] = None
        self._filter: Optional[str] = None
        self._session_id: Optional[str] = None

    @property
    def status(self) -> str:
        return self._status

    @property
    def interface(self) -> CaptureInterface:
        return self._interface

    def set_interface(self, name: str, channel: Optional[int] = None, rssi_threshold: Optional[int] = None) -> None:
        """Select capture interface with optional wireless parameters."""
        if self._status == "capturing":
            raise RuntimeError("Cannot change interface while capture is actively running")
        if name not in STANDARD_INTERFACES:
            raise ValueError(f"Unknown interface '{name}'")
        iface = STANDARD_INTERFACES[name]
        if channel is not None and iface.is_wireless and iface.supported_channels:
            if channel not in iface.supported_channels:
                raise ValueError(f"Channel {channel} not supported on {name}")
            iface.selected_channel = channel
        if rssi_threshold is not None:
            iface.rssi_threshold = rssi_threshold
        self._interface = iface

    def start(self, bpf_filter: Optional[str] = None) -> Dict[str, Any]:
        """Start a new capture session."""
        if self._status == "capturing":
            raise RuntimeError("Capture is already running")
        self._status = "capturing"
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._filter = bpf_filter
        self._session_id = f"pps-sess-{int(datetime.now(timezone.utc).timestamp())}"
        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        """Stop current capture session."""
        if self._status != "capturing":
            raise RuntimeError("Capture is not running")
        self._status = "stopped"
        return self.get_status()

    def enqueue_raw_packet(self, raw_bytes: bytes) -> bool:
        """Enqueue captured frame into the ring buffer."""
        return self.buffer.push({
            "bytes": raw_bytes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface": self._interface.name,
        })

    def get_status(self) -> Dict[str, Any]:
        """Return status payload for API / dashboard."""
        return {
            "interface": self._interface.to_dict(),
            "capture": {
                "status": self._status,
                "started_at": self._started_at,
                "session_id": self._session_id,
                "filter": self._filter,
            },
            "buffer": self.buffer.get_stats(),
        }
