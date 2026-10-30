"""Mock capture service for the Pocket Packet Sniffer (PPS).

No hardware (Raspberry Pi / ESP32) is available during development, so this
module stands in for the real capture layer. It exposes the same kind of
information the real backend will later provide: which interface is selected
and what the capture status is.

When real capture code is written, replace the internals of ``MockCaptureService``
but keep the shape of ``get_status()`` so the dashboard does not need to change.

Mock behaviour can be tweaked with environment variables (handy for demos):
    PPS_MOCK_INTERFACE   e.g. "wlan0", "eth0", "ble0"       (default: wlan0)
    PPS_MOCK_STATUS      "idle" | "capturing" | "stopped" | "error"
                         (default: idle)
"""

import os
from datetime import datetime, timezone
from copy import deepcopy

# Interfaces the real device will eventually expose (SRS FR-1, FR-2, FR-3).
MOCK_INTERFACES = {
    "wlan0": {"name": "wlan0", "type": "WiFi (802.11 monitor mode)"},
    "eth0": {"name": "eth0", "type": "Ethernet"},
    "ble0": {"name": "ble0", "type": "Bluetooth Low Energy"},
}

VALID_STATUSES = {"idle", "capturing", "stopped", "error"}

MOCK_PACKETS = [
    {
        "id": 1,
        "timestamp": "2025-01-15T10:15:30Z",
        "protocol": "TCP",
        "source": "192.168.1.10:51524",
        "destination": "142.250.72.14:443",
        "length": 128,
        "info": "TLS client hello",
    },
    {
        "id": 2,
        "timestamp": "2025-01-15T10:15:31Z",
        "protocol": "DNS",
        "source": "192.168.1.10:5353",
        "destination": "192.168.1.1:53",
        "length": 74,
        "info": "Standard query A example.com",
    },
    {
        "id": 3,
        "timestamp": "2025-01-15T10:15:32Z",
        "protocol": "UDP",
        "source": "192.168.1.1:67",
        "destination": "192.168.1.10:68",
        "length": 342,
        "info": "DHCP offer",
    },
    {
        "id": 4,
        "timestamp": "2025-01-15T10:15:33Z",
        "protocol": "HTTP",
        "source": "192.168.1.10:49152",
        "destination": "93.184.216.34:80",
        "length": 512,
        "info": "GET / HTTP/1.1",
    },
]


class MockCaptureService:
    def __init__(self) -> None:
        iface_key = os.getenv("PPS_MOCK_INTERFACE", "wlan0")
        self._interface = MOCK_INTERFACES.get(iface_key, MOCK_INTERFACES["wlan0"])

        status = os.getenv("PPS_MOCK_STATUS", "idle").lower()
        self._status = status if status in VALID_STATUSES else "idle"

        self._started_at = (
            datetime.now(timezone.utc).isoformat()
            if self._status == "capturing"
            else None
        )
        self._packets = deepcopy(MOCK_PACKETS)
        self._sessions = []
        self._active_session_id = None
        self._next_session_id = 1

    def start(self) -> dict:
        """Start capture and return the resulting status."""
        if self._status == "capturing":
            raise RuntimeError("Capture is already running")
        self._status = "capturing"
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._active_session_id = f"session-{self._next_session_id}"
        self._next_session_id += 1
        self._sessions.append({
            "id": self._active_session_id,
            "interface": dict(self._interface),
            "started_at": self._started_at,
            "ended_at": None,
            "status": "capturing",
            "packet_count": 0,
            "analysis": {"protocol_counts": {}, "total_bytes": 0},
        })
        return self.get_status()

    def stop(self) -> dict:
        """Stop capture and return the resulting status."""
        if self._status != "capturing":
            raise RuntimeError("Capture is not running")
        self._status = "stopped"
        session = self._get_active_session()
        session.update({
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "packet_count": len(self._packets),
            "analysis": self._analyse_packets(self._packets),
        })
        self._active_session_id = None
        return self.get_status()

    def get_sessions(self) -> list[dict]:
        """Return completed and in-progress capture sessions, newest first."""
        return deepcopy(list(reversed(self._sessions)))

    def get_session(self, session_id: str) -> dict | None:
        """Return one capture session, or ``None`` if it does not exist."""
        for session in self._sessions:
            if session["id"] == session_id:
                return deepcopy(session)
        return None

    def _get_active_session(self) -> dict:
        for session in self._sessions:
            if session["id"] == self._active_session_id:
                return session
        raise RuntimeError("Capture session is not available")

    @staticmethod
    def _analyse_packets(packets: list[dict]) -> dict:
        protocol_counts = {}
        total_bytes = 0
        for packet in packets:
            protocol = packet["protocol"]
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            total_bytes += packet["length"]
        return {"protocol_counts": protocol_counts, "total_bytes": total_bytes}

    def get_packets(self, filters: dict | None = None) -> list[dict]:
        """Return mock packets matching non-empty, case-insensitive filters."""
        filters = filters or {}
        packets = self._packets
        for field in ("protocol", "source", "destination"):
            value = filters.get(field, "").strip().lower()
            if value:
                packets = [
                    packet for packet in packets
                    if value in str(packet[field]).lower()
                ]
        search = filters.get("search", "").strip().lower()
        if search:
            packets = [
                packet for packet in packets
                if any(search in str(value).lower() for value in packet.values())
            ]
        return deepcopy(packets)

    def get_status(self) -> dict:
        """Return the data the dashboard needs to render its header."""
        return {
            "interface": dict(self._interface),
            "capture": {
                "status": self._status,
                "started_at": self._started_at,
            },
        }
