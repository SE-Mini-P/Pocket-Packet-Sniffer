"""Mock capture service for the Pocket Packet Sniffer (PPS).

Decouples edge capture from development/simulation environments.
Integrates with:
- processing.metadata (PacketMetadata, MetadataExtractor) - Issue #6 & FR-04
- capture.interfaces (CaptureInterface, STANDARD_INTERFACES) - Issue #1 & FR-1/2/3
- capture.buffer (CaptureBuffer) - NFR-REL-1
"""

import os
from datetime import datetime, timezone
from copy import deepcopy
from typing import Optional, Dict, Any, List

try:
    from processing.metadata import PacketMetadata, MetadataExtractor
    from capture.interfaces import STANDARD_INTERFACES
    from capture.buffer import CaptureBuffer
except ImportError:
    # Support direct backend module execution
    import sys
    from pathlib import Path
    root = str(Path(__file__).resolve().parent.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    from processing.metadata import PacketMetadata, MetadataExtractor
    from capture.interfaces import STANDARD_INTERFACES
    from capture.buffer import CaptureBuffer

# Backwards compatible alias for interface definitions
MOCK_INTERFACES = {k: v.to_dict() for k, v in STANDARD_INTERFACES.items()}

VALID_STATUSES = {"idle", "capturing", "stopped", "error"}

RAW_MOCK_PACKETS = [
    {
        "id": 1,
        "timestamp": "2025-01-15T10:15:30Z",
        "protocol": "TCP",
        "source": "192.168.1.10:51524",
        "destination": "142.250.72.14:443",
        "length": 128,
        "info": "TLS client hello",
        "flags": {"SYN": True, "ACK": False},
        "src_port": 51524,
        "dst_port": 443,
        "ip_version": 4,
    },
    {
        "id": 2,
        "timestamp": "2025-01-15T10:15:31Z",
        "protocol": "DNS",
        "source": "192.168.1.10:5353",
        "destination": "192.168.1.1:53",
        "length": 74,
        "info": "Standard query A example.com",
        "src_port": 5353,
        "dst_port": 53,
        "ip_version": 4,
    },
    {
        "id": 3,
        "timestamp": "2025-01-15T10:15:32Z",
        "protocol": "UDP",
        "source": "192.168.1.1:67",
        "destination": "192.168.1.10:68",
        "length": 342,
        "info": "DHCP offer",
        "src_port": 67,
        "dst_port": 68,
        "ip_version": 4,
    },
    {
        "id": 4,
        "timestamp": "2025-01-15T10:15:33Z",
        "protocol": "HTTP",
        "source": "192.168.1.10:49152",
        "destination": "93.184.216.34:80",
        "length": 512,
        "info": "GET / HTTP/1.1",
        "flags": {"ACK": True, "PSH": True},
        "src_port": 49152,
        "dst_port": 80,
        "ip_version": 4,
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
        self.ring_buffer = CaptureBuffer(maxsize=1000)
        self._packets: List[PacketMetadata] = [
            PacketMetadata.from_dict(p) for p in RAW_MOCK_PACKETS
        ]
        for p in self._packets:
            self.ring_buffer.push(p.to_dict())

    def start(self) -> dict:
        """Start capture and return resulting status."""
        if self._status == "capturing":
            raise RuntimeError("Capture is already running")
        self._status = "capturing"
        self._started_at = datetime.now(timezone.utc).isoformat()
        return self.get_status()

    def stop(self) -> dict:
        """Stop capture and return resulting status."""
        if self._status != "capturing":
            raise RuntimeError("Capture is not running")
        self._status = "stopped"
        return self.get_status()

    def add_packet(self, packet: PacketMetadata | dict) -> None:
        """Add a processed packet to the active session stream."""
        normalized = MetadataExtractor.normalize(packet)
        self._packets.append(normalized)
        self.ring_buffer.push(normalized.to_dict())

    def get_packets(self, filters: dict | None = None) -> list[dict]:
        """Return packets matching filters with extracted metadata."""
        filters = filters or {}
        packets = [p.to_dict() for p in self._packets]

        for field in ("protocol", "source", "destination"):
            value = filters.get(field, "").strip().lower()
            if value:
                packets = [
                    pkt for pkt in packets
                    if value in str(pkt.get(field, "")).lower()
                ]

        search = filters.get("search", "").strip().lower()
        if search:
            packets = [
                pkt for pkt in packets
                if any(search in str(v).lower() for v in pkt.values())
            ]
        return deepcopy(packets)

    def get_statistics(self) -> dict:
        """Compute live traffic stats and protocol distribution (FR-6, SADS 3.2)."""
        return MetadataExtractor.extract_statistics(self._packets)

    def get_status(self) -> dict:
        """Return status payload required by the dashboard header."""
        return {
            "interface": dict(self._interface),
            "capture": {
                "status": self._status,
                "started_at": self._started_at,
            },
        }
