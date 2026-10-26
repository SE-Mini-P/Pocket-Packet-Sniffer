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

# Interfaces the real device will eventually expose (SRS FR-1, FR-2, FR-3).
MOCK_INTERFACES = {
    "wlan0": {
        "id": "wlan0",
        "name": "wlan0",
        "type": "WiFi (802.11 monitor mode)",
        "status": "available",
        "channel": 6,
        "details": "2.4/5 GHz Promiscuous",
    },
    "eth0": {
        "id": "eth0",
        "name": "eth0",
        "type": "Ethernet",
        "status": "available",
        "speed": "100 Mbps",
        "details": "Wired tap",
    },
    "ble0": {
        "id": "ble0",
        "name": "ble0",
        "type": "Bluetooth Low Energy",
        "status": "available",
        "rssi_threshold": -70,
        "details": "HCI BLE scanner",
    },
}

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
        self._interface = deepcopy(MOCK_INTERFACES.get(iface_key, MOCK_INTERFACES["wlan0"]))

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

    def get_interfaces(self) -> dict[str, dict]:
        """Detect and return supported network interfaces (FR-02, NFR-02, SADS 3.2)."""
        current_name = self._interface.get("name")
        interfaces = {}
        for iface_id, iface_data in MOCK_INTERFACES.items():
            item = deepcopy(iface_data)
            item["selected"] = (iface_id == current_name or item.get("name") == current_name)
            interfaces[iface_id] = item
        return interfaces

    def select_interface(self, iface_name: str) -> dict:
        """Select an available capture interface prior to capture (FR-02, NFR-02)."""
        if self._status == "capturing":
            raise RuntimeError("Cannot change interface while capture is running")
        if iface_name not in MOCK_INTERFACES:
            raise ValueError(
                f"Invalid interface '{iface_name}'. Supported: {', '.join(MOCK_INTERFACES.keys())}"
            )
        self._interface = deepcopy(MOCK_INTERFACES[iface_name])
        return dict(self._interface)

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

    def get_stats(self) -> dict:
        """Calculate and return capture traffic statistics (FR-05, FR-6, SADS 3.2)."""
        packets_dicts = [p.to_dict() if hasattr(p, "to_dict") else p for p in self._packets]
        total_packets = len(packets_dicts)
        total_bytes = sum(p.get("length", 0) for p in packets_dicts)

        # Protocol distribution
        protocol_counts: dict[str, int] = {}
        for p in packets_dicts:
            proto = str(p.get("protocol", "UNKNOWN")).upper()
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        # Top talkers (grouping IPs from source/destination host:port)
        talker_counts: dict[str, dict] = {}
        for p in packets_dicts:
            for endpoint_key in ("source", "destination"):
                raw_addr = str(p.get(endpoint_key, ""))
                ip = raw_addr.split(":")[0] if ":" in raw_addr else raw_addr
                if not ip:
                    continue
                if ip not in talker_counts:
                    talker_counts[ip] = {"ip": ip, "packets": 0, "bytes": 0}
                talker_counts[ip]["packets"] += 1
                talker_counts[ip]["bytes"] += p.get("length", 0)

        top_talkers = sorted(
            talker_counts.values(),
            key=lambda x: (x["packets"], x["bytes"]),
            reverse=True,
        )

        duration_sec = 0.0
        rate = 0.0
        if self._started_at and self._status == "capturing":
            try:
                started_dt = datetime.fromisoformat(self._started_at.replace("Z", "+00:00"))
                duration_sec = max(1.0, (datetime.now(timezone.utc) - started_dt).total_seconds())
                rate = round(total_packets / duration_sec, 2)
            except Exception:
                duration_sec = 1.0
                rate = float(total_packets)

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_second": rate,
            "protocol_distribution": protocol_counts,
            "top_talkers": top_talkers[:5],
            "capture_duration_seconds": round(duration_sec, 1),
            "interface": dict(self._interface),
            "status": self._status,
        }

    def get_statistics(self) -> dict:
        """Compute live traffic stats and protocol distribution (FR-6, SADS 3.2)."""
        return self.get_stats()

    def get_status(self) -> dict:
        """Return status payload required by the dashboard header."""
        return {
            "interface": dict(self._interface),
            "capture": {
                "status": self._status,
                "started_at": self._started_at,
            },
        }
