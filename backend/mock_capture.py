"""Mock capture service for the Pocket Packet Sniffer (PPS).

Decouples edge capture from development/simulation environments.
Integrates with:
- processing.metadata (PacketMetadata, MetadataExtractor) - Issue #6 & FR-04
- capture.interfaces (CaptureInterface, STANDARD_INTERFACES) - Issue #1 & FR-1/2/3
- capture.buffer (CaptureBuffer) - NFR-REL-1
"""

import os
import sys
import time
import shutil
from datetime import datetime, timezone
from copy import deepcopy
from typing import Optional, Dict, Any, List

try:
    import resource
except ImportError:
    resource = None

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

RAW_MOCK_ALERTS = [
    {
        "id": 1,
        "timestamp": "2025-01-15T10:15:28Z",
        "alert_type": "PORT_SCAN_DETECTED",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.105",
        "destination_ip": "192.168.1.10",
        "details": "Heuristic triggered: 18 distinct ports probed within 8.2 seconds (FR-08, PPS-F-014)",
    },
    {
        "id": 2,
        "timestamp": "2025-01-15T10:15:30Z",
        "alert_type": "SYN_FLOOD_ANOMALY",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.200",
        "destination_ip": "192.168.1.10",
        "details": "Half-open TCP connection threshold exceeded: 62 SYN pkts/10s (FR-08, PPS-F-015)",
    },
    {
        "id": 3,
        "timestamp": "2025-01-15T10:15:31Z",
        "alert_type": "SUSPICIOUS_DNS_QUERY",
        "severity": "WARNING",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.1",
        "details": "High-entropy domain name resolution: a8f9c12b7.evil-c2.internal (FR-08, SADS 3.3)",
    },
    {
        "id": 4,
        "timestamp": "2025-01-15T10:15:32Z",
        "alert_type": "PARSING_ANOMALY",
        "severity": "INFO",
        "source_ip": "192.168.1.55",
        "destination_ip": "192.168.1.10",
        "details": "Truncated frame detected and recovered: expected >= 20 bytes IPv4 header (SADS 3.4)",
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
        self._sessions = []
        self._active_session_id = None
        self._next_session_id = 1
        self._alerts: List[Dict[str, Any]] = [deepcopy(a) for a in RAW_MOCK_ALERTS]
        self._latency_samples: List[float] = [12.4, 18.2, 14.8, 22.1, 15.6]

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
        self._active_session_id = f"session-{self._next_session_id}"
        self._next_session_id += 1
        self._sessions.append({
            "id": self._active_session_id,
            "interface": deepcopy(self._interface),
            "started_at": self._started_at,
            "ended_at": None,
            "status": "capturing",
            "packet_count": 0,
            "analysis": {"protocol_counts": {}, "total_bytes": 0},
        })
        return self.get_status()

    def stop(self) -> dict:
        """Stop capture and return resulting status."""
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
        for item in packets:
            packet = item.to_dict() if hasattr(item, "to_dict") else item
            protocol = packet.get("protocol", "UNKNOWN")
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            total_bytes += packet.get("length", 0)
        return {"protocol_counts": protocol_counts, "total_bytes": total_bytes}

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

    def get_alerts(self, severity: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return analysis observations and security alerts (FR-08, SADS 3.3)."""
        alerts = [deepcopy(a) for a in self._alerts]
        if severity:
            sev = severity.strip().upper()
            alerts = [a for a in alerts if a.get("severity", "").upper() == sev]
        if search:
            q = search.strip().lower()
            alerts = [
                a for a in alerts
                if any(q in str(val).lower() for val in a.values())
            ]
        return alerts

    def add_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new security alert or traffic observation (FR-08)."""
        new_id = len(self._alerts) + 1
        record = {
            "id": new_id,
            "timestamp": alert_data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_data.get("alert_type", "CUSTOM_OBSERVATION"),
            "severity": (alert_data.get("severity") or "INFO").upper(),
            "source_ip": alert_data.get("source_ip", "0.0.0.0"),
            "destination_ip": alert_data.get("destination_ip", "0.0.0.0"),
            "details": alert_data.get("details", ""),
        }
        self._alerts.insert(0, record)
        return record

    def record_latency(self, latency_ms: float) -> None:
        """Track API response latency sample for performance telemetry (NFR-02)."""
        self._latency_samples.append(latency_ms)
        if len(self._latency_samples) > 200:
            self._latency_samples.pop(0)

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Measure dashboard response times and observe CPU, memory, storage usage (NFR-01, NFR-07)."""
        # Latency statistics (NFR-02)
        samples = self._latency_samples if self._latency_samples else [15.0]
        sorted_samples = sorted(samples)
        mean_lat = round(sum(samples) / len(samples), 2)
        p95_idx = int(len(sorted_samples) * 0.95)
        p95_lat = round(sorted_samples[min(p95_idx, len(sorted_samples) - 1)], 2)
        min_lat = round(sorted_samples[0], 2)
        max_lat = round(sorted_samples[-1], 2)

        # CPU & Memory RSS observation (NFR-01, NFR-07, PPS-NF-003)
        cpu_time_sec = 0.0
        user_cpu_sec = 0.0
        sys_cpu_sec = 0.0
        rss_mb = 45.0
        if resource:
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            user_cpu_sec = round(rusage.ru_utime, 3)
            sys_cpu_sec = round(rusage.ru_stime, 3)
            cpu_time_sec = round(user_cpu_sec + sys_cpu_sec, 3)
            # macOS returns bytes; Linux returns KB
            max_rss_bytes = rusage.ru_maxrss if sys.platform == "darwin" else rusage.ru_maxrss * 1024
            rss_mb = round(max_rss_bytes / (1024 * 1024), 2)

        # Storage & Buffer observation (NFR-07, PPS-F-010)
        buffer_len = len(self.ring_buffer._buffer)
        buffer_cap = self.ring_buffer.maxsize
        buffer_util_pct = round((buffer_len / max(1, buffer_cap)) * 100, 1)
        total_bytes = sum(p.get("length", 0) for p in self.get_packets())

        disk_free_gb = 10.0
        try:
            usage = shutil.disk_usage(os.getcwd())
            disk_free_gb = round(usage.free / (1024 ** 3), 2)
        except Exception:
            pass

        return {
            "dashboard_response_time_ms": {
                "mean": mean_lat,
                "p95": p95_lat,
                "min": min_lat,
                "max": max_lat,
                "target_threshold_ms": 500.0,
                "status": "PASS" if p95_lat <= 500.0 else "FAIL",
            },
            "cpu_usage": {
                "process_cpu_time_sec": cpu_time_sec,
                "user_cpu_sec": user_cpu_sec,
                "system_cpu_sec": sys_cpu_sec,
                "utilization_estimate_pct": round(min(100.0, cpu_time_sec * 5), 1),
                "status": "NORMAL",
            },
            "memory_usage": {
                "rss_mb": rss_mb,
                "bounded_ceiling_mb": 512.0,
                "status": "BOUNDED" if rss_mb < 512.0 else "WARNING",
            },
            "storage_usage": {
                "ring_buffer_packets": buffer_len,
                "ring_buffer_capacity": buffer_cap,
                "ring_buffer_utilization_pct": buffer_util_pct,
                "total_captured_bytes": total_bytes,
                "disk_free_gb": disk_free_gb,
                "status": "NOMINAL",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
