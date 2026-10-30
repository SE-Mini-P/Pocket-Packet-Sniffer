"""Packet metadata extraction and data modeling for Pocket Packet Sniffer.

Implements requirements:
- FR-04: Process captured packets and extract available metadata (timestamp, source, destination, protocol).
- FR-6: Live capture statistics aggregation (packets/sec, top talkers, protocol distribution).
- SADS 2.2 / 3.3: Data model aligned with SQLite/time-series persistence and REST/WS presentation.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from collections import Counter


@dataclass
class PacketMetadata:
    """Canonical representation of processed packet metadata."""
    id: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    ip_version: Optional[int] = None
    flags: Dict[str, bool] = field(default_factory=dict)
    interface: str = "unknown"
    is_malformed: bool = False
    parsing_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to JSON-serializable dictionary."""
        data = asdict(self)
        # Omit None fields for cleaner payloads if desired, but keep core fields intact
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PacketMetadata":
        """Reconstruct PacketMetadata from dictionary with fallback defaults."""
        ts = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
        return cls(
            id=int(data.get("id", 0)),
            timestamp=str(ts),
            source=str(data.get("source", "0.0.0.0")),
            destination=str(data.get("destination", "0.0.0.0")),
            protocol=str(data.get("protocol", "UNKNOWN")).upper(),
            length=int(data.get("length", 0)),
            info=str(data.get("info", "")),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            ip_version=data.get("ip_version"),
            flags=data.get("flags") or {},
            interface=str(data.get("interface", "unknown")),
            is_malformed=bool(data.get("is_malformed", False)),
            parsing_error=data.get("parsing_error"),
        )


class MetadataExtractor:
    """Extracts, normalizes, and aggregates packet metadata from streams or raw frames."""

    @staticmethod
    def normalize(packet_obj: Any) -> PacketMetadata:
        """Normalize an input object (PacketMetadata, dict, or tuple) into a standard PacketMetadata."""
        if isinstance(packet_obj, PacketMetadata):
            return packet_obj
        if isinstance(packet_obj, dict):
            return PacketMetadata.from_dict(packet_obj)
        raise ValueError(f"Unsupported packet representation type: {type(packet_obj)}")

    @classmethod
    def extract_batch(cls, packets: List[Any]) -> List[PacketMetadata]:
        """Process a list of packet objects and return normalized metadata list."""
        return [cls.normalize(p) for p in packets]

    @classmethod
    def extract_statistics(cls, packets: List[Any]) -> Dict[str, Any]:
        """Compute aggregate traffic statistics from packet metadata (FR-6, SADS 3.2).

        Returns:
            total_packets: Total count of packets
            total_bytes: Sum of packet byte lengths
            protocol_distribution: Dict mapping protocol -> count
            top_talkers: Dict of most frequent source and destination endpoints
            malformed_count: Count of malformed/corrupted packets
        """
        if not packets:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "protocol_distribution": {},
                "top_talkers": {"sources": [], "destinations": []},
                "malformed_count": 0,
            }

        normalized = cls.extract_batch(packets)
        total_packets = len(normalized)
        total_bytes = sum(p.length for p in normalized)

        proto_counter = Counter(p.protocol for p in normalized)
        src_counter = Counter(p.source.split(":")[0] for p in normalized)
        dst_counter = Counter(p.destination.split(":")[0] for p in normalized)
        malformed = sum(1 for p in normalized if p.is_malformed)

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_distribution": dict(proto_counter.most_common()),
            "top_talkers": {
                "sources": [{"ip": ip, "count": count} for ip, count in src_counter.most_common(5)],
                "destinations": [{"ip": ip, "count": count} for ip, count in dst_counter.most_common(5)],
            },
            "malformed_count": malformed,
        }
