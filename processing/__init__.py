"""Processing Layer package for Pocket Packet Sniffer.

Exports:
- PacketMetadata: Canonical packet metadata model.
- MetadataExtractor: Extracts and aggregates packet metadata.
- PacketParser: Dissects network frames and protocols.
- PacketProcessingError, TruncatedPacketError, MalformedPacketError: Parsing exceptions.
- anomaly_log: In-memory anomalous frame tracker.
"""

from .metadata import PacketMetadata, MetadataExtractor
from .parser import PacketParser
from .error_handling import (
    PacketProcessingError,
    TruncatedPacketError,
    MalformedPacketError,
    UnsupportedProtocolError,
    anomaly_log,
)

__all__ = [
    "PacketMetadata",
    "MetadataExtractor",
    "PacketParser",
    "PacketProcessingError",
    "TruncatedPacketError",
    "MalformedPacketError",
    "UnsupportedProtocolError",
    "anomaly_log",
]
