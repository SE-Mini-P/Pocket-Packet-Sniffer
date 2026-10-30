"""PCAP Storage and export manager for Pocket Packet Sniffer.

Implements requirements:
- FR-8: Standards-compliant .pcap/.pcapng export on user request.
- SADS 2.2.1: SD/USB Storage manager for captured packets.
"""

import struct
from datetime import datetime, timezone
from typing import List, Dict, Any


class PcapExporter:
    """Exports raw packets to standard libpcap format (.pcap) compatible with Wireshark."""

    # Libpcap global header format:
    # magic_number (uint32), version_major (uint16), version_minor (uint16),
    # thiszone (int32), sigfigs (uint32), snaplen (uint32), network (uint32)
    GLOBAL_HEADER = struct.pack(
        "!IHHiIII",
        0xA1B2C3D4,  # Standard microsecond magic number (big-endian)
        2,           # Major version 2
        4,           # Minor version 4
        0,           # GMT to local correction
        0,           # Accuracy of timestamps
        65535,       # Max snapshot length
        1,           # Data link type: 1 = Ethernet (DLT_EN10MB)
    )

    @classmethod
    def write_pcap(cls, packets: List[bytes], output_path: str) -> int:
        """Write a list of raw Ethernet frames to a .pcap file on disk."""
        total_written = 0
        with open(output_path, "wb") as f:
            f.write(cls.GLOBAL_HEADER)
            now_sec = int(datetime.now(timezone.utc).timestamp())
            for pkt in packets:
                length = len(pkt)
                # Packet record header:
                # ts_sec (uint32), ts_usec (uint32), incl_len (uint32), orig_len (uint32)
                pkt_hdr = struct.pack("!IIII", now_sec, 0, length, length)
                f.write(pkt_hdr)
                f.write(pkt)
                total_written += length
        return total_written
