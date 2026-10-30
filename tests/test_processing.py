"""Unit tests for the Packet Processing Layer.

Verifies requirements:
- FR-04: Process captured packets and extract available metadata (timestamp, source, destination, protocol).
- SADS 2.2: Packet Parser (Scapy/raw dissection) for Ethernet, WiFi 802.11, BLE.
- SADS 3.4: Resilient handling of malformed and truncated frames.
- FR-6: Traffic statistics and protocol distribution calculation.
"""

import unittest
import struct
from processing.parser import PacketParser
from processing.metadata import MetadataExtractor, PacketMetadata
from processing.error_handling import (
    TruncatedPacketError,
    MalformedPacketError,
    anomaly_log,
)


class PacketProcessingTest(unittest.TestCase):
    def setUp(self):
        self.parser = PacketParser()
        anomaly_log.clear()

    # --- Helper packet builders ---

    def _build_ethernet_ipv4_tcp_packet(
        self,
        src_ip: bytes = b"\xc0\xa8\x01\x64",      # 192.168.1.100
        dst_ip: bytes = b"\x08\x08\x08\x08",      # 8.8.8.8
        src_port: int = 54321,
        dst_port: int = 80,
        flags: int = 0x02,                        # SYN
        payload: bytes = b"",
    ) -> bytes:
        # Ethernet header (14 bytes)
        eth_hdr = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
        # IPv4 header (20 bytes, no options)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,                                 # Version 4, IHL 5 (20 bytes)
            0x00,                                 # DSCP/ECN
            20 + 20 + len(payload),               # Total length
            0x1234,                               # Identification
            0x4000,                               # Flags: DF
            64,                                   # TTL
            6,                                    # Protocol: TCP
            0x0000,                               # Checksum
            src_ip,
            dst_ip,
        )
        # TCP header (20 bytes, data offset 5 = 20 bytes)
        tcp_hdr = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            1000,                                 # Sequence number
            0,                                    # Ack number
            (5 << 4),                             # Data offset (5 * 4 = 20 bytes)
            flags,                                # Flags
            65535,                                # Window size
            0x0000,                               # Checksum
            0,                                    # Urgent pointer
        )
        return eth_hdr + ip_hdr + tcp_hdr + payload

    def _build_ethernet_ipv4_udp_packet(
        self,
        src_ip: bytes = b"\xc0\xa8\x01\x0a",      # 192.168.1.10
        dst_ip: bytes = b"\xc0\xa8\x01\x01",      # 192.168.1.1
        src_port: int = 5353,
        dst_port: int = 53,
        payload: bytes = b"",
    ) -> bytes:
        eth_hdr = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", 0x0800)
        udp_len = 8 + len(payload)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0x00,
            20 + udp_len,
            0xABCD,
            0,
            64,
            17,                                   # Protocol: UDP
            0,
            src_ip,
            dst_ip,
        )
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        return eth_hdr + ip_hdr + udp_hdr + payload

    # --- Dissection Tests (FR-04) ---

    def test_parse_valid_ipv4_tcp_frame(self):
        raw = self._build_ethernet_ipv4_tcp_packet(src_port=49152, dst_port=443, flags=0x02)
        meta = self.parser.parse_raw(raw, link_type="ethernet", interface="eth0")

        self.assertFalse(meta.is_malformed)
        self.assertEqual(meta.protocol, "TLS")
        self.assertEqual(meta.source, "192.168.1.100:49152")
        self.assertEqual(meta.destination, "8.8.8.8:443")
        self.assertEqual(meta.src_port, 49152)
        self.assertEqual(meta.dst_port, 443)
        self.assertEqual(meta.ip_version, 4)
        self.assertTrue(meta.flags.get("SYN"))
        self.assertFalse(meta.flags.get("ACK"))
        self.assertEqual(meta.interface, "eth0")
        self.assertGreater(meta.length, 50)

    def test_parse_valid_ipv4_udp_dns_frame(self):
        # Build minimal DNS query payload (Query ID 0x1234, Flags 0x0100, QDCOUNT 1, question "example.com")
        dns_payload = (
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00"
            + struct.pack("!HH", 1, 1)  # Type A, Class IN
        )
        raw = self._build_ethernet_ipv4_udp_packet(src_port=5353, dst_port=53, payload=dns_payload)
        meta = self.parser.parse_raw(raw, link_type="ethernet", interface="eth0")

        self.assertFalse(meta.is_malformed)
        self.assertEqual(meta.protocol, "DNS")
        self.assertEqual(meta.source, "192.168.1.10:5353")
        self.assertEqual(meta.destination, "192.168.1.1:53")
        self.assertIn("example.com", meta.info)

    def test_parse_http_payload_detection(self):
        http_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        raw = self._build_ethernet_ipv4_tcp_packet(src_port=50000, dst_port=80, flags=0x18, payload=http_data)
        meta = self.parser.parse_raw(raw, link_type="ethernet")

        self.assertEqual(meta.protocol, "HTTP")
        self.assertIn("GET /index.html", meta.info)

    def test_parse_arp_request_and_reply(self):
        # Build ARP Request: Who has 192.168.1.1? Tell 192.168.1.50
        eth_hdr = b"\xff\xff\xff\xff\xff\xff" + b"\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0806)
        arp_data = struct.pack(
            "!HHBBH6s4s6s4s",
            1, 0x0800, 6, 4, 1,  # Request opcode 1
            b"\x00\x11\x22\x33\x44\x55", b"\xc0\xa8\x01\x32",  # Sender MAC / 192.168.1.50
            b"\x00\x00\x00\x00\x00\x00", b"\xc0\xa8\x01\x01",  # Target MAC / 192.168.1.1
        )
        meta = self.parser.parse_raw(eth_hdr + arp_data, link_type="ethernet")

        self.assertFalse(meta.is_malformed)
        self.assertEqual(meta.protocol, "ARP")
        self.assertEqual(meta.source, "192.168.1.50")
        self.assertEqual(meta.destination, "192.168.1.1")
        self.assertIn("Who has", meta.info)

    def test_parse_wifi_beacon_frame(self):
        # 802.11 Frame Control: Type 0 (Mgmt), Subtype 8 (Beacon) -> 0x8000
        # Duration: 0x0000
        # Addr1 (RA): ff:ff:ff:ff:ff:ff
        # Addr2 (TA): 00:14:22:01:23:45
        # Addr3 (BSSID): 00:14:22:01:23:45
        # SeqCtl: 0x0000
        raw_wifi = (
            struct.pack("!HH", 0x8000, 0)
            + b"\xff\xff\xff\xff\xff\xff"
            + b"\x00\x14\x22\x01\x23\x45"
            + b"\x00\x14\x22\x01\x23\x45"
            + struct.pack("!H", 0x1234)
            + b"\x00" * 12  # Timestamp & Beacon interval
        )
        meta = self.parser.parse_raw(raw_wifi, link_type="wifi", interface="wlan0")

        self.assertFalse(meta.is_malformed)
        self.assertEqual(meta.protocol, "802.11")
        self.assertIn("Beacon frame", meta.info)
        self.assertEqual(meta.destination, "ff:ff:ff:ff:ff:ff")

    def test_parse_ble_advertisement_frame(self):
        # BLE raw payload: 6 bytes advertiser address + RSSI byte (-65 dBm = 0xBF)
        ble_raw = b"\xaa\xbb\xcc\x11\x22\x33" + struct.pack("b", -65)
        meta = self.parser.parse_raw(ble_raw, link_type="ble", interface="ble0")

        self.assertFalse(meta.is_malformed)
        self.assertEqual(meta.protocol, "BLE")
        self.assertEqual(meta.source, "aa:bb:cc:11:22:33")
        self.assertIn("-65dBm", meta.info)

    # --- Error Handling & Resiliency Tests (SADS 3.4) ---

    def test_truncated_ethernet_frame_handled_gracefully(self):
        truncated_raw = b"\x00\x11\x22"  # Only 3 bytes (< 14 expected)
        meta = self.parser.parse_raw(truncated_raw, link_type="ethernet")

        self.assertTrue(meta.is_malformed)
        self.assertEqual(meta.protocol, "CORRUPT")
        self.assertIn("truncated", meta.parsing_error.lower())
        self.assertEqual(len(anomaly_log.get_entries()), 1)

    def test_truncated_ipv4_header_handled_gracefully(self):
        # 14 bytes ethernet with EtherType 0x0800 + only 5 bytes IP (incomplete IPv4)
        eth_hdr = b"\x00" * 12 + struct.pack("!H", 0x0800)
        raw = eth_hdr + b"\x45\x00\x00\x20\x01"
        meta = self.parser.parse_raw(raw, link_type="ethernet")

        self.assertTrue(meta.is_malformed)
        self.assertIn("truncated", meta.parsing_error.lower())

    def test_corrupted_ipv4_version_handled_gracefully(self):
        # Valid length but invalid version nibble (version 9 instead of 4)
        raw = self._build_ethernet_ipv4_tcp_packet()
        corrupted = raw[:14] + bytes([0x95]) + raw[15:]
        meta = self.parser.parse_raw(corrupted, link_type="ethernet")

        self.assertTrue(meta.is_malformed)
        self.assertIn("Invalid IPv4 version", meta.parsing_error)

    def test_empty_packet_handled_gracefully(self):
        meta = self.parser.parse_raw(b"", link_type="ethernet")

        self.assertTrue(meta.is_malformed)
        self.assertEqual(meta.protocol, "EMPTY")

    # --- Metadata Normalization & Statistics Tests (FR-6) ---

    def test_metadata_extractor_and_statistics(self):
        packets = [
            {"id": 1, "protocol": "TCP", "source": "192.168.1.10:80", "destination": "10.0.0.1:54321", "length": 100},
            {"id": 2, "protocol": "TCP", "source": "192.168.1.10:443", "destination": "10.0.0.2:54322", "length": 200},
            {"id": 3, "protocol": "UDP", "source": "192.168.1.20:53", "destination": "10.0.0.1:53", "length": 50},
            {"id": 4, "protocol": "DNS", "source": "192.168.1.20:53", "destination": "10.0.0.1:53", "length": 80},
        ]
        stats = MetadataExtractor.extract_statistics(packets)

        self.assertEqual(stats["total_packets"], 4)
        self.assertEqual(stats["total_bytes"], 430)
        self.assertEqual(stats["protocol_distribution"]["TCP"], 2)
        self.assertEqual(stats["protocol_distribution"]["UDP"], 1)
        self.assertEqual(stats["protocol_distribution"]["DNS"], 1)
        self.assertEqual(stats["malformed_count"], 0)
        self.assertEqual(stats["top_talkers"]["sources"][0]["ip"], "192.168.1.10")


if __name__ == "__main__":
    unittest.main()
