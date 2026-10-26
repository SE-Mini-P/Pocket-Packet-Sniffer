"""Packet parser and protocol dissector for Pocket Packet Sniffer.

Implements requirements:
- FR-04: Process captured packets and extract available metadata (timestamp, source, destination, protocol).
- SADS 2.2: Processing Layer - Packet Parser supporting multi-interface (Ethernet, WiFi 802.11, BLE).
- SADS 3.4: Resilient dissection of malformed/truncated frames without pipeline termination.
"""

import struct
import socket
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

from .error_handling import (
    TruncatedPacketError,
    MalformedPacketError,
    anomaly_log,
)
from .metadata import PacketMetadata


class PacketParser:
    """Dissects raw network frames and extracts structured metadata."""

    def __init__(self) -> None:
        self._packet_counter = 0

    def next_id(self) -> int:
        self._packet_counter += 1
        return self._packet_counter

    def parse_raw(
        self,
        raw_bytes: bytes,
        link_type: str = "ethernet",
        timestamp: Optional[str] = None,
        interface: str = "eth0",
    ) -> PacketMetadata:
        """Parse raw network bytes into PacketMetadata.

        Args:
            raw_bytes: Raw packet bytes from capture buffer or pcap.
            link_type: 'ethernet', 'wifi', or 'ble'.
            timestamp: Optional ISO timestamp, defaults to current UTC.
            interface: Name of interface packet was captured on.

        Returns:
            PacketMetadata with extracted metadata or gracefully degraded error details.
        """
        pkt_id = self.next_id()
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        length = len(raw_bytes)

        if not raw_bytes or length == 0:
            anomaly_log.log_anomaly("Empty frame received", 0)
            return PacketMetadata(
                id=pkt_id,
                timestamp=ts,
                source="0.0.0.0",
                destination="0.0.0.0",
                protocol="EMPTY",
                length=0,
                info="Empty or zero-length frame",
                interface=interface,
                is_malformed=True,
                parsing_error="Zero-length payload",
            )

        try:
            link_type_lower = link_type.lower()
            if link_type_lower == "ethernet":
                return self._dissect_ethernet(pkt_id, ts, raw_bytes, interface)
            elif link_type_lower in ("wifi", "802.11", "wlan"):
                return self._dissect_wifi(pkt_id, ts, raw_bytes, interface)
            elif link_type_lower in ("ble", "bluetooth"):
                return self._dissect_ble(pkt_id, ts, raw_bytes, interface)
            else:
                # Default to ethernet framing attempt
                return self._dissect_ethernet(pkt_id, ts, raw_bytes, interface)
        except (TruncatedPacketError, MalformedPacketError) as exc:
            anomaly_log.log_anomaly(str(exc), length, f"link_type={link_type}")
            return PacketMetadata(
                id=pkt_id,
                timestamp=ts,
                source="unknown",
                destination="unknown",
                protocol="CORRUPT",
                length=length,
                info=f"[Malformed Packet: {exc}]",
                interface=interface,
                is_malformed=True,
                parsing_error=str(exc),
            )
        except Exception as exc:
            anomaly_log.log_anomaly(f"Unexpected parsing exception: {exc}", length)
            return PacketMetadata(
                id=pkt_id,
                timestamp=ts,
                source="unknown",
                destination="unknown",
                protocol="ERROR",
                length=length,
                info=f"[Parsing Exception: {exc}]",
                interface=interface,
                is_malformed=True,
                parsing_error=str(exc),
            )

    # --- Ethernet Dissection ---

    def _dissect_ethernet(self, pkt_id: int, ts: str, data: bytes, iface: str) -> PacketMetadata:
        if len(data) < 14:
            raise TruncatedPacketError(f"Ethernet frame truncated: expected >= 14 bytes, got {len(data)}")

        dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
        src_mac = ":".join(f"{b:02x}" for b in data[6:12])
        ethertype = struct.unpack("!H", data[12:14])[0]
        payload = data[14:]

        if ethertype == 0x0800:  # IPv4
            return self._dissect_ipv4(pkt_id, ts, payload, src_mac, dst_mac, len(data), iface)
        elif ethertype == 0x0806:  # ARP
            return self._dissect_arp(pkt_id, ts, payload, src_mac, dst_mac, len(data), iface)
        elif ethertype == 0x86DD:  # IPv6
            return self._dissect_ipv6(pkt_id, ts, payload, src_mac, dst_mac, len(data), iface)
        else:
            return PacketMetadata(
                id=pkt_id,
                timestamp=ts,
                source=src_mac,
                destination=dst_mac,
                protocol=f"ETH (0x{ethertype:04x})",
                length=len(data),
                info=f"Raw Ethernet frame EtherType=0x{ethertype:04x}",
                interface=iface,
            )

    # --- ARP Dissection ---

    def _dissect_arp(self, pkt_id: int, ts: str, data: bytes, src_mac: str, dst_mac: str, total_len: int, iface: str) -> PacketMetadata:
        if len(data) < 28:
            raise TruncatedPacketError(f"ARP packet truncated: expected >= 28 bytes, got {len(data)}")

        hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack("!HHBBH", data[0:8])
        if hw_len != 6 or proto_len != 4:
            return PacketMetadata(
                id=pkt_id,
                timestamp=ts,
                source=src_mac,
                destination=dst_mac,
                protocol="ARP",
                length=total_len,
                info=f"ARP non-IPv4/Ethernet (hw_len={hw_len}, proto_len={proto_len})",
                interface=iface,
            )

        sender_ip = socket.inet_ntoa(data[14:18])
        target_ip = socket.inet_ntoa(data[24:28])

        op_name = "Request" if opcode == 1 else "Reply" if opcode == 2 else f"Opcode-{opcode}"
        info = f"Who has {target_ip}? Tell {sender_ip}" if opcode == 1 else f"{sender_ip} is at {src_mac}"

        return PacketMetadata(
            id=pkt_id,
            timestamp=ts,
            source=sender_ip,
            destination=target_ip,
            protocol="ARP",
            length=total_len,
            info=f"ARP {op_name}: {info}",
            interface=iface,
        )

    # --- IPv4 Dissection ---

    def _dissect_ipv4(self, pkt_id: int, ts: str, data: bytes, src_mac: str, dst_mac: str, total_len: int, iface: str) -> PacketMetadata:
        if len(data) < 20:
            raise TruncatedPacketError(f"IPv4 header truncated: expected >= 20 bytes, got {len(data)}")

        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        if version != 4:
            raise MalformedPacketError(f"Invalid IPv4 version: {version}")
        if ihl < 20 or ihl > len(data):
            raise MalformedPacketError(f"Invalid IPv4 IHL: {ihl} bytes (payload: {len(data)})")

        ttl = data[8]
        proto_num = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        l4_payload = data[ihl:]

        if proto_num == 6:  # TCP
            return self._dissect_tcp(pkt_id, ts, l4_payload, src_ip, dst_ip, total_len, iface)
        elif proto_num == 17:  # UDP
            return self._dissect_udp(pkt_id, ts, l4_payload, src_ip, dst_ip, total_len, iface)
        elif proto_num == 1:  # ICMP
            return self._dissect_icmp(pkt_id, ts, l4_payload, src_ip, dst_ip, total_len, iface)
        else:
            return PacketMetadata(
                id=pkt_id,
                timestamp=ts,
                source=src_ip,
                destination=dst_ip,
                protocol=f"IPv4-Proto-{proto_num}",
                length=total_len,
                info=f"IPv4 protocol {proto_num}, TTL={ttl}",
                ip_version=4,
                interface=iface,
            )

    # --- IPv6 Dissection ---

    def _dissect_ipv6(self, pkt_id: int, ts: str, data: bytes, src_mac: str, dst_mac: str, total_len: int, iface: str) -> PacketMetadata:
        if len(data) < 40:
            raise TruncatedPacketError(f"IPv6 header truncated: expected >= 40 bytes, got {len(data)}")

        version = data[0] >> 4
        if version != 6:
            raise MalformedPacketError(f"Invalid IPv6 version: {version}")

        next_header = data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        l4_payload = data[40:]

        if next_header == 6:
            return self._dissect_tcp(pkt_id, ts, l4_payload, src_ip, dst_ip, total_len, iface, ip_version=6)
        elif next_header == 17:
            return self._dissect_udp(pkt_id, ts, l4_payload, src_ip, dst_ip, total_len, iface, ip_version=6)
        else:
            return PacketMetadata(
                id=pkt_id,
                timestamp=ts,
                source=src_ip,
                destination=dst_ip,
                protocol=f"IPv6-Next-{next_header}",
                length=total_len,
                info=f"IPv6 Next Header={next_header}",
                ip_version=6,
                interface=iface,
            )

    # --- TCP Dissection ---

    def _dissect_tcp(
        self,
        pkt_id: int,
        ts: str,
        data: bytes,
        src_ip: str,
        dst_ip: str,
        total_len: int,
        iface: str,
        ip_version: int = 4,
    ) -> PacketMetadata:
        if len(data) < 20:
            raise TruncatedPacketError(f"TCP header truncated: expected >= 20 bytes, got {len(data)}")

        src_port, dst_port, seq, ack, offset_reserved, flags_byte = struct.unpack("!HHIIBB", data[0:14])
        data_offset = (offset_reserved >> 4) * 4
        if data_offset < 20 or data_offset > len(data):
            raise MalformedPacketError(f"Invalid TCP data offset: {data_offset}")

        flags = {
            "FIN": bool(flags_byte & 0x01),
            "SYN": bool(flags_byte & 0x02),
            "RST": bool(flags_byte & 0x04),
            "PSH": bool(flags_byte & 0x08),
            "ACK": bool(flags_byte & 0x10),
            "URG": bool(flags_byte & 0x20),
        }
        active_flags = [k for k, v in flags.items() if v]
        flag_str = f"[{','.join(active_flags)}]" if active_flags else "[None]"

        payload = data[data_offset:]
        protocol = "TCP"
        info = f"{src_port} -> {dst_port} {flag_str} Seq={seq} Ack={ack}"

        # Application layer checks (HTTP / TLS)
        if src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080:
            if payload:
                try:
                    head_line = payload.split(b"\r\n")[0].decode("latin-1", errors="ignore")
                    if any(head_line.startswith(m) for m in ("GET ", "POST ", "PUT ", "DELETE ", "HTTP/")):
                        protocol = "HTTP"
                        info = f"{head_line} ({flag_str})"
                except Exception:
                    pass
        elif src_port == 443 or dst_port == 443:
            protocol = "TLS"
            if len(payload) >= 5 and payload[0] == 22:  # Handshake record
                info = f"TLS Handshake {flag_str}"
            else:
                info = f"HTTPS / TLS Application Data {flag_str}"

        return PacketMetadata(
            id=pkt_id,
            timestamp=ts,
            source=f"{src_ip}:{src_port}",
            destination=f"{dst_ip}:{dst_port}",
            protocol=protocol,
            length=total_len,
            info=info,
            src_port=src_port,
            dst_port=dst_port,
            ip_version=ip_version,
            flags=flags,
            interface=iface,
        )

    # --- UDP Dissection ---

    def _dissect_udp(
        self,
        pkt_id: int,
        ts: str,
        data: bytes,
        src_ip: str,
        dst_ip: str,
        total_len: int,
        iface: str,
        ip_version: int = 4,
    ) -> PacketMetadata:
        if len(data) < 8:
            raise TruncatedPacketError(f"UDP header truncated: expected >= 8 bytes, got {len(data)}")

        src_port, dst_port, udp_len, checksum = struct.unpack("!HHHH", data[0:8])
        payload = data[8:]
        protocol = "UDP"
        info = f"{src_port} -> {dst_port} Len={udp_len}"

        # Check DNS (port 53)
        if src_port == 53 or dst_port == 53:
            protocol = "DNS"
            dns_info = self._parse_dns_summary(payload)
            info = f"DNS {dns_info}"
        elif src_port in (67, 68) or dst_port in (67, 68):
            protocol = "DHCP"
            info = f"DHCP message {src_port} -> {dst_port}"

        return PacketMetadata(
            id=pkt_id,
            timestamp=ts,
            source=f"{src_ip}:{src_port}",
            destination=f"{dst_ip}:{dst_port}",
            protocol=protocol,
            length=total_len,
            info=info,
            src_port=src_port,
            dst_port=dst_port,
            ip_version=ip_version,
            interface=iface,
        )

    def _parse_dns_summary(self, payload: bytes) -> str:
        if len(payload) < 12:
            return "message"
        tx_id, flags, qdcount, ancount = struct.unpack("!HHHH", payload[0:8])
        is_response = bool(flags & 0x8000)
        mode = "Response" if is_response else "Query"

        # Attempt to read query domain
        idx = 12
        labels = []
        while idx < len(payload):
            label_len = payload[idx]
            if label_len == 0 or idx + 1 + label_len > len(payload):
                break
            labels.append(payload[idx + 1:idx + 1 + label_len].decode("ascii", errors="ignore"))
            idx += 1 + label_len

        domain = ".".join(labels) if labels else "unknown"
        return f"{mode} (ID=0x{tx_id:04x}, Q='{domain}')"

    # --- ICMP Dissection ---

    def _dissect_icmp(self, pkt_id: int, ts: str, data: bytes, src_ip: str, dst_ip: str, total_len: int, iface: str) -> PacketMetadata:
        if len(data) < 4:
            raise TruncatedPacketError("ICMP packet truncated")
        icmp_type, icmp_code = struct.unpack("!BB", data[0:2])
        if icmp_type == 8:
            info = "Echo (ping) request"
        elif icmp_type == 0:
            info = "Echo (ping) reply"
        elif icmp_type == 3:
            info = f"Destination unreachable (code {icmp_code})"
        else:
            info = f"Type {icmp_type}, Code {icmp_code}"

        return PacketMetadata(
            id=pkt_id,
            timestamp=ts,
            source=src_ip,
            destination=dst_ip,
            protocol="ICMP",
            length=total_len,
            info=f"ICMP {info}",
            ip_version=4,
            interface=iface,
        )

    # --- WiFi 802.11 Dissection ---

    def _dissect_wifi(self, pkt_id: int, ts: str, data: bytes, iface: str) -> PacketMetadata:
        # 802.11 MAC header is typically 24 bytes (Frame Control, Duration, Addr1, Addr2, Addr3, SeqCtl)
        if len(data) < 24:
            raise TruncatedPacketError(f"802.11 frame truncated: expected >= 24 bytes, got {len(data)}")

        # Frame control byte 0: [Subtype: 4 bits | Type: 2 bits | Version: 2 bits]
        b0 = data[0]
        f_type = (b0 >> 2) & 0x03
        f_subtype = (b0 >> 4) & 0x0F

        addr1 = ":".join(f"{b:02x}" for b in data[4:10])   # Receiver / BSSID
        addr2 = ":".join(f"{b:02x}" for b in data[10:16])  # Transmitter
        addr3 = ":".join(f"{b:02x}" for b in data[16:22])  # Destination or Source

        type_names = {0: "Mgmt", 1: "Control", 2: "Data"}
        type_str = type_names.get(f_type, f"Type-{f_type}")

        info = f"802.11 {type_str} Subtype={f_subtype}"
        if f_type == 0:
            if f_subtype == 8:
                info = f"802.11 Beacon frame (BSSID={addr3})"
            elif f_subtype == 4:
                info = f"802.11 Probe Request (Src={addr2})"

        return PacketMetadata(
            id=pkt_id,
            timestamp=ts,
            source=addr2,
            destination=addr1,
            protocol="802.11",
            length=len(data),
            info=info,
            interface=iface,
        )

    # --- BLE Dissection ---

    def _dissect_ble(self, pkt_id: int, ts: str, data: bytes, iface: str) -> PacketMetadata:
        # BLE advertising packet payload representation
        if len(data) < 6:
            raise TruncatedPacketError(f"BLE packet truncated: expected >= 6 bytes, got {len(data)}")

        adv_addr = ":".join(f"{b:02x}" for b in data[0:6])
        rssi = None
        info = f"BLE Adv Address={adv_addr}"

        if len(data) >= 7:
            # Last byte frequently carries signed RSSI in our mock/driver format
            rssi = struct.unpack("b", data[-1:])[0]
            info += f" RSSI={rssi}dBm"

        return PacketMetadata(
            id=pkt_id,
            timestamp=ts,
            source=adv_addr,
            destination="ff:ff:ff:ff:ff:ff",
            protocol="BLE",
            length=len(data),
            info=info,
            interface=iface,
        )
