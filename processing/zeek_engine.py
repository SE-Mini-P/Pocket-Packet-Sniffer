"""Zeek Analysis Engine for Pocket Packet Sniffer (PPS).

Implements requirements:
- FR-5: Route captured traffic through Zeek analysis engine and produce structured
  logs (conn.log, dns.log, weird.log, notice.log).
- FR-10: Anomaly detection (port scans, ARP spoofing, traffic floods, protocol anomalies).
- SADS 2.2.1: Zeek Analysis Engine consuming packet stream and emitting structured event logs.
- SADS 3.4: Resilient handling where malformed/unparsable frames are routed to weird.log.
"""

import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set


class ZeekLogEntry:
    """Represents a structured Zeek log entry."""

    def __init__(self, log_type: str, fields: Dict[str, Any]) -> None:
        self.log_type = log_type
        self.fields = fields
        if "ts" not in self.fields:
            self.fields["ts"] = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {"log_type": self.log_type, **self.fields}

    def to_tsv(self, headers: List[str]) -> str:
        values = [str(self.fields.get(h, "-")) for h in headers]
        return "\t".join(values)


class ZeekAnalysisEngine:
    """Lightweight, embedded Zeek-compatible analysis and anomaly detection engine.

    Produces standard Zeek log formats:
    - conn.log: connection lifecycle, state tracking, duration, byte counts
    - dns.log: DNS lookups, queries, answers, response codes
    - weird.log: protocol anomalies, malformed headers, illegal flag combinations
    - notice.log: security notices (port scan, ARP spoofing, floods, suspicious payloads)
    """

    # Common port to service mappings
    WELL_KNOWN_SERVICES = {
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        80: "http",
        443: "ssl",
        22: "ssh",
        21: "ftp",
        25: "smtp",
        110: "pop3",
        143: "imap",
        8080: "http-proxy",
        1883: "mqtt",
    }

    def __init__(self) -> None:
        # Structured log stores
        self.conn_log: List[Dict[str, Any]] = []
        self.dns_log: List[Dict[str, Any]] = []
        self.weird_log: List[Dict[str, Any]] = []
        self.notice_log: List[Dict[str, Any]] = []

        # Connection flow tracker: (orig_h, orig_p, resp_h, resp_p, proto) -> state
        self._flows: Dict[str, Dict[str, Any]] = {}

        # Heuristic state tracking for anomaly detection
        # Port scan detection: (src_ip, dst_ip) -> set of contacted ports
        self._port_scan_tracker: Dict[str, Set[int]] = {}
        # ARP cache tracker: ip -> mac
        self._arp_tracker: Dict[str, str] = {}
        # Rate tracking: src_ip -> list of timestamps
        self._rate_tracker: Dict[str, List[float]] = {}

        # Scan threshold (ports targeted before alert)
        self.port_scan_threshold = 4
        # Flood threshold (packets/sec from single host)
        self.flood_threshold = 50

    def clear(self) -> None:
        """Reset all state and log records."""
        self.conn_log.clear()
        self.dns_log.clear()
        self.weird_log.clear()
        self.notice_log.clear()
        self._flows.clear()
        self._port_scan_tracker.clear()
        self._arp_tracker.clear()
        self._rate_tracker.clear()

    @staticmethod
    def _generate_uid(orig_h: str, orig_p: int, resp_h: str, resp_p: int, proto: str) -> str:
        """Generate a deterministic or unique Zeek connection UID (e.g. 'Cxxxxxxxxxxxx')."""
        raw = f"{orig_h}:{orig_p}->{resp_h}:{resp_p}:{proto}"
        digest = hashlib.md5(raw.encode("utf-8")).hexdigest()[:16]
        return f"C{digest}"

    def process_packet(self, packet: Any) -> Dict[str, Any]:
        """Ingest and analyze a packet or PacketMetadata object through Zeek analysis.

        Returns a dictionary of newly produced events/notices.
        """
        # Normalize to dictionary
        pkt = packet.to_dict() if hasattr(packet, "to_dict") else dict(packet)
        ts = pkt.get("timestamp") or datetime.now(timezone.utc).isoformat()
        length = int(pkt.get("length", 0))
        proto = str(pkt.get("protocol", "UNKNOWN")).upper()
        now_epoch = time.time()

        events_produced = {
            "conn": None,
            "dns": None,
            "weird": None,
            "notices": [],
        }

        # 1. Check for malformed / weird packet (SADS 3.4)
        if pkt.get("is_malformed"):
            weird_entry = {
                "ts": ts,
                "uid": pkt.get("uid") or f"W{int(now_epoch * 1000) % 1000000}",
                "name": pkt.get("malformed_reason") or "malformed_packet_format",
                "addl": pkt.get("info") or "Truncated or unparsable packet bytes",
                "notice": False,
                "peer": pkt.get("source") or "unknown",
            }
            self.weird_log.append(weird_entry)
            events_produced["weird"] = weird_entry
            return events_produced

        # Extract endpoints and ports
        src_raw = str(pkt.get("source", ""))
        dst_raw = str(pkt.get("destination", ""))

        orig_h = src_raw.split(":")[0] if ":" in src_raw else src_raw
        resp_h = dst_raw.split(":")[0] if ":" in dst_raw else dst_raw

        src_port_val = int(src_raw.split(":")[1]) if ":" in src_raw and src_raw.split(":")[1].isdigit() else 0
        dst_port_val = int(dst_raw.split(":")[1]) if ":" in dst_raw and dst_raw.split(":")[1].isdigit() else 0
        orig_p = int(pkt.get("src_port") or src_port_val)
        resp_p = int(pkt.get("dst_port") or dst_port_val)

        # Check TCP flags for weird anomalies
        flags = pkt.get("flags") or {}
        if isinstance(flags, dict):
            # SYN + FIN combination is illegal in RFC 793
            if flags.get("SYN") and flags.get("FIN"):
                weird_entry = {
                    "ts": ts,
                    "uid": self._generate_uid(orig_h, orig_p, resp_h, resp_p, proto),
                    "name": "tcp_syn_and_fin",
                    "addl": "Simultaneous SYN and FIN flags set in TCP segment",
                    "notice": True,
                    "peer": orig_h,
                }
                self.weird_log.append(weird_entry)
                events_produced["weird"] = weird_entry

        # 2. Connection Tracking (conn.log)
        service = self.WELL_KNOWN_SERVICES.get(resp_p) or self.WELL_KNOWN_SERVICES.get(orig_p) or "-"
        flow_key = f"{orig_h}:{orig_p}-{resp_h}:{resp_p}-{proto}"
        rev_flow_key = f"{resp_h}:{resp_p}-{orig_h}:{orig_p}-{proto}"

        conn_uid = self._generate_uid(orig_h, orig_p, resp_h, resp_p, proto)

        if flow_key in self._flows:
            flow = self._flows[flow_key]
            flow["orig_bytes"] += length
            flow["orig_pkts"] += 1
            flow["duration"] = round(max(0.001, now_epoch - flow["start_epoch"]), 4)
            flow["last_seen"] = ts
        elif rev_flow_key in self._flows:
            flow = self._flows[rev_flow_key]
            flow["resp_bytes"] += length
            flow["resp_pkts"] += 1
            flow["duration"] = round(max(0.001, now_epoch - flow["start_epoch"]), 4)
            flow["last_seen"] = ts
            # If reply seen, update conn_state
            if flow.get("conn_state") == "S0":
                flow["conn_state"] = "SF"
        else:
            conn_state = "SF" if proto in ("UDP", "DNS", "DHCP", "ICMP") else "S0"
            if flags.get("ACK") and not flags.get("SYN"):
                conn_state = "OTH"

            flow = {
                "ts": ts,
                "uid": conn_uid,
                "id.orig_h": orig_h or "0.0.0.0",
                "id.orig_p": orig_p,
                "id.resp_h": resp_h or "0.0.0.0",
                "id.resp_p": resp_p,
                "proto": proto.lower(),
                "service": service,
                "duration": 0.001,
                "orig_bytes": length,
                "resp_bytes": 0,
                "conn_state": conn_state,
                "orig_pkts": 1,
                "resp_pkts": 0,
                "start_epoch": now_epoch,
                "last_seen": ts,
            }
            self._flows[flow_key] = flow
            self.conn_log.append(flow)

        events_produced["conn"] = flow

        # 3. Protocol-Specific Dissection (dns.log)
        info_str = str(pkt.get("info", ""))
        if proto == "DNS" or resp_p == 53 or orig_p == 53 or "DNS" in info_str:
            query = "example.com"
            qtype_name = "A"
            rcode_name = "NOERROR"
            answers: List[str] = []

            # Extract from info if formatted as query
            if "query" in info_str.lower() or "Standard query" in info_str:
                parts = info_str.split()
                if len(parts) >= 4:
                    qtype_name = parts[2] if len(parts) > 2 else "A"
                    query = parts[3] if len(parts) > 3 else "example.com"
            elif "response" in info_str.lower():
                answers = ["192.168.1.1"]

            dns_entry = {
                "ts": ts,
                "uid": conn_uid,
                "id.orig_h": orig_h or "0.0.0.0",
                "id.orig_p": orig_p,
                "id.resp_h": resp_h or "0.0.0.0",
                "id.resp_p": resp_p,
                "proto": "udp",
                "trans_id": 0x1234,
                "query": query,
                "qclass_name": "C_INTERNET",
                "qtype_name": qtype_name,
                "rcode_name": rcode_name,
                "answers": answers,
            }
            self.dns_log.append(dns_entry)
            events_produced["dns"] = dns_entry

        # 4. Anomaly Detection & Notice Generation (FR-10, notice.log)
        notices = self._evaluate_anomalies(pkt, orig_h, resp_h, resp_p, proto, ts, now_epoch)
        for notice in notices:
            self.notice_log.append(notice)
            events_produced["notices"].append(notice)

        return events_produced

    def _evaluate_anomalies(
        self,
        pkt: Dict[str, Any],
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        ts: str,
        now_epoch: float,
    ) -> List[Dict[str, Any]]:
        """Evaluate traffic against Zeek heuristic anomaly rules."""
        notices: List[Dict[str, Any]] = []

        if not src_ip or src_ip in ("0.0.0.0", "unknown"):
            return notices

        # Heuristic 1: Port Scan Detection
        if dst_port > 0 and proto in ("TCP", "UDP"):
            target_key = f"{src_ip}->{dst_ip}"
            if target_key not in self._port_scan_tracker:
                self._port_scan_tracker[target_key] = set()
            self._port_scan_tracker[target_key].add(dst_port)

            if len(self._port_scan_tracker[target_key]) >= self.port_scan_threshold:
                port_list = sorted(list(self._port_scan_tracker[target_key]))
                notice = {
                    "ts": ts,
                    "note": "Scan::Port_Scan",
                    "msg": f"Host {src_ip} attempted connections to {len(port_list)} ports on {dst_ip}",
                    "sub": f"Targeted ports: {port_list[:10]}",
                    "src": src_ip,
                    "dst": dst_ip,
                    "p": dst_port,
                    "actions": ["Notice::ACTION_ALERT", "Notice::ACTION_LOG"],
                    "severity": "CRITICAL",
                }
                # Emit once per threshold crossing
                if len(self._port_scan_tracker[target_key]) == self.port_scan_threshold:
                    notices.append(notice)

        # Heuristic 2: ARP Spoofing / Inconsistency Detection
        if proto == "ARP" or "ARP" in str(pkt.get("info", "")):
            mac = pkt.get("src_mac") or pkt.get("source_mac")
            if mac and src_ip:
                if src_ip in self._arp_tracker and self._arp_tracker[src_ip] != mac:
                    old_mac = self._arp_tracker[src_ip]
                    notice = {
                        "ts": ts,
                        "note": "Notice::ARP_Spoofing",
                        "msg": f"ARP conflict detected for IP {src_ip}: MAC changed from {old_mac} to {mac}",
                        "sub": "Potential ARP cache poisoning / spoofing attempt",
                        "src": src_ip,
                        "dst": dst_ip or "255.255.255.255",
                        "p": 0,
                        "actions": ["Notice::ACTION_ALERT", "Notice::ACTION_LOG"],
                        "severity": "CRITICAL",
                    }
                    notices.append(notice)
                self._arp_tracker[src_ip] = mac

        # Heuristic 3: Traffic Flood Detection
        if src_ip not in self._rate_tracker:
            self._rate_tracker[src_ip] = []
        timestamps = self._rate_tracker[src_ip]
        timestamps.append(now_epoch)
        # Keep window to last 2 seconds
        self._rate_tracker[src_ip] = [t for t in timestamps if now_epoch - t <= 2.0]

        if len(self._rate_tracker[src_ip]) > self.flood_threshold:
            notice = {
                "ts": ts,
                "note": "Notice::Traffic_Flood",
                "msg": f"High packet rate detected from host {src_ip} ({len(self._rate_tracker[src_ip])} pkts in 2s)",
                "sub": f"Packet flood threshold ({self.flood_threshold}) exceeded",
                "src": src_ip,
                "dst": dst_ip or "multiple",
                "p": dst_port,
                "actions": ["Notice::ACTION_ALERT"],
                "severity": "WARNING",
            }
            if len(self._rate_tracker[src_ip]) == self.flood_threshold + 1:
                notices.append(notice)

        return notices

    def get_logs(self, log_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve Zeek logs with optional type filter ('conn', 'dns', 'weird', 'notice', 'all')."""
        target = (log_type or "all").lower().strip()
        if target == "conn":
            return list(reversed(self.conn_log[-limit:]))
        elif target == "dns":
            return list(reversed(self.dns_log[-limit:]))
        elif target == "weird":
            return list(reversed(self.weird_log[-limit:]))
        elif target == "notice":
            return list(reversed(self.notice_log[-limit:]))
        elif target in ("all", ""):
            combined = []
            for item in self.conn_log:
                combined.append({"log_type": "conn", **item})
            for item in self.dns_log:
                combined.append({"log_type": "dns", **item})
            for item in self.weird_log:
                combined.append({"log_type": "weird", **item})
            for item in self.notice_log:
                combined.append({"log_type": "notice", **item})
            combined.sort(key=lambda x: str(x.get("ts", "")), reverse=True)
            return combined[:limit]
        else:
            raise ValueError(f"Unknown Zeek log type '{log_type}'. Supported: conn, dns, weird, notice, all")

    def get_summary(self) -> Dict[str, Any]:
        """Return statistical summary of Zeek analysis engine."""
        services_count: Dict[str, int] = {}
        states_count: Dict[str, int] = {}
        for c in self.conn_log:
            svc = c.get("service", "-")
            services_count[svc] = services_count.get(svc, 0) + 1
            st = c.get("conn_state", "OTH")
            states_count[st] = states_count.get(st, 0) + 1

        notice_types: Dict[str, int] = {}
        for n in self.notice_log:
            note = n.get("note", "UNKNOWN")
            notice_types[note] = notice_types.get(note, 0) + 1

        return {
            "total_connections": len(self.conn_log),
            "active_flows": len(self._flows),
            "dns_transactions": len(self.dns_log),
            "weird_events": len(self.weird_log),
            "security_notices": len(self.notice_log),
            "services_breakdown": services_count,
            "connection_states": states_count,
            "notice_types": notice_types,
        }
