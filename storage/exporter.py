"""Export and Reporting Subsystem for Pocket Packet Sniffer (PPS).

Implements requirements:
- FR-8: Standards-compliant .pcap export on user request.
- FR-9: Human-readable session summary report (HTML) containing capture duration,
  packet/byte counts, protocol distribution, and detected anomalies.
- FR-10 (Issue #13): Allow users to export selected packet metadata or analysis
  results in supported formats (JSON, CSV, PCAP, HTML).
- SADS 3.2: Export and reporting endpoints.
"""

import io
import csv
import json
import struct
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from .pcap_store import PcapExporter


class AnalysisExporter:
    """Provides formatting and export generation for capture metadata, analysis, and reports."""

    SUPPORTED_FORMATS = {"json", "csv", "pcap", "html"}
    SUPPORTED_DATA_TYPES = {"packets", "analysis", "alerts", "zeek", "all"}

    @staticmethod
    def export_json(data: Any, pretty: bool = True) -> str:
        """Serialize data to formatted JSON string."""
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent, default=str)

    @staticmethod
    def export_csv(items: List[Dict[str, Any]], fieldnames: Optional[List[str]] = None) -> str:
        """Convert a list of dictionaries into a CSV string.

        Flattens or stringifies nested objects to ensure strict tabular validity.
        """
        if not items:
            return ""

        # Auto-detect fieldnames if not explicitly provided
        if not fieldnames:
            keys: List[str] = []
            for item in items:
                for k in item.keys():
                    if k not in keys:
                        keys.append(k)
            fieldnames = keys

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for raw_row in items:
            row: Dict[str, Any] = {}
            for field in fieldnames:
                val = raw_row.get(field, "")
                if isinstance(val, (dict, list)):
                    row[field] = json.dumps(val)
                elif val is None:
                    row[field] = ""
                else:
                    row[field] = str(val)
            writer.writerow(row)

        return output.getvalue()

    @classmethod
    def export_pcap(cls, packets: List[Any], output_path: Optional[str] = None) -> bytes:
        """Convert packet metadata or raw packets to standard libpcap binary stream.

        If packets are PacketMetadata or dicts, synthesizes valid Ethernet/IP frames.
        """
        raw_frames: List[bytes] = []

        for pkt in packets:
            data = pkt.to_dict() if hasattr(pkt, "to_dict") else pkt
            if isinstance(data, (bytes, bytearray)):
                raw_frames.append(bytes(data))
                continue

            raw_hex = data.get("raw_hex")
            if raw_hex:
                try:
                    raw_frames.append(bytes.fromhex(raw_hex))
                    continue
                except ValueError:
                    pass

            # Synthesize standard Ethernet + IPv4 + UDP/TCP frame from metadata
            frame = cls._synthesize_ethernet_frame(data)
            raw_frames.append(frame)

        # Write libpcap header and frames to in-memory buffer
        buffer = io.BytesIO()
        buffer.write(PcapExporter.GLOBAL_HEADER)
        now_sec = int(datetime.now(timezone.utc).timestamp())

        for frame in raw_frames:
            length = len(frame)
            pkt_hdr = struct.pack("!IIII", now_sec, 0, length, length)
            buffer.write(pkt_hdr)
            buffer.write(frame)

        pcap_bytes = buffer.getvalue()
        if output_path:
            with open(output_path, "wb") as f:
                f.write(pcap_bytes)

        return pcap_bytes

    @staticmethod
    def _synthesize_ethernet_frame(pkt_dict: Dict[str, Any]) -> bytes:
        """Construct a minimal valid Ethernet II + IPv4 + payload frame from metadata."""
        src_str = str(pkt_dict.get("source", "192.168.1.100:50000"))
        dst_str = str(pkt_dict.get("destination", "192.168.1.1:80"))
        src_ip_str = src_str.split(":")[0] if ":" in src_str else src_str
        dst_ip_str = dst_str.split(":")[0] if ":" in dst_str else dst_str

        # Convert IP to 4 bytes or fallback to localhost
        def parse_ip(ip: str) -> bytes:
            try:
                parts = [int(p) for p in ip.split(".")]
                if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
                    return bytes(parts)
            except Exception:
                pass
            return bytes([192, 168, 1, 1])

        src_ip_bytes = parse_ip(src_ip_str)
        dst_ip_bytes = parse_ip(dst_ip_str)

        # Ethernet header (14 bytes)
        eth_hdr = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00])

        proto_name = str(pkt_dict.get("protocol", "TCP")).upper()
        payload = (pkt_dict.get("info") or "PPS Captured Packet").encode("utf-8")
        total_len = 20 + 20 + len(payload)

        # IPv4 header (20 bytes)
        ip_proto = 6 if proto_name == "TCP" else 17
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0x00, total_len, 0x1234, 0x4000, 64, ip_proto, 0x0000,
            src_ip_bytes, dst_ip_bytes
        )

        # Transport header (20 bytes for TCP, 8 bytes for UDP)
        src_port_parsed = int(src_str.split(":")[1]) if ":" in src_str and src_str.split(":")[1].isdigit() else 50000
        dst_port_parsed = int(dst_str.split(":")[1]) if ":" in dst_str and dst_str.split(":")[1].isdigit() else 80
        src_port = int(pkt_dict.get("src_port") or src_port_parsed)
        dst_port = int(pkt_dict.get("dst_port") or dst_port_parsed)

        if ip_proto == 6:
            tcp_hdr = struct.pack(
                "!HHIIBBHHH",
                src_port, dst_port, 1000, 0, (5 << 4), 0x02, 65535, 0, 0
            )
            return eth_hdr + ip_hdr + tcp_hdr + payload
        else:
            udp_len = 8 + len(payload)
            udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
            return eth_hdr + ip_hdr + udp_hdr + payload

    @classmethod
    def export_html_report(
        cls,
        session: Dict[str, Any],
        packets: Optional[List[Dict[str, Any]]] = None,
        alerts: Optional[List[Dict[str, Any]]] = None,
        stats: Optional[Dict[str, Any]] = None,
        zeek_summary: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a complete, self-contained HTML session summary report (FR-9)."""
        session_id = session.get("id", "current-session")
        iface = session.get("interface", {})
        iface_name = iface.get("name") if isinstance(iface, dict) else str(iface)
        started_at = session.get("started_at", "N/A")
        ended_at = session.get("ended_at", "In progress / Current")
        status = session.get("status", "completed")

        packets_list = packets or []
        alerts_list = alerts or []
        analysis = session.get("analysis", {})
        proto_counts = analysis.get("protocol_counts") or (stats.get("protocol_distribution") if stats else {}) or {}
        total_packets = session.get("packet_count", len(packets_list))
        total_bytes = analysis.get("total_bytes") or (stats.get("total_bytes") if stats else 0)


        # Rows for protocol breakdown
        proto_rows = ""
        for proto, count in proto_counts.items():
            pct = round((count / max(1, total_packets)) * 100, 1)
            proto_rows += f"<tr><td><strong>{proto}</strong></td><td>{count}</td><td>{pct}%</td></tr>"
        if not proto_rows:
            proto_rows = "<tr><td colspan='3'>No protocol data recorded.</td></tr>"

        # Rows for alerts
        alert_rows = ""
        for a in alerts_list:
            sev = a.get("severity", "INFO").upper()
            sev_class = "badge-critical" if sev == "CRITICAL" else ("badge-warning" if sev == "WARNING" else "badge-info")
            ts_val = a.get("timestamp", "N/A")
            at_val = a.get("alert_type", "ANOMALY")
            sip_val = a.get("source_ip", "unknown")
            det_val = a.get("details", "")
            alert_rows += f"<tr><td>{ts_val}</td><td><span class='badge {sev_class}'>{sev}</span></td>"
            alert_rows += f"<td><strong>{at_val}</strong></td><td><code>{sip_val}</code></td><td>{det_val}</td></tr>"
        if not alert_rows:
            alert_rows = "<tr><td colspan='5' style='text-align: center; color: #64748b;'>"
            alert_rows += "Zero security anomalies detected during this session. Traffic nominal.</td></tr>"

        # Zeek summary section
        zeek_html = ""
        if zeek_summary:
            c_cnt = zeek_summary.get("total_connections", 0)
            d_cnt = zeek_summary.get("dns_transactions", 0)
            w_cnt = zeek_summary.get("weird_events", 0)
            n_cnt = zeek_summary.get("security_notices", 0)
            zeek_html = f"""<div class="card"><h2>Zeek Analysis Summary (FR-5)</h2><div class="grid">
<div class="metric"><div class="num">{c_cnt}</div><div class="lbl">Connections (conn.log)</div></div>
<div class="metric"><div class="num">{d_cnt}</div><div class="lbl">DNS Lookups (dns.log)</div></div>
<div class="metric"><div class="num">{w_cnt}</div><div class="lbl">Weird Events (weird.log)</div></div>
<div class="metric"><div class="num">{n_cnt}</div><div class="lbl">Notices (notice.log)</div></div>
</div></div>"""

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PPS Session Summary Report - {session_id}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0; padding: 2rem; background: #0b0f19; color: #f1f5f9; line-height: 1.5;
    }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{ border-bottom: 2px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }}
    h1 {{ margin: 0 0 0.5rem 0; color: #38bdf8; font-size: 1.8rem; }}
    .subtitle {{ color: #94a3b8; font-size: 0.9rem; margin: 0; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
    .card h2 {{ margin-top: 0; font-size: 1.2rem; color: #f8fafc; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-top: 1rem; }}
    .metric {{ background: #0f172a; padding: 1rem; border-radius: 6px; border: 1px solid #334155; text-align: center; }}
    .metric .num {{ font-size: 1.5rem; font-weight: bold; color: #38bdf8; }}
    .metric .lbl {{ font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; text-transform: uppercase; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }}
    th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: bold; }}
    .badge-critical {{ background: #ef4444; color: #fff; }}
    .badge-warning {{ background: #f59e0b; color: #000; }}
    .badge-info {{ background: #3b82f6; color: #fff; }}
    code {{ background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; color: #e2e8f0; font-family: monospace; }}
    .footer {{ margin-top: 3rem; text-align: center; font-size: 0.8rem; color: #64748b; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Pocket Packet Sniffer — Session Report</h1>
      <p class="subtitle">Session: <strong>{session_id}</strong> | Generated: {generated_at} | Compliance: FR-9, SADS 3.2</p>
    </div>

    <div class="card">
      <h2>Session Metadata</h2>
      <div class="grid">
        <div class="metric"><div class="num">{iface_name}</div><div class="lbl">Capture Interface</div></div>
        <div class="metric"><div class="num">{total_packets}</div><div class="lbl">Total Packets</div></div>
        <div class="metric"><div class="num">{total_bytes} B</div><div class="lbl">Total Volume</div></div>
        <div class="metric"><div class="num">{status.upper()}</div><div class="lbl">Session Status</div></div>
      </div>
      <p style="font-size: 0.85rem; color: #94a3b8; margin-top: 1rem;">
        Started: <strong>{started_at}</strong> &nbsp;|&nbsp; Ended: <strong>{ended_at}</strong>
      </p>
    </div>

    {zeek_html}

    <div class="card">
      <h2>Protocol Breakdown</h2>
      <table>
        <thead><tr><th>Protocol</th><th>Packet Count</th><th>Percentage</th></tr></thead>
        <tbody>{proto_rows}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Security Anomalies & Alerts (FR-10, FR-11)</h2>
      <table>
        <thead><tr><th>Time</th><th>Severity</th><th>Alert Type</th><th>Source</th><th>Details</th></tr></thead>
        <tbody>{alert_rows}</tbody>
      </table>
    </div>

    <div class="footer">
      Generated automatically by Pocket Packet Sniffer (PPS) v1.0 Edge Appliance.
    </div>
  </div>
</body>
</html>"""
        return html
