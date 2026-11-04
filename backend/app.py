"""Flask backend for the Pocket Packet Sniffer (PPS) dashboard.

Serves the static single-page dashboard and JSON API.
Runs entirely locally (offline-first, SRS 2.5). Capture is modularized.
Implements:
- SADS 2.2 & Issue #1: Modular architecture across capture, processing, backend, storage.
- FR-02, NFR-02 & Issue #4: Interface detection and selection (GET /api/interfaces, POST /api/interfaces/select).
- FR-04 & Issue #6: Packet metadata extraction, protocol dissection, and error handling.
- FR-05, FR-6 & Issue #7: Live statistics snapshot (GET /api/capture/stats) & traffic metrics.
- SADS 3.4 & FR-11: Centralized error handling and strict input validation.
- SEC-REQ-2 & SEC-REQ-6: Authentication with token session & 5-attempt lockout.
- SEC-REQ-3: Role-based access control (Field Engineer vs Admin).
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from copy import deepcopy
from typing import Any
from flask import Flask, jsonify, request, send_from_directory, g, Response

try:
    from .mock_capture import MockCaptureService, MOCK_INTERFACES
    from .auth import AuthService
except ImportError:
    from mock_capture import MockCaptureService, MOCK_INTERFACES
    from auth import AuthService

# Import processing and storage modules (Issue #1, Issue #6)
import sys
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from processing.parser import PacketParser
from processing.metadata import MetadataExtractor
from storage.exporter import AnalysisExporter

FRONTEND_DIR = ROOT_DIR / "frontend"

app = Flask(__name__, static_folder=None)
capture = MockCaptureService()
auth_service = AuthService()
packet_parser = PacketParser()

# Disallowed characters for safe BPF filter tokens to prevent injection
DISALLOWED_FILTER_CHARS = set(";&|`$><!\\")


@app.before_request
def record_start_time():
    g.start_time = time.time()


@app.after_request
def track_response_latency(response):
    if hasattr(g, "start_time"):
        latency_ms = round((time.time() - g.start_time) * 1000, 2)
        capture.record_latency(latency_ms)
    return response


def get_current_user():
    """Extract authenticated user from Authorization header or cookie."""
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "session_token" in request.cookies:
        token = request.cookies.get("session_token")
    if token:
        return auth_service.validate_session(token)
    return None


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


# --- Authentication & RBAC Routes (Issue #14) ---

@app.post("/api/auth/login")
def api_login():
    """Authenticate user with credentials (SEC-REQ-2, SEC-REQ-6)."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    try:
        result = auth_service.authenticate(username, password)
        resp = jsonify({
            "message": "Login successful",
            "token": result["token"],
            "user": result["user"],
        })
        resp.set_cookie("session_token", result["token"], httponly=True, samesite="Lax")
        return resp, 200
    except PermissionError as e:
        return jsonify({"error": str(e), "error_code": "AUTH_LOCKED"}), 423
    except ValueError as e:
        return jsonify({"error": str(e), "error_code": "AUTH_FAILED"}), 401


@app.post("/api/auth/logout")
def api_logout():
    """Invalidate session token."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.cookies.get("session_token", "")
    auth_service.logout(token)
    resp = jsonify({"message": "Logged out successfully"})
    resp.delete_cookie("session_token")
    return resp, 200


@app.get("/api/auth/me")
def api_current_user():
    """Get active session details."""
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False, "user": None}), 200
    return jsonify({"authenticated": True, "user": user}), 200


@app.get("/api/admin/system")
def api_admin_system():
    """Admin-only endpoint verifying RBAC boundaries (SEC-REQ-3)."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required", "error_code": "UNAUTHORIZED"}), 401
    if user.get("role") != "admin":
        return jsonify({"error": "Admin role required to access system settings", "error_code": "FORBIDDEN"}), 403
    return jsonify({
        "status": "ok",
        "system_version": "PPS-1.0-Sprint1",
        "storage_mode": "mock_encrypted_sqlite",
        "retention_days": 14,
    }), 200


# --- Status, Interface & Capture Controls (Issues #4, #7, #8) ---

@app.get("/api/interfaces")
def api_interfaces():
    """List available capture interfaces (WiFi/Ethernet/BLE) (FR-1, FR-2, FR-3, SADS 3.2)."""
    return jsonify({
        "interfaces": capture.get_interfaces(),
        "selected": capture._interface.get("name", "wlan0"),
    }), 200


@app.post("/api/interfaces/select")
def api_select_interface():
    """Select active capture interface prior to starting capture (FR-02, NFR-02)."""
    data = request.get_json(silent=True) or {}
    iface = data.get("interface", "").strip()
    if not iface:
        return jsonify({
            "error": "Field 'interface' is required",
            "error_code": "MISSING_INTERFACE"
        }), 400

    try:
        updated = capture.select_interface(iface)
        return jsonify({
            "message": f"Selected interface '{iface}'",
            "interface": updated
        }), 200
    except ValueError as exc:
        return jsonify({"error": str(exc), "error_code": "INVALID_INTERFACE"}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc), "error_code": "CONFLICT"}), 409


@app.route("/api/status")
def api_status():
    """Current interface + capture status (consumed by the dashboard header)."""
    return jsonify(capture.get_status())


# --- Capture Controls with Input Validation (Issue #8, FR-4, FR-7) ---

@app.post("/api/capture/start")
def start_capture():
    """Start capture with input validation on interface and filters (FR-4, FR-7, SADS 3.2.1)."""
    data = request.get_json(silent=True) or {}

    selected_iface = data.get("interface")
    if selected_iface:
        if selected_iface not in MOCK_INTERFACES:
            return jsonify({
                "error": f"Invalid interface '{selected_iface}'. Supported: {', '.join(MOCK_INTERFACES.keys())}",
                "error_code": "INVALID_INTERFACE"
            }), 400
        capture._interface = deepcopy(MOCK_INTERFACES[selected_iface])

    filter_expr = data.get("filter")
    if filter_expr:
        if len(filter_expr) > 256:
            return jsonify({
                "error": "Filter expression exceeds maximum length of 256 characters",
                "error_code": "FILTER_TOO_LONG"
            }), 400
        if any(char in filter_expr for char in DISALLOWED_FILTER_CHARS):
            return jsonify({
                "error": "Filter expression contains disallowed characters",
                "error_code": "MALFORMED_FILTER"
            }), 400

    try:
        return jsonify(capture.start()), 200
    except RuntimeError as exc:
        return jsonify({"error": str(exc), "error_code": "CONFLICT"}), 409


@app.post("/api/capture/stop")
def stop_capture():
    """Stop active capture session."""
    try:
        return jsonify(capture.stop()), 200
    except RuntimeError as exc:
        return jsonify({"error": str(exc), "error_code": "CONFLICT"}), 409


# --- Packet Processing & Metadata Extraction (Issue #6, FR-04, FR-6) ---

@app.get("/api/capture/stats")
def api_capture_stats():
    """Retrieve current session statistics snapshot (FR-6, SADS 3.2)."""
    stats = capture.get_statistics()
    return jsonify(stats), 200


@app.get("/api/packets")
def api_packets():
    """Return filtered traffic with extracted metadata."""
    filters = {}
    for field in ("protocol", "source", "destination", "search"):
        val = request.args.get(field, "")
        if len(val) > 128:
            return jsonify({
                "error": f"Query filter '{field}' exceeds maximum length of 128 characters",
                "error_code": "FILTER_TOO_LONG"
            }), 400
        filters[field] = val

    packets = capture.get_packets(filters)
    return jsonify({
        "packets": packets,
        "filters": filters,
        "count": len(packets),
    }), 200


@app.post("/api/packets/process")
def api_process_packet():
    """Process a raw packet (hex string) or packet dictionary and extract metadata (Issue #6, FR-04).

    Request Body:
        {"hex": "...", "link_type": "ethernet|wifi|ble", "interface": "eth0"}
        or
        {"packet": {"protocol": "TCP", "source": "...", ...}}
    """
    data = request.get_json(silent=True) or {}

    if "hex" in data:
        hex_data = data.get("hex", "").strip()
        link_type = data.get("link_type", "ethernet")
        iface = data.get("interface", capture._interface["name"])
        try:
            raw_bytes = bytes.fromhex(hex_data)
        except ValueError:
            return jsonify({
                "error": "Invalid hex payload format",
                "error_code": "MALFORMED_HEX"
            }), 400

        metadata = packet_parser.parse_raw(raw_bytes, link_type=link_type, interface=iface)
        capture.add_packet(metadata)
        return jsonify({
            "status": "processed",
            "metadata": metadata.to_dict()
        }), 201

    elif "packet" in data:
        raw_dict = data.get("packet")
        if not isinstance(raw_dict, dict):
            return jsonify({
                "error": "Packet must be a valid JSON dictionary",
                "error_code": "INVALID_PACKET_FORMAT"
            }), 400
        metadata = MetadataExtractor.normalize(raw_dict)
        capture.add_packet(metadata)
        return jsonify({
            "status": "processed",
            "metadata": metadata.to_dict()
        }), 201

    return jsonify({
        "error": "Request body must contain 'hex' string or 'packet' object",
        "error_code": "MISSING_PAYLOAD"
    }), 400


# --- Security Alerts & Observations (Issue #11, FR-08, SADS 3.3) ---

@app.get("/api/alerts")
def api_alerts():
    """Return security alerts and analysis observations (FR-08, SADS 3.3)."""
    severity = request.args.get("severity", "").strip()
    search = request.args.get("search", "").strip()
    if len(severity) > 64 or len(search) > 128:
        return jsonify({
            "error": "Filter parameter exceeds allowable length",
            "error_code": "FILTER_TOO_LONG"
        }), 400

    alerts = capture.get_alerts(severity=severity if severity else None, search=search if search else None)
    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
        "filter": {"severity": severity, "search": search},
    }), 200


@app.post("/api/alerts")
def api_create_alert():
    """Record an analysis alert or security observation (FR-08, SADS 3.3)."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({
            "error": "Request body must be a JSON dictionary",
            "error_code": "MISSING_PAYLOAD"
        }), 400

    alert_type = data.get("alert_type", "").strip()
    if not alert_type:
        return jsonify({
            "error": "Field 'alert_type' is required",
            "error_code": "MISSING_ALERT_TYPE"
        }), 400

    if len(alert_type) > 64:
        return jsonify({
            "error": "Field 'alert_type' exceeds maximum length of 64 characters",
            "error_code": "FIELD_TOO_LONG"
        }), 400

    severity = data.get("severity", "INFO").strip().upper()
    valid_severities = {"CRITICAL", "WARNING", "INFO"}
    if severity not in valid_severities:
        return jsonify({
            "error": f"Invalid severity '{severity}'. Supported: {', '.join(sorted(valid_severities))}",
            "error_code": "INVALID_SEVERITY"
        }), 400

    details = data.get("details", "")
    if len(details) > 512:
        return jsonify({
            "error": "Field 'details' exceeds maximum length of 512 characters",
            "error_code": "FIELD_TOO_LONG"
        }), 400

    source_ip = data.get("source_ip", "")
    if len(source_ip) > 45:
        return jsonify({
            "error": "Field 'source_ip' exceeds maximum IPv4/IPv6 length of 45 characters",
            "error_code": "FIELD_TOO_LONG"
        }), 400

    created = capture.add_alert(data)
    return jsonify({
        "status": "created",
        "alert": created
    }), 201


# --- Performance & Resource Telemetry (Issue #15, NFR-01, NFR-07) ---

@app.get("/api/system/performance")
def api_system_performance():
    """Return dashboard response times, CPU, memory, and storage telemetry (NFR-01, NFR-07)."""
    metrics = capture.get_performance_metrics()
    return jsonify(metrics), 200


# --- Centralized Structured Error Handlers (SADS 3.4 & Issue #8) ---

@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({"error": getattr(e, "description", "Bad Request"), "error_code": "BAD_REQUEST"}), 400


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({"error": "Resource not found", "error_code": "NOT_FOUND"}), 404


@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({"error": "HTTP method not allowed", "error_code": "METHOD_NOT_ALLOWED"}), 405


@app.errorhandler(500)
def handle_server_error(e):
    return jsonify({"error": "Internal server error occurred", "error_code": "INTERNAL_ERROR"}), 500


@app.get("/api/sessions")
def api_sessions():
    """Return capture history, including analysis summaries for each session."""
    return jsonify({"sessions": capture.get_sessions()})


@app.get("/api/sessions/<session_id>")
def api_session(session_id):
    session = capture.get_session(session_id)
    if session is None:
        return jsonify({"error": "Capture session not found"}), 404
    return jsonify({"session": session})

# --- Zeek Analysis Engine Endpoints (Issue #9, FR-07/FR-5, SADS 2.2, 3.1) ---

@app.get("/api/zeek/logs")
def api_zeek_logs():
    """Retrieve structured Zeek analysis logs (conn.log, dns.log, weird.log, notice.log) (FR-5)."""
    log_type = request.args.get("type") or request.args.get("log_type", "all")
    log_type = log_type.strip().lower()
    valid_types = {"conn", "dns", "weird", "notice", "all"}
    if log_type not in valid_types:
        return jsonify({
            "error": f"Invalid Zeek log type '{log_type}'. Supported: {', '.join(sorted(valid_types))}",
            "error_code": "INVALID_LOG_TYPE"
        }), 400

    limit_str = request.args.get("limit", "100")
    try:
        limit = min(500, max(1, int(limit_str)))
    except ValueError:
        return jsonify({
            "error": "Parameter 'limit' must be a valid integer",
            "error_code": "INVALID_LIMIT"
        }), 400

    search = request.args.get("search", "").strip().lower()
    try:
        logs = capture.get_zeek_logs(log_type=log_type, limit=limit)
    except ValueError as e:
        return jsonify({"error": str(e), "error_code": "INVALID_LOG_TYPE"}), 400

    if search:
        logs = [
            item for item in logs
            if any(search in str(v).lower() for v in item.values())
        ]

    return jsonify({
        "log_type": log_type,
        "count": len(logs),
        "logs": logs,
    }), 200


@app.get("/api/zeek/stats")
def api_zeek_stats():
    """Retrieve summary statistics for Zeek protocol analysis and anomaly detection (FR-5, FR-10)."""
    stats = capture.get_zeek_summary()
    return jsonify({
        "status": "active",
        "zeek_summary": stats,
    }), 200


@app.post("/api/zeek/analyze")
def api_zeek_analyze():
    """Trigger on-demand Zeek analysis on a packet, batch, or session (FR-5, SADS 3.4)."""
    data = request.get_json(silent=True) or {}
    results = []

    if "packet" in data:
        pkt = data.get("packet")
        if not isinstance(pkt, dict):
            return jsonify({
                "error": "Field 'packet' must be a valid dictionary",
                "error_code": "INVALID_PACKET_FORMAT"
            }), 400
        event = capture.zeek_engine.process_packet(pkt)
        results.append(event)
    elif "packets" in data:
        pkts = data.get("packets")
        if not isinstance(pkts, list):
            return jsonify({
                "error": "Field 'packets' must be a valid list",
                "error_code": "INVALID_PACKET_LIST"
            }), 400
        for p in pkts:
            if isinstance(p, dict):
                results.append(capture.zeek_engine.process_packet(p))
    else:
        # Run Zeek analysis across all currently captured packets
        all_packets = capture.get_packets()
        for p in all_packets:
            results.append(capture.zeek_engine.process_packet(p))

    return jsonify({
        "status": "analyzed",
        "processed_count": len(results),
        "zeek_summary": capture.get_zeek_summary(),
    }), 200


# --- Export & Reporting Endpoints (Issue #13, FR-10 / FR-8 / FR-9, SADS 3.2) ---

@app.get("/api/export")
def api_export():
    """Export selected packet metadata or analysis results in supported formats (FR-10).

    Query Parameters:
        format: json | csv | pcap | html (default: json)
        data_type: packets | analysis | alerts | zeek | all (default: packets)
        session_id: optional capture session ID
        protocol: optional filter (for packets)
        severity: optional filter (for alerts)
    """
    fmt = request.args.get("format", "json").strip().lower()
    valid_formats = AnalysisExporter.SUPPORTED_FORMATS
    if fmt not in valid_formats:
        return jsonify({
            "error": f"Invalid export format '{fmt}'. Supported: {', '.join(sorted(valid_formats))}",
            "error_code": "INVALID_EXPORT_FORMAT"
        }), 400

    data_type = request.args.get("data_type", "packets").strip().lower()
    valid_data_types = AnalysisExporter.SUPPORTED_DATA_TYPES
    if data_type not in valid_data_types:
        return jsonify({
            "error": f"Invalid data_type '{data_type}'. Supported: {', '.join(sorted(valid_data_types))}",
            "error_code": "INVALID_DATA_TYPE"
        }), 400

    session_id = request.args.get("session_id", "").strip()
    session = None
    if session_id:
        session = capture.get_session(session_id)
        if not session:
            return jsonify({
                "error": f"Capture session '{session_id}' not found",
                "error_code": "NOT_FOUND"
            }), 404

    # Collect relevant data
    protocol_filter = request.args.get("protocol", "").strip().lower()
    severity_filter = request.args.get("severity", "").strip().upper()

    packets = capture.get_packets({"protocol": protocol_filter} if protocol_filter else None)
    alerts = capture.get_alerts(severity=severity_filter if severity_filter else None)
    stats = capture.get_statistics()
    zeek_summary = capture.get_zeek_summary()

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Handle PCAP export
    if fmt == "pcap":
        pcap_bytes = AnalysisExporter.export_pcap(packets)
        filename = f"capture_{session_id or 'live'}_{timestamp_str}.pcap"
        return Response(
            pcap_bytes,
            mimetype="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    # Handle HTML report export
    if fmt == "html":
        report_session = session or {
            "id": "current-session",
            "interface": capture._interface,
            "started_at": capture._started_at,
            "ended_at": None,
            "status": capture._status,
            "packet_count": len(packets),
            "analysis": stats,
        }
        html_content = AnalysisExporter.export_html_report(
            session=report_session,
            packets=packets,
            alerts=alerts,
            stats=stats,
            zeek_summary=zeek_summary,
        )
        filename = f"report_{session_id or 'live'}_{timestamp_str}.html"
        return Response(
            html_content,
            mimetype="text/html; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    # Handle CSV export
    if fmt == "csv":
        if data_type == "packets":
            csv_content = AnalysisExporter.export_csv(packets)
            filename = f"packets_{session_id or 'live'}_{timestamp_str}.csv"
        elif data_type == "alerts":
            csv_content = AnalysisExporter.export_csv(alerts)
            filename = f"alerts_{session_id or 'live'}_{timestamp_str}.csv"
        elif data_type == "zeek":
            zeek_logs = capture.get_zeek_logs()
            csv_content = AnalysisExporter.export_csv(zeek_logs)
            filename = f"zeek_logs_{session_id or 'live'}_{timestamp_str}.csv"
        else:
            # Flatten top talkers / summary
            summary_rows = [
                {"metric": "total_packets", "value": stats.get("total_packets")},
                {"metric": "total_bytes", "value": stats.get("total_bytes")},
                {"metric": "packets_per_second", "value": stats.get("packets_per_second")},
                {"metric": "duration_seconds", "value": stats.get("capture_duration_seconds")},
            ]
            csv_content = AnalysisExporter.export_csv(summary_rows, fieldnames=["metric", "value"])
            filename = f"analysis_{session_id or 'live'}_{timestamp_str}.csv"

        return Response(
            csv_content,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    # Handle JSON export (default)
    payload_to_export: Any = {}
    if data_type == "packets":
        payload_to_export = {"packets": packets, "count": len(packets)}
    elif data_type == "alerts":
        payload_to_export = {"alerts": alerts, "count": len(alerts)}
    elif data_type == "zeek":
        payload_to_export = {
            "zeek_summary": zeek_summary,
            "logs": capture.get_zeek_logs(),
        }
    elif data_type == "analysis":
        payload_to_export = {
            "session": session or "active",
            "statistics": stats,
            "zeek_summary": zeek_summary,
            "alert_count": len(alerts),
        }
    else:  # all
        payload_to_export = {
            "session": session,
            "packets": packets,
            "alerts": alerts,
            "statistics": stats,
            "zeek_summary": zeek_summary,
            "zeek_logs": capture.get_zeek_logs(),
        }

    json_str = AnalysisExporter.export_json(payload_to_export)
    filename = f"export_{data_type}_{session_id or 'live'}_{timestamp_str}.json"
    return Response(
        json_str,
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/api/sessions/<session_id>/export")
def api_session_export(session_id):
    """Download stored session as .pcap, JSON, or CSV (FR-8, SADS 3.2)."""
    session = capture.get_session(session_id)
    if session is None:
        return jsonify({"error": "Capture session not found", "error_code": "NOT_FOUND"}), 404

    fmt = request.args.get("format", "pcap").strip().lower()
    valid_formats = {"pcap", "json", "csv"}
    if fmt not in valid_formats:
        return jsonify({
            "error": f"Invalid format '{fmt}'. Supported: {', '.join(sorted(valid_formats))}",
            "error_code": "INVALID_EXPORT_FORMAT"
        }), 400

    packets = capture.get_packets()
    if fmt == "pcap":
        pcap_bytes = AnalysisExporter.export_pcap(packets)
        return Response(
            pcap_bytes,
            mimetype="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="{session_id}.pcap"'}
        )
    elif fmt == "csv":
        csv_data = AnalysisExporter.export_csv(packets)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{session_id}_packets.csv"'}
        )
    else:
        json_data = AnalysisExporter.export_json({
            "session": session,
            "packets": packets,
        })
        return Response(
            json_data,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{session_id}.json"'}
        )


@app.get("/api/sessions/<session_id>/report")
def api_session_report(session_id):
    """Generate and download human-readable session summary report (FR-9, SADS 3.2)."""
    session = capture.get_session(session_id)
    if session is None:
        return jsonify({"error": "Capture session not found", "error_code": "NOT_FOUND"}), 404

    fmt = request.args.get("format", "html").strip().lower()
    packets = capture.get_packets()
    alerts = capture.get_alerts()
    stats = capture.get_statistics()
    zeek_summary = capture.get_zeek_summary()

    if fmt == "json":
        report_data = {
            "session": session,
            "statistics": stats,
            "alerts": alerts,
            "zeek_summary": zeek_summary,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return Response(
            AnalysisExporter.export_json(report_data),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="report_{session_id}.json"'}
        )

    html_report = AnalysisExporter.export_html_report(
        session=session,
        packets=packets,
        alerts=alerts,
        stats=stats,
        zeek_summary=zeek_summary,
    )
    return Response(
        html_report,
        mimetype="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report_{session_id}.html"'}
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
