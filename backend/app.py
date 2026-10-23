"""Flask backend for the Pocket Packet Sniffer (PPS) dashboard.

Serves the static single-page dashboard and JSON API.
Runs entirely locally (offline-first, SRS 2.5). Capture is mocked for now.
Implements:
- SADS 3.4 & FR-11: Centralized error handling and strict input validation
- SEC-REQ-2 & SEC-REQ-6: Authentication with token session & 5-attempt lockout
- SEC-REQ-3: Role-based access control (Field Engineer vs Admin)
"""

from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, abort

try:
    from .mock_capture import MockCaptureService, MOCK_INTERFACES
    from .auth import AuthService
except ImportError:
    from mock_capture import MockCaptureService, MOCK_INTERFACES
    from auth import AuthService

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

app = Flask(__name__, static_folder=None)
capture = MockCaptureService()
auth_service = AuthService()

# Disallowed characters for safe BPF filter tokens to prevent injection
DISALLOWED_FILTER_CHARS = set(";&|`$><!\\")


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
        # Optionally set cookie for browser-friendly session
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


# --- Status & Capture Controls with Input Validation (Issue #8) ---

@app.route("/api/status")
def api_status():
    """Current interface + capture status (consumed by the dashboard header)."""
    return jsonify(capture.get_status())


@app.post("/api/capture/start")
def start_capture():
    """Start capture with input validation on interface and filters (FR-4, FR-7, SADS 3.2.1)."""
    data = request.get_json(silent=True) or {}

    # Validate interface if provided
    selected_iface = data.get("interface")
    if selected_iface:
        if selected_iface not in MOCK_INTERFACES:
            return jsonify({
                "error": f"Invalid interface '{selected_iface}'. Supported: {', '.join(MOCK_INTERFACES.keys())}",
                "error_code": "INVALID_INTERFACE"
            }), 400
        capture._interface = MOCK_INTERFACES[selected_iface]

    # Validate filter expression if provided
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


@app.get("/api/packets")
def api_packets():
    """Return filtered traffic with input validation."""
    filters = {}
    for field in ("protocol", "source", "destination", "search"):
        val = request.args.get(field, "")
        if len(val) > 128:
            return jsonify({
                "error": f"Query filter '{field}' exceeds maximum length of 128 characters",
                "error_code": "FILTER_TOO_LONG"
            }), 400
        filters[field] = val

    return jsonify({
        "packets": capture.get_packets(filters),
        "filters": filters
    })


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
