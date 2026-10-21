"""Flask backend for the Pocket Packet Sniffer (PPS) dashboard.

Serves the static single-page dashboard and a small JSON API.
Runs entirely locally (offline-first, SRS 2.5). Capture is mocked for now.

Run from the repository root:
    python backend/app.py
Then open http://127.0.0.1:5000
"""

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

try:  # Works both as ``python backend/app.py`` and as an import in tests.
    from .mock_capture import MockCaptureService
except ImportError:
    from mock_capture import MockCaptureService

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

app = Flask(__name__, static_folder=None)
capture = MockCaptureService()


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/api/status")
def api_status():
    """Current interface + capture status (consumed by the dashboard header)."""
    return jsonify(capture.get_status())


@app.post("/api/capture/start")
def start_capture():
    try:
        return jsonify(capture.start())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 409


@app.post("/api/capture/stop")
def stop_capture():
    try:
        return jsonify(capture.stop())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 409


@app.get("/api/packets")
def api_packets():
    filters = {
        field: request.args.get(field, "")
        for field in ("protocol", "source", "destination", "search")
    }
    return jsonify({"packets": capture.get_packets(filters), "filters": filters})


if __name__ == "__main__":
    # host 0.0.0.0 so a phone on the same network can open it later (SRS 3.1).
    app.run(host="0.0.0.0", port=5000, debug=True)
