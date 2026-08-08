"""SentinelOS backend API.

Endpoints:
    POST /api/scan            - run all scanners, analyze, persist, return report
    POST /api/scan/av         - run only the antivirus scanners (file + YARA), persist, return report
    GET  /api/scans            - list past scan summaries
    GET  /api/scans/<id>       - fetch a full stored report
    GET  /api/scans/<id>/pdf   - download the report as a PDF
    GET  /api/monitor          - background monitor status
    GET  /api/realtime/status  - real-time protection status
    GET  /api/realtime/events  - recent real-time detection events
    GET  /api/quarantine       - list quarantined files
    POST /api/quarantine/<id>/restore - restore a quarantined file
    DELETE /api/quarantine/<id>       - permanently delete a quarantined file
    GET  /api/network/status   - network threat detection status
    GET  /api/network/events   - recent network threat detection events
    GET  /api/reputation       - file reputation entries, worst risk first
    GET  /api/reputation/<hash> - reputation for a single SHA256 hash
"""
import hmac
import os

from flask import Flask, jsonify, request, send_file

from reports.pdf import generate_pdf_report
from database import db
import monitor
import network_threat_detection
import realtime_protection
import scan_service

app = Flask(__name__)

try:
    from flask_cors import CORS
    # Restrict to known frontend origin(s) - a bare CORS(app) sends
    # Access-Control-Allow-Origin: * on every response, which lets any
    # website open in the browser call this API from JS and read the
    # results (system processes/users/permissions) with no interaction.
    _allowed_origins = [
        o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()
    ]
    CORS(app, resources={r"/api/*": {"origins": _allowed_origins}})
except ImportError:
    pass  # fine for same-origin use; `pip install flask-cors` to enable cross-origin requests

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports", "generated")
os.makedirs(REPORTS_DIR, exist_ok=True)

if not os.environ.get("API_KEY"):
    print(
        "WARNING: API_KEY is not set - all /api/* endpoints are unauthenticated. "
        "Set API_KEY (and REACT_APP_API_KEY for the frontend) to require a key.",
    )


@app.before_request
def _enforce_api_key():
    # Read fresh per-request (not cached at import time) so it reflects the
    # current environment rather than whatever it was when the module loaded.
    expected_key = os.environ.get("API_KEY")
    if not expected_key:
        return None  # auth disabled - see startup warning

    # Preflight requests don't (and can't) carry custom headers, and the
    # health check is deliberately public so monitoring doesn't need a key.
    if request.method == "OPTIONS" or request.path == "/api/health":
        return None

    provided_key = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(provided_key, expected_key):
        return jsonify({"error": "unauthorized"}), 401
    return None


@app.before_request
def _ensure_db():
    if not os.path.exists(db.DB_PATH):
        db.init_db()
    else:
        # Patches an already-existing scans.db up to the current schema
        # (e.g. a scan_type column added after the file was first created).
        db.migrate()


@app.route("/api/scan", methods=["POST"])
def run_scan():
    return jsonify(scan_service.run_and_persist_scan())


@app.route("/api/scan/av", methods=["POST"])
def run_av_scan():
    return jsonify(scan_service.run_and_persist_av_scan())


@app.route("/api/scans", methods=["GET"])
def list_scans():
    return jsonify(db.list_scans())


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    report = db.get_scan(scan_id)
    if report is None:
        return jsonify({"error": "scan not found"}), 404
    return jsonify(report)


@app.route("/api/scans/<int:scan_id>/pdf", methods=["GET"])
def get_scan_pdf(scan_id):
    report = db.get_scan(scan_id)
    if report is None:
        return jsonify({"error": "scan not found"}), 404

    output_path = os.path.join(REPORTS_DIR, f"scan_{scan_id}.pdf")
    actual_path = generate_pdf_report(report, output_path)
    return send_file(actual_path, as_attachment=True)


@app.route("/api/monitor", methods=["GET"])
def monitor_status():
    return jsonify(monitor.status())


@app.route("/api/realtime/status", methods=["GET"])
def realtime_status():
    return jsonify(realtime_protection.status())


@app.route("/api/realtime/events", methods=["GET"])
def realtime_events():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(db.list_realtime_events(limit=limit))


@app.route("/api/quarantine", methods=["GET"])
def list_quarantine():
    status_filter = request.args.get("status")
    return jsonify(db.list_quarantine(status=status_filter))


@app.route("/api/quarantine/<int:item_id>/restore", methods=["POST"])
def restore_quarantine(item_id):
    try:
        item = realtime_protection.restore_quarantine_item(item_id)
    except (ValueError, FileExistsError) as exc:
        return jsonify({"error": str(exc)}), 409
    if item is None:
        return jsonify({"error": "quarantine item not found"}), 404
    return jsonify(item)


@app.route("/api/quarantine/<int:item_id>", methods=["DELETE"])
def delete_quarantine(item_id):
    try:
        item = realtime_protection.delete_quarantine_item(item_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409
    if item is None:
        return jsonify({"error": "quarantine item not found"}), 404
    return jsonify(item)


@app.route("/api/network/status", methods=["GET"])
def network_threat_status():
    return jsonify(network_threat_detection.status())


@app.route("/api/network/events", methods=["GET"])
def network_threat_events():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(db.list_network_threat_events(limit=limit))


@app.route("/api/reputation", methods=["GET"])
def list_reputation():
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(db.list_file_reputation(limit=limit))


@app.route("/api/reputation/<hash_>", methods=["GET"])
def get_reputation(hash_):
    entry = db.get_file_reputation(hash_)
    if entry is None:
        return jsonify({"error": "no reputation on file for this hash"}), 404
    return jsonify(entry)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    db.init_db()
    monitor.start()
    realtime_protection.start()
    network_threat_detection.start()
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=debug)
