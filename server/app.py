"""Flask web server for PatchVerify dashboard"""
from flask import Flask, jsonify, send_from_directory, request
import json
from cli.config import C, HISTORY_FILE
from cli.streamer import STREAM_FILE

app = Flask(__name__,
            template_folder='../web',
            static_folder='../web')

@app.route('/')
def index():
    """Main dashboard page"""
    return send_from_directory('../web', 'dashboard.html')

@app.route('/login')
def login():
    """Login page"""
    return send_from_directory('../web', 'login.html')

@app.route('/api/stream')
def get_stream():
    """Get current scan stream data"""
    if STREAM_FILE.exists():
        with open(STREAM_FILE) as f:
            return jsonify(json.load(f))
    return jsonify({"status": "no_active_scan"})

@app.route('/api/history')
def get_history():
    """Get scan history"""
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE) as f:
            history = json.load(f)
            return jsonify(history[:20])  # Return last 20 scans
    return jsonify([])

@app.route('/api/stats')
def get_stats():
    """Get overall statistics"""
    if not HISTORY_FILE.exists():
        return jsonify({
            "total_scans": 0,
            "critical_findings": 0,
            "total_fixed": 0,
            "total_vulnerabilities": 0
        })

    with open(HISTORY_FILE) as f:
        history = json.load(f)

    stats = {
        "total_scans": len(history),
        "critical_findings": sum(1 for h in history if h.get('risk_label') in ['CRITICAL', 'HIGH']),
        "total_fixed": sum(h.get('fixed', 0) for h in history),
        "total_vulnerabilities": sum(h.get('total', 0) for h in history)
    }

    return jsonify(stats)

@app.route('/api/profile')
def get_profile():
    """Get registered device profile"""
    try:
        from cli.config import load_config
        config = load_config()
        return jsonify({
            "email":           config.get("email", "Not configured"),
            "device_id":       config.get("device_id", ""),
            "registered":      config.get("registered", ""),
            "smtp_configured": bool(config.get("smtp", {}).get("host")),
            "smtp_host":       config.get("smtp", {}).get("host", "Not configured"),
        })
    except Exception:
        return jsonify({"email": "Not configured", "device_id": "", "smtp_configured": False})


@app.route('/api/profile', methods=['DELETE'])
def delete_account():
    """Delete registered account and all scan history"""
    try:
        from cli.config import CONFIG_FILE, CONFIG_DIR
        import shutil
        # Remove config file
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
        # Remove scan history
        if HISTORY_FILE.exists():
            HISTORY_FILE.unlink()
        # Remove stream file
        if STREAM_FILE.exists():
            STREAM_FILE.unlink()
        return jsonify({"status": "deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/<scan_id>')
def get_scan_details(scan_id):
    """Get detailed information for a specific scan"""
    if not HISTORY_FILE.exists():
        return jsonify({"error": "No scan history"}), 404

    with open(HISTORY_FILE) as f:
        history = json.load(f)

    # Find scan by ID
    scan = next((s for s in history if s.get('scan_id') == scan_id), None)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify(scan)

def run_server():
    """Start the Flask web server"""
    import logging

    # Suppress all werkzeug output including bad-request noise
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    logging.getLogger('werkzeug').addFilter(
        type('_BadReq', (logging.Filter,), {
            'filter': staticmethod(lambda r: 'Bad' not in r.getMessage())
        })()
    )

    print(f"\n{C.CYAN}{C.BOLD}╔═══════════════════════════════════════╗{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}║   PatchVerify Web Dashboard          ║{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}╚═══════════════════════════════════════╝{C.RESET}\n")
    print(f"  🌐 Dashboard: {C.BOLD}http://localhost:8080{C.RESET}")
    print(f"\n  {C.GREEN}✓ Server running{C.RESET}")
    print(f"  {C.GRAY}Press Ctrl+C to stop{C.RESET}\n")
    print(f"{C.GRAY}{'─'*45}{C.RESET}\n")

    app.run(host='0.0.0.0', port=8080, debug=False)

if __name__ == '__main__':
    run_server()