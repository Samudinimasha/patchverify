"""Flask web server for PatchVerify dashboard"""
from flask import Flask, jsonify, send_from_directory
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

    # Reduce Flask logging verbosity
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    print(f"\n{C.CYAN}{C.BOLD}╔═══════════════════════════════════════╗{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}║   PatchVerify Web Dashboard          ║{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}╚═══════════════════════════════════════╝{C.RESET}\n")
    print(f"  🌐 Dashboard: {C.BOLD}http://localhost:8080{C.RESET}")
    print(f"  🔒 Secure:    {C.BOLD}https://localhost:8443{C.RESET}")
    print(f"\n  {C.GREEN}✓ Server running{C.RESET}")
    print(f"  {C.GRAY}Press Ctrl+C to stop{C.RESET}\n")
    print(f"{C.GRAY}{'─'*45}{C.RESET}\n")

    # Try HTTPS with self-signed certificate
    try:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Generate adhoc certificate
        app.run(host='0.0.0.0', port=8443, debug=False, ssl_context='adhoc')
    except Exception as e:
        # Fallback to HTTP if HTTPS fails
        print(f"{C.YELLOW}HTTPS failed, using HTTP instead{C.RESET}\n")
        app.run(host='0.0.0.0', port=8080, debug=False)

if __name__ == '__main__':
    run_server()