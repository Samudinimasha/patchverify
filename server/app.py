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

def run_server():
    """Start the Flask web server"""
    print(f"\n{C.CYAN}{C.BOLD}PatchVerify — Web Dashboard{C.RESET}\n")
    print(f"Starting server at {C.BOLD}http://localhost:5000{C.RESET}")
    print(f"\n{C.GRAY}Press Ctrl+C to stop{C.RESET}\n")

    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    run_server()