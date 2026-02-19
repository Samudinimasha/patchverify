"""Scanner orchestration for PatchVerify"""
from .config import C, HISTORY_FILE
from .streamer import init_stream, update_stream, complete_stream
import json
from datetime import datetime
import uuid
import time

def run_scan(app_name, old_version, new_version, github_token=None, skip_probe=False):
    """
    Run a complete scan comparing two versions of an application

    Args:
        app_name: Name of the application
        old_version: Old version number
        new_version: New version number
        github_token: GitHub token for API access
        skip_probe: Whether to skip behavioral probing

    Returns:
        dict: Scan results
    """
    print(f"\n{C.CYAN}{C.BOLD}PatchVerify — Scanning {app_name}{C.RESET}\n")
    print(f"Comparing versions: {C.BOLD}{old_version}{C.RESET} → {C.BOLD}{new_version}{C.RESET}\n")

    scan_id = str(uuid.uuid4())[:8]
    print(f"{C.GRAY}Scan ID: {scan_id}{C.RESET}")

    # Initialize live stream for web dashboard
    init_stream(scan_id, app_name, old_version, new_version)

    # Simulate scan progress (replace with actual scanning logic)
    update_stream(scan_id, status="initializing", progress=10, step="Initializing scan")
    time.sleep(0.5)

    update_stream(scan_id, status="scanning", progress=30, step="Analyzing vulnerabilities",
                  event=f"Scanning {app_name} {old_version} → {new_version}")
    time.sleep(0.5)

    update_stream(scan_id, status="scanning", progress=60, step="Comparing versions",
                  event="Checking CVE database")
    time.sleep(0.5)

    update_stream(scan_id, status="scanning", progress=90, step="Generating report",
                  event="Calculating risk score")
    time.sleep(0.5)

    # Placeholder scan result
    result = {
        "scan_id": scan_id,
        "app": app_name,
        "old_version": old_version,
        "new_version": new_version,
        "started": datetime.now().isoformat(),
        "fixed": 0,
        "not_fixed": 0,
        "total": 0,
        "unconfirmed": 0,
        "risk_score": 0,
        "risk_label": "NONE"
    }

    # Complete the stream
    complete_stream(scan_id, result)

    # Save to history
    _save_to_history(result)

    print(f"{C.YELLOW}[*] Scan functionality not yet implemented{C.RESET}\n")
    print(f"{C.GREEN}✓ Scan complete! View at: http://localhost:8080{C.RESET}\n")

    return result

def _save_to_history(result):
    """Save scan result to history file"""
    history = []
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE) as f:
            history = json.load(f)

    history.insert(0, result)  # Add to beginning
    history = history[:100]  # Keep last 100 scans

    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)
