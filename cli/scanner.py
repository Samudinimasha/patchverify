"""Scanner orchestration for PatchVerify"""
from .config import C, HISTORY_FILE
from .streamer import init_stream, update_stream, complete_stream
import sys
import json
from datetime import datetime
import uuid
import time

# Import CVE module from parent directory (works on Windows and Unix)
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cve import query_nvd, query_osv, check_version_fixed, detect_ecosystem

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
    print(f"{C.GRAY}Scan ID: {scan_id}{C.RESET}\n")

    # Initialize live stream for web dashboard
    init_stream(scan_id, app_name, old_version, new_version)

    # Step 1: Detect ecosystem
    update_stream(scan_id, status="initializing", progress=10, step="Detecting ecosystem")
    print(f"{C.CYAN}[1/4] Detecting ecosystem...{C.RESET}")
    ecosystem = detect_ecosystem(app_name)
    if ecosystem:
        print(f"  {C.GREEN}✓ Detected: {ecosystem}{C.RESET}")
        update_stream(scan_id, event=f"Detected {app_name} in {ecosystem} ecosystem")
    else:
        print(f"  {C.YELLOW}⚠ Could not detect ecosystem, using NVD only{C.RESET}")
        update_stream(scan_id, event=f"Unknown ecosystem, using NVD database")

    time.sleep(0.5)

    # Step 2: Query CVE databases for old version
    update_stream(scan_id, status="scanning", progress=30, step=f"Querying CVEs for {old_version}")
    print(f"\n{C.CYAN}[2/4] Querying CVE databases for version {old_version}...{C.RESET}")

    old_cves = []
    # Query NVD
    nvd_cves = query_nvd(app_name, old_version)
    old_cves.extend(nvd_cves)
    print(f"  {C.GRAY}Found {len(nvd_cves)} CVEs from NVD{C.RESET}")

    # Query OSV if ecosystem detected
    if ecosystem:
        osv_cves = query_osv(app_name, old_version, ecosystem)
        old_cves.extend(osv_cves)
        print(f"  {C.GRAY}Found {len(osv_cves)} CVEs from OSV.dev{C.RESET}")

    print(f"  {C.BOLD}Total CVEs affecting {old_version}: {len(old_cves)}{C.RESET}")
    update_stream(scan_id, event=f"Found {len(old_cves)} CVEs in version {old_version}")

    time.sleep(0.5)

    # Step 3: Check which CVEs were fixed in new version
    update_stream(scan_id, status="scanning", progress=60, step=f"Analyzing fixes in {new_version}")
    print(f"\n{C.CYAN}[3/4] Checking if CVEs were fixed in version {new_version}...{C.RESET}")

    fixed_count = 0
    not_fixed_count = 0
    unconfirmed_count = 0
    cve_details = []

    for cve in old_cves:
        check_result = check_version_fixed(cve, new_version)

        cve_details.append({
            "id": cve["id"],
            "severity": cve["severity"],
            "score": cve["score"],
            "description": cve["description"],
            "fixed": check_result["fixed"],
            "method": check_result["method"],
            "detail": check_result["detail"]
        })

        if check_result["fixed"] is True:
            fixed_count += 1
        elif check_result["fixed"] is False:
            not_fixed_count += 1
        else:
            unconfirmed_count += 1

    print(f"  {C.GREEN}✓ Fixed: {fixed_count}{C.RESET}")
    print(f"  {C.RED}✗ Not Fixed: {not_fixed_count}{C.RESET}")
    print(f"  {C.YELLOW}? Unconfirmed: {unconfirmed_count}{C.RESET}")

    update_stream(scan_id, event=f"Analysis complete: {fixed_count} fixed, {not_fixed_count} not fixed")

    time.sleep(0.5)

    # Step 4: Calculate risk score
    update_stream(scan_id, status="scanning", progress=90, step="Calculating risk score")
    print(f"\n{C.CYAN}[4/4] Calculating risk score...{C.RESET}")

    # Calculate weighted risk score
    total_score = 0
    max_possible = 0
    for cve in old_cves:
        if cve["score"]:
            try:
                score_val = float(cve["score"])
                max_possible += 10
                if not check_version_fixed(cve, new_version)["fixed"]:
                    total_score += score_val
            except (ValueError, TypeError):
                # Skip non-numeric scores (CVSS vectors)
                pass

    # Normalize to 0-100
    risk_score = 0
    if max_possible > 0:
        risk_score = min(100, int((total_score / max_possible) * 100))

    # Determine risk label
    if risk_score >= 80:
        risk_label = "CRITICAL"
    elif risk_score >= 60:
        risk_label = "HIGH"
    elif risk_score >= 40:
        risk_label = "MEDIUM"
    elif risk_score >= 20:
        risk_label = "LOW"
    else:
        risk_label = "NONE"

    risk_color = {
        "CRITICAL": C.RED,
        "HIGH": C.ORANGE,
        "MEDIUM": C.YELLOW,
        "LOW": C.GREEN,
        "NONE": C.GRAY
    }.get(risk_label, C.GRAY)

    print(f"  {C.BOLD}Risk Score: {risk_color}{risk_score}/100{C.RESET}")
    print(f"  {C.BOLD}Risk Level: {risk_color}{risk_label}{C.RESET}")

    # Scan result
    result = {
        "scan_id": scan_id,
        "app": app_name,
        "old_version": old_version,
        "new_version": new_version,
        "started": datetime.now().isoformat(),
        "fixed": fixed_count,
        "not_fixed": not_fixed_count,
        "total": len(old_cves),
        "unconfirmed": unconfirmed_count,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "cve_details": cve_details,
        "ecosystem": ecosystem or "Unknown"
    }

    # Complete the stream
    complete_stream(scan_id, result)

    # Save to history
    _save_to_history(result)

    print(f"\n{C.GREEN}{'='*60}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}✓ Scan Complete!{C.RESET}")
    print(f"{C.GREEN}{'='*60}{C.RESET}")
    print(f"\n  {C.BOLD}View full report at: {C.CYAN}http://localhost:8080{C.RESET}\n")

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