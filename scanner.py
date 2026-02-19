"""
PatchVerify — main scanner
Orchestrates the full scan: extract → CVE → diff → probe → score → output.
"""
import json
import datetime
import hashlib
import time
import sys

from cli.config       import C, SEVERITY_COLOR, HISTORY_FILE
from cli.streamer     import emit, reset_stream, banner, section, verdict_line
from cli.extractor    import fetch_release_notes, extract_promises
from cli.cve          import query_nvd, query_osv, check_version_fixed, detect_ecosystem
from cli.differ       import diff_versions, file_changed_for_promise
from cli.prober       import run_probe
from cli.scorer       import score_promise, compute_risk_score


def run_scan(app_name: str, old_version: str, new_version: str,
             github_token: str = None, skip_probe: bool = False) -> dict:

    scan_id = hashlib.md5(
        f"{app_name}{old_version}{new_version}{time.time()}".encode()
    ).hexdigest()[:8]
    started = datetime.datetime.utcnow().isoformat()

    reset_stream()
    banner()

    emit(f"  {C.BOLD}Scan ID   :{C.RESET} {scan_id}")
    emit(f"  {C.BOLD}App       :{C.RESET} {app_name}")
    emit(f"  {C.BOLD}Old Ver   :{C.RESET} {old_version}")
    emit(f"  {C.BOLD}New Ver   :{C.RESET} {new_version}")
    emit(f"  {C.BOLD}Started   :{C.RESET} {started}\n")

    # ─────────────────────────────────────────────────────────────────────────
    section("PHASE 1 — PROMISE EXTRACTION")
    # ─────────────────────────────────────────────────────────────────────────

    # Detect ecosystem (PyPI / npm / unknown)
    emit(f"{C.GRAY}[~] Detecting ecosystem for '{app_name}'...{C.RESET}")
    ecosystem = detect_ecosystem(app_name)
    if ecosystem:
        emit(f"{C.GREEN}[✓] Detected ecosystem: {ecosystem}{C.RESET}\n")
    else:
        emit(f"{C.YELLOW}[~] Could not detect ecosystem — will use GitHub + NVD only.{C.RESET}\n")

    # Fetch GitHub release notes
    emit(f"{C.GRAY}[~] Fetching release notes for {app_name} v{new_version} from GitHub...{C.RESET}")
    release_notes = fetch_release_notes(app_name, new_version, github_token)

    # Extract promises from release notes
    promises = []
    if release_notes:
        promises = extract_promises(release_notes, app_name)
        if promises:
            emit(f"{C.GREEN}[✓] Extracted {len(promises)} fix promise(s) from release notes:{C.RESET}\n")
            for p in promises:
                col = C.YELLOW if p["type"] == "cve" else C.CYAN
                emit(f"  {col}• [{p['id']}] {p['description'][:80]}...{C.RESET}")
        else:
            emit(f"{C.YELLOW}[~] Release notes found but no fix promises extracted.{C.RESET}")
    else:
        emit(f"{C.YELLOW}[~] No release notes available — falling back to NVD/OSV only.{C.RESET}")

    emit("")

    # ─────────────────────────────────────────────────────────────────────────
    section("PHASE 2 — CVE LOOKUP")
    # ─────────────────────────────────────────────────────────────────────────

    # Query OSV.dev (most accurate for pip/npm)
    osv_cves = []
    if ecosystem:
        osv_cves = query_osv(app_name, old_version, ecosystem)
        if osv_cves:
            emit(f"{C.GREEN}[✓] OSV.dev: {len(osv_cves)} CVE(s) found for {app_name} v{old_version}{C.RESET}")

    # Query NVD
    nvd_cves = query_nvd(app_name, old_version)
    if nvd_cves:
        emit(f"{C.GREEN}[✓] NVD: {len(nvd_cves)} CVE(s) found{C.RESET}")

    # Merge, deduplicate by CVE ID
    all_cves = _merge_cves(osv_cves, nvd_cves)

    # Add CVEs from release notes promises as stubs if not already present
    existing_ids = {c["id"] for c in all_cves}
    for p in promises:
        if p["type"] == "cve" and p["id"] not in existing_ids:
            all_cves.append({
                "id":          p["id"],
                "description": p["description"],
                "severity":    "UNKNOWN",
                "score":       None,
                "fixed_in":    None,
                "source":      "release_notes_only",
            })
            existing_ids.add(p["id"])

    if all_cves:
        emit(f"\n{C.CYAN}[✓] Total unique CVEs to verify: {len(all_cves)}{C.RESET}\n")
        for cve in all_cves:
            col = SEVERITY_COLOR.get(cve.get("severity", "UNKNOWN"), C.GRAY)
            score_str = f"CVSS {cve['score']}" if cve.get("score") else "no score"
            emit(f"  {col}{C.BOLD}{cve['id']}{C.RESET}  [{col}{cve.get('severity','?')}{C.RESET}  {score_str}]")
            emit(f"  {C.GRAY}{cve.get('description','')[:100]}...{C.RESET}\n")
    else:
        emit(f"{C.YELLOW}[~] No CVEs found. The app may not be in NVD/OSV, or the name differs.{C.RESET}")
        emit(f"{C.GRAY}    Tip: Try common naming (e.g. 'Pillow' not 'PIL', 'PyYAML' not 'yaml'){C.RESET}")

    # Non-CVE bug promises
    bug_promises = [p for p in promises if p["type"] == "bug_fix"]
    if bug_promises:
        emit(f"\n{C.CYAN}[✓] Non-CVE fix promises from release notes: {len(bug_promises)}{C.RESET}")
        for p in bug_promises:
            emit(f"  {C.CYAN}• [{p['id']}] {p['description'][:80]}{C.RESET}")

    # All items to verify = CVEs + bug promises
    all_items  = all_cves + bug_promises
    if not all_items:
        emit(f"\n{C.YELLOW}Nothing to verify. Try a different app name or version.{C.RESET}")
        return _save_scan(scan_id, app_name, old_version, new_version, started, [], [], 0)

    # ─────────────────────────────────────────────────────────────────────────
    section("PHASE 3 — STATIC FILE DIFF")
    # ─────────────────────────────────────────────────────────────────────────

    diff_result = {"available": False, "reason": "File diff requires PyPI or npm ecosystem."}
    if ecosystem in ("PyPI", "npm"):
        diff_result = diff_versions(app_name, old_version, new_version, ecosystem)
        if diff_result.get("available"):
            changed = diff_result.get("changed_count", 0)
            total   = diff_result.get("total_files", 0)
            emit(f"{C.GREEN}[✓] File diff complete: {changed}/{total} files changed between versions{C.RESET}")
            if diff_result.get("changed"):
                emit(f"{C.GRAY}    Changed: {', '.join(diff_result['changed'][:5])}{C.RESET}")
        else:
            emit(f"{C.YELLOW}[~] File diff unavailable: {diff_result.get('reason')}{C.RESET}")
    else:
        emit(f"{C.GRAY}[~] File diff skipped — only supported for PyPI and npm packages.{C.RESET}")

    # ─────────────────────────────────────────────────────────────────────────
    section("PHASE 4 — BEHAVIORAL PROBING")
    # ─────────────────────────────────────────────────────────────────────────

    if skip_probe:
        emit(f"{C.GRAY}[~] Behavioral probing skipped (--no-probe flag).{C.RESET}")

    # ─────────────────────────────────────────────────────────────────────────
    section("PHASE 5 — VERDICT PER PROMISE")
    # ─────────────────────────────────────────────────────────────────────────

    verdicts = []

    for item in all_items:
        is_cve      = "severity" in item
        item_id     = item.get("id", "?")
        bug_class   = item.get("bug_class")
        description = item.get("description", "")

        emit(f"{C.BOLD}{'─'*58}{C.RESET}")
        col = SEVERITY_COLOR.get(item.get("severity", "UNKNOWN"), C.GRAY)
        if is_cve:
            score_str = f" · CVSS {item['score']}" if item.get("score") else ""
            emit(f"{col}{C.BOLD}{item_id}{C.RESET}{col}{score_str} · {item.get('severity','?')}{C.RESET}")
        else:
            emit(f"{C.CYAN}{C.BOLD}{item_id}{C.RESET}  {C.CYAN}Bug fix promise{C.RESET}")
        emit(f"{C.GRAY}{description[:100]}{C.RESET}\n")

        # Signal 1: CVE version range check
        if is_cve and item.get("source") != "release_notes_only":
            cve_check = check_version_fixed(item, new_version)
        else:
            cve_check = {"fixed": None, "method": "none", "detail": "No version range data available."}

        emit(f"  {C.GRAY}CVE range  : {cve_check['detail'][:80]}{C.RESET}")

        # Signal 2: File diff
        diff_check = file_changed_for_promise(diff_result, item)
        emit(f"  {C.GRAY}File diff  : {diff_check.get('reason','')[:80]}{C.RESET}")

        # Signal 3: Behavioral probe
        probe_result = {"ran": False, "reason": "Not applicable."}
        if not skip_probe and ecosystem == "PyPI" and bug_class:
            emit(f"  {C.GRAY}Probe      : Running {bug_class} probe...{C.RESET}")
            # Run on new version (should pass) and old version (should fail)
            new_probe = run_probe(app_name, new_version, bug_class, ecosystem)
            old_probe = run_probe(app_name, old_version, bug_class, ecosystem)

            if new_probe.get("ran") and old_probe.get("ran"):
                old_passed = old_probe.get("passed")
                new_passed = new_probe.get("passed")
                if old_passed is False and new_passed is True:
                    probe_result = {
                        "ran":     True,
                        "passed":  True,
                        "message": f"Old v{old_version} failed probe, new v{new_version} passed — fix confirmed."
                    }
                elif new_passed is False:
                    probe_result = {
                        "ran":     True,
                        "passed":  False,
                        "message": f"New v{new_version} still fails probe — fix not effective."
                    }
                else:
                    probe_result = {
                        "ran":     True,
                        "passed":  None,
                        "message": f"Probe results inconclusive (old: {old_probe.get('result')}, new: {new_probe.get('result')})."
                    }
            else:
                probe_result = new_probe if new_probe.get("ran") else old_probe

        emit(f"  {C.GRAY}Probe      : {probe_result.get('message') or probe_result.get('reason','')}{C.RESET}")

        # Score
        verdict = score_promise(item, cve_check, diff_check, probe_result)
        verdicts.append({**item, **verdict})

        emit("")
        verdict_line(item_id, verdict["status"], verdict["confidence"],
                     " | ".join(verdict["signals"]))

    # ─────────────────────────────────────────────────────────────────────────
    section("SUMMARY")
    # ─────────────────────────────────────────────────────────────────────────

    fixed       = sum(1 for v in verdicts if v["status"] == "FIXED")
    not_fixed   = sum(1 for v in verdicts if v["status"] == "NOT_FIXED")
    unconfirmed = sum(1 for v in verdicts if v["status"] == "UNCONFIRMED")
    total       = len(verdicts)

    risk = compute_risk_score(verdicts, all_items)

    risk_colors = {"green": C.GREEN, "yellow": C.YELLOW, "orange": C.ORANGE, "red": C.RED}
    rcol = risk_colors.get(risk["color"], C.GRAY)

    emit(f"  Promises checked : {total}")
    emit(f"  {C.GREEN}[✅ FIXED]        : {fixed}{C.RESET}")
    emit(f"  {C.RED}[❌ NOT FIXED]    : {not_fixed}{C.RESET}")
    emit(f"  {C.YELLOW}[⚠  UNCONFIRMED] : {unconfirmed}{C.RESET}")
    emit(f"\n  {rcol}{C.BOLD}Overall Risk     : {risk['label']}  ({risk['score']}/100){C.RESET}")

    if not_fixed > 0:
        emit(f"\n  {C.RED}{C.BOLD}⚠  Recommendation: Do NOT fully trust this update.{C.RESET}")
        emit(f"  {C.RED}   {not_fixed} promise(s) remain unpatched.{C.RESET}")
    elif unconfirmed > 0:
        emit(f"\n  {C.YELLOW}  Recommendation: Update appears mostly safe but {unconfirmed} promise(s) unconfirmed.{C.RESET}")
    else:
        emit(f"\n  {C.GREEN}{C.BOLD}✅ All checked promises appear to be fixed.{C.RESET}")

    emit(f"\n  {C.GRAY}Scan ID: {scan_id}  |  Dashboard: http://localhost:5000{C.RESET}\n")

    return _save_scan(scan_id, app_name, old_version, new_version,
                      started, verdicts, all_items, risk["score"], risk["label"])


def _merge_cves(osv: list, nvd: list) -> list:
    """Merge OSV and NVD results, preferring OSV for version ranges (more accurate)."""
    seen   = {}
    merged = []
    for cve in osv + nvd:
        cid = cve["id"]
        if cid not in seen:
            seen[cid] = cve
            merged.append(cve)
        else:
            # Prefer OSV version data
            existing = seen[cid]
            if not existing.get("fixed_in") and cve.get("fixed_in"):
                existing["fixed_in"] = cve["fixed_in"]
            if not existing.get("score") and cve.get("score"):
                existing["score"]    = cve["score"]
                existing["severity"] = cve["severity"]
    return merged


def _save_scan(scan_id, app, old_v, new_v, started, verdicts, items, risk_score, risk_label="NONE"):
    """Save completed scan to history file."""
    record = {
        "scan_id":    scan_id,
        "app":        app,
        "old_version": old_v,
        "new_version": new_v,
        "started":    started,
        "completed":  datetime.datetime.utcnow().isoformat(),
        "total":      len(verdicts),
        "fixed":      sum(1 for v in verdicts if v.get("status") == "FIXED"),
        "not_fixed":  sum(1 for v in verdicts if v.get("status") == "NOT_FIXED"),
        "unconfirmed":sum(1 for v in verdicts if v.get("status") == "UNCONFIRMED"),
        "risk_score": risk_score,
        "risk_label": risk_label,
        "verdicts":   verdicts,
    }

    history = []
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                history = json.load(f)
        except Exception:
            history = []

    history.insert(0, record)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history[:100], f, indent=2)

    return record
