"""
PatchVerify — confidence scorer
Combines CVE range data + file diff + behavioral probe into final verdicts.
"""

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH":     7,
    "MEDIUM":   4,
    "LOW":      1,
    "UNKNOWN":  3,
}


def score_promise(promise: dict, cve_check: dict, diff_check: dict, probe_result: dict) -> dict:
    """
    Combine all three signals into a final verdict + confidence score.

    Signals:
      cve_check  : { fixed: True/False/None, method, detail }
      diff_check : { checked, files_changed: True/False/None, reason }
      probe      : { ran, passed: True/False/None, message }

    Returns:
      { status, confidence, verdict_detail, signals }
    """
    signals = []
    weights = []   # (weight, positive: bool)

    # ── Signal 1: CVE version range ─────────────────────────────────────────
    cve_fixed = cve_check.get("fixed")
    if cve_fixed is True:
        signals.append(f"✅ CVE version range: {cve_check.get('detail', '')}")
        weights.append((40, True))
    elif cve_fixed is False:
        signals.append(f"❌ CVE version range: {cve_check.get('detail', '')}")
        weights.append((40, False))
    else:
        signals.append(f"⚠  CVE range: {cve_check.get('detail', 'No version range data in NVD/OSV.')}")
        # No weight contribution — inconclusive

    # ── Signal 2: File diff ──────────────────────────────────────────────────
    if diff_check.get("checked"):
        fc = diff_check.get("files_changed")
        if fc is True:
            signals.append(f"✅ File diff: {diff_check.get('reason', 'Relevant files changed.')}")
            weights.append((35, True))
        elif fc is False:
            signals.append(f"❌ File diff: {diff_check.get('reason', 'No relevant files changed.')}")
            weights.append((35, False))
        else:
            signals.append(f"⚠  File diff: {diff_check.get('reason', 'Change scope unclear.')}")
            weights.append((15, True))  # partial positive
    else:
        signals.append(f"─  File diff: {diff_check.get('reason', 'Not available.')}")

    # ── Signal 3: Behavioral probe ───────────────────────────────────────────
    if probe_result.get("ran"):
        passed = probe_result.get("passed")
        if passed is True:
            signals.append(f"✅ Behavioral probe: {probe_result.get('message', 'Passed.')}")
            weights.append((25, True))
        elif passed is False:
            signals.append(f"❌ Behavioral probe: {probe_result.get('message', 'Failed.')}")
            weights.append((25, False))
        else:
            signals.append(f"⚠  Behavioral probe: {probe_result.get('message', 'Inconclusive.')}")
    else:
        signals.append(f"─  Behavioral probe: {probe_result.get('reason', 'Not applicable.')}")

    # ── Compute verdict ──────────────────────────────────────────────────────
    status, confidence = _compute_verdict(weights, cve_fixed)

    return {
        "status":     status,
        "confidence": confidence,
        "signals":    signals,
    }


def _compute_verdict(weights: list, cve_fixed) -> tuple[str, int]:
    """
    Compute final status and confidence from weighted signals.
    """
    if not weights:
        return "UNCONFIRMED", 30

    total_weight    = sum(w for w, _ in weights)
    positive_weight = sum(w for w, pos in weights if pos)
    negative_weight = sum(w for w, pos in weights if not pos)

    ratio = positive_weight / total_weight if total_weight > 0 else 0.5

    # Strong negative signal override
    if cve_fixed is False:
        # NVD explicitly says still vulnerable
        if ratio < 0.4:
            return "NOT_FIXED", int(70 + (1 - ratio) * 25)
        else:
            return "NOT_FIXED", 65

    if ratio >= 0.75:
        confidence = int(70 + ratio * 28)
        return "FIXED", min(confidence, 97)
    elif ratio >= 0.5:
        confidence = int(50 + ratio * 30)
        return "FIXED", min(confidence, 75)
    elif ratio >= 0.25:
        return "UNCONFIRMED", int(30 + ratio * 30)
    else:
        confidence = int(60 + (1 - ratio) * 35)
        return "NOT_FIXED", min(confidence, 95)


def compute_risk_score(verdicts: list[dict], cves: list[dict]) -> dict:
    """
    Compute overall risk score 0–100.
    Weighted by severity of unresolved issues.
    """
    if not verdicts:
        return {"score": 0, "label": "NONE", "color": "green"}

    total_weight  = 0
    exposed_weight = 0

    for v, cve in zip(verdicts, cves):
        sev = cve.get("severity", "UNKNOWN")
        w   = SEVERITY_WEIGHTS.get(sev, 3)
        total_weight += w
        if v["status"] in ("NOT_FIXED", "UNCONFIRMED"):
            # UNCONFIRMED counts as partial risk
            multiplier = 1.0 if v["status"] == "NOT_FIXED" else 0.5
            exposed_weight += w * multiplier

    score = round((exposed_weight / total_weight) * 100, 1) if total_weight else 0

    if score >= 70:
        label, color = "CRITICAL", "red"
    elif score >= 45:
        label, color = "HIGH",     "orange"
    elif score >= 20:
        label, color = "MEDIUM",   "yellow"
    elif score > 0:
        label, color = "LOW",      "green"
    else:
        label, color = "NONE",     "green"

    return {"score": score, "label": label, "color": color}
