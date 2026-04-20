"""
PatchVerify — CVE lookup module
Queries NVD API v2 and OSV.dev for known vulnerabilities.
"""
import requests
import time
from packaging.version import Version, InvalidVersion
from cli.config import NVD_BASE, OSV_BASE, C
from cli.streamer import emit


def query_nvd(app_name: str, version: str) -> list[dict]:
    """Query NVD for CVEs affecting app_name at version.
    Searches by package name only — version filtering happens via CPE ranges.
    Implements exponential backoff with max 3 retries for rate limiting (REQ 2.3, 2.4).
    """
    emit(f"  {C.GRAY}Querying NVD for '{app_name} {version}'...{C.RESET}")
    max_retries = 3
    backoff = 6  # seconds — NVD allows 5 req/30s unauthenticated
    for attempt in range(max_retries):
        try:
            r = requests.get(
                NVD_BASE,
                params={"keywordSearch": app_name, "resultsPerPage": 50},
                timeout=15
            )
            if r.status_code in (403, 429):
                wait = backoff * (2 ** attempt)
                emit(f"  {C.YELLOW}NVD rate limit hit — waiting {wait}s (attempt {attempt+1}/{max_retries})...{C.RESET}")
                time.sleep(wait)
                continue
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            all_cves = [_parse_nvd_item(v) for v in vulns]
            relevant = []
            for cve in all_cves:
                fi = cve.get("fixed_in")
                ab = cve.get("affected_below")
                if fi or ab:
                    try:
                        v = Version(version)
                        if fi and v < Version(fi):
                            relevant.append(cve)
                        elif ab and v < Version(ab):
                            relevant.append(cve)
                    except InvalidVersion:
                        relevant.append(cve)
            return relevant
        except requests.exceptions.ConnectionError:
            emit(f"  {C.RED}Cannot reach NVD API — check internet connection.{C.RESET}")
            return []
        except Exception as e:
            if attempt < max_retries - 1:
                wait = backoff * (2 ** attempt)
                emit(f"  {C.YELLOW}NVD query error: {e} — retrying in {wait}s...{C.RESET}")
                time.sleep(wait)
            else:
                emit(f"  {C.YELLOW}NVD query failed after {max_retries} attempts: {e}{C.RESET}")
                return []
    return []


def query_osv(app_name: str, version: str, ecosystem: str = None) -> list[dict]:
    """Query OSV.dev for vulnerabilities. Tries all ecosystems if none provided."""
    # If no ecosystem, try both PyPI and npm
    if not ecosystem:
        for eco in ["PyPI", "npm"]:
            results = query_osv(app_name, version, eco)
            if results:
                return results
        return []

    emit(f"  {C.GRAY}Querying OSV.dev for '{app_name}' in {ecosystem}...{C.RESET}")
    try:
        payload = {
            "package": {"name": app_name, "ecosystem": ecosystem},
            "version": version
        }
        r = requests.post(OSV_BASE, json=payload, timeout=10)
        r.raise_for_status()
        vulns = r.json().get("vulns", [])
        results = []
        for v in vulns:
            results.append(_parse_osv_item(v))
        return results
    except Exception as e:
        emit(f"  {C.YELLOW}OSV.dev query error: {e}{C.RESET}")
        return []


def check_version_fixed(cve: dict, new_version: str) -> dict:
    """
    Check if new_version falls outside the vulnerable range.
    Returns: { "fixed": bool|None, "method": str, "detail": str }
    """
    fixed_in = cve.get("fixed_in")
    affected_below = cve.get("affected_below")

    if fixed_in:
        try:
            if Version(new_version) >= Version(fixed_in):
                return {
                    "fixed": True,
                    "method": "version_range",
                    "detail": f"Fixed in >= {fixed_in}. New version {new_version} is safe."
                }
            else:
                return {
                    "fixed": False,
                    "method": "version_range",
                    "detail": f"Fixed in >= {fixed_in}. New version {new_version} is still vulnerable."
                }
        except InvalidVersion:
            pass

    if affected_below:
        try:
            if Version(new_version) < Version(affected_below):
                return {
                    "fixed": False,
                    "method": "version_range",
                    "detail": f"Affects versions below {affected_below}. New version {new_version} is still affected."
                }
            else:
                return {
                    "fixed": True,
                    "method": "version_range",
                    "detail": f"Affects versions below {affected_below}. New version {new_version} is safe."
                }
        except InvalidVersion:
            pass

    return {
        "fixed": None,
        "method": "no_range_data",
        "detail": "NVD/OSV did not provide clean version range data for this CVE."
    }


def detect_ecosystem(app_name: str) -> str | None:
    """Try to detect if app is a PyPI or npm package."""
    # Check PyPI
    try:
        r = requests.get(f"https://pypi.org/pypi/{app_name}/json", timeout=6)
        if r.status_code == 200:
            return "PyPI"
    except Exception:
        pass

    # Check npm
    try:
        r = requests.get(f"https://registry.npmjs.org/{app_name}", timeout=6)
        if r.status_code == 200:
            return "npm"
    except Exception:
        pass

    return None


def _parse_nvd_item(item: dict) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Description
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d["lang"] == "en"), "No description.")

    # Severity + score
    severity, score = "UNKNOWN", None
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss = m.get("cvssData", {})
            severity = (cvss.get("baseSeverity") or m.get("baseSeverity", "UNKNOWN")).upper()
            score = cvss.get("baseScore") or m.get("baseScore")
            break

    # Version ranges from configurations
    fixed_in, affected_below = _extract_nvd_version_range(cve)

    return {
        "id":             cve_id,
        "description":    desc[:300],
        "severity":       severity,
        "score":          score,
        "published":      cve.get("published", "")[:10],
        "fixed_in":       fixed_in,
        "affected_below": affected_below,
        "source":         "nvd",
        "references":     [r.get("url") for r in cve.get("references", [])[:2]],
    }


def _parse_osv_item(item: dict) -> dict:
    osv_id = item.get("id", "UNKNOWN")

    # Map to CVE if available
    cve_id = osv_id
    for alias in item.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # Description
    desc = item.get("summary") or item.get("details", "No description.")

    # Severity
    severity, score = "UNKNOWN", None
    for sev in item.get("severity", []):
        score = sev.get("score")
        if score:
            try:
                s = float(score)
                if s >= 9.0:   severity = "CRITICAL"
                elif s >= 7.0: severity = "HIGH"
                elif s >= 4.0: severity = "MEDIUM"
                else:          severity = "LOW"
            except Exception:
                pass
            break

    # Version ranges
    fixed_in = None
    for affected in item.get("affected", []):
        for rng in affected.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed_in = ev["fixed"]
                    break

    return {
        "id":             cve_id,
        "description":    str(desc)[:300],
        "severity":       severity,
        "score":          score,
        "published":      item.get("published", "")[:10],
        "fixed_in":       fixed_in,
        "affected_below": None,
        "source":         "osv",
        "references":     [],
    }


def _extract_nvd_version_range(cve: dict):
    """Try to extract fixed_in and affected_below from NVD configurations."""
    fixed_in = None
    affected_below = None
    try:
        configs = cve.get("configurations", [])
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        vi = match.get("versionEndIncluding")
                        ve = match.get("versionEndExcluding")
                        if ve:
                            fixed_in = ve
                        elif vi:
                            affected_below = vi
    except Exception:
        pass
    return fixed_in, affected_below
