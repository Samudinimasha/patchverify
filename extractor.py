"""
PatchVerify — promise extractor
Fetches GitHub release notes and extracts fix promises.
"""
import re
import os
import requests
from cli.config import GITHUB_API, C
from cli.streamer import emit

# Bug category keywords to detect in release notes
BUG_PATTERNS = {
    "buffer_overflow":    r"buffer overflow|stack overflow|heap overflow|out.of.bounds write",
    "memory_leak":        r"memory leak|mem leak|resource leak|unreleased memory",
    "null_pointer":       r"null pointer|null dereference|nullptr|segfault|segmentation fault",
    "integer_overflow":   r"integer overflow|int overflow|arithmetic overflow|wrap.around",
    "input_validation":   r"input validation|improper validation|sanitiz|injection|xss|sql injection",
    "use_after_free":     r"use.after.free|uaf|dangling pointer|freed memory",
    "race_condition":     r"race condition|data race|concurrency|thread safe",
    "denial_of_service":  r"denial.of.service|dos |crash|hang |infinite loop|deadlock",
    "auth_bypass":        r"auth.bypass|authentication bypass|privilege escalat|unauthorized access",
    "information_leak":   r"information (leak|disclosure)|data (leak|exposure)|sensitive data",
}

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

FIX_VERBS = re.compile(
    r'\b(fix(ed|es)?|patch(ed)?|resolv(ed|es)?|correct(ed)?|address(ed)?|mitigat(ed)?|remediat(ed)?|clos(ed|es)?)\b',
    re.IGNORECASE
)


def find_github_repo(app_name: str, token: str = None) -> str | None:
    """Search GitHub for the most likely repo for app_name."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        r = requests.get(
            f"{GITHUB_API}/search/repositories",
            params={"q": f"{app_name} in:name", "sort": "stars", "per_page": 5},
            headers=headers,
            timeout=10
        )
        r.raise_for_status()
        items = r.json().get("items", [])
        if items:
            repo = items[0]["full_name"]
            emit(f"  {C.GRAY}Found GitHub repo: {repo}{C.RESET}")
            return repo
    except Exception as e:
        emit(f"  {C.GRAY}GitHub search failed: {e}{C.RESET}")
    return None


def fetch_release_notes(app_name: str, version: str, token: str = None) -> str | None:
    """Fetch release notes for app_name at version from GitHub."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    repo = find_github_repo(app_name, token)
    if not repo:
        emit(f"  {C.GRAY}Could not find GitHub repo for '{app_name}'{C.RESET}")
        return None

    # Try common tag formats
    tag_formats = [f"v{version}", version, f"{app_name}-{version}", f"release-{version}"]

    for tag in tag_formats:
        try:
            url = f"{GITHUB_API}/repos/{repo}/releases/tags/{tag}"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                body = data.get("body", "")
                emit(f"  {C.GREEN}Found release notes for tag '{tag}'{C.RESET}")
                return body
        except Exception:
            continue

    # Fallback: list releases and find by version string
    try:
        r = requests.get(
            f"{GITHUB_API}/repos/{repo}/releases",
            headers=headers,
            params={"per_page": 30},
            timeout=10
        )
        r.raise_for_status()
        for release in r.json():
            name = release.get("name", "") or ""
            tag  = release.get("tag_name", "") or ""
            if version in name or version in tag:
                emit(f"  {C.GREEN}Found release notes via listing (tag: {tag}){C.RESET}")
                return release.get("body", "")
    except Exception as e:
        emit(f"  {C.GRAY}Release listing failed: {e}{C.RESET}")

    emit(f"  {C.YELLOW}No release notes found for {app_name} v{version} on GitHub{C.RESET}")
    return None


def extract_promises(release_notes: str, app_name: str) -> list[dict]:
    """
    Extract fix promises from release note text.
    Returns list of promise dicts.
    """
    promises = []

    if not release_notes:
        return promises

    lines = release_notes.split('\n')

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue

        is_fix_line = bool(FIX_VERBS.search(line_stripped))
        cves_in_line = CVE_PATTERN.findall(line_stripped)

        # Explicit CVE mentions
        for cve_id in cves_in_line:
            promises.append({
                "type":        "cve",
                "id":          cve_id.upper(),
                "description": line_stripped[:200],
                "raw_line":    line_stripped,
                "bug_class":   _detect_bug_class(line_stripped),
                "source":      "release_notes",
            })

        # Bug fix mentions without CVE
        if is_fix_line and not cves_in_line:
            bug_class = _detect_bug_class(line_stripped)
            if bug_class:
                promises.append({
                    "type":        "bug_fix",
                    "id":          f"BUG-{len(promises)+1:03d}",
                    "description": line_stripped[:200],
                    "raw_line":    line_stripped,
                    "bug_class":   bug_class,
                    "source":      "release_notes",
                })

    return promises


def _detect_bug_class(text: str) -> str | None:
    """Detect bug category from text."""
    text_lower = text.lower()
    for cls, pattern in BUG_PATTERNS.items():
        if re.search(pattern, text_lower):
            return cls
    return None
