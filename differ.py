"""
PatchVerify — file differ
Downloads pip/npm package versions and compares file hashes.
"""
import hashlib
import os
import shutil
import subprocess
import tempfile
import zipfile
import tarfile
from pathlib import Path
from cli.config import C
from cli.streamer import emit


def diff_versions(app_name: str, old_version: str, new_version: str, ecosystem: str) -> dict:
    """
    Download both versions and compare file hashes.
    Returns dict with changed, unchanged, added, removed files + summary.
    """
    emit(f"  {C.GRAY}Downloading {app_name} {old_version} and {new_version} for file diff...{C.RESET}")

    with tempfile.TemporaryDirectory() as tmpdir:
        old_dir = os.path.join(tmpdir, "old")
        new_dir = os.path.join(tmpdir, "new")
        os.makedirs(old_dir)
        os.makedirs(new_dir)

        if ecosystem == "PyPI":
            old_ok = _download_pip(app_name, old_version, old_dir)
            new_ok = _download_pip(app_name, new_version, new_dir)
        elif ecosystem == "npm":
            old_ok = _download_npm(app_name, old_version, old_dir)
            new_ok = _download_npm(app_name, new_version, new_dir)
        else:
            return {"available": False, "reason": f"File diff not supported for ecosystem: {ecosystem}"}

        if not old_ok or not new_ok:
            return {"available": False, "reason": "Could not download one or both versions."}

        old_hashes = _hash_dir(old_dir)
        new_hashes = _hash_dir(new_dir)

        return _compare_hashes(old_hashes, new_hashes)


def _download_pip(package: str, version: str, dest_dir: str) -> bool:
    """Download a pip package and extract it."""
    try:
        result = subprocess.run(
            ["pip", "download", f"{package}=={version}",
             "--no-deps", "--dest", dest_dir, "--quiet"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            emit(f"  {C.YELLOW}pip download failed for {package}=={version}: {result.stderr[:100]}{C.RESET}")
            return False

        # Extract archives
        for fname in os.listdir(dest_dir):
            fpath = os.path.join(dest_dir, fname)
            extract_dir = os.path.join(dest_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            try:
                if fname.endswith(".whl") or fname.endswith(".zip"):
                    with zipfile.ZipFile(fpath, 'r') as z:
                        z.extractall(extract_dir)
                elif fname.endswith(".tar.gz") or fname.endswith(".tgz"):
                    with tarfile.open(fpath, 'r:gz') as t:
                        t.extractall(extract_dir)
                os.remove(fpath)
            except Exception:
                pass
        return True
    except Exception as e:
        emit(f"  {C.YELLOW}pip download error: {e}{C.RESET}")
        return False


def _download_npm(package: str, version: str, dest_dir: str) -> bool:
    """Download an npm package and extract it."""
    try:
        # npm pack downloads and creates a tarball
        result = subprocess.run(
            ["npm", "pack", f"{package}@{version}", "--quiet"],
            capture_output=True, text=True, timeout=60, cwd=dest_dir
        )
        if result.returncode != 0:
            emit(f"  {C.YELLOW}npm pack failed for {package}@{version}{C.RESET}")
            return False

        # Extract the tarball
        for fname in os.listdir(dest_dir):
            if fname.endswith(".tgz"):
                fpath = os.path.join(dest_dir, fname)
                extract_dir = os.path.join(dest_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                with tarfile.open(fpath, 'r:gz') as t:
                    t.extractall(extract_dir)
                os.remove(fpath)
        return True
    except Exception as e:
        emit(f"  {C.YELLOW}npm pack error: {e}{C.RESET}")
        return False


def _hash_dir(base_dir: str) -> dict[str, str]:
    """Compute SHA-256 hashes of all files under base_dir."""
    hashes = {}
    for root, _, files in os.walk(base_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            # Relative path for comparison
            rel = os.path.relpath(fpath, base_dir)
            # Strip first path component (package name/version dir)
            parts = Path(rel).parts
            normalized = str(Path(*parts[1:])) if len(parts) > 1 else rel
            try:
                sha = hashlib.sha256()
                with open(fpath, 'rb') as f:
                    while chunk := f.read(65536):
                        sha.update(chunk)
                hashes[normalized] = sha.hexdigest()
            except Exception:
                pass
    return hashes


def _compare_hashes(old: dict, new: dict) -> dict:
    """Compare two hash dicts and return diff summary."""
    changed   = []
    unchanged = []
    added     = []
    removed   = []

    all_files = set(old.keys()) | set(new.keys())

    for f in sorted(all_files):
        if f in old and f in new:
            if old[f] != new[f]:
                changed.append(f)
            else:
                unchanged.append(f)
        elif f in new:
            added.append(f)
        else:
            removed.append(f)

    return {
        "available":       True,
        "changed":         changed,
        "unchanged":       unchanged,
        "added":           added,
        "removed":         removed,
        "total_files":     len(all_files),
        "changed_count":   len(changed),
        "unchanged_count": len(unchanged),
    }


def file_changed_for_promise(diff_result: dict, promise: dict) -> dict:
    """
    Check if the files relevant to a promise were changed.
    Uses keywords from promise description to match filenames.
    """
    if not diff_result.get("available"):
        return {
            "checked": False,
            "reason":  diff_result.get("reason", "File diff not available.")
        }

    changed   = diff_result.get("changed", [])
    bug_class = promise.get("bug_class", "")
    desc      = promise.get("description", "").lower()

    # Extract potential module names from description
    import re
    # Words that look like module/file names
    candidate_names = re.findall(r'\b([a-z][a-z0-9_]{2,})\b', desc)

    # Check if any changed file contains candidate names
    relevant_changes = []
    for cf in changed:
        cf_lower = cf.lower()
        for name in candidate_names:
            if name in cf_lower and name not in ("fix", "the", "was", "has", "and", "for", "in"):
                relevant_changes.append(cf)
                break

    if relevant_changes:
        return {
            "checked":          True,
            "files_changed":    True,
            "relevant_changes": relevant_changes[:5],
            "reason":           f"Relevant file(s) changed: {', '.join(relevant_changes[:3])}"
        }
    elif changed:
        # Some files changed, but not clearly related
        return {
            "checked":        True,
            "files_changed":  None,  # unclear
            "changed_sample": changed[:3],
            "reason":         f"{len(changed)} file(s) changed but none clearly match the promise description."
        }
    else:
        return {
            "checked":       True,
            "files_changed": False,
            "reason":        "No files changed between versions — fix may not have been applied."
        }
