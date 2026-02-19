"""Live streaming of scan progress to web dashboard"""
import json
from pathlib import Path
from datetime import datetime
from .config import ensure_config_dir

STREAM_FILE = Path.home() / ".patchverify" / "stream.json"

def init_stream(scan_id, app_name, old_version, new_version):
    """Initialize a new scan stream"""
    ensure_config_dir()
    stream_data = {
        "scan_id": scan_id,
        "app": app_name,
        "old_version": old_version,
        "new_version": new_version,
        "status": "starting",
        "progress": 0,
        "current_step": "Initializing scan",
        "started": datetime.now().isoformat(),
        "events": []
    }
    _write_stream(stream_data)
    return stream_data

def update_stream(scan_id, status=None, progress=None, step=None, event=None):
    """Update the scan stream with new progress"""
    stream_data = _read_stream()
    if not stream_data or stream_data.get("scan_id") != scan_id:
        return

    if status:
        stream_data["status"] = status
    if progress is not None:
        stream_data["progress"] = progress
    if step:
        stream_data["current_step"] = step
    if event:
        stream_data["events"].append({
            "timestamp": datetime.now().isoformat(),
            "message": event
        })

    stream_data["updated"] = datetime.now().isoformat()
    _write_stream(stream_data)

def complete_stream(scan_id, result):
    """Mark stream as complete with final results"""
    stream_data = _read_stream()
    if stream_data and stream_data.get("scan_id") == scan_id:
        stream_data["status"] = "complete"
        stream_data["progress"] = 100
        stream_data["result"] = result
        stream_data["completed"] = datetime.now().isoformat()
        _write_stream(stream_data)

def _read_stream():
    """Read current stream data"""
    if STREAM_FILE.exists():
        with open(STREAM_FILE) as f:
            return json.load(f)
    return None

def _write_stream(data):
    """Write stream data"""
    with open(STREAM_FILE, 'w') as f:
        json.dump(data, f, indent=2)
