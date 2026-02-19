"""Configuration management for PatchVerify"""
from pathlib import Path
import json

# Color codes for terminal output
class C:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    ORANGE = '\033[38;5;208m'

# Config file locations
CONFIG_DIR = Path.home() / ".patchverify"
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_FILE = CONFIG_DIR / "history.json"

def ensure_config_dir():
    """Ensure config directory exists"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

def load_config():
    """Load configuration from file"""
    ensure_config_dir()
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}

def save_config(config):
    """Save configuration to file"""
    ensure_config_dir()
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
