"""Authentication and registration for PatchVerify"""
from .config import CONFIG_FILE, load_config, save_config, C, ensure_config_dir
import json

def is_registered():
    """Check if device is registered"""
    try:
        config = load_config()
        return bool(config.get("device_id")) and bool(config.get("email"))
    except Exception:
        return False

def setup_flow():
    """Interactive setup flow for first-time registration"""
    ensure_config_dir()
    
    print(f"\n{C.CYAN}{C.BOLD}PatchVerify — First-Time Setup{C.RESET}\n")
    print("This tool verifies whether software updates actually fixed what they promised.")
    print("We'll register your device to track scan history.\n")
    
    email = input(f"{C.BOLD}Enter your email:{C.RESET} ").strip()
    if not email:
        print(f"{C.RED}Error: Email is required{C.RESET}")
        return
    
    # For now, generate a simple device ID
    import uuid
    device_id = str(uuid.uuid4())
    
    config = load_config()
    config["email"] = email
    config["device_id"] = device_id
    save_config(config)
    
    print(f"\n{C.GREEN}✓ Device registered successfully!{C.RESET}")
    print(f"{C.GRAY}Device ID: {device_id}{C.RESET}\n")

def send_scan_notification(result):
    """Send email notification of scan results"""
    try:
        config = load_config()
        email = config.get("email")
        if email:
            print(f"{C.GRAY}[Info] Scan notification would be sent to {email}{C.RESET}")
    except Exception:
        pass

def load_config():
    """Load configuration"""
    from .config import load_config as _load_config
    return _load_config()
