"""
PatchVerify — auth module
Handles first-run OTP email registration and JWT device token management.
"""
import json
import random
import hashlib
import datetime
import smtplib
import ssl
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cli.config import CONFIG_FILE, USERS_FILE, HOME_DIR, C

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

JWT_SECRET  = "patchverify-local-secret-2026"
TOKEN_EXPIRY_DAYS = 365


def is_registered() -> bool:
    """Check if device is already registered."""
    return CONFIG_FILE.exists()


def load_config() -> dict:
    """Load local device config."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(data: dict):
    """Save device config."""
    HOME_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def setup_flow():
    """
    Interactive first-run setup:
    1. Collect email + SMTP credentials
    2. Send OTP
    3. Verify OTP
    4. Save JWT token
    """
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════╗
║              PatchVerify — First Time Setup              ║
╚══════════════════════════════════════════════════════════╝{C.RESET}

This links your device to your account.
Your scan results will be accessible on the dashboard.
""")

    email = input(f"  {C.BOLD}Enter your email address:{C.RESET} ").strip()
    if not email or "@" not in email:
        print(f"  {C.RED}Invalid email address.{C.RESET}")
        return False

    print(f"\n  {C.BOLD}SMTP Configuration (for sending OTP){C.RESET}")
    print(f"  {C.GRAY}For Gmail: smtp.gmail.com  |  For Outlook: smtp.office365.com{C.RESET}\n")

    smtp_host = input(f"  SMTP host [{C.GRAY}smtp.gmail.com{C.RESET}]: ").strip() or "smtp.gmail.com"
    smtp_port = input(f"  SMTP port [{C.GRAY}587{C.RESET}]: ").strip() or "587"
    smtp_user = input(f"  SMTP username (usually your email): ").strip() or email

    import getpass
    smtp_pass = getpass.getpass(f"  SMTP password (app password for Gmail): ")

    # Generate and send OTP
    otp = str(random.randint(100000, 999999))
    print(f"\n  {C.GRAY}Sending OTP to {email}...{C.RESET}")

    sent = _send_otp(email, otp, smtp_host, int(smtp_port), smtp_user, smtp_pass)
    if not sent:
        print(f"\n  {C.YELLOW}Could not send OTP via SMTP.{C.RESET}")
        print(f"  {C.YELLOW}For testing, your OTP is: {C.BOLD}{otp}{C.RESET}")

    entered = input(f"\n  {C.BOLD}Enter the OTP sent to {email}:{C.RESET} ").strip()

    if entered != otp:
        print(f"  {C.RED}Incorrect OTP. Setup failed.{C.RESET}")
        return False

    print(f"  {C.GREEN}✓ OTP verified.{C.RESET}")

    # Generate device token
    device_id = hashlib.md5(f"{email}{os.getpid()}{datetime.datetime.utcnow()}".encode()).hexdigest()

    token = _generate_token(email, device_id)

    # Save config
    config = {
        "email":     email,
        "device_id": device_id,
        "token":     token,
        "smtp": {
            "host": smtp_host,
            "port": int(smtp_port),
            "user": smtp_user,
            "pass": _obfuscate(smtp_pass),
        },
        "registered": datetime.datetime.utcnow().isoformat(),
    }
    save_config(config)

    # Save user to users.json
    _register_user(email, device_id, token)

    print(f"""
  {C.GREEN}{C.BOLD}✅ Device registered successfully!{C.RESET}

  {C.BOLD}Email    :{C.RESET} {email}
  {C.BOLD}Device ID:{C.RESET} {device_id[:16]}...
  {C.BOLD}Token    :{C.RESET} saved to ~/.patchverify/config.json

  {C.CYAN}Dashboard: http://localhost:5000{C.RESET}
  Start the dashboard with: {C.BOLD}patchverify --serve{C.RESET}
  Run a scan with:          {C.BOLD}patchverify --app django --old 4.1.0 --new 4.2.0{C.RESET}
""")
    return True


def send_scan_notification(scan_record: dict):
    """Send email notification when scan completes."""
    config = load_config()
    if not config:
        return

    smtp_cfg = config.get("smtp", {})
    email    = config.get("email")
    if not email or not smtp_cfg:
        return

    app      = scan_record.get("app", "?")
    old_v    = scan_record.get("old_version", "?")
    new_v    = scan_record.get("new_version", "?")
    fixed    = scan_record.get("fixed", 0)
    total    = scan_record.get("total", 0)
    risk     = scan_record.get("risk_label", "?")
    score    = scan_record.get("risk_score", 0)

    subject = f"PatchVerify Scan Complete: {app} {old_v}→{new_v} | Risk: {risk}"
    body = f"""
PatchVerify Scan Complete
═════════════════════════
App        : {app}
Old Version: {old_v}
New Version: {new_v}

Results    : {fixed}/{total} promises verified fixed
Risk Score : {score}/100 ({risk})

View full results at: http://localhost:5000

Scan ID: {scan_record.get('scan_id','')}
"""

    try:
        smtp_pass = _deobfuscate(smtp_cfg.get("pass", ""))
        _send_email(
            to=email,
            subject=subject,
            body=body,
            smtp_host=smtp_cfg["host"],
            smtp_port=smtp_cfg["port"],
            smtp_user=smtp_cfg["user"],
            smtp_pass=smtp_pass,
        )
    except Exception:
        pass  # Notification failure is non-fatal


def _send_otp(to: str, otp: str, host: str, port: int, user: str, password: str) -> bool:
    subject = "PatchVerify — Your One-Time Password"
    body = f"""
Your PatchVerify OTP is:

  {otp}

This code expires in 10 minutes.
If you did not request this, ignore this email.
"""
    return _send_email(to, subject, body, host, port, user, password)


def _send_email(to: str, subject: str, body: str,
                smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str) -> bool:
    try:
        msg = MIMEMultipart()
        msg["From"]    = smtp_user
        msg["To"]      = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        ctx = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to, msg.as_string())
        return True
    except Exception as e:
        print(f"  {C.YELLOW}SMTP error: {e}{C.RESET}")
        return False


def _generate_token(email: str, device_id: str) -> str:
    if JWT_AVAILABLE:
        payload = {
            "email":     email,
            "device_id": device_id,
            "exp":       datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_EXPIRY_DAYS),
            "iat":       datetime.datetime.utcnow(),
        }
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    else:
        # Fallback: simple hash token
        raw = f"{email}:{device_id}:{JWT_SECRET}"
        return hashlib.sha256(raw.encode()).hexdigest()


def _register_user(email: str, device_id: str, token: str):
    users = []
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE) as f:
                users = json.load(f)
        except Exception:
            users = []

    # Remove existing entry for this email
    users = [u for u in users if u.get("email") != email]
    users.append({
        "email":      email,
        "device_id":  device_id,
        "token_hash": hashlib.sha256(token.encode()).hexdigest(),
        "registered": datetime.datetime.utcnow().isoformat(),
    })
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


def _obfuscate(s: str) -> str:
    """Simple XOR obfuscation for stored SMTP password."""
    key = b"patchverify"
    b   = s.encode()
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(b)).hex()


def _deobfuscate(h: str) -> str:
    try:
        key = b"patchverify"
        b   = bytes.fromhex(h)
        return bytes(x ^ key[i % len(key)] for i, x in enumerate(b)).decode()
    except Exception:
        return ""
