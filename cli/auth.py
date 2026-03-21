"""Authentication and registration for PatchVerify — full OTP flow"""
import json
import random
import hashlib
import datetime
import smtplib
import ssl
import os
import getpass
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

from .config import CONFIG_FILE, CONFIG_DIR, load_config, save_config, C, ensure_config_dir

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

JWT_SECRET = "patchverify-local-secret-2026"
TOKEN_EXPIRY_DAYS = 365


def is_registered():
    """Check if device is registered with a valid email and device_id."""
    try:
        config = load_config()
        return bool(config.get("device_id")) and bool(config.get("email"))
    except Exception:
        return False


def setup_flow():
    """
    Interactive first-run setup:
    1. Collect email
    2. Collect SMTP credentials
    3. Send OTP via email
    4. Verify OTP
    5. Save JWT token and config
    """
    ensure_config_dir()

    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════╗
║              PatchVerify — First-Time Setup              ║
╚══════════════════════════════════════════════════════════╝{C.RESET}

This tool verifies whether software updates actually fixed what they promised.
We'll register your device and verify your email via OTP.
""")

    email = input(f"  {C.BOLD}Enter your email address:{C.RESET} ").strip()
    if not email or "@" not in email:
        print(f"  {C.RED}Invalid email address.{C.RESET}")
        return False

    print(f"\n  {C.BOLD}SMTP Configuration{C.RESET} {C.GRAY}(needed to send your OTP){C.RESET}")
    print(f"  {C.GRAY}Gmail users: use an App Password — myaccount.google.com → Security → App Passwords{C.RESET}")
    print(f"  {C.GRAY}Gmail: smtp.gmail.com:587  |  Outlook: smtp.office365.com:587{C.RESET}\n")

    smtp_host = input(f"  SMTP host [{C.GRAY}smtp.gmail.com{C.RESET}]: ").strip() or "smtp.gmail.com"
    smtp_port_str = input(f"  SMTP port [{C.GRAY}587{C.RESET}]: ").strip() or "587"
    smtp_user = input(f"  SMTP username [{C.GRAY}{email}{C.RESET}]: ").strip() or email
    smtp_pass = getpass.getpass(f"  SMTP password (app password): ")

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    print(f"\n  {C.GRAY}Sending OTP to {email}...{C.RESET}")

    sent = _send_otp(email, otp, smtp_host, int(smtp_port_str), smtp_user, smtp_pass)

    if sent:
        print(f"  {C.GREEN}✓ OTP sent to {email}{C.RESET}")
    else:
        print(f"  {C.YELLOW}Could not send via SMTP. Check your credentials above.{C.RESET}")
        print(f"  {C.YELLOW}For testing only, your OTP is: {C.BOLD}{otp}{C.RESET}")

    entered = input(f"\n  {C.BOLD}Enter the OTP:{C.RESET} ").strip()

    if entered != otp:
        print(f"  {C.RED}Incorrect OTP. Setup failed.{C.RESET}")
        return False

    print(f"  {C.GREEN}✓ OTP verified.{C.RESET}")

    # Generate device ID and token
    device_id = str(uuid.uuid4())
    token = _generate_token(email, device_id)

    config = {
        "email":      email,
        "device_id":  device_id,
        "token":      token,
        "smtp": {
            "host": smtp_host,
            "port": int(smtp_port_str),
            "user": smtp_user,
            "pass": _obfuscate(smtp_pass),
        },
        "registered": datetime.datetime.utcnow().isoformat(),
    }
    save_config(config)

    print(f"""
  {C.GREEN}{C.BOLD}✅ Device registered successfully!{C.RESET}

  {C.BOLD}Email    :{C.RESET} {email}
  {C.BOLD}Device ID:{C.RESET} {device_id}

  Run a scan:  {C.BOLD}patchverify --app django --old 4.1.0 --new 4.2.0{C.RESET}
  Dashboard:   {C.CYAN}http://localhost:8080{C.RESET} {C.GRAY}(auto-starts on scan){C.RESET}
""")
    return True


def send_scan_notification(result):
    """Send email notification when a scan completes."""
    try:
        config = load_config()
        email = config.get("email")
        smtp_cfg = config.get("smtp", {})
        if not email or not smtp_cfg.get("host"):
            return

        app   = result.get("app", "?")
        old_v = result.get("old_version", "?")
        new_v = result.get("new_version", "?")
        fixed = result.get("fixed", 0)
        total = result.get("total", 0)
        risk  = result.get("risk_label", "?")
        score = result.get("risk_score", 0)

        subject = f"PatchVerify: {app} {old_v}→{new_v} | Risk: {risk}"
        body = f"""PatchVerify Scan Complete
═════════════════════════
App        : {app}
Version    : {old_v} → {new_v}

Results    : {fixed}/{total} promises verified fixed
Risk Score : {score}/100 ({risk})

View full results at: http://localhost:8080
Scan ID: {result.get('scan_id', '')}
"""
        smtp_pass = _deobfuscate(smtp_cfg.get("pass", ""))
        _send_email(
            to=email,
            subject=subject,
            body=body,
            smtp_host=smtp_cfg["host"],
            smtp_port=int(smtp_cfg["port"]),
            smtp_user=smtp_cfg["user"],
            smtp_pass=smtp_pass,
        )
    except Exception:
        pass  # Non-fatal


# ── Internal helpers ──────────────────────────────────────────────────────────

def _send_otp(to, otp, host, port, user, password):
    subject = "PatchVerify — Your One-Time Password"
    body = f"""Your PatchVerify verification code is:

  {otp}

Enter this code to complete device registration.
This code expires in 10 minutes.
If you did not request this, ignore this email.
"""
    return _send_email(to, subject, body, host, port, user, password)


def _send_email(to, subject, body, smtp_host, smtp_port, smtp_user, smtp_pass):
    try:
        msg = MIMEMultipart()
        msg["From"]    = smtp_user
        msg["To"]      = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        ctx = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to, msg.as_string())
        return True
    except Exception as e:
        print(f"  {C.YELLOW}SMTP error: {e}{C.RESET}")
        return False


def _generate_token(email, device_id):
    if JWT_AVAILABLE:
        payload = {
            "email":     email,
            "device_id": device_id,
            "exp":       datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_EXPIRY_DAYS),
            "iat":       datetime.datetime.utcnow(),
        }
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    raw = f"{email}:{device_id}:{JWT_SECRET}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _obfuscate(s):
    key = b"patchverify"
    b = s.encode()
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(b)).hex()


def _deobfuscate(h):
    try:
        key = b"patchverify"
        b = bytes.fromhex(h)
        return bytes(x ^ key[i % len(key)] for i, x in enumerate(b)).decode()
    except Exception:
        return ""
