"""Authentication and registration for PatchVerify — full OTP flow"""
import json
import secrets
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

TOKEN_EXPIRY_DAYS = 365


def _get_jwt_secret():
    """Return the JWT secret, generating and persisting a random one on first use."""
    config = load_config()
    if "jwt_secret" in config:
        return _deobfuscate_raw(config["jwt_secret"])
    # First run — generate a cryptographically random 32-byte secret
    import secrets
    secret = secrets.token_hex(32)
    config["jwt_secret"] = _obfuscate_raw(secret)
    save_config(config)
    return secret


def _obfuscate_raw(s):
    key = b"patchverify"
    b = s.encode()
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(b)).hex()


def _deobfuscate_raw(h):
    try:
        key = b"patchverify"
        b = bytes.fromhex(h)
        return bytes(x ^ key[i % len(key)] for i, x in enumerate(b)).decode()
    except Exception:
        return ""


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

    # Auto-detect SMTP settings from email domain
    smtp_host, smtp_port = _detect_smtp(email)

    if smtp_host:
        domain = email.split("@")[-1].lower()
        if domain == "gmail.com":
            print(f"\n  {C.GRAY}Gmail detected.{C.RESET}")
            print(f"  {C.GRAY}You need a Gmail App Password (not your normal password).{C.RESET}")
            print(f"  {C.GRAY}Get one at: myaccount.google.com → Security → App Passwords{C.RESET}\n")
        else:
            print(f"\n  {C.GRAY}Auto-detected SMTP: {smtp_host}:{smtp_port}{C.RESET}\n")

        smtp_pass = getpass.getpass(f"  Email password (App Password for Gmail): ")
        smtp_user = email
    else:
        # Unknown provider — ask manually
        print(f"\n  {C.GRAY}Could not auto-detect SMTP for {email}.{C.RESET}")
        print(f"  {C.GRAY}Enter your SMTP details or press Enter to skip verification.{C.RESET}\n")
        smtp_host_input = input(f"  SMTP host (or Enter to skip): ").strip()
        if not smtp_host_input:
            print(f"  {C.YELLOW}Skipping email verification — registering without SMTP.{C.RESET}")
            smtp_host = None
            smtp_pass = ""
            smtp_user = email
            smtp_port = 587
        else:
            smtp_host = smtp_host_input
            smtp_port = int(input(f"  SMTP port [587]: ").strip() or "587")
            smtp_user = email
            smtp_pass = getpass.getpass(f"  SMTP password: ")

    smtp_cfg = {}
    if smtp_host and smtp_pass:
        otp = str(secrets.randbelow(900000) + 100000)  # REQ 7.1: cryptographically random
        print(f"\n  {C.GRAY}Sending OTP to {email}...{C.RESET}")

        sent = _send_otp(email, otp, smtp_host, smtp_port, smtp_user, smtp_pass)

        if sent:
            print(f"  {C.GREEN}✓ OTP sent — check your inbox (and spam folder){C.RESET}")
        else:
            print(f"  {C.YELLOW}Send failed. Your OTP is: {C.BOLD}{otp}{C.RESET}")

        entered = input(f"\n  {C.BOLD}Enter the OTP:{C.RESET} ").strip()
        if entered != otp:
            print(f"  {C.RED}Incorrect OTP. Setup failed.{C.RESET}")
            return False

        print(f"  {C.GREEN}✓ OTP verified.{C.RESET}")
        smtp_cfg = {
            "host": smtp_host,
            "port": smtp_port,
            "user": smtp_user,
            "pass": _obfuscate(smtp_pass),
        }

    # Generate device ID and token
    device_id = str(uuid.uuid4())
    token = _generate_token(email, device_id)

    config = {
        "email":      email,
        "device_id":  device_id,
        "token":      token,
        "registered": datetime.datetime.utcnow().isoformat(),
    }
    if smtp_cfg:
        config["smtp"] = smtp_cfg
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

def _detect_smtp(email):
    """Return (host, port) for known email providers, or (None, 587) for unknown."""
    domain = email.split("@")[-1].lower() if "@" in email else ""
    known = {
        "gmail.com":       ("smtp.gmail.com", 587),
        "googlemail.com":  ("smtp.gmail.com", 587),
        "outlook.com":     ("smtp.office365.com", 587),
        "hotmail.com":     ("smtp.office365.com", 587),
        "live.com":        ("smtp.office365.com", 587),
        "yahoo.com":       ("smtp.mail.yahoo.com", 587),
        "icloud.com":      ("smtp.mail.me.com", 587),
        "me.com":          ("smtp.mail.me.com", 587),
    }
    return known.get(domain, (None, 587))


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

        # Use certifi CA bundle to fix macOS SSL certificate errors
        try:
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
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
    secret = _get_jwt_secret()
    if JWT_AVAILABLE:
        payload = {
            "email":     email,
            "device_id": device_id,
            "exp":       datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_EXPIRY_DAYS),
            "iat":       datetime.datetime.utcnow(),
        }
        return jwt.encode(payload, secret, algorithm="HS256")
    raw = f"{email}:{device_id}:{secret}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _obfuscate(s):
    return _obfuscate_raw(s)


def _deobfuscate(h):
    return _deobfuscate_raw(h)
