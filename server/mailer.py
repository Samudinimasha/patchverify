"""Email notification service for PatchVerify"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Import the real SMTP helpers and config loader from auth
try:
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from auth import load_config, _deobfuscate
    _AUTH_AVAILABLE = True
except Exception:
    _AUTH_AVAILABLE = False


def send_scan_complete_email(email, scan_result):
    """
    Send email notification when scan completes.
    Uses SMTP credentials saved during patchverify --setup.
    Falls back to console log if no credentials are configured.
    """
    subject = f"PatchVerify Scan Complete: {scan_result['app']} {scan_result['old_version']} → {scan_result['new_version']}"

    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
          <h1 style="color: white; margin: 0;">PatchVerify Scan Complete</h1>
        </div>

        <div style="padding: 30px; background: #f9fafb;">
          <h2 style="color: #1f2937;">Scan Results</h2>

          <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <p><strong>Application:</strong> {scan_result['app']}</p>
            <p><strong>Version Change:</strong> {scan_result['old_version']} → {scan_result['new_version']}</p>
            <p><strong>Scan ID:</strong> {scan_result['scan_id']}</p>
            <p><strong>Started:</strong> {scan_result.get('started', 'N/A')}</p>
          </div>

          <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h3 style="color: #1f2937; margin-top: 0;">Verdict</h3>
            <p><strong>Risk Level:</strong> <span style="color: {_get_risk_color(scan_result.get('risk_label', 'NONE'))}; font-weight: bold;">{scan_result.get('risk_label', 'NONE')}</span></p>
            <p><strong>Risk Score:</strong> {scan_result.get('risk_score', 0)}/100</p>
          </div>

          <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h3 style="color: #1f2937; margin-top: 0;">Patch Analysis</h3>
            <p>✅ <strong>Fixed:</strong> {scan_result.get('fixed', 0)}/{scan_result.get('total', 0)} vulnerabilities</p>
            <p>❌ <strong>Not Fixed:</strong> {scan_result.get('not_fixed', 0)} vulnerabilities</p>
            <p>❓ <strong>Unconfirmed:</strong> {scan_result.get('unconfirmed', 0)} vulnerabilities</p>
          </div>

          <div style="text-align: center; margin-top: 30px;">
            <a href="http://localhost:5000" style="background: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">View Full Report</a>
          </div>
        </div>

        <div style="padding: 20px; text-align: center; color: #6b7280; font-size: 12px;">
          <p>This is an automated message from PatchVerify</p>
          <p>Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
      </body>
    </html>
    """

    # Try to send via SMTP using saved credentials from --setup
    if _AUTH_AVAILABLE:
        try:
            config = load_config()
            smtp_cfg = config.get("smtp", {})
            if smtp_cfg and smtp_cfg.get("host") and smtp_cfg.get("user"):
                _send_smtp_email(email, subject, html_body, smtp_cfg)
                return
        except Exception as e:
            print(f"\n[Email] SMTP send failed: {e}")

    # Fallback: log to console when no credentials are configured
    print(f"\n[Email] Would send to {email}:")
    print(f"Subject: {subject}")
    print(f"Risk Level: {scan_result.get('risk_label', 'NONE')}")
    print(f"Fixed: {scan_result.get('fixed', 0)}/{scan_result.get('total', 0)}\n")


def _get_risk_color(risk_level):
    """Get color for risk level"""
    colors = {
        "NONE": "#10b981",
        "LOW": "#3b82f6",
        "MEDIUM": "#f59e0b",
        "HIGH": "#ef4444",
        "CRITICAL": "#dc2626"
    }
    return colors.get(risk_level, "#6b7280")


def _send_smtp_email(to_email, subject, html_body, smtp_cfg):
    """
    Send email via SMTP using credentials from ~/.patchverify/config.json.
    Credentials are saved by `patchverify --setup`.
    """
    smtp_server   = smtp_cfg.get("host", "smtp.gmail.com")
    smtp_port     = int(smtp_cfg.get("port", 587))
    sender_email  = smtp_cfg.get("user", "")
    sender_password = _deobfuscate(smtp_cfg.get("pass", "")) if _AUTH_AVAILABLE else smtp_cfg.get("pass", "")

    if not sender_email or not sender_password:
        raise ValueError("SMTP credentials incomplete — run `patchverify --setup` to configure.")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = to_email

    html_part = MIMEText(html_body, 'html')
    msg.attach(html_part)

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
