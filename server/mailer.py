"""Email notification service for PatchVerify"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def send_scan_complete_email(email, scan_result):
    """
    Send email notification when scan completes

    Args:
        email: Recipient email address
        scan_result: Dict containing scan results
    """
    subject = f"PatchVerify Scan Complete: {scan_result['app']} {scan_result['old_version']} → {scan_result['new_version']}"

    # Create HTML email body
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

    # For now, just log that email would be sent
    # In production, you'd configure SMTP settings
    print(f"\n[Email] Would send to {email}:")
    print(f"Subject: {subject}")
    print(f"Risk Level: {scan_result.get('risk_label', 'NONE')}")
    print(f"Fixed: {scan_result.get('fixed', 0)}/{scan_result.get('total', 0)}\n")

    # TODO: Uncomment and configure for production
    # _send_smtp_email(email, subject, html_body)

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

def _send_smtp_email(to_email, subject, html_body):
    """
    Send email via SMTP (configure for production)
    """
    # Configure these settings
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SENDER_EMAIL = "patchverify@example.com"
    SENDER_PASSWORD = "your-app-password"

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email

    html_part = MIMEText(html_body, 'html')
    msg.attach(html_part)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)