"""
Email utility for CyberShield AI.
Sends welcome and login notification emails to users.

Setup: add your Gmail credentials to .streamlit/secrets.toml:
    [email]
    sender   = "your.email@gmail.com"
    password = "your_app_password"   # Gmail App Password (not account password)

To create a Gmail App Password:
  1. Go to https://myaccount.google.com/security
  2. Enable 2-Step Verification
  3. Go to App Passwords → Select "Mail" → Generate
  4. Use the 16-character password here
"""

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime


def _get_credentials() -> tuple[str, str]:
    """Get email credentials from Streamlit secrets or environment variables."""
    try:
        import streamlit as st
        sender   = st.secrets["email"]["sender"]
        password = st.secrets["email"]["password"]
        return sender, password
    except Exception:
        pass
    # Fallback to environment variables
    sender   = os.environ.get("EMAIL_SENDER", "")
    password = os.environ.get("EMAIL_PASSWORD", "")
    return sender, password


def _send(to_email: str, subject: str, html_body: str) -> bool:
    """Send an email. Returns True on success, False on failure."""
    sender, password = _get_credentials()
    if not sender or not password:
        return False  # credentials not configured

    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = f"CyberShield AI <{sender}>"
        msg["To"]      = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
            server.login(sender, password)
            server.sendmail(sender, to_email, msg.as_string())
        return True
    except Exception:
        return False


# ── Email templates ────────────────────────────────────────────────────────────

def send_welcome_email(to_email: str, full_name: str, username: str) -> bool:
    """Send welcome email after account registration."""
    subject = "🛡️ Welcome to CyberShield AI — Your Account is Ready!"
    now_str = datetime.now().strftime("%B %d, %Y at %I:%M %p")

    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#f0f4ff;font-family:'Segoe UI',Arial,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4ff;padding:40px 0;">
        <tr><td align="center">
          <table width="600" cellpadding="0" cellspacing="0"
                 style="background:#ffffff;border-radius:16px;overflow:hidden;
                        box-shadow:0 4px 24px rgba(37,99,235,0.12);">

            <!-- Header -->
            <tr>
              <td style="background:linear-gradient(135deg,#e53935,#ef5350);
                         padding:36px 40px;text-align:center;">
                <div style="font-size:48px;margin-bottom:8px;">🛡️</div>
                <h1 style="color:#ffffff;font-size:26px;font-weight:900;
                           margin:0;letter-spacing:-0.5px;">CyberShield AI</h1>
                <p style="color:rgba(255,255,255,0.85);font-size:14px;margin:6px 0 0 0;">
                  KANAD S.H.I.E.L.D Cybersecurity Hackathon 2026
                </p>
              </td>
            </tr>

            <!-- Body -->
            <tr>
              <td style="padding:40px 40px 32px 40px;">
                <h2 style="color:#0f172a;font-size:22px;font-weight:800;margin:0 0 16px 0;">
                  Welcome aboard, {full_name}! 🎉
                </h2>
                <p style="color:#475569;font-size:15px;line-height:1.7;margin:0 0 20px 0;">
                  Your CyberShield AI account has been successfully created.
                  You now have access to our complete cybersecurity analysis platform.
                </p>

                <!-- Account details box -->
                <table width="100%" cellpadding="0" cellspacing="0"
                       style="background:#f8faff;border:1px solid #e2e8f0;
                              border-radius:12px;margin-bottom:28px;">
                  <tr>
                    <td style="padding:20px 24px;">
                      <p style="color:#64748b;font-size:13px;font-weight:700;
                                text-transform:uppercase;letter-spacing:0.8px;
                                margin:0 0 12px 0;">Account Details</p>
                      <table>
                        <tr>
                          <td style="color:#64748b;font-size:14px;padding:4px 16px 4px 0;">
                            👤 Username
                          </td>
                          <td style="color:#0f172a;font-size:14px;font-weight:700;">
                            {username}
                          </td>
                        </tr>
                        <tr>
                          <td style="color:#64748b;font-size:14px;padding:4px 16px 4px 0;">
                            📧 Email
                          </td>
                          <td style="color:#0f172a;font-size:14px;font-weight:700;">
                            {to_email}
                          </td>
                        </tr>
                        <tr>
                          <td style="color:#64748b;font-size:14px;padding:4px 16px 4px 0;">
                            📅 Registered
                          </td>
                          <td style="color:#0f172a;font-size:14px;font-weight:700;">
                            {now_str}
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                </table>

                <!-- Tools available -->
                <p style="color:#1e293b;font-size:15px;font-weight:700;margin:0 0 14px 0;">
                  🔧 Tools Available to You:
                </p>
                <table width="100%" cellpadding="0" cellspacing="0">
                  <tr>
                    <td width="50%" style="padding:0 8px 8px 0;">
                      <div style="background:#fff1f2;border-radius:8px;padding:12px 14px;">
                        <span style="font-size:20px;">🔍</span>
                        <span style="color:#1e293b;font-size:13px;font-weight:700;
                                     margin-left:8px;">IP Analyzer</span>
                      </div>
                    </td>
                    <td width="50%" style="padding:0 0 8px 0;">
                      <div style="background:#fff1f2;border-radius:8px;padding:12px 14px;">
                        <span style="font-size:20px;">📧</span>
                        <span style="color:#1e293b;font-size:13px;font-weight:700;
                                     margin-left:8px;">Phishing Detector</span>
                      </div>
                    </td>
                  </tr>
                  <tr>
                    <td width="50%" style="padding:0 8px 8px 0;">
                      <div style="background:#fff1f2;border-radius:8px;padding:12px 14px;">
                        <span style="font-size:20px;">🔗</span>
                        <span style="color:#1e293b;font-size:13px;font-weight:700;
                                     margin-left:8px;">URL Scanner</span>
                      </div>
                    </td>
                    <td width="50%" style="padding:0 0 8px 0;">
                      <div style="background:#fff1f2;border-radius:8px;padding:12px 14px;">
                        <span style="font-size:20px;">📊</span>
                        <span style="color:#1e293b;font-size:13px;font-weight:700;
                                     margin-left:8px;">Log Analyzer</span>
                      </div>
                    </td>
                  </tr>
                  <tr>
                    <td width="50%" style="padding:0 8px 0 0;">
                      <div style="background:#fff1f2;border-radius:8px;padding:12px 14px;">
                        <span style="font-size:20px;">🛡️</span>
                        <span style="color:#1e293b;font-size:13px;font-weight:700;
                                     margin-left:8px;">Vuln Scanner</span>
                      </div>
                    </td>
                    <td width="50%">
                      <div style="background:#fff1f2;border-radius:8px;padding:12px 14px;">
                        <span style="font-size:20px;">📄</span>
                        <span style="color:#1e293b;font-size:13px;font-weight:700;
                                     margin-left:8px;">PDF Reports</span>
                      </div>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- Security tip -->
            <tr>
              <td style="padding:0 40px 32px 40px;">
                <div style="background:#f0fdf4;border:1px solid #86efac;border-left:4px solid #22c55e;
                            border-radius:10px;padding:14px 16px;">
                  <p style="color:#14532d;font-size:13px;font-weight:600;margin:0;">
                    🔒 <strong>Security tip:</strong> Never share your password.
                    CyberShield AI will never ask for it via email.
                    If you did not create this account, please ignore this email.
                  </p>
                </div>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="background:#f8faff;border-top:1px solid #e2e8f0;
                         padding:20px 40px;text-align:center;">
                <p style="color:#94a3b8;font-size:12px;margin:0;line-height:1.8;">
                  CyberShield AI · KANAD S.H.I.E.L.D Hackathon 2026<br>
                  Organised by Cyber Crime Branch · For educational use only
                </p>
              </td>
            </tr>

          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """
    return _send(to_email, subject, html)


def send_login_notification(to_email: str, full_name: str, username: str) -> bool:
    """Send login notification email each time user signs in."""
    now     = datetime.now()
    now_str = now.strftime("%B %d, %Y at %I:%M %p")
    subject = f"🔐 CyberShield AI — Login Notification ({now.strftime('%d %b %Y')})"

    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#f0f4ff;font-family:'Segoe UI',Arial,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4ff;padding:40px 0;">
        <tr><td align="center">
          <table width="560" cellpadding="0" cellspacing="0"
                 style="background:#ffffff;border-radius:16px;overflow:hidden;
                        box-shadow:0 4px 24px rgba(37,99,235,0.12);">

            <!-- Header -->
            <tr>
              <td style="background:linear-gradient(135deg,#1e293b,#334155);
                         padding:28px 36px;text-align:center;">
                <div style="font-size:36px;margin-bottom:6px;">🛡️</div>
                <h2 style="color:#ffffff;font-size:20px;font-weight:800;margin:0;">
                  Login Detected
                </h2>
                <p style="color:rgba(255,255,255,0.7);font-size:13px;margin:4px 0 0 0;">
                  CyberShield AI Security Alert
                </p>
              </td>
            </tr>

            <!-- Body -->
            <tr>
              <td style="padding:32px 36px;">
                <p style="color:#0f172a;font-size:16px;font-weight:600;margin:0 0 20px 0;">
                  Hi {full_name},
                </p>
                <p style="color:#475569;font-size:14px;line-height:1.7;margin:0 0 24px 0;">
                  A successful login was recorded for your CyberShield AI account.
                </p>

                <!-- Login details -->
                <table width="100%" cellpadding="0" cellspacing="0"
                       style="background:#f8faff;border:1px solid #e2e8f0;
                              border-radius:12px;margin-bottom:24px;">
                  <tr>
                    <td style="padding:20px 24px;">
                      <p style="color:#64748b;font-size:12px;font-weight:700;
                                text-transform:uppercase;letter-spacing:0.8px;
                                margin:0 0 12px 0;">Login Details</p>
                      <table>
                        <tr>
                          <td style="color:#64748b;font-size:13px;padding:5px 20px 5px 0;">
                            👤 Account
                          </td>
                          <td style="color:#0f172a;font-size:13px;font-weight:700;">
                            {username}
                          </td>
                        </tr>
                        <tr>
                          <td style="color:#64748b;font-size:13px;padding:5px 20px 5px 0;">
                            🕐 Time
                          </td>
                          <td style="color:#0f172a;font-size:13px;font-weight:700;">
                            {now_str}
                          </td>
                        </tr>
                        <tr>
                          <td style="color:#64748b;font-size:13px;padding:5px 20px 5px 0;">
                            ✅ Status
                          </td>
                          <td style="color:#16a34a;font-size:13px;font-weight:700;">
                            Successful
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                </table>

                <!-- Warning box -->
                <div style="background:#fff7ed;border:1px solid #fdba74;
                            border-left:4px solid #f97316;border-radius:10px;
                            padding:14px 16px;">
                  <p style="color:#9a3412;font-size:13px;font-weight:600;margin:0;">
                    ⚠️ If you did not log in, your account may be at risk.
                    Change your password immediately from My Account → Change Password.
                  </p>
                </div>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="background:#f8faff;border-top:1px solid #e2e8f0;
                         padding:16px 36px;text-align:center;">
                <p style="color:#94a3b8;font-size:11px;margin:0;line-height:1.8;">
                  CyberShield AI · KANAD S.H.I.E.L.D Hackathon 2026<br>
                  This is an automated security notification. Do not reply.
                </p>
              </td>
            </tr>

          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """
    return _send(to_email, subject, html)
