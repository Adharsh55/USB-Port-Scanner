import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

DEFAULT_CONFIG_PATH = "config.json"

DEFAULT_CONFIG = {
    "smtp_server": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "recipient_email": "",
    "enable_email_alerts": False,
    "enable_blocking": False
}

def load_config(config_path=DEFAULT_CONFIG_PATH):
    """Loads config.json from path, creating default if not exists."""
    if not os.path.exists(config_path):
        save_config(DEFAULT_CONFIG, config_path)
        return DEFAULT_CONFIG
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            # Ensure all keys exist
            for k, v in DEFAULT_CONFIG.items():
                if k not in config:
                    config[k] = v
            return config
    except Exception:
        return DEFAULT_CONFIG

def save_config(config, config_path=DEFAULT_CONFIG_PATH):
    """Saves config to config.json."""
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
        return True
    except Exception:
        return False

class Notifier:
    def __init__(self, config_path=DEFAULT_CONFIG_PATH):
        self.config_path = config_path

    def send_email_alert(self, subject, body_html):
        """Sends an HTML formatted email alert based on SMTP configuration."""
        config = load_config(self.config_path)
        
        if not config.get("enable_email_alerts"):
            return False, "Email alerts are disabled in config."

        server = config.get("smtp_server")
        port = config.get("smtp_port")
        user = config.get("smtp_user")
        pwd = config.get("smtp_password")
        recipient = config.get("recipient_email")

        if not all([server, port, user, pwd, recipient]):
            return False, "SMTP parameters are not fully configured."

        try:
            # Create message container
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = user
            msg['To'] = recipient

            # HTML Content
            part = MIMEText(body_html, 'html')
            msg.attach(part)

            # Establish Connection
            if port == 465:
                # SSL
                smtp_conn = smtplib.SMTP_SSL(server, port, timeout=10)
            else:
                # STARTTLS (usually 587)
                smtp_conn = smtplib.SMTP(server, port, timeout=10)
                smtp_conn.ehlo()
                smtp_conn.starttls()
                smtp_conn.ehlo()

            smtp_conn.login(user, pwd)
            smtp_conn.sendmail(user, recipient, msg.as_string())
            smtp_conn.quit()
            return True, "Email alert sent successfully."
        except Exception as e:
            return False, f"SMTP Error: {str(e)}"

    def send_test_email(self):
        """Sends a test verification email."""
        subject = "⚠️ USB Trust Manager - SMTP Test Email"
        html = """
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="background-color: #f7f9fa; border: 1px solid #e1e4e6; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto;">
                    <h2 style="color: #007bff; margin-top: 0;">USB Device Trust Manager</h2>
                    <p style="font-size: 16px; font-weight: bold; color: #28a745;">✓ SMTP Connection Verified</p>
                    <p>This is a test email confirming that your email notification settings for the USB Device Trust Manager are functioning correctly.</p>
                    <hr style="border: 0; border-top: 1px solid #e1e4e6; margin: 20px 0;">
                    <p style="font-size: 12px; color: #777;">Generated automatically. Please do not reply to this email.</p>
                </div>
            </body>
        </html>
        """
        # Temporarily bypass the "enable_email_alerts" check for test emails
        config = load_config(self.config_path)
        server = config.get("smtp_server")
        port = config.get("smtp_port")
        user = config.get("smtp_user")
        pwd = config.get("smtp_password")
        recipient = config.get("recipient_email")

        if not all([server, port, user, pwd, recipient]):
            return False, "SMTP configuration is incomplete. Please set all values."

        # Perform the actual SMTP send
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = user
            msg['To'] = recipient
            msg.attach(MIMEText(html, 'html'))

            if port == 465:
                smtp_conn = smtplib.SMTP_SSL(server, port, timeout=10)
            else:
                smtp_conn = smtplib.SMTP(server, port, timeout=10)
                smtp_conn.ehlo()
                smtp_conn.starttls()
                smtp_conn.ehlo()

            smtp_conn.login(user, pwd)
            smtp_conn.sendmail(user, recipient, msg.as_string())
            smtp_conn.quit()
            return True, "Test email sent successfully."
        except Exception as e:
            return False, f"Test Email Failed: {str(e)}"
