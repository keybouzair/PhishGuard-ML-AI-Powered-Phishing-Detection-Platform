"""
Email Notification Service
Sends email alerts for phishing detections and system notifications
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
from datetime import datetime
from typing import List, Optional
import sqlite3

import html

# Email Configuration (use environment variables in production)
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', 'your_email@gmail.com')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', 'your_app_password')
FROM_EMAIL = os.environ.get('FROM_EMAIL', 'noreply@phishingdetector.com')
FROM_NAME = 'Phishing Detection System'

DATABASE_PATH = os.environ.get("DATABASE_PATH")
if not DATABASE_PATH:
    if os.environ.get("VERCEL") == "1":
        DATABASE_PATH = '/tmp/phishing_detection.db'
    else:
        DATABASE_PATH = 'phishing_detection.db'


class EmailService:
    """Email notification service for the phishing detection system"""
    
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.username = SMTP_USERNAME
        self.password = SMTP_PASSWORD
        self.from_email = FROM_EMAIL
        self.from_name = FROM_NAME
    
    def _get_connection(self):
        """Create SMTP connection"""
        context = ssl.create_default_context()
        server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        server.starttls(context=context)
        server.login(self.username, self.password)
        return server
    
    def send_email(self, to_email: str, subject: str, html_body: str, 
                   text_body: str = None, attachments: List[str] = None) -> bool:
        """
        Send an email
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_body: HTML content of the email
            text_body: Plain text fallback (optional)
            attachments: List of file paths to attach (optional)
        
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            message = MIMEMultipart('alternative')
            message['From'] = f'{self.from_name} <{self.from_email}>'
            message['To'] = to_email
            message['Subject'] = subject
            
            # Add text body if provided
            if text_body:
                text_part = MIMEText(text_body, 'plain')
                message.attach(text_part)
            
            # Add HTML body
            html_part = MIMEText(html_body, 'html')
            message.attach(html_part)
            
            # Add attachments
            if attachments:
                for filepath in attachments:
                    if os.path.exists(filepath):
                        with open(filepath, 'rb') as f:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(f.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename={os.path.basename(filepath)}'
                            )
                            message.attach(part)
            
            # Send email
            server = self._get_connection()
            server.sendmail(self.from_email, to_email, message.as_string())
            server.quit()
            
            # Log the email
            self._log_email(to_email, subject, 'sent')
            
            return True
            
        except Exception as e:
            print(f"Email error: {e}")
            self._log_email(to_email, subject, f'failed: {str(e)}')
            return False
    
    def _log_email(self, to_email: str, subject: str, status: str):
        """Log email sending attempt to database"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Create table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_email TEXT,
                    subject TEXT,
                    status TEXT,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                INSERT INTO email_log (to_email, subject, status)
                VALUES (?, ?, ?)
            ''', (to_email, subject, status))
            
            conn.commit()
            conn.close()
        except Exception:
            # D-04: Fixed bare except to catch general Exception
            pass
    
    def send_phishing_alert(self, user_email: str, username: str, 
                           url: str, threat_score: float, details: dict = None):
        """Send phishing detection alert to user"""
        
        # C-16: HTML escape user values
        username_esc = html.escape(username)
        url_esc = html.escape(url)

        subject = "⚠️ Phishing Alert - Dangerous URL Detected!"
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #eb3349, #f45c43); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #fff; padding: 30px; border: 1px solid #ddd; }}
        .alert-box {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 5px; padding: 15px; margin: 20px 0; }}
        .danger {{ color: #dc3545; }}
        .url-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; word-break: break-all; font-family: monospace; }}
        .score {{ font-size: 48px; font-weight: bold; color: #dc3545; text-align: center; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }}
        .btn {{ display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Phishing Alert</h1>
            <p>Dangerous URL Detected</p>
        </div>
        
        <div class="content">
            <p>Hello <strong>{username_esc}</strong>,</p>
            
            <p>Our system has detected a potentially <span class="danger">dangerous phishing URL</span> that you recently checked:</p>
            
            <div class="url-box">
                {url_esc}
            </div>
            
            <div class="alert-box">
                <h3>⚠️ Threat Assessment</h3>
                <p class="score">{threat_score:.1f}%</p>
                <p style="text-align: center;">Threat Score</p>
            </div>
            
            <h3>🛡️ Recommended Actions:</h3>
            <ul>
                <li><strong>Do not click</strong> on this link or enter any personal information</li>
                <li><strong>Do not download</strong> any files from this website</li>
                <li><strong>Report</strong> this URL to your IT security team</li>
                <li><strong>Delete</strong> any emails containing this URL</li>
                <li>If you've already visited, <strong>change your passwords</strong> immediately</li>
            </ul>
            
            <h3>🔍 Why is this dangerous?</h3>
            <p>This URL exhibits characteristics commonly associated with phishing attacks, including:</p>
            <ul>
                <li>Suspicious domain patterns</li>
                <li>Deceptive URL structure</li>
                <li>Known malicious indicators</li>
            </ul>
            
            <p style="text-align: center; margin-top: 30px;">
                <a href="#" class="btn">View Full Report</a>
            </p>
        </div>
        
        <div class="footer">
            <p>This is an automated message from the Phishing Detection System.</p>
            <p>Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>If you have questions, contact your system administrator.</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_body = f"""
PHISHING ALERT - DANGEROUS URL DETECTED

Hello {username},

Our system has detected a potentially dangerous phishing URL that you recently checked:

URL: {url}
Threat Score: {threat_score:.1f}%

RECOMMENDED ACTIONS:
- Do not click on this link or enter any personal information
- Do not download any files from this website
- Report this URL to your IT security team
- Delete any emails containing this URL
- If you've already visited, change your passwords immediately

This is an automated message from the Phishing Detection System.
Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return self.send_email(user_email, subject, html_body, text_body)
    
    def send_daily_digest(self, admin_email: str, stats: dict):
        """Send daily security digest to admin"""
        
        subject = f"📊 Daily Security Digest - {datetime.now().strftime('%Y-%m-%d')}"
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #fff; padding: 30px; border: 1px solid #ddd; }}
        .stats-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 32px; font-weight: bold; color: #007bff; }}
        .stat-label {{ color: #666; font-size: 14px; }}
        .danger {{ color: #dc3545; }}
        .success {{ color: #28a745; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Daily Security Digest</h1>
            <p>{datetime.now().strftime('%B %d, %Y')}</p>
        </div>
        
        <div class="content">
            <h2>Today's Summary</h2>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats.get('urls_today', 0)}</div>
                    <div class="stat-label">URLs Checked Today</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number danger">{stats.get('phishing_today', 0)}</div>
                    <div class="stat-label">Phishing Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number success">{stats.get('safe_today', 0)}</div>
                    <div class="stat-label">Safe URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats.get('active_users', 0)}</div>
                    <div class="stat-label">Active Users</div>
                </div>
            </div>
            
            <h3>📈 Overall Statistics</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #ddd;">
                    <td style="padding: 10px;">Total URLs Checked (All Time)</td>
                    <td style="padding: 10px; text-align: right; font-weight: bold;">{stats.get('total_urls', 0)}</td>
                </tr>
                <tr style="border-bottom: 1px solid #ddd;">
                    <td style="padding: 10px;">Total Phishing Detected</td>
                    <td style="padding: 10px; text-align: right; font-weight: bold; color: #dc3545;">{stats.get('total_phishing', 0)}</td>
                </tr>
                <tr style="border-bottom: 1px solid #ddd;">
                    <td style="padding: 10px;">Detection Rate</td>
                    <td style="padding: 10px; text-align: right; font-weight: bold;">{stats.get('detection_rate', 0):.1f}%</td>
                </tr>
                <tr style="border-bottom: 1px solid #ddd;">
                    <td style="padding: 10px;">Registered Users</td>
                    <td style="padding: 10px; text-align: right; font-weight: bold;">{stats.get('total_users', 0)}</td>
                </tr>
                <tr>
                    <td style="padding: 10px;">Blocklist Size</td>
                    <td style="padding: 10px; text-align: right; font-weight: bold;">{stats.get('blocklist_size', 0)}</td>
                </tr>
            </table>
        </div>
        
        <div class="footer">
            <p>This is an automated daily digest from the Phishing Detection System.</p>
            <p>Login to the admin dashboard for detailed analytics.</p>
        </div>
    </div>
</body>
</html>
"""
        
        return self.send_email(admin_email, subject, html_body)
    
    def send_welcome_email(self, user_email: str, username: str):
        """Send welcome email to new user"""
        
        # C-16: HTML escape user values
        username_esc = html.escape(username)

        subject = "🎉 Welcome to Phishing Detection System!"
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #11998e, #38ef7d); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #fff; padding: 30px; border: 1px solid #ddd; }}
        .feature {{ display: flex; margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; }}
        .feature-icon {{ font-size: 30px; margin-right: 15px; }}
        .btn {{ display: inline-block; padding: 12px 30px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome!</h1>
            <p>You're now protected against phishing attacks</p>
        </div>
        
        <div class="content">
            <h2>Hello {username_esc}!</h2>
            
            <p>Welcome to the Phishing Detection System. Your account has been successfully created.</p>
            
            <h3>What you can do:</h3>
            
            <div class="feature">
                <div class="feature-icon">🔍</div>
                <div>
                    <strong>Check URLs</strong>
                    <p>Instantly verify if a URL is safe or potentially malicious.</p>
                </div>
            </div>
            
            <div class="feature">
                <div class="feature-icon">📊</div>
                <div>
                    <strong>View Statistics</strong>
                    <p>Track your URL checking history and safety score.</p>
                </div>
            </div>
            
            <div class="feature">
                <div class="feature-icon">🔔</div>
                <div>
                    <strong>Get Alerts</strong>
                    <p>Receive instant notifications when dangerous URLs are detected.</p>
                </div>
            </div>
            
            <div class="feature">
                <div class="feature-icon">📱</div>
                <div>
                    <strong>API Access</strong>
                    <p>Integrate our detection system with your applications.</p>
                </div>
            </div>
            
            <p style="text-align: center; margin-top: 30px;">
                <a href="#" class="btn">Start Checking URLs</a>
            </p>
        </div>
        
        <div class="footer">
            <p>Stay safe online!</p>
            <p>The Phishing Detection Team</p>
        </div>
    </div>
</body>
</html>
"""
        
        return self.send_email(user_email, subject, html_body)
    
    def send_password_reset(self, user_email: str, username: str, reset_token: str):
        """Send password reset email"""
        
        # C-16: HTML escape user values
        username_esc = html.escape(username)
        reset_token_esc = html.escape(reset_token)

        subject = "🔐 Password Reset Request"
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #fff; padding: 30px; border: 1px solid #ddd; }}
        .token-box {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 24px; font-family: monospace; border-radius: 8px; letter-spacing: 3px; margin: 20px 0; }}
        .btn {{ display: inline-block; padding: 12px 30px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Password Reset</h1>
        </div>
        
        <div class="content">
            <p>Hello <strong>{username_esc}</strong>,</p>
            
            <p>We received a request to reset your password. Use the code below to complete the process:</p>
            
            <div class="token-box">
                {reset_token_esc}
            </div>
            
            <div class="warning">
                <strong>⚠️ Security Notice:</strong>
                <ul>
                    <li>This code expires in 15 minutes</li>
                    <li>Never share this code with anyone</li>
                    <li>If you didn't request this, ignore this email</li>
                </ul>
            </div>
            
            <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message. Please do not reply.</p>
            <p>Phishing Detection System</p>
        </div>
    </div>
</body>
</html>
"""
        
        return self.send_email(user_email, subject, html_body)


class NotificationManager:
    """Manages all system notifications"""
    
    def __init__(self):
        self.email_service = EmailService()
    
    def notify_phishing_detection(self, username: str, url: str, 
                                  threat_score: float, details: dict = None):
        """Notify user about phishing detection"""
        # Get user email from database
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT email FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            conn.close()
            
            if result and result[0]:
                return self.email_service.send_phishing_alert(
                    result[0], username, url, threat_score, details
                )
        except Exception as e:
            print(f"Notification error: {e}")
        
        return False
    
    def send_admin_digest(self, stats: dict):
        """Send digest to all admin users"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT email FROM users WHERE role = "admin" AND email IS NOT NULL')
            admins = cursor.fetchall()
            conn.close()
            
            success_count = 0
            for admin in admins:
                if admin[0]:
                    if self.email_service.send_daily_digest(admin[0], stats):
                        success_count += 1
            
            return success_count
        except Exception as e:
            print(f"Admin digest error: {e}")
            return 0


# Create singleton instance
email_service = EmailService()
notification_manager = NotificationManager()


def send_phishing_alert(user_email: str, username: str, url: str, threat_score: float):
    """Quick function to send phishing alert"""
    return email_service.send_phishing_alert(user_email, username, url, threat_score)


def send_welcome(user_email: str, username: str):
    """Quick function to send welcome email"""
    return email_service.send_welcome_email(user_email, username)
