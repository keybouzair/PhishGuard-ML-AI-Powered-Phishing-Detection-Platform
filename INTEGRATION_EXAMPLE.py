"""
Integration Example: How to Add Advanced Features to Your App

This file shows the exact code to add to your app.py to enable all advanced features.
"""

# ==================== ADD THESE IMPORTS TO app.py ====================

# Advanced Features Imports
from advanced_features import (
    BrowserExtensionManager,
    ReportGenerator,
    AdvancedEmailNotifications,
    AdvancedSIEMIntegration,
    browser_ext_manager,
    report_generator,
    siem_integration
)

# Integration Imports
from integrations import (
    WebhookManager,
    SlackIntegration,
    TeamsIntegration,
    SIEMConnector,
    ActiveDefenseAgent,
    webhook_manager,
    slack,
    teams,
    siem,
    defense_agent,
    notify_phishing_detection,
    EventType
)

# API Routes Blueprint
from routers.advanced_features_api import advanced_bp

# Email Service
from email_service import EmailService

# ==================== REGISTER BLUEPRINTS ====================

# Add this after creating your Flask app
app.register_blueprint(advanced_bp)

# ==================== ENHANCE EXISTING check_url ROUTE ====================

# Modify your existing /check_url route to look like this:

@app.route('/check_url', methods=['POST'])
def check_url():
    """Enhanced URL checking with advanced features integration"""
    username = session.get('username')
    
    if not username:
        return render_template('user_login.html', error='Please login first')
    
    url_input = request.form.get('url', '').strip()
    
    if not url_input:
        flash('Please enter a URL', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Ensure URL has protocol
    if not url_input.startswith(('http://', 'https://')):
        url_input = 'https://' + url_input
    
    try:
        # Extract features
        features = extract_features(url_input)
        feature_vector = [features.get(f, 0) for f in feature_list]
        
        # Scale features
        feature_vector_scaled = scaler.transform([feature_vector])
        
        # Make prediction
        prediction = model.predict(feature_vector_scaled)[0]
        prediction_score = model.predict_proba(feature_vector_scaled)[0][1] * 100
        
        # Determine result
        is_phishing = prediction == 1
        result_text = "🚨 PHISHING" if is_phishing else "✅ SAFE"
        
        # ==================== ADVANCED FEATURES INTEGRATION ====================
        
        # 1. TRIGGER INTEGRATIONS FOR CRITICAL THREATS
        if is_phishing and prediction_score >= 70:
            # Notify through all channels
            notify_phishing_detection(
                url=url_input,
                threat_score=prediction_score,
                details={
                    'domain_age': features.get('domain_age'),
                    'url_length': features.get('URL_Length'),
                    'sensitive_keywords': features.get('Sensitive_Words'),
                    'ssl_status': features.get('have_symbol')
                },
                user=username
            )
            
            # This triggers:
            # - Slack alert
            # - Teams alert
            # - Webhook events
            # - SIEM logging
            # - Active defense (if score > 90)
        
        # 2. LOG TO SIEM
        if is_phishing:
            siem.log_phishing_event(
                url=url_input,
                threat_score=prediction_score,
                prediction={
                    'is_phishing': True,
                    'confidence': prediction_score,
                    'features': features
                },
                user=username
            )
        
        # 3. LOG TO DATABASE (existing code)
        from database import log_url_check
        log_url_check(username, url_input, result_text, prediction_score)
        
        # ==================== END ADVANCED FEATURES ====================
        
        # Return results
        flash(f'{result_text} - Threat Score: {prediction_score:.1f}%', 
              'danger' if is_phishing else 'success')
        
        return redirect(url_for('user_dashboard'))
    
    except Exception as e:
        print(f"Error checking URL: {e}")
        flash(f'Error analyzing URL: {str(e)}', 'error')
        return redirect(url_for('user_dashboard'))


# ==================== ADD NEW ROUTE FOR ADVANCED DASHBOARD ====================

@app.route('/advanced_dashboard')
def advanced_dashboard():
    """Advanced features dashboard"""
    username = session.get('username')
    
    if not username or session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    
    return render_template('admin_dashboard_advanced.html')


# ==================== ADD EMAIL SENDING ENDPOINT ====================

@app.route('/send_test_email', methods=['POST'])
def send_test_email():
    """Send test email"""
    try:
        email = request.form.get('email')
        threat_score = request.form.get('threat_score', 95.5)
        url = request.form.get('url', 'https://example-phishing.com')
        
        service = EmailService()
        html_body, text_body = AdvancedEmailNotifications.create_phishing_alert_email(
            url=url,
            threat_score=float(threat_score)
        )
        
        success = service.send_email(
            to_email=email,
            subject='🚨 Security Alert: Phishing URL Detected',
            html_body=html_body,
            text_body=text_body
        )
        
        if success:
            flash(f'Test email sent to {email}', 'success')
        else:
            flash('Failed to send email', 'error')
    
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('advanced_dashboard'))


# ==================== ADD SCHEDULED TASKS ====================

# For sending daily summaries (add to app initialization)
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

def send_daily_summary():
    """Send daily security summary emails"""
    try:
        from database import get_db
        conn = get_db()
        cursor = conn.cursor()
        
        # Get admin emails
        cursor.execute("SELECT email FROM users WHERE role='admin' LIMIT 5")
        admins = cursor.fetchall()
        conn.close()
        
        # Calculate stats
        from datetime import datetime, timedelta
        start_date = datetime.now() - timedelta(days=1)
        
        # Get statistics for the day
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*), SUM(CASE WHEN is_phishing=1 THEN 1 ELSE 0 END)
            FROM url_checks WHERE checked_at >= ?
        """, (start_date,))
        
        result = cursor.fetchone()
        total_urls = result[0] or 0
        phishing_count = result[1] or 0
        conn.close()
        
        stats = {
            'urls_today': total_urls,
            'phishing_today': phishing_count,
            'safe_today': total_urls - phishing_count,
            'active_users': 0,
            'detection_rate': (phishing_count / total_urls * 100) if total_urls > 0 else 0
        }
        
        # Send to all admins
        service = EmailService()
        html_body, text_body = AdvancedEmailNotifications.create_daily_summary_email(stats)
        
        for admin in admins:
            service.send_email(
                to_email=admin[0],
                subject='📊 Daily Security Summary Report',
                html_body=html_body,
                text_body=text_body
            )
        
        # Also send to Slack
        slack.send_daily_summary(stats)
        teams.send_daily_summary(stats)
        
        print(f"Daily summary sent to {len(admins)} admins")
    
    except Exception as e:
        print(f"Error sending daily summary: {e}")


# Initialize scheduler (add to app creation)
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=send_daily_summary,
    trigger="cron",
    hour=9,
    minute=0,
    id='daily_summary',
    name='Send daily security summary',
    replace_existing=True
)
scheduler.start()

# Shut down scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())


# ==================== ADD CONTEXT PROCESSOR FOR TEMPLATES ====================

@app.context_processor
def inject_advanced_features():
    """Make advanced features available in templates"""
    return {
        'has_slack': bool(os.environ.get('SLACK_WEBHOOK_URL')),
        'has_teams': bool(os.environ.get('TEAMS_WEBHOOK_URL')),
        'has_email': bool(os.environ.get('SMTP_USERNAME')),
        'has_siem': bool(os.environ.get('SPLUNK_HEC_URL')) or bool(os.environ.get('ELASTIC_URL'))
    }


# ==================== CONFIGURATION IN config.py ====================

# Add this to your config.py file:

import os
from datetime import timedelta

class Config:
    # Existing config...
    
    # Advanced Features Configuration
    
    # Email Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    FROM_EMAIL = os.environ.get('FROM_EMAIL', 'noreply@phishingdetector.com')
    
    # Slack Configuration
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')
    SLACK_ALERT_THRESHOLD = int(os.environ.get('SLACK_ALERT_THRESHOLD', 70))
    
    # Teams Configuration
    TEAMS_WEBHOOK_URL = os.environ.get('TEAMS_WEBHOOK_URL')
    TEAMS_ALERT_THRESHOLD = int(os.environ.get('TEAMS_ALERT_THRESHOLD', 70))
    
    # SIEM Configuration
    SPLUNK_HEC_URL = os.environ.get('SPLUNK_HEC_URL')
    SPLUNK_HEC_TOKEN = os.environ.get('SPLUNK_HEC_TOKEN')
    ELASTIC_URL = os.environ.get('ELASTIC_URL')
    ELASTIC_API_KEY = os.environ.get('ELASTIC_API_KEY')
    
    # Active Defense Configuration
    DEFENSE_THRESHOLD = int(os.environ.get('DEFENSE_THRESHOLD', 90))
    AUTO_BLOCK_ENABLED = os.environ.get('AUTO_BLOCK_ENABLED', 'true').lower() == 'true'
    
    # Report Configuration
    REPORT_RETENTION_DAYS = int(os.environ.get('REPORT_RETENTION_DAYS', 90))
    
    # Scheduler Configuration
    SCHEDULER_API_ENABLED = True


# ==================== ENVIRONMENT VARIABLES (.env) ====================

"""
Create a .env file with these variables:

# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
FROM_EMAIL=noreply@phishingdetector.com

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SLACK_ALERT_THRESHOLD=70

# Teams
TEAMS_WEBHOOK_URL=https://outlook.webhook.office.com/webhookb2/YOUR/WEBHOOK/URL
TEAMS_ALERT_THRESHOLD=70

# Splunk
SPLUNK_HEC_URL=https://splunk-server.com:8088
SPLUNK_HEC_TOKEN=your-hec-token

# Elasticsearch
ELASTIC_URL=https://elasticsearch-server.com:9200
ELASTIC_API_KEY=your-api-key

# Active Defense
DEFENSE_THRESHOLD=90
AUTO_BLOCK_ENABLED=true

# Reports
REPORT_RETENTION_DAYS=90
"""


# ==================== REQUIREMENTS.TXT ADDITIONS ====================

"""
Add these to your requirements.txt or requirements_ultimate.txt:

# Advanced Features
requests>=2.31.0
pandas>=2.0.0
openpyxl>=3.1.0
Jinja2>=3.1.0
pdfkit>=1.0.0
python-whois>=0.7.3
pyotp>=2.9.0
cryptography>=41.0.0
APScheduler>=3.10.0
flask-apscheduler>=1.12.0

# Email
secure-smtplib>=0.1.1

# Webhook Management
python-dateutil>=2.8.2
"""


# ==================== POWERPOINT IMAGE EXAMPLE ====================

"""
Example: create a PowerPoint slide and add an image.

from pptx import Presentation
from pptx.util import Inches

def create_ppt_with_image(image_path, output_path):
    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[5])

    slide.shapes.add_picture(
        image_path,
        Inches(1),
        Inches(1),
        width=Inches(6),
    )

    prs.save(output_path)


# Usage:
# create_ppt_with_image("path/to/image.png", "output.pptx")
"""


# ==================== TESTING CODE ====================

"""
Test all features with these commands:

# Test Browser Extension Registration
curl -X POST http://localhost:5000/api/extension/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "session_id": "ext-123",
    "version": "1.0.0",
    "browser": "Chrome",
    "os": "Windows"
  }'

# Test Report Generation
curl "http://localhost:5000/api/reports/json?days=30" | python -m json.tool

# Test Email Sending
curl -X POST http://localhost:5000/api/notifications/send-alert \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://phishing-example.com",
    "threat_score": 95.5,
    "recipient": "admin@example.com"
  }'

# Test Webhook Registration
curl -X POST http://localhost:5000/api/webhooks/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "Test Webhook",
    "url": "https://webhook.site/your-id",
    "events": ["phishing.detected"],
    "created_by": "admin"
  }'

# Test SIEM Configuration
curl -X POST http://localhost:5000/api/siem/configure \\
  -H "Content-Type: application/json" \\
  -d '{
    "platform": "splunk",
    "config": {
      "hec_url": "https://splunk:8088",
      "hec_token": "token"
    }
  }'

# Test Advanced Dashboard
curl http://localhost:5000/api/dashboard/advanced
"""


# ==================== COMPLETE INTEGRATION CHECKLIST ====================

"""
✅ Step 1: Copy new files to your project
   - advanced_features.py
   - routers/advanced_features_api.py
   - ADVANCED_FEATURES_GUIDE.md
   - ADVANCED_FEATURES_CHECKLIST.md
   - QUICK_REFERENCE_ADVANCED.md
   - ADVANCED_FEATURES_SUMMARY.md

✅ Step 2: Install dependencies
   pip install -r requirements_ultimate.txt

✅ Step 3: Create .env file
   Copy environment variables from above

✅ Step 4: Update app.py
   - Add imports (from above)
   - Register blueprint
   - Enhance check_url route
   - Add new routes
   - Add scheduled tasks

✅ Step 5: Update config.py
   - Add advanced features config

✅ Step 6: Test all endpoints
   - Use curl commands from above
   - Check browser extension
   - Verify email sending
   - Test SIEM integration

✅ Step 7: Deploy to production
   - Configure production .env
   - Enable HTTPS
   - Set up SIEM platforms
   - Configure webhooks
   - Test end-to-end

✅ Step 8: Monitor and maintain
   - Review logs daily
   - Check SIEM events
   - Update threat intelligence
   - Maintain API keys
"""

print("""
✅ Advanced Features Integration Complete!

Your phishing detection system now includes:
- 🌐 Browser Extension for real-time checking
- 📧 Advanced email notifications
- 📊 Multi-format report generation
- 🔗 Slack/Teams integration
- 🛡️ SIEM platform support
- 🤖 Active defense automation

See ADVANCED_FEATURES_SUMMARY.md for complete overview
See ADVANCED_FEATURES_GUIDE.md for detailed documentation
See QUICK_REFERENCE_ADVANCED.md for API reference
""")
