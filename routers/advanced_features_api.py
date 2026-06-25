"""
Advanced Features API Routes
Includes browser extension endpoints, report generation, and advanced integrations
"""

from flask import Blueprint, jsonify, request, send_file, render_template_string, session
from functools import wraps
import json
from datetime import datetime
from advanced_features import (
    BrowserExtensionManager, ReportGenerator, AdvancedEmailNotifications, 
    AdvancedSIEMIntegration, browser_ext_manager, report_generator, siem_integration
)
from email_service import EmailService

advanced_bp = Blueprint('advanced', __name__, url_prefix='/api')

# Email service instance
email_service = EmailService()


# A-04: Require admin authentication for ALL routes in this blueprint
@advanced_bp.before_request
def _require_admin_session():
    """Block unauthenticated access to the entire /api/ advanced blueprint."""
    # Allow CORS preflight
    if request.method == 'OPTIONS':
        return None
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Authentication required', 'status': 'forbidden'}), 403


# ==================== BROWSER EXTENSION ENDPOINTS ====================

@advanced_bp.route('/extension/register', methods=['POST'])
def register_extension():
    """Register browser extension session"""
    try:
        data = request.get_json()
        result = browser_ext_manager.register_session(
            session_id=data.get('session_id'),
            extension_version=data.get('version'),
            browser_type=data.get('browser'),
            os_type=data.get('os'),
            user_id=data.get('user_id')
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/extension/log-action', methods=['POST'])
def log_extension_action():
    """Log browser extension action"""
    try:
        data = request.get_json()
        success = browser_ext_manager.log_extension_action(
            session_id=data.get('session_id'),
            action=data.get('action'),
            url=data.get('url'),
            result=data.get('result')
        )
        return jsonify({'success': success}), 200 if success else 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/extension/stats/<session_id>', methods=['GET'])
def get_extension_stats(session_id):
    """Get browser extension statistics"""
    try:
        stats = browser_ext_manager.get_extension_stats(session_id)
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/extension/sessions', methods=['GET'])
def get_extension_sessions():
    """Get all browser extension sessions"""
    try:
        sessions = browser_ext_manager.get_all_sessions()
        return jsonify(sessions), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ==================== REPORT GENERATION ENDPOINTS ====================

@advanced_bp.route('/reports/html', methods=['GET'])
def generate_html_report():
    """Generate HTML report"""
    try:
        days = request.args.get('days', 30, type=int)
        html_content = report_generator.generate_html_report(days)
        return html_content, 200, {'Content-Type': 'text/html'}
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/reports/csv', methods=['GET'])
def generate_csv_report():
    """Generate CSV report"""
    try:
        days = request.args.get('days', 30, type=int)
        csv_content = report_generator.generate_csv_report(days)
        
        return send_file(
            io.BytesIO(csv_content.encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'phishing_report_{datetime.now().strftime("%Y%m%d")}.csv'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/reports/json', methods=['GET'])
def generate_json_report():
    """Generate JSON report"""
    try:
        days = request.args.get('days', 30, type=int)
        json_content = report_generator.generate_json_report(days)
        return jsonify(json.loads(json_content)), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/reports/pdf', methods=['GET'])
def generate_pdf_report():
    """Generate PDF report"""
    try:
        days = request.args.get('days', 30, type=int)
        pdf_content = report_generator.generate_pdf_report(days)
        
        return send_file(
            io.BytesIO(pdf_content),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'phishing_report_{datetime.now().strftime("%Y%m%d")}.pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/reports/export', methods=['GET'])
def export_detection_history():
    """Export detection history"""
    try:
        format_type = request.args.get('format', 'csv', type=str)
        days = request.args.get('days', 30, type=int)
        
        content = report_generator.export_detection_history(format_type, days)
        
        if format_type == 'csv':
            return send_file(
                io.BytesIO(content.encode()),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'detection_history_{datetime.now().strftime("%Y%m%d")}.csv'
            )
        elif format_type == 'json':
            return send_file(
                io.BytesIO(content.encode()),
                mimetype='application/json',
                as_attachment=True,
                download_name=f'detection_history_{datetime.now().strftime("%Y%m%d")}.json'
            )
        elif format_type == 'excel':
            return send_file(
                io.BytesIO(content),
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'detection_history_{datetime.now().strftime("%Y%m%d")}.xlsx'
            )
        
        return jsonify({'error': 'Invalid format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ==================== EMAIL NOTIFICATION ENDPOINTS ====================

@advanced_bp.route('/notifications/send-alert', methods=['POST'])
def send_alert_email():
    """Send phishing alert email"""
    try:
        data = request.get_json()
        url = data.get('url')
        threat_score = data.get('threat_score', 0)
        recipient = data.get('recipient')
        
        html_body, text_body = AdvancedEmailNotifications.create_phishing_alert_email(
            url, threat_score
        )
        
        success = email_service.send_email(
            to_email=recipient,
            subject='🚨 Security Alert: Phishing URL Detected',
            html_body=html_body,
            text_body=text_body
        )
        
        return jsonify({'success': success}), 200 if success else 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/notifications/send-summary', methods=['POST'])
def send_summary_email():
    """Send daily summary email"""
    try:
        data = request.get_json()
        stats = data.get('stats', {})
        recipient = data.get('recipient')
        
        html_body, text_body = AdvancedEmailNotifications.create_daily_summary_email(stats)
        
        success = email_service.send_email(
            to_email=recipient,
            subject='📊 Daily Security Summary Report',
            html_body=html_body,
            text_body=text_body
        )
        
        return jsonify({'success': success}), 200 if success else 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ==================== SIEM INTEGRATION ENDPOINTS ====================

@advanced_bp.route('/siem/configure', methods=['POST'])
def configure_siem():
    """Configure SIEM platform"""
    try:
        data = request.get_json()
        platform = data.get('platform')
        config = data.get('config', {})
        
        siem_integration.configure_siem(platform, config)
        
        return jsonify({'success': True, 'platform': platform}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/siem/send-event', methods=['POST'])
def send_siem_event():
    """Send event to SIEM"""
    try:
        data = request.get_json()
        platform = data.get('platform')
        event_data = data.get('event_data', {})
        
        success = siem_integration.send_event_to_siem(platform, event_data)
        
        return jsonify({'success': success}), 200 if success else 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ==================== SLACK/TEAMS WEBHOOK ENDPOINTS ====================

@advanced_bp.route('/webhooks/register', methods=['POST'])
def register_webhook():
    """Register webhook"""
    try:
        from integrations import webhook_manager
        
        data = request.get_json()
        result = webhook_manager.register_webhook(
            name=data.get('name'),
            url=data.get('url'),
            events=data.get('events', []),
            secret=data.get('secret'),
            created_by=data.get('created_by', 'api')
        )
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/webhooks', methods=['GET'])
def get_webhooks():
    """Get all webhooks"""
    try:
        from integrations import webhook_manager
        webhooks = webhook_manager.get_webhooks()
        return jsonify(webhooks), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/webhooks/<int:webhook_id>', methods=['DELETE'])
def delete_webhook(webhook_id):
    """Delete webhook"""
    try:
        from integrations import webhook_manager
        success = webhook_manager.delete_webhook(webhook_id)
        return jsonify({'success': success}), 200 if success else 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@advanced_bp.route('/webhooks/test', methods=['POST'])
def test_webhook():
    """Test webhook"""
    try:
        from integrations import webhook_manager
        
        data = request.get_json()
        event_type = data.get('event_type', 'test.event')
        payload = data.get('payload', {'test': True})
        
        webhook_manager.trigger_event(event_type, payload)
        
        return jsonify({'success': True, 'message': 'Webhook test triggered'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ==================== ADVANCED FEATURES DASHBOARD ====================

@advanced_bp.route('/dashboard/advanced', methods=['GET'])
def advanced_dashboard():
    """Advanced features dashboard"""
    try:
        # Collect all data for advanced dashboard
        sessions = browser_ext_manager.get_all_sessions(active_only=True)
        
        dashboard_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Advanced Features Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; }
                h1 { color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }
                .section { background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .feature-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin: 20px 0; }
                .feature-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; cursor: pointer; transition: transform 0.3s; }
                .feature-card:hover { transform: translateY(-5px); }
                .feature-card h3 { margin: 0; font-size: 20px; }
                .feature-card p { margin: 10px 0 0 0; font-size: 14px; }
                button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
                button:hover { background: #764ba2; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th { background: #667eea; color: white; padding: 12px; text-align: left; }
                td { padding: 10px; border-bottom: 1px solid #ddd; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚀 Advanced Features Dashboard</h1>
                
                <div class="section">
                    <h2>📱 Browser Extension</h2>
                    <div class="feature-grid">
                        <div class="feature-card">
                            <h3>Active Sessions</h3>
                            <p>''' + str(len(sessions)) + ''' extension instances running</p>
                            <button onclick="loadSessions()">View Details</button>
                        </div>
                        <div class="feature-card">
                            <h3>Auto-Scan</h3>
                            <p>Automatic URL checking while browsing</p>
                            <button onclick="configureAutoScan()">Configure</button>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>📊 Report Generation</h2>
                    <div class="feature-grid">
                        <div class="feature-card">
                            <h3>Export Reports</h3>
                            <p>Download in CSV, JSON, PDF, or Excel format</p>
                            <button onclick="generateReport('csv')">Download CSV</button>
                        </div>
                        <div class="feature-card">
                            <h3>Security Analytics</h3>
                            <p>Detailed threat analysis and statistics</p>
                            <button onclick="viewAnalytics()">View Analytics</button>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>🔔 Notifications</h2>
                    <div class="feature-grid">
                        <div class="feature-card">
                            <h3>Email Alerts</h3>
                            <p>Real-time phishing detection alerts</p>
                            <button onclick="configureEmail()">Configure</button>
                        </div>
                        <div class="feature-card">
                            <h3>Slack/Teams</h3>
                            <p>Webhook integration with chat platforms</p>
                            <button onclick="configureWebhooks()">Setup</button>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>🛡️ SIEM Integration</h2>
                    <div class="feature-grid">
                        <div class="feature-card">
                            <h3>Splunk</h3>
                            <p>Send events to Splunk HEC</p>
                            <button onclick="configureSIEM('splunk')">Configure</button>
                        </div>
                        <div class="feature-card">
                            <h3>Elasticsearch</h3>
                            <p>Forward logs to Elastic Stack</p>
                            <button onclick="configureSIEM('elastic')">Configure</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                function generateReport(format) {
                    window.location.href = `/api/reports/${format}?days=30`;
                }
                function loadSessions() {
                    alert('Fetching browser extension sessions...');
                }
                function configureAutoScan() {
                    alert('Open browser extension settings to enable auto-scan');
                }
                function configureEmail() {
                    alert('Configure email notifications in admin panel');
                }
                function configureWebhooks() {
                    alert('Setup webhooks in integrations panel');
                }
                function configureSIEM(platform) {
                    alert('Configure ' + platform + ' integration');
                }
                function viewAnalytics() {
                    alert('Viewing detailed analytics...');
                }
            </script>
        </body>
        </html>
        '''
        
        return render_template_string(dashboard_html), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# Import necessary modules
import io
