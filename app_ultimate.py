"""Compatibility wrapper for ultimate app mode.

This module now delegates to the canonical Flask application in `app.py`
to eliminate duplicated runtime logic.
"""

from app import app


if __name__ == "__main__":
    print("[DEPRECATED] app_ultimate.py now delegates to app.py")
    app.run(debug=False, host="0.0.0.0", port=5000)
    raise SystemExit(0)


if False:
    '''

from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify, send_file
from flask_session import Session
import os
import json
from datetime import datetime
import io

# Import our modules
from simple_classifier import predict_url
import database as db

# Import advanced modules
try:
    from threat_intelligence import threat_intel, get_comprehensive_analysis
    THREAT_INTEL_ENABLED = True
except ImportError:
    THREAT_INTEL_ENABLED = False
    print("Warning: Threat intelligence module not loaded")

try:
    from analytics import analytics, report_generator, get_chart_data
    ANALYTICS_ENABLED = True
except ImportError:
    ANALYTICS_ENABLED = False
    print("Warning: Analytics module not loaded")

try:
    from email_service import email_service, notification_manager
    EMAIL_ENABLED = True
except ImportError:
    EMAIL_ENABLED = False
    print("Warning: Email service not loaded")

try:
    from advanced_ml import get_comprehensive_prediction, explainer, typosquatting_detector
    ADVANCED_ML_ENABLED = True
except ImportError:
    ADVANCED_ML_ENABLED = False
    print("Warning: Advanced ML module not loaded")

try:
    from security import rate_limiter, rate_limit, two_factor_auth, ip_manager, api_key_manager, require_api_key
    SECURITY_ENABLED = True
except ImportError:
    SECURITY_ENABLED = False
    def rate_limit(*_args, **_kwargs):
        def _decorator(func):
            return func
        return _decorator
    print("Warning: Security module not loaded")

try:
    from integrations import webhook_manager, slack, teams, siem, notify_phishing_detection, EventType
    INTEGRATIONS_ENABLED = True
except ImportError:
    INTEGRATIONS_ENABLED = False
    print("Warning: Integrations module not loaded")

try:
    from api_docs import api_docs
    API_DOCS_ENABLED = True
except ImportError:
    API_DOCS_ENABLED = False
    print("Warning: API docs module not loaded")

# Initialize database
db.init_db()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_super_secret_key_change_in_production_2026')

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = 'session_files'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 100
Session(app)

# Register blueprints
if API_DOCS_ENABLED:
    app.register_blueprint(api_docs)

# Ensure directories exist
for directory in ['session_files', 'reports', 'exports']:
    if not os.path.exists(directory):
        os.makedirs(directory)


# ============== Middleware ==============

@app.before_request
def check_ip_blacklist():
    """Check if IP is blacklisted"""
    if SECURITY_ENABLED:
        ip = request.remote_addr
        if not ip_manager.is_allowed(ip):
            return jsonify({'error': 'Access denied', 'ip': ip}), 403


# ============== Helper Functions ==============

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


def is_admin():
    """Check if current user is admin"""
    return session.get('role') == 'admin'


def is_logged_in():
    """Check if user is logged in"""
    return 'user' in session


def predict_and_save(url, username, advanced=False):
    """Predict URL and save to database with optional advanced analysis"""
    
    # Basic prediction
    result = predict_url(url)
    
    # Advanced analysis if enabled and requested
    if advanced and ADVANCED_ML_ENABLED:
        try:
            from featureExtractor import featureExtraction
            features = featureExtraction(url)
            advanced_result = get_comprehensive_prediction(url, features)
            result['advanced'] = advanced_result
            result['explanation'] = advanced_result.get('explanation', {})
            result['typosquatting'] = advanced_result.get('typosquatting', {})
        except Exception as e:
            print(f"Advanced analysis error: {e}")
    
    # Threat intelligence if enabled
    if THREAT_INTEL_ENABLED:
        try:
            threat_result = threat_intel.check_url(url)
            result['threat_intel'] = threat_result
            
            # Combine scores
            if threat_result.get('threat_score', 0) > result.get('prediction_score', 0):
                result['combined_score'] = (result['prediction_score'] + threat_result['threat_score']) / 2
            else:
                result['combined_score'] = result['prediction_score']
        except Exception as e:
            print(f"Threat intel error: {e}")
    
    # Save to database
    db.save_url_check(
        username=username,
        url=url,
        prediction_label=result['prediction_label'],
        prediction_score=result['prediction_score'],
        is_phishing=1 if result['is_phishing'] else 0
    )
    
    # Auto-add to blocklist if phishing
    if result['is_phishing']:
        db.add_to_blocklist(url, added_by='auto', reason='Auto-detected as phishing')
        
        # Send notifications
        if INTEGRATIONS_ENABLED:
            notify_phishing_detection(url, result['prediction_score'], result, username)
        
        # Email alert
        if EMAIL_ENABLED:
            notification_manager.notify_phishing_detection(
                username, url, result['prediction_score'], result
            )
    
    # Log activity
    db.log_activity(
        username=username,
        action='URL Check',
        details=f"Checked: {url[:50]}... - Result: {result['prediction_label']}",
        ip_address=get_client_ip()
    )
    
    # Trigger webhook
    if INTEGRATIONS_ENABLED:
        webhook_manager.trigger_event(
            EventType.URL_CHECKED if not result['is_phishing'] else EventType.PHISHING_DETECTED,
            {'url': url, 'result': result, 'user': username}
        )
    
    return result


# ============== Authentication Routes ==============

@app.route("/")
def index():
    """Root route - redirect to appropriate dashboard"""
    if not is_logged_in():
        return redirect(url_for('login_options'))
    
    if is_admin():
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))


@app.route("/login_options")
def login_options():
    """Landing page with login options"""
    return render_template("landing_page.html")


@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    """Admin login page"""
    if request.method == "POST":
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        totp_token = request.form.get('totp_token', '')
        
        user = db.validate_user(username, password)
        
        if user and user['role'] == 'admin':
            # Check 2FA if enabled
            if SECURITY_ENABLED and two_factor_auth.is_enabled(username):
                if not totp_token or not two_factor_auth.verify_token(username, totp_token):
                    flash('Invalid 2FA token.', 'danger')
                    return render_template("admin_login.html", show_2fa=True, username=username)
            
            session['user'] = username
            session['role'] = 'admin'
            
            db.log_activity(username, 'Login', 'Admin logged in', get_client_ip())
            
            if INTEGRATIONS_ENABLED:
                webhook_manager.trigger_event(EventType.USER_LOGIN, {'username': username, 'role': 'admin'})
            
            flash('Welcome back, Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
    
    return render_template("admin_login.html")


@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    """User login page"""
    if request.method == "POST":
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        user = db.validate_user(username, password)
        
        if user:
            session['user'] = username
            session['role'] = user['role']
            
            db.log_activity(username, 'Login', 'User logged in', get_client_ip())
            flash(f'Welcome back, {username}!', 'success')
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    
    return render_template("user_login.html")


@app.route("/logout")
def logout():
    """Logout user"""
    username = session.get('user', 'unknown')
    db.log_activity(username, 'Logout', 'User logged out', get_client_ip())
    
    if INTEGRATIONS_ENABLED:
        webhook_manager.trigger_event(EventType.USER_LOGOUT, {'username': username})
    
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login_options'))


# ============== Admin Routes ==============

@app.route("/admin_dashboard")
def admin_dashboard():
    """Advanced admin dashboard with analytics"""
    if not is_logged_in() or not is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('login_options'))
    
    # Get global statistics
    stats = db.get_global_stats()
    
    # Get advanced analytics if available
    chart_data = {}
    if ANALYTICS_ENABLED:
        chart_data = get_chart_data()
    
    return render_template("admin_dashboard.html",
                         total_urls=stats['total_urls'],
                         safe_urls=stats['safe_urls'],
                         unsafe_urls=stats['unsafe_urls'],
                         active_users=stats['active_users'],
                         total_users=stats['total_users'],
                         urls_today=stats['urls_today'],
                         chart_data=json.dumps(chart_data),
                         features={
                             'threat_intel': THREAT_INTEL_ENABLED,
                             'analytics': ANALYTICS_ENABLED,
                             'email': EMAIL_ENABLED,
                             'advanced_ml': ADVANCED_ML_ENABLED,
                             'security': SECURITY_ENABLED,
                             'integrations': INTEGRATIONS_ENABLED
                         })


@app.route("/admin", methods=["GET", "POST"])
def admin_index():
    """Admin URL check page"""
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login_options'))
    
    data = None
    blocklist_status = None
    url = None
    
    if request.method == "POST":
        url = request.form.get("url")
        advanced = request.form.get("advanced", "false") == "true"
        
        if 'add_to_blocklist' in request.form and url:
            db.add_to_blocklist(url, added_by=session['user'], reason='Manually added by admin')
            db.log_activity(session['user'], 'Blocklist Add', f'Added: {url}', get_client_ip())
            flash('URL added to blocklist.', 'success')
            return redirect(url_for('admin_index'))
        
        if url:
            data = predict_and_save(url, session['user'], advanced=advanced)
            if db.is_blocklisted(url):
                blocklist_status = "This URL is in the blocklist."
    
    return render_template("admin_index.html", url=url, data=data, blocklist_status=blocklist_status)


# ============== User Routes ==============

@app.route("/user_dashboard", methods=["GET", "POST"])
def user_dashboard():
    """Advanced user dashboard"""
    if not is_logged_in():
        return redirect(url_for('login_options'))
    
    if is_admin():
        return redirect(url_for('admin_dashboard'))
    
    username = session['user']
    data = None
    blocklist_status = None
    url = None
    
    # Get user statistics
    stats = db.get_user_stats(username)
    
    # Get recent URL checks
    recent_checks = db.get_user_url_checks(username, limit=10)
    
    if request.method == "POST":
        url = request.form.get("url")
        advanced = request.form.get("advanced", "false") == "true"
        
        if url:
            data = predict_and_save(url, username, advanced=advanced)
            if db.is_blocklisted(url):
                blocklist_status = "This URL is blocklisted by admin."
            
            # Refresh stats after new check
            stats = db.get_user_stats(username)
            recent_checks = db.get_user_url_checks(username, limit=10)
    
    return render_template("user_dashboard.html",
                         data=data,
                         url=url,
                         blocklist_status=blocklist_status,
                         total_checked=stats['total_checked'],
                         safe_count=stats['safe_count'],
                         unsafe_count=stats['unsafe_count'],
                         safety_rate=stats['safety_rate'],
                         recent_checks=recent_checks)


# ============== Advanced API Routes ==============

@app.route("/api/check_url", methods=["POST"])
@rate_limit(max_requests=120, window_seconds=60)
def api_check_url():
    """API endpoint for URL checking"""
    if not is_logged_in():
        # Check for API key
        if SECURITY_ENABLED:
            api_key = request.headers.get('X-API-Key')
            if api_key:
                valid, key_info = api_key_manager.validate_key(api_key)
                if valid:
                    username = key_info['username']
                else:
                    return jsonify({'error': 'Invalid API key'}), 401
            else:
                return jsonify({'error': 'Authentication required'}), 401
        else:
            return jsonify({'error': 'Authentication required'}), 401
    else:
        username = session['user']
    
    data = request.get_json() or {}
    url = data.get('url') or request.form.get('url')
    advanced = data.get('advanced', False)
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    result = predict_and_save(url, username, advanced=advanced)
    result['blocklisted'] = db.is_blocklisted(url)
    
    return jsonify(result)


@app.route("/api/check_url_advanced", methods=["POST"])
def api_check_url_advanced():
    """Advanced URL analysis with full features"""
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    result = predict_and_save(url, session['user'], advanced=True)
    
    # Add threat intelligence
    if THREAT_INTEL_ENABLED and data.get('include_threat_intel', True):
        result['threat_intelligence'] = threat_intel.check_url(url)
        result['domain_reputation'] = threat_intel.get_domain_reputation(url)
    
    # Add typosquatting check
    if ADVANCED_ML_ENABLED:
        result['typosquatting'] = typosquatting_detector.check_typosquatting(url)
    
    return jsonify(result)


@app.route("/api/threat_intel/<path:url>")
def api_threat_intel(url):
    """Get threat intelligence for URL"""
    if not THREAT_INTEL_ENABLED:
        return jsonify({'error': 'Threat intelligence not enabled'}), 503
    
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    result = threat_intel.check_url(url)
    return jsonify(result)


# ============== Analytics API Routes ==============

@app.route("/api/analytics/dashboard")
def api_analytics_dashboard():
    """Get dashboard analytics data"""
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    if not ANALYTICS_ENABLED:
        return jsonify({'error': 'Analytics not enabled'}), 503
    
    return jsonify(get_chart_data())


@app.route("/api/report/generate", methods=["POST"])
def api_generate_report():
    """Generate and download report"""
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    if not ANALYTICS_ENABLED:
        return jsonify({'error': 'Analytics not enabled'}), 503
    
    data = request.get_json() or {}
    format_type = data.get('format', 'json')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    if format_type == 'json':
        content = report_generator.generate_json_report(start_date, end_date)
        return jsonify(json.loads(content))
    
    elif format_type == 'html':
        content = report_generator.generate_html_report(start_date, end_date)
        return content, 200, {'Content-Type': 'text/html'}
    
    elif format_type == 'csv':
        report_data = analytics.generate_report_data(start_date, end_date)
        content = report_generator.generate_csv_report(report_data['daily_breakdown'])
        
        buffer = io.BytesIO()
        buffer.write(content.encode())
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'phishing_report_{datetime.now().strftime("%Y%m%d")}.csv'
        )
    
    return jsonify({'error': 'Invalid format'}), 400


# ============== Security API Routes ==============

@app.route("/api/2fa/setup", methods=["POST"])
def api_2fa_setup():
    """Set up 2FA for current user"""
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    if not SECURITY_ENABLED:
        return jsonify({'error': 'Security features not enabled'}), 503
    
    result = two_factor_auth.setup_2fa(session['user'])
    return jsonify(result)


@app.route("/api/2fa/enable", methods=["POST"])
def api_2fa_enable():
    """Enable 2FA after verification"""
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    if not SECURITY_ENABLED:
        return jsonify({'error': 'Security features not enabled'}), 503
    
    data = request.get_json() or {}
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    if two_factor_auth.enable_2fa(session['user'], token):
        return jsonify({'success': True, 'message': '2FA enabled successfully'})
    
    return jsonify({'success': False, 'message': 'Invalid token'}), 400


@app.route("/api/keys", methods=["GET", "POST"])
def api_manage_keys():
    """Manage API keys"""
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    if not SECURITY_ENABLED:
        return jsonify({'error': 'Security features not enabled'}), 503
    
    if request.method == "GET":
        keys = api_key_manager.get_user_keys(session['user'])
        return jsonify({'keys': keys})
    
    elif request.method == "POST":
        data = request.get_json() or {}
        name = data.get('name', 'API Key')
        permissions = data.get('permissions', ['read'])
        expires_days = data.get('expires_days')
        
        result = api_key_manager.generate_key(
            session['user'], name, permissions, 
            expires_days=expires_days
        )
        
        return jsonify(result)


@app.route("/api/keys/<int:key_id>", methods=["DELETE"])
def api_revoke_key(key_id):
    """Revoke an API key"""
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    if not SECURITY_ENABLED:
        return jsonify({'error': 'Security features not enabled'}), 503
    
    if api_key_manager.revoke_key(key_id):
        return jsonify({'success': True, 'message': 'Key revoked'})
    
    return jsonify({'success': False, 'message': 'Failed to revoke key'}), 400


# ============== Webhook API Routes ==============

@app.route("/api/webhooks", methods=["GET", "POST"])
def api_manage_webhooks():
    """Manage webhooks"""
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    
    if not INTEGRATIONS_ENABLED:
        return jsonify({'error': 'Integrations not enabled'}), 503
    
    if request.method == "GET":
        webhooks = webhook_manager.get_webhooks()
        return jsonify({'webhooks': webhooks})
    
    elif request.method == "POST":
        data = request.get_json() or {}
        
        result = webhook_manager.register_webhook(
            name=data.get('name', 'Webhook'),
            url=data.get('url'),
            events=data.get('events', ['*']),
            secret=data.get('secret'),
            created_by=session['user']
        )
        
        return jsonify(result)


@app.route("/api/webhooks/<int:webhook_id>", methods=["DELETE"])
def api_delete_webhook(webhook_id):
    """Delete a webhook"""
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    
    if not INTEGRATIONS_ENABLED:
        return jsonify({'error': 'Integrations not enabled'}), 503
    
    if webhook_manager.delete_webhook(webhook_id):
        return jsonify({'success': True, 'message': 'Webhook deleted'})
    
    return jsonify({'success': False, 'message': 'Failed to delete webhook'}), 400


# ============== Original API Routes ==============

@app.route("/get_blocklist")
def get_blocklist():
    """Get blocklist as JSON"""
    blocklist = db.get_blocklist()
    return jsonify({
        'urls': [dict(row) for row in blocklist],
        'count': len(blocklist)
    })


@app.route("/remove_from_blocklist", methods=["POST"])
def remove_from_blocklist():
    """Remove URL from blocklist (admin only)"""
    if not is_logged_in() or not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'success': False, 'message': 'URL required'}), 400
    
    if db.remove_from_blocklist(url):
        db.log_activity(session['user'], 'Blocklist Remove', f'Removed: {url}', get_client_ip())
        
        if INTEGRATIONS_ENABLED:
            webhook_manager.trigger_event(EventType.BLOCKLIST_REMOVED, {'url': url})
        
        return jsonify({'success': True, 'message': 'URL removed'})
    
    return jsonify({'success': False, 'message': 'URL not found'}), 404


@app.route("/api/users")
def api_get_users():
    """Get all users (admin only)"""
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = db.get_all_users()
    user_list = []
    
    for user in users:
        url_count = db.get_user_url_count(user['username'])
        user_list.append({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'] or '',
            'role': user['role'],
            'is_active': user['is_active'],
            'created_at': user['created_at'],
            'last_login': user['last_login'] or 'Never',
            'url_count': url_count
        })
    
    return jsonify({'users': user_list})


@app.route("/api/users/add", methods=["POST"])
def api_add_user():
    """Add new user (admin only)"""
    if not is_logged_in() or not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    
    if db.add_user(username, password, email):
        db.log_activity(session['user'], 'User Add', f'Added user: {username}', get_client_ip())
        
        if INTEGRATIONS_ENABLED:
            webhook_manager.trigger_event(EventType.USER_CREATED, {'username': username})
        
        if EMAIL_ENABLED and email:
            email_service.send_welcome_email(email, username)
        
        return jsonify({'success': True, 'message': 'User added successfully'})
    
    return jsonify({'success': False, 'message': 'Username already exists'}), 400


@app.route("/api/users/delete", methods=["POST"])
def api_delete_user():
    """Delete user (admin only)"""
    if not is_logged_in() or not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json() or {}
    username = data.get('username')
    
    if not username:
        return jsonify({'success': False, 'message': 'Username required'}), 400
    
    if db.delete_user(username):
        db.log_activity(session['user'], 'User Delete', f'Deleted user: {username}', get_client_ip())
        return jsonify({'success': True, 'message': 'User deleted'})
    
    return jsonify({'success': False, 'message': 'Cannot delete user'}), 400


@app.route("/api/activity")
def api_get_activity():
    """Get activity log (admin only)"""
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    activities = db.get_activity_log(limit=100)
    return jsonify({
        'activities': [dict(row) for row in activities]
    })


@app.route("/api/stats")
def api_get_stats():
    """Get global statistics"""
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    if is_admin():
        return jsonify(db.get_global_stats())
    else:
        return jsonify(db.get_user_stats(session['user']))


@app.route("/api/history")
def api_get_history():
    """Get URL check history"""
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    limit = request.args.get('limit', 50, type=int)
    
    if is_admin():
        checks = db.get_all_url_checks(limit)
    else:
        checks = db.get_user_url_checks(session['user'], limit)
    
    return jsonify({
        'history': [dict(row) for row in checks],
        'count': len(checks)
    })


@app.route("/api/export")
def api_export_history():
    """Export user's URL check history"""
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    history = db.export_user_history(session['user'])
    
    return jsonify({
        'username': session['user'],
        'exported_at': datetime.now().isoformat(),
        'history': history
    })


# ============== IP Management Routes ==============

@app.route("/api/ip/whitelist", methods=["POST"])
def api_whitelist_ip():
    """Add IP to whitelist (admin only)"""
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    
    if not SECURITY_ENABLED:
        return jsonify({'error': 'Security features not enabled'}), 503
    
    data = request.get_json() or {}
    ip = data.get('ip')
    reason = data.get('reason', '')
    
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    
    if ip_manager.add_to_whitelist(ip, reason, session['user']):
        return jsonify({'success': True, 'message': 'IP whitelisted'})
    
    return jsonify({'success': False, 'message': 'Failed to whitelist IP'}), 400


@app.route("/api/ip/blacklist", methods=["POST"])
def api_blacklist_ip():
    """Add IP to blacklist (admin only)"""
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    
    if not SECURITY_ENABLED:
        return jsonify({'error': 'Security features not enabled'}), 503
    
    data = request.get_json() or {}
    ip = data.get('ip')
    reason = data.get('reason', '')
    duration = data.get('duration_hours')
    
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    
    if ip_manager.add_to_blacklist(ip, reason, session['user'], duration):
        return jsonify({'success': True, 'message': 'IP blacklisted'})
    
    return jsonify({'success': False, 'message': 'Failed to blacklist IP'}), 400


@app.route("/api/ip/list")
def api_list_ips():
    """Get all managed IPs (admin only)"""
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    
    if not SECURITY_ENABLED:
        return jsonify({'error': 'Security features not enabled'}), 503
    
    list_type = request.args.get('type')
    ips = ip_manager.get_all(list_type)
    
    return jsonify({'ips': ips})


# ============== Page Routes ==============

@app.route("/about")
def about():
    """About page"""
    if not is_logged_in():
        return redirect(url_for('login_options'))
    
    if is_admin():
        return render_template("about_admin.html")
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    """Contact page"""
    if not is_logged_in():
        return redirect(url_for('login_options'))
    
    if request.method == "POST":
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        message = request.form.get('message', '')
        
        db.log_activity(session['user'], 'Contact Form', f'From: {name}', get_client_ip())
        flash('Your message has been sent!', 'success')
    
    if is_admin():
        return render_template("contact_admin.html")
    return render_template("contact.html")


@app.route("/about_admin")
def about_admin():
    """Admin about page"""
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login_options'))
    return render_template("about_admin.html")


@app.route("/contact_admin", methods=["GET", "POST"])
def contact_admin():
    """Admin contact page"""
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login_options'))
    return render_template("contact_admin.html")


# ============== System Status Route ==============

@app.route("/api/system/status")
def api_system_status():
    """Get system status and enabled features"""
    return jsonify({
        'status': 'online',
        'version': '2.0.0',
        'features': {
            'threat_intelligence': THREAT_INTEL_ENABLED,
            'analytics': ANALYTICS_ENABLED,
            'email_notifications': EMAIL_ENABLED,
            'advanced_ml': ADVANCED_ML_ENABLED,
            'security': SECURITY_ENABLED,
            'integrations': INTEGRATIONS_ENABLED,
            'api_docs': API_DOCS_ENABLED
        },
        'timestamp': datetime.now().isoformat()
    })


# ============== Error Handlers ==============

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    return render_template('landing_page.html'), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return "Internal server error. Please try again.", 500


@app.errorhandler(429)
def rate_limit_error(e):
    """Handle rate limit errors"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429


# ============== Main ==============

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("🔒 Phishing Detection System - Ultimate Edition v2.0")
    print("=" * 70)
    print("\n📌 Server starting at: http://127.0.0.1:5000")
    print("\n👤 Login Credentials:")
    print("   Admin: admin / admin123")
    print("   Users: user1 / user123 (or user2-4)")
    print("\n🔧 Enabled Features:")
    print(f"   ✓ Threat Intelligence: {'Yes' if THREAT_INTEL_ENABLED else 'No'}")
    print(f"   ✓ Analytics: {'Yes' if ANALYTICS_ENABLED else 'No'}")
    print(f"   ✓ Email Notifications: {'Yes' if EMAIL_ENABLED else 'No'}")
    print(f"   ✓ Advanced ML: {'Yes' if ADVANCED_ML_ENABLED else 'No'}")
    print(f"   ✓ Security (2FA, Rate Limiting): {'Yes' if SECURITY_ENABLED else 'No'}")
    print(f"   ✓ Integrations (Webhooks, Slack, SIEM): {'Yes' if INTEGRATIONS_ENABLED else 'No'}")
    print(f"   ✓ API Documentation: {'Yes' if API_DOCS_ENABLED else 'No'}")
    print("\n📚 API Documentation: http://127.0.0.1:5000/api/docs")
    print("=" * 70 + "\n")
    
    # Clear session files on start
    if os.path.exists('session_files'):
        for f in os.listdir('session_files'):
            try:
                os.remove(os.path.join('session_files', f))
            except:
                pass
    
    app.run(debug=False, host='0.0.0.0', port=5000)

    '''
