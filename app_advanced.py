"""Compatibility wrapper for advanced app mode.

This module now delegates to the canonical Flask application in `app.py`
to eliminate duplicated runtime logic.
"""

from app import app


if __name__ == "__main__":
    print("[DEPRECATED] app_advanced.py now delegates to app.py")
    app.run(debug=False, host="0.0.0.0", port=5000)
    raise SystemExit(0)


if False:
    '''

from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_session import Session
import os
import json
from datetime import datetime

# Import our modules
from simple_classifier import predict_url
import database as db

# Initialize database
db.init_db()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = 'session_files'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 100
Session(app)

# Ensure directories exist
if not os.path.exists('session_files'):
    os.makedirs('session_files')


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


def predict_and_save(url, username):
    """Predict URL and save to database"""
    result = predict_url(url)
    
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
    
    # Log activity
    db.log_activity(
        username=username,
        action='URL Check',
        details=f"Checked: {url[:50]}... - Result: {result['prediction_label']}",
        ip_address=get_client_ip()
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
        
        user = db.validate_user(username, password)
        
        if user and user['role'] == 'admin':
            session['user'] = username
            session['role'] = 'admin'
            
            db.log_activity(username, 'Login', 'Admin logged in', get_client_ip())
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
    
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login_options'))


# ============== Admin Routes ==============

@app.route("/admin_dashboard")
def admin_dashboard():
    """Advanced admin dashboard"""
    if not is_logged_in() or not is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('login_options'))
    
    # Get global statistics
    stats = db.get_global_stats()
    
    return render_template("admin_dashboard.html",
                         total_urls=stats['total_urls'],
                         safe_urls=stats['safe_urls'],
                         unsafe_urls=stats['unsafe_urls'],
                         active_users=stats['active_users'],
                         total_users=stats['total_users'],
                         urls_today=stats['urls_today'])


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
        
        if 'add_to_blocklist' in request.form and url:
            db.add_to_blocklist(url, added_by=session['user'], reason='Manually added by admin')
            db.log_activity(session['user'], 'Blocklist Add', f'Added: {url}', get_client_ip())
            flash('URL added to blocklist.', 'success')
            return redirect(url_for('admin_index'))
        
        if url:
            data = predict_and_save(url, session['user'])
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
        if url:
            data = predict_and_save(url, username)
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


# ============== API Routes ==============

@app.route("/api/check_url", methods=["POST"])
def api_check_url():
    """API endpoint for URL checking"""
    if not is_logged_in():
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json() or {}
    url = data.get('url') or request.form.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    result = predict_and_save(url, session['user'])
    result['blocklisted'] = db.is_blocklisted(url)
    
    return jsonify(result)


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
        # Handle contact form
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


# ============== Error Handlers ==============

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('landing_page.html'), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return "Internal server error. Please try again.", 500


# ============== Main ==============

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🔒 Phishing Detection System - Advanced Edition")
    print("=" * 60)
    print("\n📌 Server starting at: http://127.0.0.1:5000")
    print("\n👤 Login Credentials:")
    print("   Admin: admin / admin123")
    print("   Users: user1 / user123 (or user2-4)")
    print("\n" + "=" * 60 + "\n")
    
    # Clear session files on start
    if os.path.exists('session_files'):
        for f in os.listdir('session_files'):
            try:
                os.remove(os.path.join('session_files', f))
            except:
                pass
    
    app.run(debug=False, host='0.0.0.0', port=5000)

    '''
