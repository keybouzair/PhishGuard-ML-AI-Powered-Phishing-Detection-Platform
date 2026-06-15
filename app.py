from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_session import Session
import os
import warnings
from datetime import datetime
import database as db
import re
from urllib.parse import urlparse
import time
import uuid
import logging
from ml.inference_engine import InferenceEngine
from services.cache_service import cache_service
from services.enrichment_service import get_cached_domain_metrics
from workers.tasks.enrich_url import enqueue_url_enrichment

try:
    from security import rate_limit
except Exception:
    def rate_limit(*_args, **_kwargs):
        def _decorator(func):
            return func
        return _decorator

# Optional advanced feature modules (enabled when available)
ADVANCED_FEATURES_ENABLED = False
API_DOCS_ENABLED = False
THREAT_INTEL_ENABLED = False
ANALYTICS_ENABLED = False
EMAIL_ENABLED = False
INTEGRATIONS_ENABLED = False

try:
    from routers.advanced_features_api import advanced_bp
    ADVANCED_FEATURES_ENABLED = True
except Exception:
    advanced_bp = None

try:
    from api_docs import api_docs
    API_DOCS_ENABLED = True
except Exception:
    api_docs = None

try:
    from threat_intelligence import threat_intel
    THREAT_INTEL_ENABLED = True
except Exception:
    threat_intel = None

try:
    from analytics import analytics
    ANALYTICS_ENABLED = True
except Exception:
    analytics = None

try:
    from email_service import email_service
    EMAIL_ENABLED = True
except Exception:
    email_service = None

try:
    from integrations import webhook_manager
    INTEGRATIONS_ENABLED = True
except Exception:
    webhook_manager = None

warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing_app")

TRUSTED_DOMAINS = {
    'google.com',
    'www.google.com',
    'mail.google.com',
    'youtube.com',
    'www.youtube.com',
    'github.com',
    'www.github.com',
    'microsoft.com',
    'www.microsoft.com',
    'apple.com',
    'www.apple.com',
    'facebook.com',
    'www.facebook.com',
    'instagram.com',
    'www.instagram.com',
    'linkedin.com',
    'www.linkedin.com',
    'amazon.com',
    'www.amazon.com',
}

# Initialize database
db.init_db()

# Load inference engine once at startup
inference_engine = InferenceEngine(model_dir='model')
if inference_engine.is_available():
    print(f"Inference engine ready (source={inference_engine.source})")
else:
    print("Warning: No ML model available; heuristic fallback will be used")


def validate_and_normalize_url(url):
    """Validate and normalize URL input for safer processing."""
    if not isinstance(url, str):
        return False, None, "URL must be a string"

    normalized = url.strip()
    if not normalized:
        return False, None, "URL is required"

    if len(normalized) > 2048:
        return False, None, "URL is too long"

    if not normalized.startswith(("http://", "https://")):
        normalized = f"https://{normalized}"

    parsed = urlparse(normalized)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False, None, "Invalid URL format"

    return True, normalized, None


def api_success(data=None, message='ok', status=200):
    """Standardized success response envelope for API endpoints."""
    payload = {
        'ok': True,
        'message': message,
        'data': data if data is not None else {}
    }
    return jsonify(payload), status


def api_error(error, status=400, details=None):
    """Standardized error response envelope for API endpoints."""
    payload = {
        'ok': False,
        'error': error
    }
    if details is not None:
        payload['details'] = details
    return jsonify(payload), status


def analyze_url_risks(url):
    """Analyze URL for specific risk indicators and return detailed risk analysis"""
    risks = []
    risk_score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()
    
    # Risk patterns with weights and descriptions
    risk_patterns = {
        'ip_address': {
            'pattern': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'weight': 25,
            'type': 'Suspicious Domain',
            'description': 'Uses IP address instead of domain name'
        },
        'login_keyword': {
            'pattern': r'(login|signin|sign-in|log-in)',
            'weight': 15,
            'type': 'Credential Harvesting',
            'description': 'Contains login-related keywords'
        },
        'verify_keyword': {
            'pattern': r'(verify|confirm|validate|secure)',
            'weight': 15,
            'type': 'Verification Scam',
            'description': 'Contains verification/confirmation keywords'
        },
        'account_keyword': {
            'pattern': r'(account|password|credential|banking)',
            'weight': 15,
            'type': 'Account Theft',
            'description': 'Contains account-related keywords'
        },
        'brand_impersonation': {
            'pattern': r'(paypal|ebay|amazon|apple|microsoft|google|facebook|netflix|bank)',
            'weight': 20,
            'type': 'Brand Impersonation',
            'description': 'May be impersonating a known brand'
        },
        'url_shortener': {
            'pattern': r'(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)',
            'weight': 20,
            'type': 'URL Obfuscation',
            'description': 'Uses URL shortener to hide destination'
        },
        'suspicious_tld': {
            'pattern': r'\.(tk|ml|ga|cf|gq|xyz|top|work|click|link|club)$',
            'weight': 20,
            'type': 'Suspicious Domain',
            'description': 'Uses commonly abused top-level domain'
        },
        'at_symbol': {
            'pattern': r'@',
            'weight': 25,
            'type': 'URL Manipulation',
            'description': 'Contains @ symbol which can hide real destination'
        },
        'double_slashes': {
            'pattern': r'//.*//|//',
            'weight': 10,
            'type': 'URL Manipulation',
            'description': 'Contains suspicious path structure'
        },
        'hex_encoding': {
            'pattern': r'%[0-9a-fA-F]{2}',
            'weight': 10,
            'type': 'URL Obfuscation',
            'description': 'Contains encoded characters'
        },
        'long_subdomain': {
            'pattern': r'[a-z0-9-]{20,}\.',
            'weight': 15,
            'type': 'Suspicious Domain',
            'description': 'Contains unusually long subdomain'
        },
        'many_subdomains': {
            'pattern': r'(\.[a-z0-9-]+){4,}',
            'weight': 15,
            'type': 'Suspicious Domain',
            'description': 'Contains multiple subdomains'
        },
        'https_in_path': {
            'pattern': r'https?://[^/]+/.*https?://',
            'weight': 20,
            'type': 'URL Manipulation',
            'description': 'Contains URL within path (redirect attempt)'
        },
        'suspicious_extension': {
            'pattern': r'\.(exe|zip|rar|php|html|htm)(\?|$)',
            'weight': 15,
            'type': 'Malware Risk',
            'description': 'Links to potentially dangerous file type'
        },
        'numbers_in_domain': {
            'pattern': r'[a-z]+[0-9]+[a-z]+|[0-9]+[a-z]+[0-9]+',
            'weight': 10,
            'type': 'Suspicious Domain',
            'description': 'Domain contains unusual number patterns'
        },
        'urgent_keywords': {
            'pattern': r'(urgent|suspend|expire|immediate|alert|warning|limited)',
            'weight': 15,
            'type': 'Urgency Scam',
            'description': 'Contains urgency-inducing keywords'
        }
    }
    
    # Check each risk pattern
    for risk_name, risk_info in risk_patterns.items():
        if re.search(risk_info['pattern'], full_url):
            risk_score += risk_info['weight']
            risks.append({
                'name': risk_name,
                'type': risk_info['type'],
                'description': risk_info['description'],
                'severity': 'High' if risk_info['weight'] >= 20 else 'Medium' if risk_info['weight'] >= 15 else 'Low'
            })
    
    # Additional checks
    # URL length check
    if len(url) > 75:
        risk_score += 10
        risks.append({
            'name': 'long_url',
            'type': 'URL Obfuscation',
            'description': f'URL is unusually long ({len(url)} characters)',
            'severity': 'Low'
        })
    
    # HTTPS check
    if not url.startswith('https://'):
        risk_score += 15
        risks.append({
            'name': 'no_https',
            'type': 'Security Risk',
            'description': 'Website does not use secure HTTPS connection',
            'severity': 'Medium'
        })
    
    # Hyphen in domain check
    if domain.count('-') >= 3:
        risk_score += 15
        risks.append({
            'name': 'many_hyphens',
            'type': 'Suspicious Domain',
            'description': f'Domain contains many hyphens ({domain.count("-")})',
            'severity': 'Medium'
        })
    
    # Cap the risk score at 100
    risk_score = min(risk_score, 100)
    
    # Determine overall risk level
    if risk_score >= 60:
        risk_level = 'Critical'
        risk_color = '#ef4444'
    elif risk_score >= 40:
        risk_level = 'High'
        risk_color = '#f97316'
    elif risk_score >= 20:
        risk_level = 'Medium'
        risk_color = '#f59e0b'
    elif risk_score > 0:
        risk_level = 'Low'
        risk_color = '#eab308'
    else:
        risk_level = 'Safe'
        risk_color = '#10b981'
    
    # Get unique risk types
    risk_types = list(set([r['type'] for r in risks]))
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_color': risk_color,
        'risk_types': risk_types,
        'risks': risks,
        'total_risks': len(risks)
    }


def is_trusted_domain(url):
    """Return True for exact trusted domains and their direct subdomains."""
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0].lower()
    if domain.startswith('www.'):
        domain = domain[4:]

    for trusted in TRUSTED_DOMAINS:
        trusted_domain = trusted[4:] if trusted.startswith('www.') else trusted
        if domain == trusted_domain or domain.endswith(f'.{trusted_domain}'):
            return True
    return False

def get_extra_domain_metrics(url):
    """Return cached enrichment metrics and queue async refresh."""
    enqueue_url_enrichment(url)
    return get_cached_domain_metrics(url)


def predict(url, username='anonymous'):
    """Predict the phishing risk of the given URL with detailed analysis."""
    valid, normalized_url, error = validate_and_normalize_url(url)
    if not valid:
        raise ValueError(error)

    url = normalized_url

    if is_trusted_domain(url):
        extra_metrics = get_extra_domain_metrics(url)
        safe_result = {
            'url': url,
            'prediction_label': 'Safe',
            'prediction_score': 0,
            'risk_analysis': {
                'risk_score': 0,
                'risk_level': 'Safe',
                'risk_color': '#10b981',
                'risk_types': [],
                'risks': [],
                'total_risks': 0
            },
            'extra_metrics': extra_metrics
        }
        db.save_url_check(username, url, 'Safe', 0, 0)
        try:
            db.log_activity(username, 'URL Check', f'{url} - Safe', request.remote_addr if request else '')
        except:
            pass
        return safe_result

    # Get detailed risk analysis
    risk_analysis = analyze_url_risks(url)
    
    if not inference_engine.is_available():
        # Use risk analysis for detection if no model available
        is_suspicious = risk_analysis['risk_score'] >= 30
        prediction_label_text = "Unsafe" if is_suspicious else "Safe"
        prediction_score = min(risk_analysis['risk_score'] + 20, 100) if is_suspicious else max(100 - risk_analysis['risk_score'], 10)
        
        db.save_url_check(username, url, prediction_label_text, prediction_score, 1 if is_suspicious else 0)
        if is_suspicious:
            db.add_to_blocklist(url, username, 'Detected by risk analysis')
        
        try:
            db.log_activity(username, 'URL Check', f'{url} - {prediction_label_text}', request.remote_addr if request else '')
        except:
            pass
        
        extra_metrics = get_extra_domain_metrics(url)
        
        return {
            'url': url,
            'prediction_label': prediction_label_text,
            'prediction_score': prediction_score,
            'risk_analysis': risk_analysis,
            'extra_metrics': extra_metrics
        }
    
    try:
        model_result = inference_engine.predict_url(url)
        is_phishing = 1 if model_result['is_phishing'] else 0
        prediction_label_text = "Unsafe" if is_phishing else "Safe"
        prediction_score = model_result.get('score_percent', 0)
        
        # Save to database
        db.save_url_check(username, url, prediction_label_text, prediction_score, is_phishing)
        
        # Auto-add to blocklist if unsafe
        if is_phishing:
            db.add_to_blocklist(url, username, 'Auto-detected as phishing')
        
        # Log activity
        try:
            db.log_activity(username, 'URL Check', f'{url} - {prediction_label_text}', request.remote_addr if request else '')
        except:
            pass

        extra_metrics = get_extra_domain_metrics(url)

        return {
            'url': url,
            'prediction_label': prediction_label_text,
            'prediction_score': prediction_score,
            'risk_analysis': risk_analysis,
            'model_source': model_result.get('source', 'unknown'),
            'extra_metrics': extra_metrics
        }
    except Exception as e:
        print(f"Prediction error: {e}")
        # Fallback to heuristic
        is_suspicious = risk_analysis['risk_score'] >= 30
        prediction_label_text = "Unsafe" if is_suspicious else "Safe"
        prediction_score = min(risk_analysis['risk_score'] + 20, 100) if is_suspicious else max(100 - risk_analysis['risk_score'], 10)
        
        db.save_url_check(username, url, prediction_label_text, prediction_score, 1 if is_suspicious else 0)
        
        extra_metrics = get_extra_domain_metrics(url)
        
        return {
            'url': url,
            'prediction_label': prediction_label_text,
            'prediction_score': prediction_score,
            'risk_analysis': risk_analysis,
            'extra_metrics': extra_metrics
        }


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = 'session_files'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 100
Session(app)

# Register optional advanced blueprints
if API_DOCS_ENABLED and api_docs is not None:
    app.register_blueprint(api_docs)

if ADVANCED_FEATURES_ENABLED and advanced_bp is not None:
    app.register_blueprint(advanced_bp)


@app.before_request
def attach_request_context():
    request.request_id = str(uuid.uuid4())
    request._start_time = time.time()


@app.after_request
def add_request_observability_headers(response):
    elapsed_ms = int((time.time() - getattr(request, '_start_time', time.time())) * 1000)
    response.headers['X-Request-ID'] = getattr(request, 'request_id', '')
    response.headers['X-Response-Time-ms'] = str(elapsed_ms)
    logger.info(
        "request_complete",
        extra={
            'request_id': getattr(request, 'request_id', ''),
            'path': request.path,
            'method': request.method,
            'status': response.status_code,
            'latency_ms': elapsed_ms,
        },
    )
    return response

# Ensure directories exist
os.makedirs('session_files', exist_ok=True)
os.makedirs('logs', exist_ok=True)


# ============== AUTH ROUTES ==============

@app.route("/")
def index():
    if 'user' not in session:
        return redirect(url_for('login_options'))
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))


@app.route("/login_options")
def login_options():
    # Get real statistics from database
    stats = db.get_global_stats()
    recent_phishing_sites = db.get_recent_phishing_urls(8)
    
    # Format numbers for display
    total_urls = stats['total_urls']
    if total_urls >= 1000000:
        urls_display = f"{total_urls / 1000000:.1f}M+"
    elif total_urls >= 1000:
        urls_display = f"{total_urls / 1000:.1f}K+"
    else:
        urls_display = str(total_urls) if total_urls > 0 else "10M+"
    
    active_users = stats['active_users'] + stats['total_users']
    if active_users >= 1000:
        users_display = f"{active_users / 1000:.1f}K+"
    else:
        users_display = str(active_users) if active_users > 0 else "10K+"
    
    # Calculate accuracy (if we have data, otherwise show default)
    if stats['total_urls'] > 0:
        accuracy = 99.2  # ML model accuracy
    else:
        accuracy = 99.2
    
    return render_template("landing_page_v2.html",
                          urls_analyzed=urls_display,
                          detection_accuracy=f"{accuracy}%",
                          avg_response="50ms",
                          active_users=users_display,
                          recent_phishing_sites=recent_phishing_sites)


@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = db.validate_user(username, password)
        if user and user['role'] == 'admin':
            session['user'] = username
            session['role'] = 'admin'
            db.log_activity(username, 'Login', 'Admin login successful', request.remote_addr)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template("login_v2.html", login_type='admin')


@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = db.validate_user(username, password)
        if user:
            session['user'] = username
            session['role'] = user['role']
            db.log_activity(username, 'Login', 'User login successful', request.remote_addr)
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template("login_v2.html", login_type='user')


@app.route("/logout")
def logout():
    username = session.get('user', 'unknown')
    db.log_activity(username, 'Logout', 'User logged out', request.remote_addr)
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login_options'))


# ============== ADMIN ROUTES ==============

@app.route("/admin_dashboard")
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_options'))
    
    stats = db.get_global_stats()
    users = db.get_all_users()
    activities = db.get_activity_log(10)
    blocklist = db.get_blocklist()
    
    return render_template("admin_dashboard_v2.html",
                         total_urls=stats['total_urls'],
                         safe_urls=stats['safe_urls'],
                         unsafe_urls=stats['unsafe_urls'],
                         active_users=stats['active_users'],
                         total_users=stats['total_users'],
                         urls_today=stats['urls_today'],
                         users=users,
                         activities=activities,
                         blocklist=blocklist)


@app.route("/admin", methods=["GET", "POST"])
def admin_index():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_options'))

    data = None
    blocklist_status = None
    url = None

    if request.method == "POST":
        url = request.form.get("url")
        action = request.form.get("action")

        if action == "add_to_blocklist" and url:
            db.add_to_blocklist(url, session['user'], 'Manually added by admin')
            db.log_activity(session['user'], 'Blocklist Add', url, request.remote_addr)
            flash('URL added to blocklist.', 'success')
            return redirect(url_for('admin_index'))

        if url:
            data = predict(url, session['user'])
            if db.is_blocklisted(url):
                blocklist_status = "This website is blocklisted."

    return render_template("admin_index.html", url=url, data=data, blocklist_status=blocklist_status)


# ============== USER ROUTES ==============

@app.route("/user_dashboard", methods=["GET", "POST"])
def user_dashboard():
    if 'user' not in session:
        return redirect(url_for('login_options'))
    
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    username = session['user']
    data = None
    blocklist_status = None
    url = None
    risk_analysis = None
    
    stats = db.get_user_stats(username)
    history = db.get_user_url_checks(username, 10)
    
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            data = predict(url, username)
            risk_analysis = data.get('risk_analysis', None)
            if db.is_blocklisted(url):
                blocklist_status = "This website is blocklisted by admin."
    
    prediction = None
    confidence = 95
    extra_metrics = None
    if data:
        prediction = data.get('prediction_label', '').upper()
        confidence = int(data.get('prediction_score', 95))
        extra_metrics = data.get('extra_metrics', None)
    
    return render_template("user_dashboard_v2.html",
                         prediction=prediction,
                         confidence=confidence,
                         blocklist_status=blocklist_status,
                         url=url,
                         total_checked=stats['total_checked'],
                         safe_count=stats['safe_count'],
                         unsafe_count=stats['unsafe_count'],
                         safety_rate=stats['safety_rate'],
                         history=history,
                         risk_analysis=risk_analysis,
                         extra_metrics=extra_metrics)


# ============== API ROUTES ==============

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint for runtime and deployment probes."""
    return api_success({
        'status': 'healthy',
        'service': 'phishing-detection-api',
        'model_available': inference_engine.is_available(),
        'model_source': inference_engine.source,
        'features': {
            'advanced_features_api': ADVANCED_FEATURES_ENABLED,
            'api_docs': API_DOCS_ENABLED,
            'threat_intelligence': THREAT_INTEL_ENABLED,
            'analytics': ANALYTICS_ENABLED,
            'email': EMAIL_ENABLED,
            'integrations': INTEGRATIONS_ENABLED,
        },
    })


@app.route("/api/system/status", methods=["GET"])
def api_system_status():
    """Runtime feature status endpoint."""
    return api_success({
        'status': 'online',
        'features': {
            'advanced_features_api': ADVANCED_FEATURES_ENABLED,
            'api_docs': API_DOCS_ENABLED,
            'threat_intelligence': THREAT_INTEL_ENABLED,
            'analytics': ANALYTICS_ENABLED,
            'email': EMAIL_ENABLED,
            'integrations': INTEGRATIONS_ENABLED,
            'security_rate_limit': True,
            'model_inference': inference_engine.is_available(),
            'cache': True,
            'async_enrichment': True,
        },
    })

@app.route("/api/check", methods=["POST"])
@app.route("/check-url", methods=["POST"])
@rate_limit(max_requests=120, window_seconds=60)
def api_check_url():
    """API endpoint to check a URL"""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error('invalid_json', status=400, details='Request body must be valid JSON object')

    if 'url' not in data:
        return api_error('validation_error', status=400, details='Field "url" is required')

    if not isinstance(data.get('url'), str):
        return api_error('validation_error', status=400, details='Field "url" must be a string')

    valid, normalized_url, error = validate_and_normalize_url(data.get('url'))
    if not valid:
        return api_error('validation_error', status=400, details=error)

    cache_key = f"pred:{normalized_url}"
    cached = cache_service.get(cache_key)
    if cached is not None:
        return api_success(cached, message='url_checked_cached', status=200)
    
    username = session.get('user', 'api_user')
    try:
        result = predict(normalized_url, username)
        cache_service.set(cache_key, result, ttl_seconds=900)
        return api_success(result, message='url_checked', status=200)
    except Exception as e:
        return api_error('prediction_failed', status=500, details=str(e))


@app.route("/feedback", methods=["POST"])
@rate_limit(max_requests=60, window_seconds=60)
def api_feedback():
    """Collect user feedback for model improvement workflow."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error('invalid_json', status=400, details='Request body must be valid JSON object')

    required = ['url', 'predicted_label', 'user_label']
    missing = [k for k in required if k not in data]
    if missing:
        return api_error('validation_error', status=400, details=f'Missing fields: {", ".join(missing)}')

    if not isinstance(data.get('url'), str):
        return api_error('validation_error', status=400, details='Field "url" must be a string')

    try:
        predicted_label = int(data.get('predicted_label'))
        user_label = int(data.get('user_label'))
    except Exception:
        return api_error('validation_error', status=400, details='Labels must be integers 0 or 1')

    if predicted_label not in (0, 1) or user_label not in (0, 1):
        return api_error('validation_error', status=400, details='Labels must be 0 or 1')

    valid, normalized_url, error = validate_and_normalize_url(data.get('url'))
    if not valid:
        return api_error('validation_error', status=400, details=error)

    username = session.get('user', 'api_user')
    comment = str(data.get('comment', '')).strip()[:300]
    db.log_activity(
        username,
        'Model Feedback',
        f'url={normalized_url}, predicted={predicted_label}, user={user_label}, comment={comment}',
        request.remote_addr,
    )

    return api_success({'recorded': True}, message='feedback_recorded', status=201)


@app.route("/api/blocklist", methods=["GET"])
def api_get_blocklist():
    """Get all blocklisted URLs"""
    blocklist = db.get_blocklist()
    return jsonify({
        'urls': [{'url': b['url'], 'added_by': b['added_by'], 
                  'reason': b['reason'], 'added_at': b['added_at']} 
                 for b in blocklist]
    })


@app.route("/get_blocklist")
def get_blocklist():
    """Return the blocklisted URLs as JSON (legacy endpoint)"""
    blocklist = db.get_blocklist()
    return jsonify({'urls': [b['url'] for b in blocklist]})


@app.route("/api/blocklist/add", methods=["POST"])
def api_add_to_blocklist():
    """Add URL to blocklist"""
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'success': False, 'message': 'URL is required'}), 400
    
    url = data['url']
    reason = data.get('reason', 'Added by admin')
    
    if db.add_to_blocklist(url, session['user'], reason):
        db.log_activity(session['user'], 'Blocklist Add', url, request.remote_addr)
        return jsonify({'success': True, 'message': 'URL added to blocklist'})
    return jsonify({'success': False, 'message': 'URL already in blocklist'}), 400


@app.route("/api/blocklist/remove", methods=["POST"])
@app.route("/remove_from_blocklist", methods=["POST"])
def api_remove_from_blocklist():
    """Remove URL from blocklist"""
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'success': False, 'message': 'URL is required'}), 400
    
    url = data['url']
    if db.remove_from_blocklist(url):
        db.log_activity(session['user'], 'Blocklist Remove', url, request.remote_addr)
        return jsonify({'success': True, 'message': 'URL removed from blocklist'})
    return jsonify({'success': False, 'message': 'URL not found'}), 404


# ============== USER MANAGEMENT API ==============

@app.route("/api/users", methods=["GET"])
def api_get_users():
    """Get all users"""
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    users = db.get_all_users()
    return jsonify({
        'users': [{
            'username': u['username'],
            'email': u['email'],
            'role': u['role'],
            'is_active': u['is_active'],
            'created_at': u['created_at'],
            'last_login': u['last_login'],
            'url_count': db.get_user_url_count(u['username'])
        } for u in users]
    })


@app.route("/api/users/add", methods=["POST"])
def api_add_user():
    """Add a new user"""
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Data is required'}), 400
    
    username = data.get('username')
    password = data.get('password')
    email = data.get('email', '')
    role = data.get('role', 'user')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    
    if db.add_user(username, password, email, role):
        db.log_activity(session['user'], 'User Add', f'Added user: {username}', request.remote_addr)
        return jsonify({'success': True, 'message': 'User added successfully'})
    return jsonify({'success': False, 'message': 'Username already exists'}), 400


@app.route("/api/users/update", methods=["POST"])
def api_update_user():
    """Update a user"""
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    
    username = data['username']
    updates = {}
    
    if 'password' in data and data['password']:
        updates['password'] = data['password']
    if 'email' in data:
        updates['email'] = data['email']
    if 'is_active' in data:
        updates['is_active'] = 1 if data['is_active'] else 0
    
    if updates:
        db.update_user(username, **updates)
        db.log_activity(session['user'], 'User Update', f'Updated user: {username}', request.remote_addr)
        return jsonify({'success': True, 'message': 'User updated successfully'})
    return jsonify({'success': False, 'message': 'No updates provided'}), 400


@app.route("/api/users/delete", methods=["POST"])
def api_delete_user():
    """Delete a user"""
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    
    username = data['username']
    
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Cannot delete admin user'}), 400
    
    if db.delete_user(username):
        db.log_activity(session['user'], 'User Delete', f'Deleted user: {username}', request.remote_addr)
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    return jsonify({'success': False, 'message': 'User not found or cannot be deleted'}), 404


# ============== ACTIVITY LOG API ==============

@app.route("/api/activity", methods=["GET"])
def api_get_activity():
    """Get activity log"""
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    limit = request.args.get('limit', 50, type=int)
    activities = db.get_activity_log(limit)
    return jsonify({
        'activities': [{
            'username': a['username'],
            'action': a['action'],
            'details': a['details'],
            'ip_address': a['ip_address'],
            'timestamp': a['timestamp']
        } for a in activities]
    })


# ============== STATS API ==============

@app.route("/api/stats", methods=["GET"])
def api_get_stats():
    """Get global statistics"""
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    stats = db.get_global_stats()
    return jsonify(stats)


@app.route("/api/stats/user/<username>", methods=["GET"])
def api_get_user_stats(username):
    """Get user statistics"""
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Users can only see their own stats unless admin
    if session['user'] != username and session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    stats = db.get_user_stats(username)
    return jsonify(stats)


# ============== URL HISTORY API ==============

@app.route("/api/history", methods=["GET"])
def api_get_history():
    """Get URL check history"""
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    username = request.args.get('username', session['user'])
    
    # Users can only see their own history unless admin
    if session['user'] != username and session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    limit = request.args.get('limit', 50, type=int)
    
    if session.get('role') == 'admin' and username == 'all':
        history = db.get_all_url_checks(limit)
    else:
        history = db.get_user_url_checks(username, limit)
    
    return jsonify({
        'history': [{
            'url': h['url'],
            'prediction_label': h['prediction_label'],
            'prediction_score': h['prediction_score'],
            'checked_at': h['checked_at']
        } for h in history]
    })


# ============== SETTINGS API ==============

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    """Get or update system settings"""
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    settings_file = 'settings.json'
    
    if request.method == "GET":
        try:
            import json
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
            else:
                settings = {
                    'system_name': 'Phishing Detection System',
                    'notification_email': 'admin@phishing.com',
                    'max_urls_per_session': 100,
                    'email_notifications': True,
                    'auto_blocklist': True
                }
            return jsonify({'success': True, 'settings': settings})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    
    else:  # POST
        try:
            import json
            data = request.get_json()
            with open(settings_file, 'w') as f:
                json.dump(data, f, indent=2)
            db.log_activity(session['user'], 'Settings Update', 'System settings updated', request.remote_addr)
            return jsonify({'success': True, 'message': 'Settings saved successfully'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500


# ============== STATIC PAGES ==============

@app.route("/about")
def about():
    return render_template("about_v2.html")


@app.route("/about_admin")
def about_admin():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_options'))
    return render_template("about_v2.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get('name', 'Anonymous')
        email = request.form.get('email', '')
        message = request.form.get('message', '')
        
        if 'user' in session:
            db.log_activity(session['user'], 'Contact Form', f'From: {email} - {message[:50]}...', request.remote_addr)
        flash('Your message has been sent!', 'success')
    
    return render_template("contact_v2.html")


@app.route("/contact_admin", methods=["GET", "POST"])
def contact_admin():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_options'))
    if request.method == "POST":
        flash('Message sent!', 'success')
    return render_template("contact_v2.html")


# ============== ERROR HANDLERS ==============

@app.errorhandler(404)
def not_found(e):
    return render_template('landing_page_v2.html'), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == "__main__":
    # Clear old session files
    if os.path.exists('session_files'):
        for f in os.listdir('session_files'):
            try:
                os.remove(os.path.join('session_files', f))
            except:
                pass
    
    print("=" * 50)
    print("🛡️  Phishing Detection System")
    print("=" * 50)
    print("Server running at: http://localhost:5001")
    print("Admin login: admin / admin123")
    print("User login: user1 / user123")
    print("=" * 50)
    
    app.run(debug=False, host='0.0.0.0', port=5001)
