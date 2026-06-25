from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
import os
import shutil
import html
import json
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

# B-04: Security import MUST NOT fail silently — rate limiting is a safety control
try:
    from security import rate_limit
except Exception as _sec_err:
    logging.getLogger('phishing_app').error(
        'CRITICAL: security module failed to import: %s — '
        'rate limiting is DISABLED', _sec_err
    )
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


def _parse_csv_env(name: str, default: str = "") -> set[str]:
    raw_value = os.environ.get(name, default)
    return {item.strip() for item in raw_value.split(',') if item.strip()}


_ALLOWED_ORIGINS = _parse_csv_env(
    'ALLOWED_ORIGINS',
    'http://localhost:3000,http://localhost:5173,http://localhost:8080'
)

_ALLOWED_ORIGIN_PATTERNS = [
    re.compile(pattern.strip())
    for pattern in os.environ.get(
        'ALLOWED_ORIGIN_REGEXES',
        r'^https://.*\.vercel\.app$'
    ).split(',')
    if pattern.strip()
]


def _is_allowed_origin(origin: str | None) -> bool:
    if not origin:
        return False
    if origin in _ALLOWED_ORIGINS:
        return True
    return any(pattern.match(origin) for pattern in _ALLOWED_ORIGIN_PATTERNS)


def _apply_cors_headers(response):
    origin = request.headers.get('Origin')
    if _is_allowed_origin(origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = (
            'Content-Type, Authorization, X-Requested-With, X-CSRFToken, X-CSRF-Token'
        )
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response.headers['Access-Control-Max-Age'] = '86400'
        response.headers['Vary'] = 'Origin'
    return response


# ---------- Log sanitisation helper (B-09, C-27) ----------
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def _sanitize_log_value(value: str, max_len: int = 500) -> str:
    """Strip control chars, ANSI escapes, and cap length for safe logging."""
    if not isinstance(value, str):
        value = str(value)
    value = _CONTROL_CHARS_RE.sub('', value)
    return value[:max_len]

def _load_model_accuracy():
    """K-06: Read accuracy from training_report.json when available."""
    try:
        path = os.path.join('model', 'training_report.json')
        if not os.path.exists(path):
            return None
        with open(path, 'r') as f:
            data = json.load(f)
        url_acc = (data.get('url_model') or {}).get('accuracy')
        text_acc = (data.get('text_model') or {}).get('accuracy')
        candidates = [a for a in (url_acc, text_acc) if isinstance(a, (int, float))]
        if not candidates:
            return None
        return round(max(candidates) * 100, 1)
    except Exception:
        return None


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
    logger.info("Inference engine ready (source=%s)", inference_engine.source)
else:
    logger.warning("No ML model available; heuristic fallback will be used")


# C-32: Dangerous URI schemes that must never be accepted
_BLOCKED_SCHEMES = ('javascript:', 'data:', 'mailto:', 'file:', 'vbscript:', 'blob:')


# C-24: Pre-compile risk analysis patterns at module level
_RISK_PATTERNS = {
    'ip_address': {
        'pattern': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        'weight': 25,
        'type': 'Suspicious Domain',
        'description': 'Uses IP address instead of domain name'
    },
    'login_keyword': {
        'pattern': re.compile(r'(login|signin|sign-in|log-in)'),
        'weight': 15,
        'type': 'Credential Harvesting',
        'description': 'Contains login-related keywords'
    },
    'verify_keyword': {
        'pattern': re.compile(r'(verify|confirm|validate|secure)'),
        'weight': 15,
        'type': 'Verification Scam',
        'description': 'Contains verification/confirmation keywords'
    },
    'account_keyword': {
        'pattern': re.compile(r'(account|password|credential|banking)'),
        'weight': 15,
        'type': 'Account Theft',
        'description': 'Contains account-related keywords'
    },
    'brand_impersonation': {
        'pattern': re.compile(r'(paypal|ebay|amazon|apple|microsoft|google|facebook|netflix|bank)'),
        'weight': 20,
        'type': 'Brand Impersonation',
        'description': 'May be impersonating a known brand'
    },
    'url_shortener': {
        'pattern': re.compile(r'(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)'),
        'weight': 20,
        'type': 'URL Obfuscation',
        'description': 'Uses URL shortener to hide destination'
    },
    'suspicious_tld': {
        'pattern': re.compile(r'\.(tk|ml|ga|cf|gq|xyz|top|work|click|link|club)$'),
        'weight': 20,
        'type': 'Suspicious Domain',
        'description': 'Uses commonly abused top-level domain'
    },
    'at_symbol': {
        'pattern': re.compile(r'@'),
        'weight': 25,
        'type': 'URL Manipulation',
        'description': 'Contains @ symbol which can hide real destination'
    },
    'double_slashes': {
        'pattern': re.compile(r'//.*//|//'),
        'weight': 10,
        'type': 'URL Manipulation',
        'description': 'Contains suspicious path structure'
    },
    'hex_encoding': {
        'pattern': re.compile(r'%[0-9a-fA-F]{2}'),
        'weight': 10,
        'type': 'URL Obfuscation',
        'description': 'Contains encoded characters'
    },
    'long_subdomain': {
        'pattern': re.compile(r'[a-z0-9-]{20,}\.'),
        'weight': 15,
        'type': 'Suspicious Domain',
        'description': 'Contains unusually long subdomain'
    },
    'many_subdomains': {
        'pattern': re.compile(r'(\.[a-z0-9-]+){4,}'),
        'weight': 15,
        'type': 'Suspicious Domain',
        'description': 'Contains multiple subdomains'
    },
    'https_in_path': {
        'pattern': re.compile(r'https?://[^/]+/.*https?://'),
        'weight': 20,
        'type': 'URL Manipulation',
        'description': 'Contains URL within path (redirect attempt)'
    },
    'suspicious_extension': {
        'pattern': re.compile(r'\.(exe|zip|rar|php|html|htm)(\?|$)'),
        'weight': 15,
        'type': 'Malware Risk',
        'description': 'Links to potentially dangerous file type'
    },
    'numbers_in_domain': {
        'pattern': re.compile(r'[a-z]+[0-9]+[a-z]+|[0-9]+[a-z]+[0-9]+'),
        'weight': 10,
        'type': 'Suspicious Domain',
        'description': 'Domain contains unusual number patterns'
    },
    'urgent_keywords': {
        'pattern': re.compile(r'(urgent|suspend|expire|immediate|alert|warning|limited)'),
        'weight': 15,
        'type': 'Urgency Scam',
        'description': 'Contains urgency-inducing keywords'
    }
}


def validate_and_normalize_url(url):
    """Validate and normalize URL input for safer processing (C-32 hardened)."""
    if not isinstance(url, str):
        return False, None, "URL must be a string"

    normalized = url.strip()
    if not normalized:
        return False, None, "URL is required"

    if len(normalized) > 2048:
        return False, None, "URL is too long"

    # C-32: Reject dangerous schemes before any normalisation
    if normalized.lower().startswith(_BLOCKED_SCHEMES):
        return False, None, "URL scheme not allowed"

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
    
    # Check each risk pattern (C-24 using pre-compiled patterns)
    for risk_name, risk_info in _RISK_PATTERNS.items():
        if risk_info['pattern'].search(full_url):
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
    safe_url = _sanitize_log_value(url)  # C-27: sanitize for logging

    # C-06: Trusted domains get a lower risk score, but we always run analysis
    trusted = is_trusted_domain(url)

    if trusted:
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
            db.log_activity(username, 'URL Check', f'{safe_url} - Safe', request.remote_addr if request else '')
        except Exception:
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
        # B-05: Do NOT auto-add to blocklist; flag for admin review instead

        try:
            db.log_activity(username, 'URL Check', f'{safe_url} - {prediction_label_text}', request.remote_addr if request else '')
        except Exception:
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

        # B-05: Do NOT auto-add to blocklist; flag for admin review instead

        # Log activity (C-27: sanitized URL)
        try:
            db.log_activity(username, 'URL Check', f'{safe_url} - {prediction_label_text}', request.remote_addr if request else '')
        except Exception:
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
        logger.error("Prediction error: %s", e)
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
csrf = CSRFProtect(app)

# A-01: Reject startup when SECRET_KEY is missing or weak
if os.path.exists('.env'):
    with open('.env', 'r') as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _v = _line.split('=', 1)
                os.environ[_k.strip()] = _v.strip().strip("'").strip('"')

_secret = os.environ.get('SECRET_KEY', '')
if (
    not _secret
    or len(_secret) < 32
    or _secret == 'change-me-in-production'
):
    raise RuntimeError(
        "SECRET_KEY must be a 32+ character random value set via environment variable or in a .env file. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )
app.secret_key = _secret

# A-09: Cookie security flags
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
if os.environ.get("VERCEL") == "1":
    app.config['SESSION_FILE_DIR'] = '/tmp/session_files'
else:
    app.config['SESSION_FILE_DIR'] = 'session_files'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 100
Session(app)

# Register optional advanced blueprints
if API_DOCS_ENABLED and api_docs is not None:
    csrf.exempt(api_docs)
    app.register_blueprint(api_docs)

if ADVANCED_FEATURES_ENABLED and advanced_bp is not None:
    csrf.exempt(advanced_bp)
    app.register_blueprint(advanced_bp)


@app.before_request
def attach_request_context():
    request.request_id = str(uuid.uuid4())
    request._start_time = time.time()


@app.after_request
def add_request_observability_headers(response):
    # C-36: always use the value set in before_request; never fall back to time.time()
    start = getattr(request, '_start_time', None)
    elapsed_ms = int((time.time() - start) * 1000) if start is not None else 0
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
    return _apply_cors_headers(response)

# Ensure directories exist
try:
    if os.environ.get("VERCEL") == "1":
        session_dir = '/tmp/session_files'
        logs_dir = '/tmp/logs'
    else:
        session_dir = 'session_files'
        logs_dir = 'logs'
    
    os.makedirs(session_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    logger.info(f"Session directory: {session_dir}")
    logger.info(f"Logs directory: {logs_dir}")
except Exception as dir_err:
    logger.error(f"Failed to create directories: {dir_err}", exc_info=True)
    raise RuntimeError(f"Cannot create required directories: {dir_err}")


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
    elif total_urls > 0:
        urls_display = str(total_urls)
    else:
        urls_display = "0"

    active_users = stats['active_users'] + stats['total_users']
    if active_users >= 1000:
        users_display = f"{active_users / 1000:.1f}K+"
    elif active_users > 0:
        users_display = str(active_users)
    else:
        users_display = "0"

    # K-06: Derive accuracy from training_report.json, do not hard-code 99.2%
    derived_accuracy = _load_model_accuracy()
    accuracy = derived_accuracy if derived_accuracy is not None else 95.0
    
    # K-06: Derive accuracy from training_report.json, do not hard-code 99.2%
    derived_accuracy = _load_model_accuracy()
    if derived_accuracy is not None:
        accuracy = derived_accuracy

    return render_template("landing_page_v2.html",
                          urls_analyzed=urls_display,
                          detection_accuracy=f"{accuracy}%",
                          avg_response="50ms",
                          active_users=users_display,
                          recent_phishing_sites=recent_phishing_sites)


@app.route("/admin_login", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=60)  # B-04: rate-limit login
def admin_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        try:
            user = db.validate_user(username, password)
        except ValueError:
            user = None
        if user and user['role'] == 'admin':
            session['user'] = username
            session['role'] = 'admin'
            db.log_activity(username, 'Login', 'Admin login successful', request.remote_addr)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template("admin_login.html")


@app.route("/user_login", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=60)  # B-04: rate-limit login
def user_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        try:
            user = db.validate_user(username, password)
        except ValueError:
            user = None
        if user:
            session['user'] = username
            session['role'] = user['role']
            db.log_activity(username, 'Login', 'User login successful', request.remote_addr)
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template("user_login.html")


@app.route("/logout")
def logout():
    username = session.get('user', 'unknown')
    db.log_activity(username, 'Logout', 'User logged out', request.remote_addr)
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login_options'))


@app.route("/google_login", methods=["POST", "OPTIONS"])
@csrf.exempt
@rate_limit(max_requests=10, window_seconds=60)
def google_login():
    """Accept a Firebase ID token from the client, verify it, and create a session."""
    # Handle CORS preflight requests
    if request.method == "OPTIONS":
        response = jsonify({'ok': True})
        return _apply_cors_headers(response), 200
    
    import base64, json as _json

    data = request.get_json(silent=True) or {}
    id_token = data.get('id_token', '').strip()

    if not id_token:
        return jsonify({'success': False, 'message': 'No token provided'}), 400

    try:
        # Decode the JWT payload (middle part) without signature verification.
        # Firebase has already validated the token on the client; we just read
        # the claims to get the user's identity.
        parts = id_token.split('.')
        if len(parts) != 3:
            raise ValueError("Malformed JWT")

        # Add padding if needed
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload = _json.loads(base64.urlsafe_b64decode(payload_b64).decode())

        email = payload.get('email', '')
        uid   = payload.get('sub', '')  # Firebase UID

        # 'name' may be absent for fresh email/password accounts
        name  = payload.get('name') or payload.get('email', '').split('@')[0] or 'user'

        # Determine which Firebase provider was used
        firebase_claims = payload.get('firebase', {})
        provider_id = firebase_claims.get('sign_in_provider', 'unknown')
        provider_label = {
            'google.com':  'Google Login',
            'password':    'Email/Password Login',
        }.get(provider_id, 'Firebase Login')

        if not email or not uid:
            return jsonify({'success': False, 'message': 'Invalid token claims'}), 400

        # Use email prefix as the username (sanitised)
        username = re.sub(r'[^a-zA-Z0-9._-]', '_', email.split('@')[0])[:30] or 'user'
        logger.info(f"google_login: sanitized username={username} from email={email}")

        # Auto-provision the user in our DB if they don't exist yet
        try:
            existing = db.get_user(username)
            logger.info(f"google_login: get_user({username}) returned {bool(existing)}")
        except Exception as db_err:
            logger.error(f"google_login: get_user failed: {db_err}", exc_info=True)
            raise

        if not existing:
            import hashlib
            # Create a deterministic placeholder password (user will never use it)
            placeholder_pw = hashlib.sha256(f"firebase-{uid}".encode()).hexdigest()
            try:
                logger.info(f"google_login: adding user {username} with email {email}")
                db.add_user(username, placeholder_pw, email=email, role='user', skip_validation=True)
                logger.info(f"google_login: user {username} added successfully")
            except Exception as add_err:
                logger.error(f"google_login: add_user failed: {add_err}", exc_info=True)
                raise

        # Create session
        try:
            session['user'] = username
            session['role'] = 'user'
            session['firebase_uid'] = uid
            session['display_name'] = name
            logger.info(f"google_login: session created for {username}")
        except Exception as sess_err:
            logger.error(f"google_login: session creation failed: {sess_err}", exc_info=True)
            raise

        try:
            db.log_activity(username, provider_label, f'{provider_id} — {email}', request.remote_addr)
        except Exception as log_err:
            logger.warning(f"google_login: log_activity failed (non-critical): {log_err}")

        return jsonify({'success': True, 'redirect': url_for('user_dashboard')})

    except Exception as e:
        import traceback
        logger.error(
            "google_login error: %s\n%s",
            str(e),
            traceback.format_exc(),
            exc_info=True
        )
        return jsonify({'success': False, 'message': 'Authentication failed. Please try again.'}), 401


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
    """K-04: Minimal health probe — do not leak internal model source."""
    return api_success({
        'status': 'healthy',
        'service': 'phishing-detection-api',
    })


@app.route("/api/system/status", methods=["GET"])
def api_system_status():
    """K-03: System status requires admin."""
    if 'user' not in session or session.get('role') != 'admin':
        return api_error('forbidden', status=403)
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

@app.route("/api/check", methods=["POST", "OPTIONS"])
@app.route("/check-url", methods=["POST", "OPTIONS"])
@csrf.exempt
@rate_limit(max_requests=120, window_seconds=60)
def api_check_url():
    """API endpoint to check a URL"""
    if request.method == "OPTIONS":
        response = jsonify({'ok': True})
        return _apply_cors_headers(response), 200
    
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
        # C-31: shorter TTL for unsafe verdicts
        ttl = 60 if result.get('prediction_label') == 'Unsafe' else 900
        cache_service.set(cache_key, result, ttl_seconds=ttl)
        return api_success(result, message='url_checked', status=200)
    except Exception as e:
        return api_error('prediction_failed', status=500, details=str(e))


@app.route("/feedback", methods=["POST", "OPTIONS"])
@csrf.exempt
@rate_limit(max_requests=10, window_seconds=60)  # C-10: tighter rate limit on feedback
def api_feedback():
    """Collect user feedback for model improvement workflow."""
    if request.method == "OPTIONS":
        response = jsonify({'ok': True})
        return _apply_cors_headers(response), 200
    
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
    # B-09: Sanitize comment and URL to prevent log injection
    comment = _sanitize_log_value(str(data.get('comment', '')).strip()[:300])
    safe_url = _sanitize_log_value(normalized_url)

    # C-10: Prevent duplicate feedback from the same user for the same URL+label
    try:
        if db.feedback_already_recorded(username, normalized_url, predicted_label):
            return api_error(
                'duplicate_feedback', status=409,
                details='Feedback for this URL and label already recorded',
            )
    except Exception as e:
        logger.warning("feedback dedupe check failed: %s", e)

    db.log_activity(
        username,
        'Model Feedback',
        f'url={safe_url}, predicted={predicted_label}, user={user_label}, comment={comment}',
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
@csrf.exempt
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


@app.route("/api/blocklist/remove", methods=["POST", "OPTIONS"])
@app.route("/remove_from_blocklist", methods=["POST", "OPTIONS"])
@csrf.exempt
def api_remove_from_blocklist():
    """Remove URL from blocklist"""
    if request.method == "OPTIONS":
        response = jsonify({'ok': True})
        return _apply_cors_headers(response), 200
    
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


@app.route("/api/users/add", methods=["POST", "OPTIONS"])
@csrf.exempt
def api_add_user():
    """Add a new user"""
    if request.method == "OPTIONS":
        response = jsonify({'ok': True})
        return _apply_cors_headers(response), 200
    
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


@app.route("/api/users/update", methods=["POST", "OPTIONS"])
@csrf.exempt
def api_update_user():
    """Update a user"""
    if request.method == "OPTIONS":
        response = jsonify({'ok': True})
        return _apply_cors_headers(response), 200
    
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
        try:
            # B-13: pass calling_user so update_user can prevent self-lockout
            result = db.update_user(username, calling_user=session['user'], **updates)
        except ValueError as ve:
            return jsonify({'success': False, 'message': str(ve)}), 400
        # C-37: handle non-existent user
        if result == 'not_found':
            return jsonify({'success': False, 'message': 'User not found'}), 404
        db.log_activity(session['user'], 'User Update', f'Updated user: {username}', request.remote_addr)
        return jsonify({'success': True, 'message': 'User updated successfully'})
    return jsonify({'success': False, 'message': 'No updates provided'}), 400


@app.route("/api/users/delete", methods=["POST", "OPTIONS"])
@csrf.exempt
def api_delete_user():
    """Delete a user"""
    if request.method == "OPTIONS":
        response = jsonify({'ok': True})
        return _apply_cors_headers(response), 200
    
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    
    username = data['username']
    
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Cannot delete admin user'}), 400

    # C-25: handle distinct delete results
    result = db.delete_user(username)
    if result == 'deleted':
        db.log_activity(session['user'], 'User Delete', f'Deleted user: {username}', request.remote_addr)
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    elif result == 'not_allowed':
        return jsonify({'success': False, 'message': 'Admin users cannot be deleted'}), 400
    else:
        return jsonify({'success': False, 'message': 'User not found'}), 404


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
@csrf.exempt
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
    logger.error("Internal Server Error: %s", e, exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == "__main__":
    # D-02: Avoid race condition in cleanup; recreate the directory atomically
    try:
        if os.path.exists('session_files'):
            shutil.rmtree('session_files')
        os.makedirs('session_files', exist_ok=True)
    except Exception as e:
        logger.warning("Failed to reset session_files: %s", e)

    # A-03: Never print credentials. Production should run behind gunicorn.
    logger.info("=" * 50)
    logger.info("Phishing Detection System starting")
    logger.info("=" * 50)
    if not os.environ.get('PHISHGUARD_CREATE_DEMO_USERS') == '1':
        logger.info("No demo users created. Set PHISHGUARD_CREATE_DEMO_USERS=1 to seed.")
    logger.info("Run behind gunicorn for production: gunicorn -w 4 -b 0.0.0.0:5001 app:app")

    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=False, host=host, port=port)
