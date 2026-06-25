"""
Database module for Phishing Detection System
Uses SQLite for persistent storage of URL checks, user stats, and activity logs
"""

import sqlite3
import os
import re
import logging
from datetime import datetime
from contextlib import contextmanager
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

# Vercel Serverless Functions have a read-only filesystem except for /tmp
DATABASE_PATH = os.environ.get("DATABASE_PATH")
if not DATABASE_PATH:
    if os.environ.get("VERCEL") == "1":
        DATABASE_PATH = '/tmp/phishing_detection.db'
    else:
        DATABASE_PATH = 'phishing_detection.db'

logger = logging.getLogger("phishing_app.db")

# ---------- Password helpers ----------

_PASSWORD_POLICY_RE = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\':\"\\|,.<>\/?]).{8,}$'
)

ALLOWED_USER_COLS = frozenset({'password', 'email', 'is_active'})


def validate_password_strength(password: str) -> None:
    """Enforce minimum password complexity (C-28).

    Rules: >=8 chars, mixed case, at least one digit, at least one symbol.
    """
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r'[a-z]', password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r'\d', password):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};\':\"\\|,.<>/?]', password):
        raise ValueError("Password must contain at least one special character")


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify password — **never** compare plaintext (A-02).

    Legacy rows that are not hashed will raise ValueError to force migration.
    """
    if stored_password.startswith('pbkdf2:') or stored_password.startswith('scrypt:'):
        return check_password_hash(stored_password, provided_password)
    # A-02: Refuse to compare plaintext passwords
    raise ValueError(
        "Legacy plaintext password detected. Run migrate_passwords.py to upgrade."
    )


# ---------- Connection management ----------

@contextmanager
def get_db():
    """Context manager for database connections (B-03 hardened)."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    # B-03: Enable WAL mode and busy timeout for concurrency
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


# ---------- Initialisation ----------

def init_db():
    """Initialize the database with all required tables"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')

        # URL Checks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                url TEXT NOT NULL,
                prediction_label TEXT,
                prediction_score REAL,
                is_phishing INTEGER,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Blocklist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                added_by TEXT,
                reason TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Activity Log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # A-03: Only seed demo users when explicitly opted-in
        if os.environ.get('PHISHGUARD_CREATE_DEMO_USERS') == '1':
            _seed_demo_users(cursor)

        conn.commit()
        logger.info("Database initialized successfully")


def _seed_demo_users(cursor):
    """Insert demo users — only called when PHISHGUARD_CREATE_DEMO_USERS=1."""
    default_users = [
        ('admin', hash_password('admin123'), 'admin@phishing.com', 'admin'),
        ('user1', hash_password('user123'), 'user1@example.com', 'user'),
        ('user2', hash_password('password2'), 'user2@example.com', 'user'),
        ('user3', hash_password('password3'), 'user3@example.com', 'user'),
        ('user4', hash_password('password4'), 'user4@example.com', 'user'),
    ]

    for username, password, email, role in default_users:
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO users (username, password, email, role)
                VALUES (?, ?, ?, ?)
            ''', (username, password, email, role))
        except Exception:
            pass


# ============== User Functions ==============

def get_user(username):
    """Get user by username"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        return cursor.fetchone()


def validate_user(username, password):
    """Validate user credentials"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user = cursor.fetchone()

        if user and verify_password(user['password'], password):
            # C-03: Log when a legacy password is migrated (should not happen now
            # since verify_password raises on plaintext, but kept for safety)
            if not (user['password'].startswith('pbkdf2:') or user['password'].startswith('scrypt:')):
                logger.warning(
                    "Legacy password migrated for user=%s (should not happen "
                    "after A-02 fix)", username
                )
                cursor.execute(
                    'UPDATE users SET password = ? WHERE username = ?',
                    (hash_password(password), username),
                )
            # Update last login
            cursor.execute('''
                UPDATE users SET last_login = ? WHERE username = ?
            ''', (datetime.now(), username))
            conn.commit()

        return user


def get_all_users():
    """Get all users"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
        return cursor.fetchall()


def add_user(username, password, email='', role='user'):
    """Add a new user (C-28: enforce password complexity)"""
    validate_password_strength(password)
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password, email, role)
                VALUES (?, ?, ?, ?)
            ''', (username, hash_password(password), email, role))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def update_user(username, calling_user=None, **kwargs):
    """Update user details (B-08: explicit column whitelist, B-13: self-lockout prevention)."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Verify user exists (C-37)
        cursor.execute('SELECT username, role FROM users WHERE username = ?', (username,))
        target = cursor.fetchone()
        if target is None:
            return 'not_found'

        for key, value in kwargs.items():
            # B-08: strict column whitelist
            if key not in ALLOWED_USER_COLS:
                raise ValueError(f'Column {key!r} is not updatable')

            if key == 'password':
                validate_password_strength(value)
                value = hash_password(value)

            # B-13: prevent admin from disabling themselves or the last admin
            if key == 'is_active' and not value:
                if calling_user and username == calling_user:
                    raise ValueError("Cannot deactivate your own account")
                # Check if this is the last active admin
                if target['role'] == 'admin':
                    cursor.execute(
                        'SELECT COUNT(*) as cnt FROM users WHERE role = ? AND is_active = 1 AND username != ?',
                        ('admin', username)
                    )
                    other_admins = cursor.fetchone()['cnt']
                    if other_admins == 0:
                        raise ValueError("Cannot deactivate the last admin account")

            cursor.execute(
                f'UPDATE users SET {key} = ? WHERE username = ?',
                (value, username)
            )
        conn.commit()
        return 'updated'


def delete_user(username):
    """Delete a user (C-25: distinguish not-found vs not-allowed)."""
    with get_db() as conn:
        cursor = conn.cursor()
        # Check if user exists first
        cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user is None:
            return 'not_found'
        if user['role'] == 'admin':
            return 'not_allowed'
        # C-02: consistent parameterized style
        cursor.execute('DELETE FROM users WHERE username = ? AND role != ?', (username, 'admin'))
        conn.commit()
        return 'deleted' if cursor.rowcount > 0 else 'not_found'


# ============== URL Check Functions ==============

def save_url_check(username, url, prediction_label, prediction_score, is_phishing):
    """Save a URL check to the database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO url_checks (username, url, prediction_label, prediction_score, is_phishing)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, url, prediction_label, prediction_score, is_phishing))
        conn.commit()


def get_user_url_checks(username, limit=50):
    """Get URL checks for a specific user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM url_checks WHERE username = ?
            ORDER BY checked_at DESC LIMIT ?
        ''', (username, limit))
        return cursor.fetchall()


def get_all_url_checks(limit=100):
    """Get all URL checks"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM url_checks ORDER BY checked_at DESC LIMIT ?
        ''', (limit,))
        return cursor.fetchall()


def get_user_stats(username):
    """Get statistics for a specific user"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Total checks
        cursor.execute('''
            SELECT COUNT(*) as total FROM url_checks WHERE username = ?
        ''', (username,))
        total = cursor.fetchone()['total']

        # Safe checks
        cursor.execute('''
            SELECT COUNT(*) as safe FROM url_checks 
            WHERE username = ? AND is_phishing = 0
        ''', (username,))
        safe = cursor.fetchone()['safe']

        # Unsafe checks
        cursor.execute('''
            SELECT COUNT(*) as unsafe FROM url_checks 
            WHERE username = ? AND is_phishing = 1
        ''', (username,))
        unsafe = cursor.fetchone()['unsafe']

        return {
            'total_checked': total,
            'safe_count': safe,
            'unsafe_count': unsafe,
            'safety_rate': round((safe / total * 100) if total > 0 else 0, 1)
        }


def get_global_stats():
    """Get global statistics"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Total URLs checked
        cursor.execute('SELECT COUNT(*) as total FROM url_checks')
        total = cursor.fetchone()['total']

        # Safe URLs
        cursor.execute('SELECT COUNT(*) as safe FROM url_checks WHERE is_phishing = 0')
        safe = cursor.fetchone()['safe']

        # Unsafe URLs
        cursor.execute('SELECT COUNT(*) as unsafe FROM url_checks WHERE is_phishing = 1')
        unsafe = cursor.fetchone()['unsafe']

        # Active users (users who checked at least one URL)
        cursor.execute('SELECT COUNT(DISTINCT username) as active FROM url_checks')
        active_users = cursor.fetchone()['active']

        # Total users
        cursor.execute('SELECT COUNT(*) as total FROM users')
        total_users = cursor.fetchone()['total']

        # URLs checked today
        cursor.execute('''
            SELECT COUNT(*) as today FROM url_checks 
            WHERE DATE(checked_at) = DATE('now')
        ''')
        today = cursor.fetchone()['today']

        return {
            'total_urls': total,
            'safe_urls': safe,
            'unsafe_urls': unsafe,
            'active_users': active_users,
            'total_users': total_users,
            'urls_today': today
        }


def get_user_url_count(username):
    """Get URL check count for a user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) as count FROM url_checks WHERE username = ?
        ''', (username,))
        return cursor.fetchone()['count']


def get_recent_phishing_urls(limit=8):
    """Get the most recent phishing URLs for the public home page"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT url, prediction_label, prediction_score, checked_at
            FROM url_checks
            WHERE is_phishing = 1
            ORDER BY checked_at DESC
            LIMIT ?
        ''', (limit,))
        return cursor.fetchall()


# ============== Blocklist Functions ==============

def _validate_blocklist_url(url: str) -> str:
    """Validate and normalize URL for blocklist (B-10)."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Blocklist URL must be a non-empty string")
    url = url.strip()
    if len(url) > 2048:
        raise ValueError("Blocklist URL too long (max 2048 chars)")
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Invalid URL scheme '{parsed.scheme}'; only http/https allowed")
    return url


def add_to_blocklist(url, added_by='admin', reason='Detected as phishing'):
    """Add URL to blocklist (B-10: validates URL)"""
    url = _validate_blocklist_url(url)
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO blocklist (url, added_by, reason)
                VALUES (?, ?, ?)
            ''', (url, added_by, reason))
            conn.commit()
            return cursor.rowcount > 0
        except Exception:
            return False


def remove_from_blocklist(url):
    """Remove URL from blocklist"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM blocklist WHERE url = ?', (url,))
        conn.commit()
        return cursor.rowcount > 0


def is_blocklisted(url):
    """Check if URL is in blocklist"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM blocklist WHERE url = ?', (url,))
        return cursor.fetchone() is not None


def get_blocklist():
    """Get all blocklisted URLs"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM blocklist ORDER BY added_at DESC')
        return cursor.fetchall()


# ============== Activity Log Functions ==============

def log_activity(username, action, details='', ip_address=''):
    """Log an activity"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO activity_log (username, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (username, action, details, ip_address))
        conn.commit()


def get_activity_log(limit=100):
    """Get activity log"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        return cursor.fetchall()


def get_user_activity(username, limit=50):
    """Get activity log for a specific user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM activity_log WHERE username = ?
            ORDER BY timestamp DESC LIMIT ?
        ''', (username, limit))
        return cursor.fetchall()


def feedback_already_recorded(username: str, url: str, predicted_label: int) -> bool:
    """C-10: Check whether this user already recorded feedback for this URL+label."""
    safe_action = 'Model Feedback'
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT 1 FROM activity_log
            WHERE username = ? AND action = ? AND details LIKE ?
            LIMIT 1
            ''',
            (username, safe_action, f'url={url}, predicted={predicted_label},%'),
        )
        return cursor.fetchone() is not None


# ============== Export Functions ==============

def export_user_history(username, limit=1000, offset=0):
    """Export user's URL check history as list of dicts (C-38: paginated)"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT url, prediction_label, prediction_score, checked_at
            FROM url_checks WHERE username = ?
            ORDER BY checked_at DESC
            LIMIT ? OFFSET ?
        ''', (username, limit, offset))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


# Initialize database on import
if not os.path.exists(DATABASE_PATH):
    init_db()
