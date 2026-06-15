"""
Database module for Phishing Detection System
Uses SQLite for persistent storage of URL checks, user stats, and activity logs
"""

import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE_PATH = 'phishing_detection.db'


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(stored_password: str, provided_password: str) -> bool:
    # Backward compatible verification:
    # - hashed passwords (preferred)
    # - legacy plaintext passwords (temporary)
    try:
        if stored_password.startswith('pbkdf2:') or stored_password.startswith('scrypt:'):
            return check_password_hash(stored_password, provided_password)
    except Exception:
        pass
    return stored_password == provided_password


@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


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
        
        # Insert default users if not exist
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
            except:
                pass
        
        conn.commit()
        print("Database initialized successfully!")


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
            # Migrate legacy plaintext password to hashed format at successful login
            if not (user['password'].startswith('pbkdf2:') or user['password'].startswith('scrypt:')):
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
    """Add a new user"""
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


def update_user(username, **kwargs):
    """Update user details"""
    with get_db() as conn:
        cursor = conn.cursor()
        for key, value in kwargs.items():
            if key in ['password', 'email', 'is_active']:
                if key == 'password':
                    value = hash_password(value)
                cursor.execute(f'''
                    UPDATE users SET {key} = ? WHERE username = ?
                ''', (value, username))
        conn.commit()


def delete_user(username):
    """Delete a user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username = ? AND role != "admin"', (username,))
        conn.commit()
        return cursor.rowcount > 0


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

def add_to_blocklist(url, added_by='admin', reason='Detected as phishing'):
    """Add URL to blocklist"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO blocklist (url, added_by, reason)
                VALUES (?, ?, ?)
            ''', (url, added_by, reason))
            conn.commit()
            return cursor.rowcount > 0
        except:
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


# ============== Export Functions ==============

def export_user_history(username):
    """Export user's URL check history as list of dicts"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT url, prediction_label, prediction_score, checked_at
            FROM url_checks WHERE username = ?
            ORDER BY checked_at DESC
        ''', (username,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


# Initialize database on import
if not os.path.exists(DATABASE_PATH):
    init_db()
