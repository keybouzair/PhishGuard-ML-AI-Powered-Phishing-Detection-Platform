"""
Security Module
Implements rate limiting, 2FA, IP management, API key management, and encryption
"""

import hashlib
import hmac
import secrets
import time
import sqlite3
import os
import json
import base64
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Tuple
from flask import request, jsonify, session
import pyotp
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DATABASE_PATH = os.environ.get("DATABASE_PATH")
if not DATABASE_PATH:
    if os.environ.get("VERCEL") == "1":
        DATABASE_PATH = '/tmp/phishing_detection.db'
    else:
        DATABASE_PATH = 'phishing_detection.db'

ENCRYPTION_KEY_FILE = os.environ.get("ENCRYPTION_KEY_FILE")
if not ENCRYPTION_KEY_FILE:
    if os.environ.get("VERCEL") == "1":
        ENCRYPTION_KEY_FILE = '/tmp/encryption.key'
    else:
        ENCRYPTION_KEY_FILE = 'encryption.key'


# ============== Rate Limiting ==============

class RateLimiter:
    """Rate limiting implementation using sliding window"""
    
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
        self._init_table()
    
    def _init_table(self):
        """Initialize rate limiting table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp REAL NOT NULL,
                UNIQUE(identifier, endpoint, timestamp)
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_rate_limits 
            ON rate_limits(identifier, endpoint, timestamp)
        ''')
        conn.commit()
        conn.close()
    
    def is_allowed(self, identifier: str, endpoint: str, 
                   max_requests: int = 100, window_seconds: int = 60) -> Tuple[bool, Dict]:
        """
        Check if request is allowed based on rate limit
        
        Args:
            identifier: IP address or user ID
            endpoint: API endpoint
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
        
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = time.time()
        window_start = current_time - window_seconds
        
        # Count requests in window
        cursor.execute('''
            SELECT COUNT(*) FROM rate_limits
            WHERE identifier = ? AND endpoint = ? AND timestamp > ?
        ''', (identifier, endpoint, window_start))
        
        count = cursor.fetchone()[0]
        
        # Clean up old entries
        cursor.execute('''
            DELETE FROM rate_limits WHERE timestamp < ?
        ''', (window_start - 3600,))  # Clean entries older than 1 hour
        
        info = {
            'limit': max_requests,
            'remaining': max(0, max_requests - count),
            'reset_at': datetime.fromtimestamp(window_start + window_seconds).isoformat(),
            'retry_after': max(0, int(window_seconds - (current_time - window_start)))
        }
        
        if count >= max_requests:
            conn.commit()
            conn.close()
            return False, info
        
        # Log this request
        cursor.execute('''
            INSERT INTO rate_limits (identifier, endpoint, timestamp)
            VALUES (?, ?, ?)
        ''', (identifier, endpoint, current_time))
        
        conn.commit()
        conn.close()
        
        info['remaining'] = max_requests - count - 1
        return True, info
    
    def get_usage(self, identifier: str, endpoint: str = None) -> Dict:
        """Get rate limit usage for an identifier"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = time.time()
        window_start = current_time - 60  # Last minute
        
        if endpoint:
            cursor.execute('''
                SELECT COUNT(*) FROM rate_limits
                WHERE identifier = ? AND endpoint = ? AND timestamp > ?
            ''', (identifier, endpoint, window_start))
        else:
            cursor.execute('''
                SELECT endpoint, COUNT(*) FROM rate_limits
                WHERE identifier = ? AND timestamp > ?
                GROUP BY endpoint
            ''', (identifier, window_start))
        
        result = cursor.fetchall()
        conn.close()
        
        if endpoint:
            return {'endpoint': endpoint, 'requests_last_minute': result[0][0]}
        
        return {'endpoints': {r[0]: r[1] for r in result}}


def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """Decorator for rate limiting endpoints"""
    limiter = RateLimiter()
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get identifier (IP or user)
            # C-12: Proxy-aware rate limiting
            identifier = request.headers.get('X-Forwarded-For', request.remote_addr)
            if identifier and ',' in identifier:
                identifier = identifier.split(',')[0].strip()
                
            if 'user' in session:
                identifier = session['user']
            
            endpoint = request.endpoint or request.path
            
            allowed, info = limiter.is_allowed(
                identifier, endpoint, max_requests, window_seconds
            )
            
            if not allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Try again in {info["retry_after"]} seconds.',
                    'rate_limit': info
                })
                response.status_code = 429
                response.headers['X-RateLimit-Limit'] = str(info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(info['remaining'])
                response.headers['X-RateLimit-Reset'] = info['reset_at']
                response.headers['Retry-After'] = str(info['retry_after'])
                return response
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ============== Two-Factor Authentication ==============

class TwoFactorAuth:
    """Two-factor authentication using TOTP"""
    
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
        self._init_table()
    
    def _init_table(self):
        """Initialize 2FA table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_2fa (
                username TEXT PRIMARY KEY,
                secret_key TEXT NOT NULL,
                is_enabled INTEGER DEFAULT 0,
                backup_codes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def setup_2fa(self, username: str) -> Dict:
        """
        Set up 2FA for a user
        
        Returns:
            Dictionary with secret key and QR code provisioning URI
        """
        # Generate secret key
        secret = pyotp.random_base32()
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        
        # Create TOTP object
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name='Phishing Detector'
        )
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO user_2fa (username, secret_key, backup_codes, is_enabled)
            VALUES (?, ?, ?, 0)
        ''', (username, secret, json.dumps(backup_codes)))
        conn.commit()
        conn.close()
        
        return {
            'secret': secret,
            'provisioning_uri': provisioning_uri,
            'backup_codes': backup_codes,
            'qr_data': provisioning_uri  # Can be used to generate QR code
        }
    
    def enable_2fa(self, username: str, token: str) -> bool:
        """Enable 2FA after verifying first token"""
        if self.verify_token(username, token):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE user_2fa SET is_enabled = 1 WHERE username = ?
            ''', (username,))
            conn.commit()
            conn.close()
            return True
        return False
    
    def disable_2fa(self, username: str) -> bool:
        """Disable 2FA for user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM user_2fa WHERE username = ?
        ''', (username,))
        conn.commit()
        conn.close()
        return True
    
    def verify_token(self, username: str, token: str) -> bool:
        """Verify TOTP token"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT secret_key, backup_codes FROM user_2fa WHERE username = ?
        ''', (username,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False
        
        secret, backup_codes_json = result
        
        # Check TOTP
        totp = pyotp.TOTP(secret)
        if totp.verify(token, valid_window=1):
            cursor.execute('''
                UPDATE user_2fa SET last_used = ? WHERE username = ?
            ''', (datetime.now(), username))
            conn.commit()
            conn.close()
            return True
        
        # Check backup codes
        try:
            backup_codes = json.loads(backup_codes_json) if backup_codes_json else []
            if token.upper() in backup_codes:
                backup_codes.remove(token.upper())
                cursor.execute('''
                    UPDATE user_2fa SET backup_codes = ?, last_used = ? WHERE username = ?
                ''', (json.dumps(backup_codes), datetime.now(), username))
                conn.commit()
                conn.close()
                return True
        except:
            pass
        
        conn.close()
        return False
    
    def is_enabled(self, username: str) -> bool:
        """Check if 2FA is enabled for user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT is_enabled FROM user_2fa WHERE username = ?
        ''', (username,))
        result = cursor.fetchone()
        conn.close()
        
        return result and result[0] == 1
    
    def get_remaining_backup_codes(self, username: str) -> int:
        """Get number of remaining backup codes"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT backup_codes FROM user_2fa WHERE username = ?
        ''', (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            try:
                return len(json.loads(result[0]))
            except:
                pass
        return 0


# ============== IP Management ==============

class IPManager:
    """Manage IP whitelist/blacklist"""
    
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
        self._init_table()
    
    def _init_table(self):
        """Initialize IP management table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_management (
                ip_address TEXT PRIMARY KEY,
                list_type TEXT NOT NULL,
                reason TEXT,
                added_by TEXT,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def add_to_whitelist(self, ip: str, reason: str = '', added_by: str = 'system') -> bool:
        """Add IP to whitelist"""
        return self._add_ip(ip, 'whitelist', reason, added_by)
    
    def add_to_blacklist(self, ip: str, reason: str = '', added_by: str = 'system',
                        duration_hours: int = None) -> bool:
        """Add IP to blacklist"""
        expires_at = None
        if duration_hours:
            expires_at = datetime.now() + timedelta(hours=duration_hours)
        return self._add_ip(ip, 'blacklist', reason, added_by, expires_at)
    
    def _add_ip(self, ip: str, list_type: str, reason: str, 
                added_by: str, expires_at: datetime = None) -> bool:
        """Add IP to list"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO ip_management 
                (ip_address, list_type, reason, added_by, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip, list_type, reason, added_by, expires_at))
            conn.commit()
            conn.close()
            return True
        except:
            return False
    
    def remove_ip(self, ip: str) -> bool:
        """Remove IP from all lists"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM ip_management WHERE ip_address = ?', (ip,))
            conn.commit()
            conn.close()
            return True
        except:
            return False
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Clean up expired entries
        cursor.execute('''
            DELETE FROM ip_management 
            WHERE expires_at IS NOT NULL AND expires_at < ?
        ''', (datetime.now(),))
        
        cursor.execute('''
            SELECT list_type, reason, expires_at FROM ip_management 
            WHERE ip_address = ?
        ''', (ip,))
        result = cursor.fetchone()
        conn.commit()
        conn.close()
        
        if not result:
            return {'status': 'unknown', 'is_allowed': True}
        
        return {
            'status': result[0],
            'reason': result[1],
            'expires_at': result[2],
            'is_allowed': result[0] == 'whitelist'
        }
    
    def is_allowed(self, ip: str) -> bool:
        """Check if IP is allowed"""
        status = self.check_ip(ip)
        return status['status'] != 'blacklist'
    
    def get_all(self, list_type: str = None) -> list:
        """Get all IPs in a list"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if list_type:
            cursor.execute('''
                SELECT * FROM ip_management WHERE list_type = ?
            ''', (list_type,))
        else:
            cursor.execute('SELECT * FROM ip_management')
        
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                'ip': r[0], 'list_type': r[1], 'reason': r[2],
                'added_by': r[3], 'expires_at': r[4], 'created_at': r[5]
            }
            for r in results
        ]


# ============== API Key Management ==============

class APIKeyManager:
    """Manage API keys for third-party integrations"""
    
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
        self._init_table()
    
    def _init_table(self):
        """Initialize API keys table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                permissions TEXT DEFAULT '["read"]',
                rate_limit INTEGER DEFAULT 1000,
                is_active INTEGER DEFAULT 1,
                last_used TIMESTAMP,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def generate_key(self, username: str, name: str, 
                    permissions: list = None, rate_limit: int = 1000,
                    expires_days: int = None) -> Dict:
        """
        Generate a new API key
        
        Returns:
            Dictionary with key (only shown once) and key info
        """
        # Generate key
        key = f"phd_{secrets.token_urlsafe(32)}"
        key_prefix = key[:12]
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        expires_at = None
        if expires_days:
            expires_at = datetime.now() + timedelta(days=expires_days)
        
        if permissions is None:
            permissions = ['read']
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO api_keys 
                (key_hash, key_prefix, name, username, permissions, rate_limit, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (key_hash, key_prefix, name, username, json.dumps(permissions), 
                  rate_limit, expires_at))
            key_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return {
                'key': key,  # Only returned once
                'key_id': key_id,
                'key_prefix': key_prefix,
                'name': name,
                'permissions': permissions,
                'rate_limit': rate_limit,
                'expires_at': expires_at.isoformat() if expires_at else None
            }
        except Exception as e:
            return {'error': str(e)}
    
    def validate_key(self, key: str) -> Tuple[bool, Optional[Dict]]:
        """
        Validate an API key
        
        Returns:
            Tuple of (is_valid, key_info)
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Clean up expired keys
        cursor.execute('''
            UPDATE api_keys SET is_active = 0 
            WHERE expires_at IS NOT NULL AND expires_at < ?
        ''', (datetime.now(),))
        
        cursor.execute('''
            SELECT id, name, username, permissions, rate_limit, is_active
            FROM api_keys WHERE key_hash = ?
        ''', (key_hash,))
        
        result = cursor.fetchone()
        
        if not result or not result[5]:  # Not found or not active
            conn.close()
            return False, None
        
        # Update last used
        cursor.execute('''
            UPDATE api_keys SET last_used = ? WHERE id = ?
        ''', (datetime.now(), result[0]))
        conn.commit()
        conn.close()
        
        return True, {
            'key_id': result[0],
            'name': result[1],
            'username': result[2],
            'permissions': json.loads(result[3]),
            'rate_limit': result[4]
        }
    
    def revoke_key(self, key_id: int) -> bool:
        """Revoke an API key"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE api_keys SET is_active = 0 WHERE id = ?
            ''', (key_id,))
            conn.commit()
            conn.close()
            return True
        except:
            return False
    
    def get_user_keys(self, username: str) -> list:
        """Get all API keys for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, key_prefix, name, permissions, rate_limit, 
                   is_active, last_used, expires_at, created_at
            FROM api_keys WHERE username = ?
        ''', (username,))
        
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': r[0], 'key_prefix': r[1], 'name': r[2],
                'permissions': json.loads(r[3]), 'rate_limit': r[4],
                'is_active': bool(r[5]), 'last_used': r[6],
                'expires_at': r[7], 'created_at': r[8]
            }
            for r in results
        ]


def require_api_key(permissions: list = None):
    """Decorator to require valid API key"""
    api_manager = APIKeyManager()
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # B-21: Reject API key in query string; require header
            api_key = request.headers.get('X-API-Key')
            auth_header = request.headers.get('Authorization')
            if not api_key and auth_header and auth_header.startswith('Bearer '):
                api_key = auth_header[7:]
            
            if not api_key:
                return jsonify({'error': 'API key required'}), 401
            
            valid, key_info = api_manager.validate_key(api_key)
            
            if not valid:
                return jsonify({'error': 'Invalid API key'}), 401
            
            # Check permissions
            if permissions:
                key_perms = key_info.get('permissions', [])
                if not any(p in key_perms for p in permissions):
                    return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Add key info to request
            request.api_key_info = key_info
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ============== Encryption ==============

class DataEncryption:
    """Encrypt sensitive data"""
    
    def __init__(self):
        self.key = self._get_or_create_key()
        self.fernet = Fernet(self.key)
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key with secure permissions (B-20)"""
        if os.path.exists(ENCRYPTION_KEY_FILE):
            # Verify permissions if we are on a POSIX system
            if os.name == 'posix':
                st = os.stat(ENCRYPTION_KEY_FILE)
                if st.st_mode & 0o077:
                    logging.getLogger('security').warning(
                        "Insecure permissions on %s. Fixing...", ENCRYPTION_KEY_FILE
                    )
                    os.chmod(ENCRYPTION_KEY_FILE, 0o600)
            with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                return f.read()
        
        # Generate new key securely
        key = Fernet.generate_key()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(ENCRYPTION_KEY_FILE, flags, 0o600)
            with open(fd, 'wb') as f:
                f.write(key)
        except FileExistsError:
            # Race condition: another process created it
            with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                return f.read()
        
        return key
    
    def encrypt(self, data: str) -> str:
        """Encrypt data"""
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data"""
        return self.fernet.decrypt(encrypted_data.encode()).decode()
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.b64encode(kdf.derive(password.encode())).decode()
        salt_b64 = base64.b64encode(salt).decode()
        
        return key, salt_b64
    
    @staticmethod
    def verify_password(password: str, hash: str, salt_b64: str) -> bool:
        """Verify password against hash"""
        salt = base64.b64decode(salt_b64)
        new_hash, _ = DataEncryption.hash_password(password, salt)
        return hmac.compare_digest(hash, new_hash)


# Create singleton instances
rate_limiter = RateLimiter()
two_factor_auth = TwoFactorAuth()
ip_manager = IPManager()
api_key_manager = APIKeyManager()
encryption = DataEncryption()


def check_ip_middleware():
    """Middleware to check IP against blacklist"""
    def middleware():
        ip = request.remote_addr
        if not ip_manager.is_allowed(ip):
            return jsonify({'error': 'Access denied', 'ip': ip}), 403
    return middleware
