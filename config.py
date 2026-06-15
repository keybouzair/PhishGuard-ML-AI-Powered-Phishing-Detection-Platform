"""
Configuration file for Phishing Detection System Ultimate
All settings can be overridden via environment variables
"""
import os
from datetime import timedelta


class Config:
    """Base configuration"""
    
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-super-secret-key-change-in-production')
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Session
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = 'session_files'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # Database
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'phishing_detector.db')
    
    # ML Model
    MODEL_PATH = os.environ.get('MODEL_PATH', 'model/phishingdetection.pkl')
    CONFIDENCE_THRESHOLD = float(os.environ.get('CONFIDENCE_THRESHOLD', '0.7'))
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS = int(os.environ.get('RATE_LIMIT_REQUESTS', '100'))
    RATE_LIMIT_WINDOW = int(os.environ.get('RATE_LIMIT_WINDOW', '60'))  # seconds
    
    # Threat Intelligence APIs
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
    URLHAUS_ENABLED = os.environ.get('URLHAUS_ENABLED', 'True').lower() == 'true'
    PHISHTANK_ENABLED = os.environ.get('PHISHTANK_ENABLED', 'True').lower() == 'true'
    
    # Threat Intelligence Cache
    THREAT_INTEL_CACHE_TTL = int(os.environ.get('THREAT_INTEL_CACHE_TTL', '3600'))  # seconds
    
    # Email Settings
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    SMTP_FROM_EMAIL = os.environ.get('SMTP_FROM_EMAIL', 'noreply@phishing-detector.local')
    EMAIL_ALERTS_ENABLED = os.environ.get('EMAIL_ALERTS_ENABLED', 'False').lower() == 'true'
    
    # Two-Factor Authentication
    TOTP_ISSUER = os.environ.get('TOTP_ISSUER', 'Phishing Detector')
    TWO_FACTOR_REQUIRED = os.environ.get('TWO_FACTOR_REQUIRED', 'False').lower() == 'true'
    
    # Webhook Settings
    WEBHOOK_TIMEOUT = int(os.environ.get('WEBHOOK_TIMEOUT', '30'))  # seconds
    WEBHOOK_MAX_RETRIES = int(os.environ.get('WEBHOOK_MAX_RETRIES', '3'))
    
    # Slack Integration
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')
    SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL', '#security-alerts')
    
    # Microsoft Teams Integration
    TEAMS_WEBHOOK_URL = os.environ.get('TEAMS_WEBHOOK_URL', '')
    
    # SIEM Integration
    SPLUNK_HEC_URL = os.environ.get('SPLUNK_HEC_URL', '')
    SPLUNK_HEC_TOKEN = os.environ.get('SPLUNK_HEC_TOKEN', '')
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL', '')
    ELASTICSEARCH_INDEX = os.environ.get('ELASTICSEARCH_INDEX', 'phishing-alerts')
    
    # Analytics
    ANALYTICS_RETENTION_DAYS = int(os.environ.get('ANALYTICS_RETENTION_DAYS', '365'))
    
    # Browser Extension
    EXTENSION_API_ENABLED = os.environ.get('EXTENSION_API_ENABLED', 'True').lower() == 'true'
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/phishing_detector.log')
    
    # Feature Flags
    FEATURES = {
        'threat_intel': os.environ.get('FEATURE_THREAT_INTEL', 'True').lower() == 'true',
        'analytics': os.environ.get('FEATURE_ANALYTICS', 'True').lower() == 'true',
        'email': os.environ.get('FEATURE_EMAIL', 'True').lower() == 'true',
        'advanced_ml': os.environ.get('FEATURE_ADVANCED_ML', 'True').lower() == 'true',
        'security': os.environ.get('FEATURE_SECURITY', 'True').lower() == 'true',
        'integrations': os.environ.get('FEATURE_INTEGRATIONS', 'True').lower() == 'true',
        '2fa': os.environ.get('FEATURE_2FA', 'True').lower() == 'true',
    }


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TWO_FACTOR_REQUIRED = True
    
    # In production, these should be set via environment variables
    # SECRET_KEY = os.environ['SECRET_KEY']  # Required
    

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DATABASE_PATH = ':memory:'
    

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(env=None):
    """Get configuration based on environment"""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
