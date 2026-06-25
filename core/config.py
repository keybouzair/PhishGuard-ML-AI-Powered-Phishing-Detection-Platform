import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """
    Centralized SOC Configuration Manager
    Loads credentials and toggles from .env
    """
    
    # Environment
    ENV: str = os.getenv("ENV", "development")
    
    # API Keys (Mocked defaults for testing, replace in production)
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "sk-mock-openai-key")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    HF_TOKEN: str = os.getenv("HF_TOKEN", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "mock-vt-key")
    CLOUDFLARE_API_KEY: str = os.getenv("CLOUDFLARE_API_KEY", "mock-cf-key")
    
    # Redis configuration for async queues and caching
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Feature Toggles
    ENABLE_ACTIVE_DEFENSE: bool = os.getenv("ENABLE_ACTIVE_DEFENSE", "True").lower() == "true"
    ENABLE_PHISHING_SIMULATOR: bool = os.getenv("ENABLE_PHISHING_SIMULATOR", "False").lower() == "true"
    
    # Thresholds
    CRITICAL_RISK_THRESHOLD: int = 90
    HIGH_RISK_THRESHOLD: int = 70
    
    class Config:
        env_file = ".env"

# Export singleton
settings = Settings()
