import secrets
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "End-to-End Encrypted Chat"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Secret key for JWT signing
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(48), min_length=32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Database
    DATABASE_PATH: Path = BASE_DIR / "chat.db"
    
    # Rate Limiting & Brute-force protection
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 5
    
    # WebSocket ping/pong
    WS_HEARTBEAT_INTERVAL: int = 30

settings = Settings()
