"""Configuration management"""
import warnings
from pydantic_settings import BaseSettings
from typing import List

_INSECURE_SECRET = "your-secret-key-change-this-in-production"


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Application settings
    APP_NAME: str = "FluxEngine"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security settings
    SECRET_KEY: str = _INSECURE_SECRET
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Database settings
    DATABASE_PATH: str = "./data/fluxengine.db"

    # CORS settings
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
    ]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()

if settings.SECRET_KEY == _INSECURE_SECRET:
    warnings.warn(
        "SECRET_KEY is set to the insecure default. "
        "Set a strong SECRET_KEY environment variable before deploying to production.",
        stacklevel=1,
    )
