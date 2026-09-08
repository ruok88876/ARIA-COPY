"""Centralized configuration for ARIA platform."""
from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """ARIA application settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Application
    app_name: str = "ARIA"
    app_version: str = "0.2.0"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"

    # MongoDB Configuration
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_database: str = "aria_db"
    mongodb_timeout_ms: int = 5000

    # Cowrie Honeypot
    cowrie_log_path: str = "honeypot/cowrie.json"

    # SDN Controller Configuration
    sdn_controller_ip: str = "127.0.0.1"
    sdn_controller_port: int = 6653
    sdn_server_ip: str = "10.0.0.10"
    sdn_honeypot_ip: str = "10.0.0.50"
    sdn_suspicious_threshold: int = 5
    sdn_backend_url: str = "http://localhost:8000/api/v1/sdn/telemetry"


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()
