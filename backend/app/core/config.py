"""
Application configuration.

FRD ref: NFR-CONFIG-01 (12-factor configuration via environment variables).
All settings are overridable via environment variables / a .env file (see
backend/.env.example at the repo root .env.example). Nothing sensitive is
hard-coded; the defaults below are safe only for local development.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- General ---
    ENV: str = "development"
    PROJECT_NAME: str = "Project Aegis"
    API_V1_PREFIX: str = "/api/v1"

    # --- Database (PostgreSQL in prod, SQLite in-memory for tests) ---
    DATABASE_URL: str = "postgresql+psycopg2://aegis:aegis@localhost:5432/aegis"

    # --- Queue (Redis Streams by default; see services/queue.py for the
    #     Kafka-compatible adapter extension point referenced in FRD-ING-03) ---
    REDIS_URL: str = "redis://localhost:6379/0"
    QUEUE_BACKEND: str = "memory"  # "memory" | "redis" — memory is the safe test default

    # --- Auth / JWT session tokens ---
    JWT_SECRET_KEY: str = "CHANGE_ME_INSECURE_DEV_ONLY_SECRET"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # --- Rate limiting (FRD-AUTH-04: login brute-force protection) ---
    LOGIN_RATE_LIMIT_ATTEMPTS: int = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 60

    # --- SLA timers by severity, in minutes (FRD-CASE-05) ---
    SLA_MINUTES_CRITICAL: int = 60
    SLA_MINUTES_HIGH: int = 240
    SLA_MINUTES_MEDIUM: int = 1440
    SLA_MINUTES_LOW: int = 4320


@lru_cache
def get_settings() -> Settings:
    return Settings()
