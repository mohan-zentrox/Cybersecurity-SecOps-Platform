"""
Application configuration.

FRD ref: NFR-CONFIG-01 (12-factor configuration via environment variables).
All settings are overridable via environment variables / a .env file (see
the repo root .env.example). Nothing sensitive is hard-coded; the defaults
below are safe only for local development, and `Settings.validate_runtime()`
refuses to let the obviously-insecure defaults through in production.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEFAULT_JWT_SECRET = "CHANGE_ME_INSECURE_DEV_ONLY_SECRET"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- General ---
    ENV: str = "development"
    PROJECT_NAME: str = "Project Aegis"
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = True

    # --- CORS (comma-separated list of allowed browser origins) ---
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:4173"

    # --- Database (PostgreSQL in prod, SQLite in-memory for tests) ---
    DATABASE_URL: str = "postgresql+psycopg2://aegis:aegis@localhost:5432/aegis"

    # --- Queue (Redis Streams by default; see services/queue.py for the
    #     Kafka-compatible adapter extension point referenced in FRD-ING-03) ---
    REDIS_URL: str = "redis://localhost:6379/0"
    QUEUE_BACKEND: str = "memory"  # "memory" | "redis" — memory is the safe test default
    QUEUE_CONSUMER_GROUP: str = "aegis-normalizers"
    QUEUE_CONSUMER_NAME: str = "worker-1"

    # --- Ingestion mode ---
    # "inline"  — the ingest request drains the queue itself (dev/test, deterministic).
    # "worker"  — the ingest request only enqueues; app/worker.py drains it.
    INGEST_MODE: str = "inline"

    # --- Auth / JWT session tokens ---
    JWT_SECRET_KEY: str = INSECURE_DEFAULT_JWT_SECRET
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

    # --- Background scheduler (SLA sweeps, threat-intel feed polls) ---
    SCHEDULER_ENABLED: bool = True
    SLA_SWEEP_INTERVAL_SECONDS: int = 60
    THREAT_INTEL_POLL_INTERVAL_SECONDS: int = 3600

    # --- Notifications (FRD-ALERT-04) ---
    NOTIFICATIONS_ENABLED: bool = True
    NOTIFY_MIN_SEVERITY: str = "medium"  # low | medium | high | critical
    NOTIFY_WEBHOOK_URL: str = ""
    NOTIFY_SLACK_WEBHOOK_URL: str = ""
    NOTIFY_HTTP_TIMEOUT_SECONDS: float = 5.0
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "aegis@example.invalid"
    SMTP_TO: str = ""
    SMTP_USE_TLS: bool = True

    # --- Detection engine ---
    # Incremental evaluation: a rule only re-reads events newer than its
    # watermark, minus this overlap so threshold windows spanning a batch
    # boundary still fire. See services/rule_engine.py.
    RULE_EVAL_LOOKBACK_SECONDS: int = 3600
    RULE_EVAL_MAX_EVENTS: int = 50_000

    # --- API pagination ---
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 500

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENV.lower() in ("production", "prod")

    def validate_runtime(self) -> list[str]:
        """Return a list of fatal misconfigurations. Empty list == safe to boot.

        FRD ref: NFR-SEC-03 — the service must refuse to start in production
        with development placeholder secrets still in place.
        """
        problems: list[str] = []
        if not self.is_production:
            return problems
        if self.JWT_SECRET_KEY == INSECURE_DEFAULT_JWT_SECRET:
            problems.append("JWT_SECRET_KEY is still the insecure development default")
        if len(self.JWT_SECRET_KEY) < 32:
            problems.append("JWT_SECRET_KEY must be at least 32 characters in production")
        if "*" in self.cors_origin_list:
            problems.append("CORS_ORIGINS must not be '*' in production")
        if self.DATABASE_URL.startswith("sqlite"):
            problems.append("DATABASE_URL must not be SQLite in production")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
