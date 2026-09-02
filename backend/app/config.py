"""Application configuration - environment driven."""
import os


class Settings:
    """Central configuration. Every value can be overridden via env vars."""

    APP_NAME: str = "SentinelLens - AI Cybersecurity Log Analyzer"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    # --- Security ---
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change-me-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

    # --- Database (SQLite for local dev, PostgreSQL in Docker/prod) ---
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./sentinel.db",
    )

    # --- Generative AI provider (optional) ---
    # If a key is present the app uses the LLM for incident summaries;
    # otherwise it falls back to the built-in heuristic analyst engine.
    OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    ANTHROPIC_API_KEY: str | None = os.getenv("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")

    # --- Detection tuning ---
    BRUTE_FORCE_THRESHOLD: int = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
    BRUTE_FORCE_WINDOW_MIN: int = int(os.getenv("BRUTE_FORCE_WINDOW_MIN", "5"))
    PORTSCAN_THRESHOLD: int = int(os.getenv("PORTSCAN_THRESHOLD", "12"))
    DOS_RPM_THRESHOLD: int = int(os.getenv("DOS_RPM_THRESHOLD", "60"))
    EXFIL_BYTES_THRESHOLD: int = int(os.getenv("EXFIL_BYTES_THRESHOLD", str(5 * 1024 * 1024)))

    # --- CORS ---
    CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "*").split(",")

    # --- Frontend static dir (production single-container mode) ---
    STATIC_DIR: str = os.getenv("STATIC_DIR", "../frontend/dist")


settings = Settings()
