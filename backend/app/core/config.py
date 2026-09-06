"""Application configuration loaded from environment variables.

All secrets live in the environment / .env file.  Nothing is hardcoded.
"""
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- App ---
    app_name: str = "AI Digital Scam Investigator"
    app_version: str = "1.0.0"
    debug: bool = False
    api_prefix: str = "/api"

    # --- Database ---
    # PostgreSQL is used in docker-compose.  SQLite is the zero-dependency
    # local fallback so the app runs even without a database server.
    database_url: str = f"sqlite+aiosqlite:///{BACKEND_DIR / 'data' / 'app.db'}"

    # --- LLM ---
    llm_provider: str = "mock"  # "mock" | "openai_compatible"
    llm_api_key: str | None = None
    llm_base_url: str | None = None
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 45.0

    # --- Threat intelligence ---
    google_safe_browsing_api_key: str | None = None
    virustotal_api_key: str | None = None
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    threat_intel_timeout_seconds: float = 10.0

    # --- OCR ---
    ocr_provider: str = "auto"  # "auto" | "tesseract" | "mock"
    tesseract_binary: str = "tesseract"
    ocr_max_image_mb: int = 10

    # --- ML ---
    ml_model_path: Path = BACKEND_DIR / "app" / "ml" / "models" / "lr_scam_model.joblib"
    ml_decision_threshold: float = 0.5

    # --- Risk engine ---
    risk_weights_path: Path | None = None  # optional JSON file with custom weights

    # --- Security / limits ---
    max_upload_mb: int = 10
    max_text_length: int = 50_000
    max_urls_per_submission: int = 20
    rate_limit_per_minute: int = 30
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # --- Storage ---
    upload_dir: Path = BACKEND_DIR / "data" / "uploads"

    @property
    def using_mock_llm(self) -> bool:
        return self.llm_provider == "mock" or not self.llm_api_key

    @property
    def using_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()