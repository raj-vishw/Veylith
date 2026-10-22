from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    environment: str = "development"
    # Runtime connection: a non-superuser role, so PostgreSQL row-level security applies.
    database_url: str  # required: set DATABASE_URL (see .env.example)
    # Migrations and test fixtures only: the schema owner.
    migration_database_url: str  # required: set MIGRATION_DATABASE_URL
    redis_url: str = "redis://localhost:6379/0"
    secret_key: str = Field(min_length=16)  # required: set SECRET_KEY

    cookie_secure: bool = False
    cookie_samesite: str = "lax"
    session_cookie_name: str = "veylith_session"
    session_ttl_hours: int = 12
    session_idle_minutes: int = 120
    allow_registration: bool = True
    trusted_origins: str = "http://localhost:3000"

    login_rate_limit: int = 10  # attempts per window, per ip+email
    login_rate_window_seconds: int = 60
    expensive_rate_limit: int = 10  # csv import, report generation, ingestion, per org+user
    expensive_rate_window_seconds: int = 60

    # Scheduled pulls from NVD/KEV. Off by default so a development stack never calls external services unprompted.
    scheduled_ingestion: bool = False
    nvd_api_key: str | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ingestion_timeout_seconds: float = 30.0
    ingestion_max_retries: int = 4

    storage_dir: str = "./storage"
    max_upload_bytes: int = 10 * 1024 * 1024
    max_csv_bytes: int = 1024 * 1024
    max_csv_rows: int = 5000
    max_report_items: int = 500

    max_traversal_depth: int = 3  # hops from an affected product through asset-to-asset dependencies
    auto_correlate: bool = True  # re-run correlation shortly after inventory changes
    auto_correlate_delay_seconds: int = 5
    celery_eager: bool = False  # run tasks inline (tests, simple local runs)

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.trusted_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
