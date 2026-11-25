from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration comes from environment variables (see docker-compose.yml / .env.example).
    Secrets have no defaults: the process refuses to start without them."""

    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    app_env: str = "development"

    database_url: str
    opa_url: str = "http://opa:8181"
    opa_token: str = Field(min_length=32)
    opa_timeout_seconds: float = 3.0

    oidc_issuer: str
    oidc_jwks_url: str
    oidc_audience: str = "enterprise-ai-api"
    oidc_allowed_clients: str = "enterprise-ai-frontend"
    oidc_leeway_seconds: int = 5

    cors_origins: str = "http://localhost:3000"

    approval_ttl_minutes: int = 60
    rate_limit_chat_per_minute: int = 30
    rate_limit_sensitive_per_minute: int = 20

    @property
    def allowed_clients(self) -> frozenset[str]:
        return frozenset(c.strip() for c in self.oidc_allowed_clients.split(",") if c.strip())

    @property
    def cors_origin_list(self) -> list[str]:
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        if "*" in origins:
            raise ValueError("CORS_ORIGINS must list explicit origins; '*' is not allowed")
        return origins

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
