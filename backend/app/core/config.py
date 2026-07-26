from functools import lru_cache

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    app_name: str = (
        "DFIR Investigation Assistant API"
    )

    api_v1_prefix: str = "/api/v1"

    database_url: str = (
        "postgresql+psycopg://"
        "dfir:dfir_dev_password@"
        "localhost:5432/dfir"
    )

    jwt_secret_key: str = (
        "development-only-change-me"
    )

    jwt_algorithm: str = "HS256"

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    cors_origins: str = (
        "http://localhost:5173"
    )

    max_failed_login_attempts: int = 5
    login_lockout_minutes: int = 15

    ai_local_enabled: bool = False

    ai_local_provider_name: str = (
        "ollama"
    )

    ai_local_base_url: str = (
        "http://host.docker.internal:11434"
    )

    ai_local_model: str = ""

    ai_local_allowed_hosts: str = (
        "localhost,"
        "127.0.0.1,"
        "::1,"
        "host.docker.internal,"
        "ollama"
    )

    ai_local_timeout_seconds: float = (
        Field(
            default=60.0,
            ge=1.0,
            le=300.0,
        )
    )

    ai_local_connect_timeout_seconds: (
        float
    ) = Field(
        default=5.0,
        ge=0.5,
        le=60.0,
    )

    ai_local_max_prompt_chars: int = (
        Field(
            default=30000,
            ge=1000,
            le=200000,
        )
    )

    ai_local_max_response_bytes: int = (
        Field(
            default=262144,
            ge=4096,
            le=2097152,
        )
    )

    ai_local_temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=2.0,
    )

    ai_local_fallback_to_deterministic: (
        bool
    ) = True

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @property
    def cors_origin_list(
        self,
    ) -> list[str]:
        return [
            origin.strip()
            for origin
            in self.cors_origins.split(",")
            if origin.strip()
        ]

    @property
    def ai_local_allowed_host_list(
        self,
    ) -> list[str]:
        return [
            host.strip().lower()
            for host
            in self.ai_local_allowed_hosts
            .split(",")
            if host.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()