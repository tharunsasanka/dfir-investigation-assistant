from functools import lru_cache
from typing import Literal

from pydantic import (
    Field,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


EnvironmentName = Literal[
    "development",
    "test",
    "production",
]


class Settings(BaseSettings):
    app_name: str = (
        "DFIR Investigation Assistant API"
    )

    api_v1_prefix: str = "/api/v1"

    environment: EnvironmentName = (
        "development"
    )

    docs_enabled: bool = True

    database_url: str = (
        "postgresql+psycopg://"
        "dfir:dfir_dev_password@"
        "localhost:5432/dfir"
    )

    jwt_secret_key: str = (
        "development-only-change-me"
    )

    jwt_algorithm: Literal[
        "HS256",
        "HS384",
        "HS512",
    ] = "HS256"

    access_token_expire_minutes: int = (
        Field(
            default=30,
            ge=5,
            le=120,
        )
    )

    refresh_token_expire_days: int = (
        Field(
            default=7,
            ge=1,
            le=30,
        )
    )

    cors_origins: str = (
        "http://localhost:5173"
    )

    cors_allow_credentials: bool = True

    trusted_hosts: str = (
        "localhost,"
        "127.0.0.1,"
        "testserver,"
        "backend"
    )

    security_headers_enabled: bool = True

    hsts_enabled: bool = False

    hsts_max_age_seconds: int = Field(
        default=31536000,
        ge=0,
        le=63072000,
    )

    max_failed_login_attempts: int = (
        Field(
            default=5,
            ge=3,
            le=20,
        )
    )

    login_lockout_minutes: int = Field(
        default=15,
        ge=1,
        le=1440,
    )

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
    def trusted_host_list(
        self,
    ) -> list[str]:
        hosts = [
            host.strip()
            for host
            in self.trusted_hosts.split(",")
            if host.strip()
        ]

        if hosts:
            return hosts

        if self.environment != "production":
            return [
                "localhost",
                "127.0.0.1",
                "testserver",
                "backend",
            ]

        return []

    @property
    def cors_allowed_method_list(
        self,
    ) -> list[str]:
        return [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
        ]

    @property
    def cors_allowed_header_list(
        self,
    ) -> list[str]:
        return [
            "Accept",
            "Authorization",
            "Content-Type",
            "Origin",
            "X-Requested-With",
        ]

    @property
    def cors_exposed_header_list(
        self,
    ) -> list[str]:
        return [
            "Content-Disposition",
            "X-Document-SHA256",
        ]

    @property
    def api_docs_enabled(
        self,
    ) -> bool:
        return (
            self.docs_enabled
            and self.environment
            != "production"
        )

    @property
    def hsts_active(
        self,
    ) -> bool:
        return (
            self.hsts_enabled
            and self.environment
            == "production"
        )

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

    @model_validator(mode="after")
    def validate_security_configuration(
        self,
    ) -> "Settings":
        if self.environment != "production":
            return self

        normalized_secret = (
            self.jwt_secret_key
            .strip()
            .lower()
        )

        insecure_secrets = {
            "development-only-change-me",
            "replace-with-a-long-random-secret",
            "change-me",
        }

        if (
            len(self.jwt_secret_key) < 32
            or normalized_secret
            in insecure_secrets
        ):
            raise ValueError(
                "Production requires a unique "
                "JWT secret containing at least "
                "32 characters."
            )

        if not self.cors_origin_list:
            raise ValueError(
                "Production requires at least "
                "one trusted CORS origin."
            )

        if "*" in self.cors_origin_list:
            raise ValueError(
                "Wildcard CORS origins are not "
                "permitted in production."
            )

        if not self.trusted_host_list:
            raise ValueError(
                "Production requires at least "
                "one trusted host."
            )

        if "*" in self.trusted_host_list:
            raise ValueError(
                "Wildcard trusted hosts are not "
                "permitted in production."
            )

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()