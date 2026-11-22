from pydantic import AliasChoices, Field, SecretStr, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Environments that are allowed to run without configured admin credentials.
# Everything else is treated as production and fails closed at startup.
NON_PRODUCTION_ENVS = frozenset({"dev", "development", "local", "test", "testing"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",
        env_ignore_empty=True,
        extra="ignore",
    )

    app_env: str = Field(
        default="dev",
        validation_alias=AliasChoices("APP_ENV", "ENV", "ENVIRONMENT"),
    )
    app_name: str = Field(
        default="home-noc",
        validation_alias=AliasChoices("APP_NAME", "APP", "SERVICE_NAME"),
    )
    db_url: str = Field(
        default="sqlite:////data/home_noc.db",
        validation_alias=AliasChoices("DB_URL", "DATABASE_URL"),
    )

    # --- Single-operator administrator authentication (M03) -------------
    # Only a PBKDF2 verifier is ever configured; the raw password is never
    # stored in the environment, the database, logs or responses.
    admin_username: str = Field(
        default="admin",
        validation_alias=AliasChoices("ADMIN_USERNAME", "HOME_NOC_ADMIN_USERNAME"),
    )
    admin_password_hash: str | None = Field(
        default=None,
        validation_alias=AliasChoices("ADMIN_PASSWORD_HASH", "HOME_NOC_ADMIN_PASSWORD_HASH"),
    )

    # Absolute session lifetime; a session is unusable after this regardless
    # of activity.
    session_ttl_seconds: int = Field(
        default=43_200,  # 12 hours
        ge=60,
        le=604_800,
        validation_alias=AliasChoices("SESSION_TTL_SECONDS"),
    )
    # Inactivity timeout; an idle session is revoked before the absolute TTL.
    session_idle_timeout_seconds: int = Field(
        default=3_600,  # 1 hour
        ge=60,
        le=604_800,
        validation_alias=AliasChoices("SESSION_IDLE_TIMEOUT_SECONDS"),
    )
    # Defaults to True in production. Deployments that deliberately serve
    # plain HTTP on a trusted loopback/LAN origin must opt out explicitly.
    session_cookie_secure_raw: bool | None = Field(
        default=None,
        validation_alias=AliasChoices("SESSION_COOKIE_SECURE"),
    )

    # --- Connector credential encryption (M04) ---------------------------
    # 32 random bytes, urlsafe-base64 encoded, supplied from OUTSIDE the
    # database (environment or a mounted secret file). It is never generated
    # automatically: a key minted at startup and kept next to the data would
    # either be lost on restart or sit beside the ciphertext it protects.
    credential_encryption_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CREDENTIAL_ENCRYPTION_KEY", "HOME_NOC_CREDENTIAL_ENCRYPTION_KEY"
        ),
    )
    # Path to a file containing the key (e.g. a Docker/Compose secret).
    credential_encryption_key_file: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CREDENTIAL_ENCRYPTION_KEY_FILE", "HOME_NOC_CREDENTIAL_ENCRYPTION_KEY_FILE"
        ),
    )

    cors_origins_raw: str | list[str] | None = Field(
        default=None,
        validation_alias=AliasChoices("CORS_ORIGINS", "CORS_ORIGIN", "CORS"),
    )

    @computed_field
    @property
    def database_url(self) -> str:
        return self.db_url

    @computed_field
    @property
    def is_production(self) -> bool:
        return self.app_env.strip().lower() not in NON_PRODUCTION_ENVS

    @computed_field
    @property
    def session_cookie_secure(self) -> bool:
        if self.session_cookie_secure_raw is None:
            return self.is_production
        return self.session_cookie_secure_raw

    @computed_field
    @property
    def cors_origins(self) -> list[str]:
        v = self.cors_origins_raw
        if not v:
            return []
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        try:
            import json
            arr = json.loads(v)
            if isinstance(arr, list):
                return [str(x).strip() for x in arr if str(x).strip()]
        except Exception:
            # If JSON parsing fails, fall back to splitting by comma.
            pass
        return [p.strip() for p in str(v).split(",") if p.strip()]

settings = Settings()
