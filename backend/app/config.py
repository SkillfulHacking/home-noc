import json
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, computed_field, AliasChoices

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

    # ✅ add this
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("API_KEY", "X_API_KEY", "X-API-KEY"),
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
            pass
        return [p.strip() for p in str(v).split(",") if p.strip()]

settings = Settings()
