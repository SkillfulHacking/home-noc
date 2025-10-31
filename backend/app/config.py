# backend/app/config.py 
import json
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, computed_field

class Settings(BaseSettings):
    app_name: str = "home-noc"
    app_env: str = "prod"
    api_key: str | None = None
    database_url: str = "sqlite:////data/home_noc.db"

    # Read raw env to avoid pydantic's complex JSON parsing on empty values
    cors_origins_raw: str | None = Field(default=None, alias="CORS_ORIGINS")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )

    @computed_field  # -> derived, read-only, safe to use everywhere
    @property
    def cors_origins(self) -> List[str]:
        v = self.cors_origins_raw
        if not v:
            return []
        s = v.strip()
        if not s:
            return []
        if s.startswith("["):
            try:
                arr = json.loads(s)
                if isinstance(arr, list):
                    return [str(x).strip() for x in arr if str(x).strip()]
            except Exception:
                pass
        return [p.strip() for p in s.split(",") if p.strip()]

settings = Settings()
