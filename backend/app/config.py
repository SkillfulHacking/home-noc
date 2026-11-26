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

    # --- Authorized scan scope (M08) -------------------------------------
    # Comma-separated (or JSON list) IPv4 CIDRs the operator owns / is
    # authorized to scan. Empty means every scan is rejected (fail closed).
    scan_allowed_cidrs_raw: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SCAN_ALLOWED_CIDRS"),
    )
    # Public (global) addresses stay blocked even if allowlisted, unless set.
    scan_allow_public: bool = Field(
        default=False, validation_alias=AliasChoices("SCAN_ALLOW_PUBLIC")
    )
    # M08A: the same variable again, but ``None`` when unset. An explicit
    # ``SCAN_ALLOW_PUBLIC=false`` is an immutable deployment restriction that the
    # runtime public toggle cannot override; ``true`` only *permits* the
    # administrator to opt in and never authorizes anything by itself.
    scan_allow_public_env: bool | None = Field(
        default=None, validation_alias=AliasChoices("SCAN_ALLOW_PUBLIC")
    )
    # The opt-in security profile is off unless explicitly enabled.
    scan_security_profile_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("SCAN_SECURITY_PROFILE_ENABLED")
    )

    # --- Durable scan/poll worker (M09) ----------------------------------
    # Hard cap on scan jobs executing at once across ALL worker processes
    # (enforced atomically in the database claim, not just per process).
    worker_max_concurrent_jobs: int = Field(
        default=1, ge=1, le=4, validation_alias=AliasChoices("WORKER_MAX_CONCURRENT_JOBS")
    )
    scheduler_max_new_jobs_per_tick: int = Field(
        default=5, ge=1, le=50,
        description="Concurrency budget: schedules fired per scheduler tick",
    )
    # Cap on queued + running jobs; further start requests get HTTP 429.
    scan_vuln_profile_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("SCAN_VULN_PROFILE_ENABLED"),
        description="Opt-in switch for the Nuclei 'vuln' profile (default off)",
    )
    nuclei_binary: str = Field(
        default="/opt/nuclei/nuclei", validation_alias=AliasChoices("NUCLEI_BINARY"))
    nuclei_templates_dir: str = Field(
        default="/opt/nuclei-templates", validation_alias=AliasChoices("NUCLEI_TEMPLATES_DIR"))
    nuclei_versions_file: str = Field(
        default="/opt/nuclei/versions.json", validation_alias=AliasChoices("NUCLEI_VERSIONS_FILE"))
    nuclei_rate_limit: int = Field(default=10, ge=1, le=50)
    nuclei_concurrency: int = Field(default=5, ge=1, le=10)
    scan_max_active_jobs: int = Field(
        default=5, ge=1, le=50, validation_alias=AliasChoices("SCAN_MAX_ACTIVE_JOBS")
    )
    worker_poll_interval_seconds: float = Field(
        default=2.0, ge=0.2, le=60, validation_alias=AliasChoices("WORKER_POLL_INTERVAL_SECONDS")
    )
    # A running job whose lease is not renewed within this window is treated
    # as abandoned (worker crash) and is requeued or failed by recovery.
    worker_lease_seconds: int = Field(
        default=30, ge=5, le=600, validation_alias=AliasChoices("WORKER_LEASE_SECONDS")
    )
    # SIGTERM -> SIGKILL grace when stopping a scanner process group.
    worker_kill_grace_seconds: float = Field(
        default=5.0, ge=0.5, le=60, validation_alias=AliasChoices("WORKER_KILL_GRACE_SECONDS")
    )
    # Attempts per job (first run included) and retry backoff base.
    scan_job_max_attempts: int = Field(
        default=3, ge=1, le=5, validation_alias=AliasChoices("SCAN_JOB_MAX_ATTEMPTS")
    )
    scan_job_retry_backoff_seconds: float = Field(
        default=5.0, ge=0, le=3600, validation_alias=AliasChoices("SCAN_JOB_RETRY_BACKOFF_SECONDS")
    )
    # Scanner executable; only ever launched with a fixed argv, never a shell.
    scan_nmap_binary: str = Field(
        default="nmap", validation_alias=AliasChoices("SCAN_NMAP_BINARY")
    )
    # Per-address ICMP response window. Discovery also remains bounded by the
    # profile's overall deadline and concurrency limit.
    scan_icmp_probe_timeout_seconds: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        validation_alias=AliasChoices("SCAN_ICMP_PROBE_TIMEOUT_SECONDS"),
    )
    # M11 TCP connect scanning. Ports are operator configuration, never API
    # input. The scanner validates every value, duplicates, and the hard cap
    # again immediately before opening any socket.
    scan_tcp_ports_raw: str = Field(
        default="22,53,80,111,135,139,443,445,548,631,2049,3306,3389,5000,"
        "5432,5900,8000,8080,8443,9100",
        validation_alias=AliasChoices("SCAN_TCP_PORTS"),
    )
    scan_tcp_max_ports: int = Field(
        default=20, ge=1, le=100, validation_alias=AliasChoices("SCAN_TCP_MAX_PORTS")
    )
    scan_tcp_connections_per_second: float = Field(
        default=20.0,
        ge=0.1,
        le=200.0,
        validation_alias=AliasChoices("SCAN_TCP_CONNECTIONS_PER_SECOND"),
    )
    scan_tcp_connection_timeout_seconds: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        validation_alias=AliasChoices("SCAN_TCP_CONNECTION_TIMEOUT_SECONDS"),
    )
    scan_tcp_max_total_connections: int = Field(
        default=5120,
        ge=1,
        le=20_000,
        validation_alias=AliasChoices("SCAN_TCP_MAX_TOTAL_CONNECTIONS"),
    )

    @computed_field
    @property
    def scan_allowed_cidrs(self) -> list[str]:
        v = self.scan_allowed_cidrs_raw
        if not v:
            return []
        v = v.strip()
        if v.startswith("["):
            try:
                import json
                arr = json.loads(v)
                return [str(x).strip() for x in arr if str(x).strip()]
            except Exception:
                return []
        return [p.strip() for p in v.split(",") if p.strip()]

    @computed_field
    @property
    def scan_tcp_ports(self) -> list[int]:
        raw = self.scan_tcp_ports_raw.strip()
        if raw.startswith("["):
            try:
                import json

                values = json.loads(raw)
            except Exception as exc:
                raise ValueError("SCAN_TCP_PORTS must be CSV or a JSON list") from exc
        else:
            values = [part.strip() for part in raw.split(",") if part.strip()]
        if not isinstance(values, list):
            raise ValueError("SCAN_TCP_PORTS must be CSV or a JSON list")
        parsed: list[int] = []
        for value in values:
            if isinstance(value, bool) or not (
                isinstance(value, int)
                or (isinstance(value, str) and value.isdecimal())
            ):
                raise ValueError("SCAN_TCP_PORTS contains a non-integer port")
            parsed.append(int(value))
        return parsed

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
