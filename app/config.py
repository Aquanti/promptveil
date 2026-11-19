"""Typed configuration loader for PromptVeil local web host."""

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR: Path = Path(__file__).resolve().parent.parent
DEFAULT_STATIC_DIR: Path = Path(__file__).resolve().parent / "static"
DEFAULT_ENV_FILE: Path = BASE_DIR / ".env"

CSP_POLICY: str = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)

VALID_LOG_LEVELS: frozenset[str] = frozenset(
    {"critical", "error", "warning", "info", "debug", "trace"}
)


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable application settings loaded from environment variables."""

    app_host: str
    app_port: int
    log_level: str
    app_version: str
    static_dir: Path
    csp_policy: str = CSP_POLICY


def load_settings(env_file: Path | None = None) -> Settings:
    """Load and validate host settings from .env and process environment."""
    target_env = env_file if env_file is not None else DEFAULT_ENV_FILE
    if target_env.is_file():
        load_dotenv(dotenv_path=target_env, override=False)

    app_host = os.getenv("APP_HOST", "127.0.0.1").strip()
    if not app_host:
        raise ValueError("APP_HOST must be a non-empty hostname or IP address.")

    raw_port = os.getenv("APP_PORT", "8000").strip()
    try:
        app_port = int(raw_port)
    except ValueError as exc:
        raise ValueError(f"APP_PORT must be an integer, got {raw_port!r}.") from exc
    if not (1 <= app_port <= 65535):
        raise ValueError(f"APP_PORT must be between 1 and 65535, got {app_port}.")

    log_level = os.getenv("LOG_LEVEL", "info").strip().lower()
    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(
            f"LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)}, got {log_level!r}."
        )

    app_version = os.getenv("APP_VERSION", "1.0.0").strip()
    if not app_version:
        raise ValueError("APP_VERSION must be a non-empty version string.")

    return Settings(
        app_host=app_host,
        app_port=app_port,
        log_level=log_level,
        app_version=app_version,
        static_dir=DEFAULT_STATIC_DIR,
        csp_policy=CSP_POLICY,
    )
