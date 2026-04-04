"""
config/__init__.py — Configuration Loader

Single entry point for all configuration in VulnScout Pro.
Every module that needs config imports from here:

    from config import get_config
    config = get_config()

The loader:
  1. Reads VULNSCOUT_ENV (default: "development")
  2. Instantiates the matching Config class
  3. Validates it (fails fast on misconfiguration)
  4. Caches the instance (singleton — loaded once per process)
  5. Creates storage directories on first load

Config is also injectable for tests:
    from config import override_config
    override_config(TestingConfig())

Environment selection:
  VULNSCOUT_ENV=development  → DevelopmentConfig  (default)
  VULNSCOUT_ENV=production   → ProductionConfig
  VULNSCOUT_ENV=testing      → TestingConfig
  VULNSCOUT_ENV=test         → TestingConfig (alias)
"""

from __future__ import annotations

import logging
import os
from typing import Optional
from dotenv import load_dotenv

from config.base import BaseConfig, ConfigError   # noqa: F401 — re-exported

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

# ── Singleton cache ────────────────────────────────────────────────────────────
_config_instance: Optional[BaseConfig] = None


def get_config() -> BaseConfig:
    """
    Return the active configuration instance.
    Loads and validates on first call; cached thereafter.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = _load()
    return _config_instance


def override_config(config: BaseConfig) -> None:
    """
    Replace the active config instance.
    Used exclusively in tests — never call this in application code.
    """
    global _config_instance
    _config_instance = config


def reset_config() -> None:
    """Clear the cached config. Forces reload on next get_config() call."""
    global _config_instance
    _config_instance = None


# ── Loader ─────────────────────────────────────────────────────────────────────

def _load() -> BaseConfig:
    env = os.environ.get("VULNSCOUT_ENV", "development").lower().strip()

    if env in ("testing", "test"):
        from config.testing import TestingConfig
        config: BaseConfig = TestingConfig()

    elif env == "production":
        from config.production import ProductionConfig
        config = ProductionConfig()

    elif env == "development":
        from config.development import DevelopmentConfig
        config = DevelopmentConfig()

    else:
        raise ConfigError(
            f"Unknown environment: VULNSCOUT_ENV={env!r}. "
            "Must be 'development', 'production', or 'testing'."
        )

    config.validate()
    config.storage.resolve()
    config.storage.create_dirs()

    _configure_logging(config)

    if env == "development":
        # Print startup banner in dev only
        try:
            from config.development import DevelopmentConfig
            if isinstance(config, DevelopmentConfig):
                print(config.quick_start_banner())
        except Exception:
            pass

    if env == "production":
        # Log startup warnings for suboptimal (but non-fatal) config
        try:
            from config.production import ProductionConfig
            if isinstance(config, ProductionConfig):
                for warning in config.startup_checks():
                    logger.warning("Production config: %s", warning)
        except Exception:
            pass

    logger.info(
        "Configuration loaded: env=%s debug=%s storage=%s",
        config.app.environment,
        config.app.debug,
        config.storage.data_dir,
    )
    return config


def _configure_logging(config: BaseConfig) -> None:
    """
    Apply logging config to the root logger.
    Called once at startup before any other module logs.
    """
    import logging.handlers
    from pathlib import Path

    level = getattr(logging, config.logging.level, logging.INFO)
    log_dir = config.storage.path(config.logging.logs_dir if hasattr(config.logging, 'logs_dir') else 'logs')

    handlers = []

    # Console handler
    console = logging.StreamHandler()
    if config.logging.format == "json":
        console.setFormatter(_JsonFormatter(redact=config.logging.redact_sensitive))
    else:
        console.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
    handlers.append(console)

    # Rotating file handler
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "vulnscout.log",
            maxBytes=config.logging.max_bytes,
            backupCount=config.logging.backup_count,
        )
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        handlers.append(file_handler)
    except OSError:
        pass  # Log dir not writable — console only

    # Audit log handler (separate file, always INFO+)
    if config.logging.audit_log_enabled:
        try:
            audit_handler = logging.handlers.RotatingFileHandler(
                log_dir / config.logging.audit_log_file,
                maxBytes=config.logging.max_bytes,
                backupCount=config.logging.backup_count,
            )
            audit_handler.setFormatter(logging.Formatter(
                "%(asctime)s AUDIT %(message)s"
            ))
            audit_logger = logging.getLogger("vulnscout.audit")
            audit_logger.addHandler(audit_handler)
            audit_logger.setLevel(logging.INFO)
            audit_logger.propagate = False
        except OSError:
            pass

    root = logging.getLogger()
    root.setLevel(level)
    # Remove existing handlers to avoid duplicates on reload
    root.handlers.clear()
    for h in handlers:
        root.addHandler(h)


class _JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter for production log aggregators."""

    def __init__(self, redact: bool = True) -> None:
        super().__init__()
        self.redact = redact
        # Patterns to redact from log messages
        import re
        self._secret_re = re.compile(
            r"(secret|password|token|key|bearer|auth)[^\s]*\s*[=:]\s*\S+",
            re.IGNORECASE,
        )

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone

        msg = record.getMessage()
        if self.redact:
            msg = self._secret_re.sub(r"\1=***REDACTED***", msg)

        payload = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "level":   record.levelname,
            "logger":  record.name,
            "message": msg,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        # Attach any extra fields passed via logger.info(..., extra={...})
        for key in ("scan_id", "user_id", "request_id"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)

        return json.dumps(payload, default=str)


# ── Public re-exports ──────────────────────────────────────────────────────────

__all__ = [
    "get_config",
    "override_config",
    "reset_config",
    "BaseConfig",
    "ConfigError",
]