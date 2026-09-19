"""Configuration and safe dotenv loading using only the standard library."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .reporting.dangerous_ports import PORT_CATALOGS


class ConfigurationError(ValueError):
    """Raised when configuration is invalid."""


def load_dotenv(path: Optional[Path]) -> Dict[str, str]:
    """Parse dotenv without shell evaluation and add missing values to environ."""
    loaded: Dict[str, str] = {}
    if path is None or not path.exists():
        return loaded
    if path.stat().st_mode & 0o077:
        raise ConfigurationError(f"Dotenv file permissions must be 0600: {path}")
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ConfigurationError(f"Invalid dotenv line {number}: missing '='")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "a").isalnum():
            raise ConfigurationError(f"Invalid dotenv key on line {number}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        loaded[key] = value
        os.environ.setdefault(key, value)
    return loaded


@dataclass(frozen=True)
class Settings:
    pce: str
    workloader_dir: str = "/DATA/WORKLOADER/ver12"
    workloader_config_file: str = ""
    state_db: str = "var/state/rules_recertify.sqlite"
    raw_dir: str = "var/raw"
    output_dir: str = "var/output"
    log_dir: str = "var/logs"
    traffic_window_days: int = 7
    traffic_batch_size: int = 100
    traffic_max_results: int = 10000
    query_initial_delay_minutes: int = 30
    query_poll_interval_minutes: int = 10
    query_deadline_minutes: int = 1380
    batch_cooldown_seconds: int = 60
    rate_limit_retry_delay_minutes: int = 10
    rate_limit_max_retries: int = 12
    empty_scope_ruleset_name_patterns: Tuple[str, ...] = ()
    retention_days: int = 550
    default_lookback_days: int = 548
    policy_version: str = "draft"
    smtp_enabled: bool = False
    dangerous_port_lists: Tuple[str, ...] = ("PORTS_TO_CONTROL", "PORTS_TO_ERADICATE")
    permissive_rule_max_ips: int = 255

    @property
    def workloader(self) -> Path:
        return Path(self.workloader_dir) / "workloader"

    def validate(self) -> None:
        if not self.pce.strip():
            raise ConfigurationError("pce must not be empty")
        if self.traffic_window_days != 7:
            raise ConfigurationError("traffic_window_days must be 7")
        if not 1 <= self.traffic_batch_size <= 500:
            raise ConfigurationError("traffic_batch_size must be between 1 and 500")
        if self.traffic_max_results < 1:
            raise ConfigurationError("traffic_max_results must be positive")
        if self.query_deadline_minutes >= 1440 or self.query_deadline_minutes < 1:
            raise ConfigurationError("query_deadline_minutes must be between 1 and 1439")
        if self.rate_limit_retry_delay_minutes < 10:
            raise ConfigurationError("rate_limit_retry_delay_minutes must be at least 10")
        if self.rate_limit_max_retries < 1:
            raise ConfigurationError("rate_limit_max_retries must be positive")
        if not isinstance(self.empty_scope_ruleset_name_patterns, (list, tuple)):
            raise ConfigurationError("empty_scope_ruleset_name_patterns must be a list")
        if any(
            not isinstance(pattern, str) or not pattern.strip()
            for pattern in self.empty_scope_ruleset_name_patterns
        ):
            raise ConfigurationError(
                "empty_scope_ruleset_name_patterns must contain non-empty strings"
            )
        if self.retention_days < 550:
            raise ConfigurationError("retention_days must be at least 550")
        if not 1 <= self.default_lookback_days <= self.retention_days:
            raise ConfigurationError("default_lookback_days must fit retention")
        if self.policy_version not in {"active", "draft"}:
            raise ConfigurationError("policy_version must be active or draft")
        if not isinstance(self.dangerous_port_lists, (list, tuple)):
            raise ConfigurationError("dangerous_port_lists must be a list or comma-separated string")
        unknown_port_lists = set(self.dangerous_port_lists) - set(PORT_CATALOGS)
        if unknown_port_lists:
            raise ConfigurationError(
                "unknown dangerous_port_lists: " + ", ".join(sorted(unknown_port_lists))
            )
        if self.permissive_rule_max_ips < 1:
            raise ConfigurationError("permissive_rule_max_ips must be positive")


def load_settings(path: Path, dotenv: Optional[Path] = None) -> Settings:
    load_dotenv(dotenv)
    try:
        data: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Configuration file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Invalid JSON configuration: {exc}") from exc
    allowed = {field.name for field in fields(Settings)}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigurationError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    if isinstance(data.get("dangerous_port_lists"), str):
        data["dangerous_port_lists"] = tuple(
            item.strip() for item in data["dangerous_port_lists"].split(",") if item.strip()
        )
    env_map = {
        "pce": "PCE",
        "workloader_dir": "WORKLOADER_DIR",
        "workloader_config_file": "WORKLOADER_CONFIG_FILE",
        "state_db": "STATE_DB",
    }
    for key, env_name in env_map.items():
        if os.getenv(env_name):
            data[key] = os.environ[env_name]
    settings = Settings(**data)
    settings.validate()
    return settings
