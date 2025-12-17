"""Configuration loading for the FIM agent."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class Config:
    """Runtime configuration for the FIM agent."""

    monitored_directories: List[str]
    exclude_directories: List[str]
    exclude_extensions: List[str]
    database_path: str
    log_file: str
    log_format: str  # "json", "text", or "wazuh"
    alert_min_risk_score: int = 70
    alert_min_ai_risk_score: int = 70
    require_admin_for_alerts: bool = True
    admin_min_risk_score: int = 80
    admin_min_ai_risk_score: int = 75
    admin_password_env_var: str = "FIM_ADMIN_PASSWORD"
    enable_ai: bool = True


def _project_root() -> Path:
    """Resolve the project root based on this file's location."""
    return Path(__file__).resolve().parents[2]


def _resolve_path(base: Path, candidate: Path) -> Path:
    """Return absolute path for candidate, relative to base when needed."""
    return candidate if candidate.is_absolute() else base / candidate


def _select_default_config(base_dir: Path) -> Path:
    """Pick the primary config if it exists, otherwise fall back to example."""
    primary = base_dir / "config" / "config.yaml"
    fallback = base_dir / "config" / "config_example.yaml"
    return primary if primary.exists() else fallback


def load_config(path: Optional[str] = None) -> Config:
    """
    Load configuration from YAML.

    If no path is provided, tries config/config.yaml, otherwise uses
    config/config_example.yaml.
    """
    base_dir = _project_root()
    if path:
        candidate = _resolve_path(base_dir, Path(path))
        if not candidate.exists():
            raise FileNotFoundError(f"Config file not found: {candidate}")
    else:
        candidate = _select_default_config(base_dir)

    with candidate.open("r", encoding="utf-8") as handle:
        raw: Dict[str, Any] = yaml.safe_load(handle) or {}

    return Config(
        monitored_directories=list(raw.get("monitored_directories") or []),
        exclude_directories=list(raw.get("exclude_directories") or []),
        exclude_extensions=list(raw.get("exclude_extensions") or []),
        database_path=str(raw.get("database_path") or (base_dir / "data" / "fim.sqlite3")),
        log_file=str(raw.get("log_file") or (base_dir / "logs" / "fim_agent.log")),
        log_format=str(raw.get("log_format") or "json"),
        alert_min_risk_score=int(raw.get("alert_min_risk_score") or 70),
        alert_min_ai_risk_score=int(raw.get("alert_min_ai_risk_score") or 70),
        require_admin_for_alerts=bool(raw.get("require_admin_for_alerts", True)),
        admin_min_risk_score=int(raw.get("admin_min_risk_score") or 80),
        admin_min_ai_risk_score=int(raw.get("admin_min_ai_risk_score") or 75),
        admin_password_env_var=str(raw.get("admin_password_env_var") or "FIM_ADMIN_PASSWORD"),
        enable_ai=bool(raw.get("enable_ai", True)),
    )


__all__ = ["Config", "load_config"]


