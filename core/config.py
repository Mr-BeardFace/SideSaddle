from __future__ import annotations
import os
from pathlib import Path
from typing import Any
import yaml
import keyring

_CONFIG_PATHS = [
    Path(os.environ["SIDESADDLE_CONFIG"]) if "SIDESADDLE_CONFIG" in os.environ else None,
    Path.home() / ".config" / "sidesaddle" / "config.yaml",
    Path("config.yaml"),  # local override (dev/compat)
]
_CONFIG_PATH: Path = next(
    (p for p in _CONFIG_PATHS if p is not None and p.exists()),
    Path.home() / ".config" / "sidesaddle" / "config.yaml",  # write target when none exist
)
_cfg: dict[str, Any] = {}


def load() -> dict[str, Any]:
    global _cfg
    if _cfg:
        return _cfg
    if _CONFIG_PATH.exists():
        _cfg = yaml.safe_load(_CONFIG_PATH.read_text()) or {}
    return _cfg


def get(key: str, default: Any = None) -> Any:
    """Dot-notation key lookup: get('analyst.interval')"""
    val: Any = load()
    for part in key.split("."):
        if not isinstance(val, dict):
            return default
        val = val.get(part, default)
        if val is default:
            return default
    return val


def set_value(key: str, value: Any) -> None:
    cfg = load()
    parts = key.split(".")
    d = cfg
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = value
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(yaml.dump(cfg, default_flow_style=False))


_KEY_CACHE: dict[str, str] = {}


def get_api_key(provider: str) -> str | None:
    if provider in _KEY_CACHE:
        return _KEY_CACHE[provider]
    env_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
    }
    if env_key := env_map.get(provider):
        if val := os.environ.get(env_key):
            _KEY_CACHE[provider] = val
            return val
    try:
        val = keyring.get_password("sidesaddle", provider) or keyring.get_password("pentest-ai", provider)
    except Exception:
        val = None
    if val:
        _KEY_CACHE[provider] = val
    return val


def set_api_key(provider: str, key: str) -> bool:
    """Returns True if key was persisted to keyring, False if session-only."""
    persisted = True
    try:
        keyring.set_password("sidesaddle", provider, key)
    except Exception:
        persisted = False
    _KEY_CACHE[provider] = key
    return persisted


_SS_BASE = Path.home() / ".local" / "share" / "sidesaddle"
_ACTIVE_LOG_DIR_FILE = _SS_BASE / ".active_log_dir"


def op_dir() -> Path:
    p = _SS_BASE / get("op.name", "default")
    p.mkdir(parents=True, exist_ok=True)
    return p


def log_dir() -> Path:
    p = op_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def publish_log_dir() -> None:
    """Write current log dir to state file so shell hooks can read it."""
    try:
        _SS_BASE.mkdir(parents=True, exist_ok=True)
        _ACTIVE_LOG_DIR_FILE.write_text(str(log_dir()))
    except Exception:
        pass


def op_name() -> str:
    return get("op.name", "unnamed_op")
