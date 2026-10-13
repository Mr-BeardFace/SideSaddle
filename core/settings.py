"""Settings registry — single source of truth for all configurable values.

/config lists, drills, and sets from here. /info reads "changed from default"
from here. Adding a setting means one entry in SETTINGS — nothing else.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from core import config as _cfg


@dataclass(frozen=True)
class Setting:
    key: str                          # dot-notation key: "analyst.interval"
    label: str                        # display label
    desc: str                         # one-line description
    default: Any                      # default value
    type: str                         # "str" | "int" | "bool" | "float"
    group: str                        # group name (must be in GROUPS)
    choices: tuple[str, ...] = ()     # valid string choices (empty = free-form)
    minimum: int | None = None        # minimum for int/float
    allow_null: bool = False          # whether None is a valid value
    info_static: bool = False         # always show in /info even if at default


GROUPS: tuple[str, ...] = (
    "Provider",
    "Analyst",
    "Op",
    "C2",
    "Scope",
)

SETTINGS: tuple[Setting, ...] = (
    # ── Provider ────────────────────────────────────────────────────────────────
    Setting(
        key="active_provider", label="Provider",
        desc="LLM provider to use",
        default="anthropic", type="str", group="Provider",
        choices=("anthropic", "bedrock", "anthropic-sub", "openrouter", "nvidia", "local"),
        info_static=True,
    ),
    Setting(
        key="anthropic.model", label="Anthropic model",
        desc="Model ID when using the Anthropic provider",
        default="claude-opus-4-5-20251101", type="str", group="Provider",
    ),
    Setting(
        key="bedrock.model", label="Bedrock model",
        desc="Model ID when using AWS Bedrock",
        default="us.anthropic.claude-opus-4-5-v1:0", type="str", group="Provider",
        info_static=True,
    ),
    Setting(
        key="bedrock.region", label="Bedrock region",
        desc="AWS region for Bedrock",
        default="us-east-1", type="str", group="Provider",
    ),
    Setting(
        key="bedrock.profile", label="Bedrock AWS profile",
        desc="AWS credential profile name (~/.aws/credentials)",
        default="default", type="str", group="Provider",
    ),
    Setting(
        key="openrouter.model", label="OpenRouter model",
        desc="Model slug for OpenRouter (e.g. anthropic/claude-sonnet-4-5)",
        default="anthropic/claude-sonnet-4-5", type="str", group="Provider",
    ),
    Setting(
        key="nvidia.model", label="NVIDIA model",
        desc="Model ID for NVIDIA NIM (e.g. meta/llama-3.1-405b-instruct)",
        default="meta/llama-3.1-405b-instruct", type="str", group="Provider",
    ),
    Setting(
        key="local.model", label="Local model",
        desc="Model name for the local OpenAI-compatible server",
        default="", type="str", group="Provider", allow_null=True,
    ),
    Setting(
        key="local_base_url", label="Local base URL",
        desc="Base URL of local OpenAI-compatible server (e.g. http://localhost:11434/v1)",
        default="", type="str", group="Provider", allow_null=True,
    ),
    Setting(
        key="temp", label="Temperature",
        desc="Sampling temperature (null = provider default; dropped if model rejects it)",
        default=None, type="float", group="Provider", allow_null=True,
    ),

    # ── Analyst ─────────────────────────────────────────────────────────────────
    Setting(
        key="analyst.interval", label="Poll interval",
        desc="Seconds between log file polls",
        default=10, type="int", group="Analyst", minimum=3,
        info_static=True,
    ),
    Setting(
        key="analyst.debounce", label="Debounce",
        desc="Seconds of silence after last new content before firing analysis",
        default=15, type="int", group="Analyst", minimum=5,
    ),

    # ── Op ──────────────────────────────────────────────────────────────────────
    Setting(
        key="op.name", label="Op name",
        desc="Current op name. Use /op new <name> to switch (resets state); /config op.name just renames",
        default="unnamed_op", type="str", group="Op",
        info_static=True,
    ),
    Setting(
        key="op.working_directory", label="Working directory",
        desc="Path to store logs and session state for this op",
        default="", type="str", group="Op", allow_null=True,
        info_static=True,
    ),

    # ── C2 ──────────────────────────────────────────────────────────────────────
    Setting(
        key="c2.enabled", label="C2 enabled",
        desc="Start C2 polling automatically on launch",
        default=False, type="bool", group="C2",
        info_static=True,
    ),
    Setting(
        key="c2.nighthawk.url", label="Nighthawk URL",
        desc="Nighthawk teamserver URL (key stored in keychain via /key set nighthawk)",
        default="", type="str", group="C2", allow_null=True,
    ),

    # ── Scope ────────────────────────────────────────────────────────────────────
    Setting(
        key="scope.targets", label="Scope targets",
        desc="Known target IPs/ranges (aids IOC tagging; not all-inclusive)",
        default=[], type="list", group="Scope",
    ),
    Setting(
        key="scope.exclusions", label="Exclusions",
        desc="IPs/hosts that are never op-related (local infra, etc.)",
        default=[], type="list", group="Scope",
    ),

    # ── Debug ────────────────────────────────────────────────────────────────────
    Setting(
        key="debug", label="Debug",
        desc="Write raw LLM request/response JSON to debug_*.json",
        default=False, type="bool", group="Analyst",
    ),
    Setting(
        key="persona", label="Analyst persona",
        desc="Active analyst persona (agents/<persona>/persona.md)",
        default="redteam", type="str", group="Analyst",
        choices=("redteam", "pentest", "ctf"),
        info_static=True,
    ),
)

_BY_KEY: dict[str, Setting] = {s.key: s for s in SETTINGS}


def get_setting(key: str) -> Setting | None:
    return _BY_KEY.get(key)


def all_keys() -> tuple[str, ...]:
    return tuple(s.key for s in SETTINGS)


def settings_in_group(group: str) -> list[Setting]:
    return [s for s in SETTINGS if s.group == group]


def current_value(s: Setting) -> Any:
    return _cfg.get(s.key, s.default)


def is_changed(s: Setting) -> bool:
    return current_value(s) != s.default


def format_value(val: Any) -> str:
    if val is None:
        return "(not set)"
    if isinstance(val, bool):
        return "on" if val else "off"
    if isinstance(val, list):
        return ", ".join(str(x) for x in val) if val else "(empty)"
    return str(val)


def coerce(s: Setting, raw: str) -> tuple[Any, str]:
    """Parse a string value for a setting. Returns (value, error_or_empty)."""
    raw = raw.strip()

    if s.type == "bool":
        if raw.lower() in ("on", "true", "yes", "1"):
            return True, ""
        if raw.lower() in ("off", "false", "no", "0"):
            return False, ""
        return None, f"{s.key}: expected on/off, got {raw!r}"

    if s.type == "int":
        try:
            val = int(raw)
        except ValueError:
            return None, f"{s.key}: expected integer, got {raw!r}"
        if s.minimum is not None and val < s.minimum:
            return None, f"{s.key}: minimum is {s.minimum}"
        return val, ""

    if s.type == "float":
        try:
            val = float(raw)
        except ValueError:
            return None, f"{s.key}: expected number, got {raw!r}"
        return val, ""

    if s.type == "list":
        # comma or space separated
        items = [x.strip() for x in raw.replace(",", " ").split() if x.strip()]
        return items, ""

    if s.choices and raw not in s.choices:
        return None, f"{s.key}: must be one of {', '.join(s.choices)}"

    if s.allow_null and raw.lower() in ("", "null", "none"):
        return "", ""

    return raw, ""
