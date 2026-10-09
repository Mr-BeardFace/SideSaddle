"""Slash-command registry and dispatcher for SideSaddle."""
from __future__ import annotations
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from core.analyst import Analyst

from core.llm_client import cfg, set_cfg, fetch_models


# ── Op resolution ─────────────────────────────────────────────────────────────

_STATE_FILE = Path.home() / ".config" / "sidesaddle" / "current_op"


def resolve_op() -> tuple[str | None, Path | None, Path | None]:
    """Return (op_name, log_dir, output_dir) or (None, None, None) if no op set.

    Priority: SS_OP env var > state file (written by SideSaddle on startup) > current_op config.
    """
    op = os.environ.get("SS_OP") or ""
    if not op:
        try:
            op = _STATE_FILE.read_text().strip()
        except OSError:
            pass
    if not op:
        op = cfg("current_op", "")
    if not op:
        return None, None, None
    log_root    = Path(cfg("log_root",    "~/.local/share/sidesaddle")).expanduser()
    output_root = Path(cfg("output_root", "~/sidesaddle-output")).expanduser()
    return op, log_root / op, output_root / op


# ── Command registry ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Sub:
    name: str           # "" for a leaf command
    desc: str
    args: str = ""      # hint shown after the path


@dataclass(frozen=True)
class Command:
    name: str
    summary: str
    subs: tuple[Sub, ...]

    @property
    def is_leaf(self) -> bool:
        return len(self.subs) == 1 and self.subs[0].name == ""


COMMANDS: list[Command] = [
    Command("/help",   "Show commands — /help <cmd> for detail",
            (Sub("", "Show all commands, or detail for one", "[cmd]"),)),
    Command("/op",     "View or set the current operation", (
        Sub("",    "Show current op name and log directory"),
        Sub("set", "Set current_op in config (restart to apply)", "<name>"),
    )),
    Command("/info",   "Op state: activities, beacons, session status",
            (Sub("", "Snapshot of current session state"),)),
    Command("/config", "View or change any setting", (
        Sub("",       "List all settings"),
        Sub("set",    "Set a config value",                        "<key> <value>"),
        Sub("models", "List available models from active provider"),
    )),
    Command("/stop",   "Stop in-progress IOC analysis",
            (Sub("", "Cancel the running IOC log build"),)),
    Command("/ioc",    "Build IOC log from disk logs",
            (Sub("", "blank = since last run · YYYY-MM-DD = from date · all = full re-run",
                 "[YYYY-MM-DD | all]"),)),
    Command("/export", "Export CSV files",
            (Sub("", "Write activities and beacons to CSV"),)),
    Command("/exit",   "Exit SideSaddle",
            (Sub("", "Save session and exit"),)),
]

_BY_NAME: dict[str, Command] = {c.name: c for c in COMMANDS}


# ── Config key definitions ────────────────────────────────────────────────────

_CONFIG_KEYS: list[tuple[str, str, str]] = [
    # (key,                   type,   description)
    ("current_op",          "str",    "Active op name — overridden by --op flag at runtime"),
    ("log_root",            "str",    "Root dir for log files (~/.local/share/sidesaddle)"),
    ("output_root",         "str",    "Root dir for op output folders (~/sidesaddle-output)"),
    ("debug",               "bool",   "Debug mode — dumps raw LLM input/output"),
    ("auto_analysis",       "bool",   "Auto-analyse new log entries"),
    ("verbosity",           "str",    "Advisory verbosity: brief | verbose"),
    ("debounce_seconds",    "int",    "Seconds to wait after last log entry before analysing"),
    ("analyze_chunk_size",  "int",    "Max chars per LLM call when chunking large logs"),
    ("max_output_chars",    "int",    "Max chars of pending output shown in state summary"),
    ("ioc_output_lines",    "int",    "Max output lines per command kept for IOC extraction"),
    ("model",               "str",    "Default model ID — run /config models to list"),
    ("ioc_model",           "str",    "Model for IOC extraction (default: model). Haiku recommended."),
    ("chat_model",          "str",    "Model for operator chat (default: model). Sonnet/Opus recommended."),
    ("active_provider",     "str",    "LLM provider: anthropic | anthropic-sub"),
    ("log_glob",            "str",    "Glob pattern for log files (default: raw_*.log; legacy: session_*.log)"),
    ("notes_dir",           "str",    "Path to external analyst notes folder"),
    ("notes_glob",          "str",    "Glob patterns for notes files (comma-separated)"),
    ("working_dir",         "str",    "Directory the advisor may write files into (unset = no writes allowed)"),
    ("brave_api_key",       "str",    "Brave Search API key for web search tool (free tier at api.search.brave.com)"),
]
_KEY_NAMES:  tuple[str, ...] = tuple(k for k, _, _ in _CONFIG_KEYS)
_BOOL_KEYS:  frozenset[str]  = frozenset(k for k, t, _ in _CONFIG_KEYS if t == "bool")
_INT_KEYS:   frozenset[str]  = frozenset(k for k, t, _ in _CONFIG_KEYS if t == "int")
_BOOL_VALS = {"on": True, "true": True, "1": True, "off": False, "false": False, "0": False}


# ── Completions ───────────────────────────────────────────────────────────────

def _sub_path(cmd: Command, sub: Sub) -> str:
    return f"{cmd.name} {sub.name}".rstrip()


def _build_completions() -> list[str]:
    out: list[str] = []
    for c in COMMANDS:
        for s in c.subs:
            out.append(_sub_path(c, s))
    # /config set <key> completions
    for key in _KEY_NAMES:
        out.append(f"/config set {key}")
        if key in _BOOL_KEYS:
            out += [f"/config set {key} on", f"/config set {key} off"]
    # /ioc date form
    out.append("/ioc all")
    # /help <cmd>
    for c in COMMANDS:
        out.append(f"/help {c.name.lstrip('/')}")
    return out


COMPLETIONS: list[str] = _build_completions()

_model_ids: list[str] = []


def _refresh_model_completions(models: list[tuple[str, str]]) -> None:
    global _model_ids
    _model_ids = [m[0] for m in models]
    for mid in _model_ids:
        entry = f"/config set model {mid}"
        if entry not in COMPLETIONS:
            COMPLETIONS.append(entry)


# ── Parser ────────────────────────────────────────────────────────────────────

_COMMAND_PATHS: list[str] = [_sub_path(c, s) for c in COMMANDS for s in c.subs] + \
                             [c.name for c in COMMANDS]


def parse(text: str) -> tuple[str, list[str]] | None:
    """Return (command_path, args) for a recognised command, or None if not a slash command."""
    text = text.strip()
    if not text.startswith("/"):
        return None
    lower = text.lower()
    for path in sorted(_COMMAND_PATHS, key=len, reverse=True):
        if lower == path or lower.startswith(path + " "):
            return path, text[len(path):].strip().split() if text[len(path):].strip() else []
    return None


def best_suggestion(value: str) -> str | None:
    """Return the first COMPLETIONS entry that extends `value`, or None."""
    if not value.startswith("/"):
        return None
    v = value.lower()
    for c in COMPLETIONS:
        if c.lower().startswith(v) and c.lower() != v:
            return c
    return None


# ── Help rendering ────────────────────────────────────────────────────────────

def _overview_lines() -> list[str]:
    def _form(c: Command) -> str:
        if c.is_leaf:
            sig = c.subs[0].args
            return f"{c.name} {sig}".rstrip() if sig else c.name
        return f"{c.name} ({' | '.join(s.name for s in c.subs)})"

    width = max(len(_form(c)) for c in COMMANDS) + 2
    lines = ["Commands:"]
    for c in COMMANDS:
        lines.append(f"  {_form(c):<{width}} {c.summary}")
    return lines


def _detail_lines(cmd: Command) -> list[str]:
    lines = [f"{cmd.name} — {cmd.summary}", ""]
    for s in cmd.subs:
        path = _sub_path(cmd, s)
        sig  = f"{path} {s.args}".rstrip()
        lines.append(f"  {sig:<40} {s.desc}")
    if cmd.name == "/config":
        lines += ["", "  Config keys:"]
        cur_model = cfg("model", "")
        for key, typ, desc in _CONFIG_KEYS:
            val = cfg(key, "(unset)")
            marker = " ◀" if key == "model" and val == cur_model else ""
            lines.append(f"    {key:<26} [{typ}]  {val}{marker}")
            lines.append(f"      {desc}")
    return lines


# ── Result type ───────────────────────────────────────────────────────────────

class CommandResult(NamedTuple):
    lines: list[str]
    action: str = ""  # "", "exit", "ioc:<iso_or_empty>:<1|0>", "export"


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch(text: str, analyst: "Analyst") -> CommandResult | None:
    """Handle a slash command. Returns None if text is not a slash command."""
    parsed = parse(text)
    if not parsed:
        return None
    path, args = parsed

    if path in ("/exit", "/quit"):
        return CommandResult([], "exit")

    if path == "/op":
        op, log_dir, out_dir = resolve_op()
        if not op:
            return CommandResult([
                "  No op set.",
                "  Pass --op <name> on launch, or set current_op in config.yaml.",
            ])
        src = "--op flag" if os.environ.get("SS_OP") else "config"
        return CommandResult([
            f"  op:        {op}  [{src}]",
            f"  log dir:   {log_dir}",
            f"  output:    {out_dir}",
        ])

    if path == "/op set":
        if not args:
            return CommandResult(["  Usage: /op set <name>"])
        new_op = args[0]
        set_cfg("current_op", new_op)
        return CommandResult([
            f"  current_op = {new_op}",
            "  Restart SideSaddle to apply. (--op flag takes precedence if passed.)",
        ])

    if path == "/help":
        if args:
            name = args[0] if args[0].startswith("/") else f"/{args[0]}"
            c = _BY_NAME.get(name)
            if c:
                return CommandResult(_detail_lines(c))
            return CommandResult([f"  Unknown command '{name}'. Type /help."])
        return CommandResult(_overview_lines())

    if path == "/info":
        lines = ["── Session ─────────────────────────────"]
        lines.append(f"  activities    {len(analyst.activities)}")
        lines.append(f"  beacons       {len(analyst.beacons)}")
        lines.append(f"  auto          {analyst.auto_analysis}")
        lines.append(f"  verbosity     {analyst.verbosity}")
        lit = getattr(analyst, "_last_ioc_time", None)
        lines.append(f"  last ioc run  {lit.strftime('%Y-%m-%d %H:%M') if lit else 'never'}")
        return CommandResult(lines)

    if path == "/config":
        lines = ["── Config ──────────────────────────────"]
        cur = cfg("model", "")
        for key, typ, desc in _CONFIG_KEYS:
            if key == "current_op":
                env_op = os.environ.get("SS_OP")
                val = env_op if env_op else cfg(key, "(unset)")
                marker = "  [--op flag]" if env_op else ""
            else:
                val    = cfg(key, "(unset)")
                marker = " ◀ active" if key == "model" and val == cur else ""
            lines.append(f"  {key:<26} {val}{marker}")
        return CommandResult(lines)

    if path == "/config set":
        if len(args) < 1:
            return CommandResult(["  Usage: /config set <key> <value>",
                                  f"  Keys: {', '.join(_KEY_NAMES)}"])
        key = args[0].lower()
        if key not in _KEY_NAMES:
            return CommandResult([f"  Unknown key '{key}'",
                                  f"  Keys: {', '.join(_KEY_NAMES)}"])
        if len(args) < 2:
            return CommandResult([f"  {key} = {cfg(key, '(unset)')}"])
        raw = " ".join(args[1:])
        if key in _BOOL_KEYS:
            if raw.lower() not in _BOOL_VALS:
                return CommandResult([f"  {key} expects on/off"])
            val: object = _BOOL_VALS[raw.lower()]
        elif key in _INT_KEYS:
            try:
                val = int(raw)
            except ValueError:
                return CommandResult([f"  {key} expects an integer"])
        else:
            val = raw
        set_cfg(key, val)
        # push live updates
        if key == "verbosity":
            analyst.verbosity = str(val)
        elif key == "auto_analysis":
            analyst.auto_analysis = bool(val)
        elif key == "model":
            analyst._llm._model = str(val)
        return CommandResult([f"  {key} = {val}"])

    if path == "/config models":
        try:
            models = fetch_models()
        except Exception as e:
            return CommandResult([f"  Error: {e}"])
        if not models:
            return CommandResult([f"  No model list available for '{cfg('active_provider', 'anthropic')}'"])
        _refresh_model_completions(models)
        cur = cfg("model", "")
        lines = [f"  Models ({cfg('active_provider', 'anthropic')}):"]
        for mid, name in models:
            marker = " ◀ active" if mid == cur else ""
            lines.append(f"    {mid:<48} {name}{marker}")
        lines.append("  Use /config set model <id> to switch.")
        return CommandResult(lines)

    if path == "/stop":
        analyst.stop_ioc()
        return CommandResult(["  Stopping IOC analysis…"])

    if path == "/ioc":
        since: datetime | None = None
        full = False
        if args:
            if args[0].lower() == "all":
                full = True
            else:
                for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
                    try:
                        since = datetime.strptime(" ".join(args), fmt)
                        break
                    except ValueError:
                        continue
                if since is None:
                    return CommandResult(["  Invalid date. Use: /ioc [YYYY-MM-DD] or /ioc all"])
        return CommandResult([], f"ioc:{since.isoformat() if since else ''}:{'1' if full else '0'}")

    if path == "/export":
        return CommandResult([], "export")

    # Unknown or bare group name — show detail
    cmd_name = path.split()[0] if path else path
    c = _BY_NAME.get(cmd_name)
    if c:
        return CommandResult(_detail_lines(c))
    return CommandResult([f"  Unknown command '{path}'. Type /help."])
