"""Slash command system for SideSaddle.

COMMANDS is the single source of truth — parsing, tab-completion, /help overview,
and per-command detail all derive from it. Adding a command means one entry here.
"""
from __future__ import annotations
from dataclasses import dataclass

_PROVIDERS     = ("anthropic", "bedrock", "anthropic-sub", "openrouter", "nvidia", "local")
_KEY_PROVIDERS = ("anthropic", "bedrock", "openrouter", "nvidia", "local", "nighthawk", "brave")
_ON_OFF        = ("on", "off")
_FRONTIER_LEVELS = ("recon", "service", "vuln", "exploited", "foothold", "user", "privesc", "root")

# Bedrock cross-region inference profile IDs (static — check AWS console for new ones)
_BEDROCK_MODELS = (
    "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    "us.anthropic.claude-3-5-haiku-20241022-v1:0",
    "us.anthropic.claude-3-opus-20240229-v1:0",
    "eu.anthropic.claude-3-5-sonnet-20241022-v2:0",
    "eu.anthropic.claude-3-5-haiku-20241022-v1:0",
    "ap.anthropic.claude-3-5-sonnet-20241022-v2:0",
)


@dataclass(frozen=True)
class Sub:
    name: str
    desc: str
    args: str = ""
    complete: tuple[str, ...] = ()


@dataclass(frozen=True)
class Command:
    name: str
    summary: str
    subs: tuple[Sub, ...]
    detail: tuple[str, ...] = ()

    @property
    def is_leaf(self) -> bool:
        return len(self.subs) == 1 and self.subs[0].name == ""


COMMANDS: list[Command] = [
    Command("/info", "Live snapshot — op, provider, model, keys, analyst state",
            (Sub("", "Show current configuration and status"),)),

    Command("/provider", "Switch provider or manage models", (
        Sub("list",        "Show available providers and their status"),
        Sub("set",         "Switch the active provider",          f"<{'|'.join(_PROVIDERS)}>",   _PROVIDERS),
        Sub("model list",  "List model IDs for a provider",       f"[{'|'.join(_PROVIDERS)}]",   _PROVIDERS),
        Sub("model set",   "Set the model for the active provider","<model-id>"),
    )),

    Command("/analyst", "Tune the background analyst", (
        Sub("interval", "Seconds between log polls (default 10)",  "<seconds>"),
        Sub("debounce", "Quiet time before firing analysis (default 15)", "<seconds>"),
        Sub("debug",    "Write raw LLM JSON to debug_*.json",      "<on|off>", _ON_OFF),
    )),

    Command("/op", "Manage operations", (
        Sub("new",  "Start a fresh op — resets all state",  "<name>"),
        Sub("list", "List saved ops"),
        Sub("load", "Open a previous op read-only",         "<name>"),
        Sub("dir",  "Set working directory base (none to use default ~/.local/share/sidesaddle/)", "<path|none>"),
    )),

    Command("/c2", "Nighthawk C2 control", (
        Sub("connect",    "Start Nighthawk polling"),
        Sub("disconnect", "Stop Nighthawk polling"),
        Sub("status",     "Show connection status and auth"),
        Sub("url",        "Set teamserver URL",   "<url>"),
        Sub("auth",       "Set Nighthawk credentials (stored in keychain)", "[<user> <pass>|clear|status]"),
    )),

    Command("/scope", "Engagement scope — aids IOC tagging", (
        Sub("add",    "Add a target IP/range",    "<target>"),
        Sub("remove", "Remove a target",          "<target>"),
        Sub("list",   "Show targets and exclusions"),
    )),

    Command("/key", "API keys (stored in system keychain)", (
        Sub("set",   "Store a key",              f"<{'|'.join(_KEY_PROVIDERS)}> <key>", _KEY_PROVIDERS),
        Sub("list",  "Show key status for all providers"),
        Sub("clear", "Remove a key",             f"[{'|'.join(_KEY_PROVIDERS)}]",       _KEY_PROVIDERS),
    )),

    Command("/frontier", "Manually override the kill-chain frontier position", (
        Sub("set", "Set frontier level (overrides analyst)", f"<{'|'.join(_FRONTIER_LEVELS)}>", _FRONTIER_LEVELS),
    )),

    Command("/config", "View or change a setting", (
        Sub("list",  "List all settings with current values",   "[group]"),
        Sub("get",   "Show one setting's value",                "<key>"),
        Sub("set",   "Change a setting",                        "<key> <value>"),
        Sub("reset", "Reset a setting to its default",          "<key>"),
    )),

    Command("/persona", "Switch the analyst persona", (
        Sub("set",  "Set active persona",  "<redteam|pentest|ctf>",
            ("redteam", "pentest", "ctf")),
        Sub("show", "Show current persona"),
    )),

    Command("/export", "Export IOC Activities + Beacons xlsx from current op state",
            (Sub("", "Generates ioc_<ts>.xlsx with Activities and Beacons sheets"),)),
    Command("/endop", "End the operation — stops analyst, exports IOC report, exits",
            (Sub("", "Stops log watching, runs IOC export, saves report to op directory"),)),
    Command("/status", "Show current op summary (beacons, hosts, creds, attack paths)",
            (Sub("", "Op state summary"),)),
    Command("/clear",  "Clear the activity log",
            (Sub("", "Clears the activity log display (on-disk files are kept)"),)),
    Command("/help",   "Show this help — /help <command> for detail",
            (Sub("", "Grouped help overview", "[command]"),)),
    Command("/exit",   "Exit SideSaddle", (Sub("", ""),)),
    Command("/quit",   "Exit SideSaddle", (Sub("", ""),)),
    Command("/q",      "Exit SideSaddle", (Sub("", ""),)),
]

_BY_NAME: dict[str, Command] = {c.name: c for c in COMMANDS}
GROUP_NAMES: frozenset[str] = frozenset(c.name for c in COMMANDS if not c.is_leaf)


# ── Derived views ─────────────────────────────────────────────────────────────

def _sub_path(cmd: Command, sub: Sub) -> str:
    return f"{cmd.name} {sub.name}".rstrip()

def _sub_sig(cmd: Command, sub: Sub) -> str:
    return f"{_sub_path(cmd, sub)} {sub.args}".rstrip()

def _build_paths() -> list[str]:
    paths: list[str] = []
    for c in COMMANDS:
        paths.append(c.name)
        for s in c.subs:
            if s.name:
                paths.append(_sub_path(c, s))
    return paths

def _build_completions() -> list[str]:
    out: list[str] = []
    for c in COMMANDS:
        for s in c.subs:
            path = _sub_path(c, s)
            out.append(path)
            for x in s.complete:
                out.append(f"{path} {x}")
    return out

COMMAND_PATHS: list[str] = _build_paths()
COMPLETIONS:   list[str] = _build_completions()


# ── Parser ────────────────────────────────────────────────────────────────────

def parse(text: str) -> tuple[str, list[str]] | None:
    text = text.strip()
    if not text.startswith("/"):
        return None
    lower = text.lower()
    for path in sorted(COMMAND_PATHS, key=len, reverse=True):
        if lower.startswith(path + " ") or lower == path:
            rest = text[len(path):].strip()
            return path, rest.split() if rest else []
    return text.split()[0], []


def complete(text: str) -> str | None:
    if not text.startswith("/"):
        return None
    lower = text.lower()
    for c in COMPLETIONS:
        if c.startswith(lower) and c != lower:
            return c
    return None


# ── Help rendering ────────────────────────────────────────────────────────────

_HELP_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Setup",      ("/info", "/key", "/provider", "/analyst", "/config", "/persona")),
    ("Operation",  ("/op", "/scope", "/c2")),
    ("Actions",    ("/export", "/endop", "/status", "/clear")),
    ("Session",    ("/help", "/exit", "/quit", "/q")),
)


def _overview_lines() -> list[str]:
    def _form(c: Command) -> str:
        if c.is_leaf:
            return c.name
        subs = [s.name for s in c.subs if s.name]
        # collapse "model list" / "model set" → "model (list|set)"
        groups: dict[str, list[str]] = {}
        singles: list[str] = []
        for s in subs:
            parts = s.split(None, 1)
            if len(parts) == 2:
                groups.setdefault(parts[0], []).append(parts[1])
            else:
                singles.append(s)
        tokens = singles[:]
        for grp, children in groups.items():
            tokens.append(f"{grp} ({'|'.join(children)})")
        return f"{c.name} ({' | '.join(tokens)})"

    width = max(len(_form(c)) for c in COMMANDS) + 2
    lines = ["Slash commands:", ""]
    for title, names in _HELP_GROUPS:
        lines.append(f"[bold]{title}[/bold]")
        for name in names:
            c = _BY_NAME.get(name)
            if not c:
                continue
            lines.append(f"  [cyan]{_form(c):<{width}}[/cyan] {c.summary}")
        lines.append("")
    lines += [
        "[dim]/help <command>[/dim]  — detail for one command",
        "",
        "Keyboard shortcuts:",
        "  Ctrl+←/→    Resize left pane",
        "  Ctrl+↑/↓    Resize leads panel",
        "  Ctrl+L      Full activity log",
        "  Ctrl+E      Export IOC",
        "  Ctrl+P/N    Command history",
        "  Tab         Complete command",
        "  Enter (finding) → detail modal",
    ]
    return lines


def _command_help(arg: str) -> list[str] | None:
    word = arg.lstrip("/").lower().split()
    cmd = _BY_NAME.get("/" + word[0]) if word else None
    if not cmd:
        return None
    if cmd.is_leaf:
        return [f"[cyan]{cmd.name}[/cyan] — {cmd.summary}"]
    lines = [f"[cyan]{cmd.name}[/cyan] — {cmd.summary}", ""]
    width = max(len(_sub_sig(cmd, s)) for s in cmd.subs) + 2
    for s in cmd.subs:
        lines.append(f"  [cyan]{_sub_sig(cmd, s):<{width}}[/cyan] {s.desc}")
    if cmd.detail:
        lines += [""] + [f"  {d}" for d in cmd.detail]
    return lines


# ── Handlers ─────────────────────────────────────────────────────────────────

def handle_help(args: list[str] | None = None) -> tuple[list[str], bool]:
    if args:
        detail = _command_help(args[0])
        if detail:
            return detail, True
        return [f"No such command: /{args[0].lstrip('/')}", ""] + _overview_lines(), False
    return _overview_lines(), True


def handle_info() -> tuple[list[str], bool]:
    from core import config
    from core.llm_client import load_sub_token

    def row(label: str, value: str) -> str:
        return f"  {label:<22}{value}"

    provider = config.get("active_provider", "bedrock")
    op_name  = config.op_name()
    op_dir   = str(config.op_dir())
    log_dir  = str(config.log_dir())
    model    = config.get("bedrock.model") if provider == "bedrock" else config.get("anthropic.model", "—")
    interval = config.get("analyst.interval", 10)
    debounce = config.get("analyst.debounce", 15)
    c2_on    = config.get("c2.enabled", False)
    c2_url   = config.get("c2.nighthawk.url", "") or "(not set)"
    debug    = config.get("debug", False)
    work_dir = config.get("op.working_directory", "") or "(default)"

    c2_user = config.get("c2.nighthawk.username", "") or "(not set)"
    c2_auth = f"user={c2_user}  pass={'set' if config.get_api_key('nighthawk_pass') else 'not set'}"

    lines = [
        "Current state",
        "",
        row("Op",           op_name),
        row("Op directory", op_dir),
        row("Log directory",log_dir),
        row("Working dir",  work_dir),
        "",
        row("Provider",     provider),
        row("Model",        str(model or "—")),
        "",
        row("Poll interval",f"{interval}s  (debounce: {debounce}s)"),
        row("C2",           f"{'enabled' if c2_on else 'off'}  url={c2_url}  auth={c2_auth}"),
        row("Debug",        "on" if debug else "off"),
    ]

    # Key / auth status
    lines += ["", "  Auth:"]
    for p in _PROVIDERS:
        if p == "bedrock":
            lines.append(f"    {'bedrock':<16} uses AWS credentials (~/.aws)")
        elif p == "anthropic-sub":
            ok = bool(load_sub_token())
            lines.append(f"    {'anthropic-sub':<16} {'[green]token ok[/green]' if ok else '[dim]not logged in — sidesaddle login[/dim]'}")
        else:
            k = config.get_api_key(p)
            if k:
                masked = k[:4] + "…" + k[-4:] if len(k) > 8 else "****"
                lines.append(f"    {p:<16} [green]key set[/green]  ({masked})")
            else:
                lines.append(f"    {p:<16} [dim]no key[/dim]")

    lines += ["", f"  Config file: {config._CONFIG_PATH}"]
    return lines, True


def handle_provider(args: list[str]) -> tuple[list[str], bool]:
    from core import config
    sub = " ".join(args[:2]) if len(args) >= 2 else (args[0] if args else "")

    if not args or sub == "list" or args[0] == "list":
        from core.llm_client import load_sub_token, PROVIDERS, resolve_provider_key
        active = config.get("active_provider", "anthropic")
        lines = [f"Active provider: [bold]{active}[/bold]", ""]
        for p in _PROVIDERS:
            if p == "bedrock":
                status = "[green]ready[/green]  (AWS credentials)"
            elif p == "anthropic-sub":
                status = "[green]ready[/green]" if load_sub_token() else "[dim]not logged in — run: sidesaddle login[/dim]"
            elif p in PROVIDERS:
                spec = PROVIDERS[p]
                key = resolve_provider_key(spec)
                if key or spec.key_optional:
                    status = "[green]key set[/green]" if key else "[green]no key needed[/green]"
                else:
                    status = f"[dim]no key — /key set {p} <key>[/dim]"
            else:
                status = "[green]ready[/green]" if config.get_api_key(p) else f"[dim]no key — /key set {p} <key>[/dim]"
            marker = "  [yellow]← active[/yellow]" if p == active else ""
            lines.append(f"  {p:<18} {status}{marker}")
        lines += ["", f"  Switch: /provider set <{'|'.join(_PROVIDERS)}>",
                     "  Models: /provider model list [provider]"]
        return lines, True

    if args[0] == "set" and len(args) >= 2:
        # /provider set local <url>  — convenience for the local base URL
        if args[1].lower() == "local" and len(args) >= 3:
            config.set_value("active_provider", "local")
            config.set_value("local_base_url", args[2])
            return [f"[green]Provider → local  base URL → {args[2]}[/green]"], True
        provider = args[1].lower()
        if provider not in _PROVIDERS:
            return [f"Unknown provider: {provider!r}  ({', '.join(_PROVIDERS)})"], False
        config.set_value("active_provider", provider)
        lines = [f"[green]Provider → {provider}[/green]"]
        if provider == "anthropic-sub":
            from core.llm_client import load_sub_token
            if not load_sub_token():
                lines.append("  [yellow]Not logged in — run: sidesaddle login[/yellow]")
        elif provider == "bedrock":
            pass
        else:
            from core.llm_client import PROVIDERS, resolve_provider_key
            spec = PROVIDERS.get(provider)
            if spec and not resolve_provider_key(spec) and not spec.key_optional:
                lines.append(f"  [yellow]No key set — run: /key set {provider} <key>[/yellow]")
        lines.append(f"  Current model: {_current_model(provider)}  (change: /provider model set <id>)")
        return lines, True

    if args[0] == "model":
        sub2 = args[1] if len(args) > 1 else ""
        if sub2 == "list":
            provider = args[2].lower() if len(args) > 2 else config.get("active_provider", "anthropic")
            return _model_list(provider)
        if sub2 == "set" and len(args) > 2:
            return _model_set(args[2])
        return [f"Usage: /provider model list [provider]  |  /provider model set <id>"], False

    return _command_help("/provider") or [], False


_MODEL_KEY = {
    "anthropic":     "anthropic.model",
    "bedrock":       "bedrock.model",
    "anthropic-sub": "anthropic.model",
    "openrouter":    "openrouter.model",
    "nvidia":        "nvidia.model",
    "local":         "local.model",
}


def _current_model(provider: str | None = None) -> str:
    from core import config
    p = provider or config.get("active_provider", "anthropic")
    key = _MODEL_KEY.get(p, "anthropic.model")
    return config.get(key, "(not set)") or "(not set)"


def _model_list(provider: str) -> tuple[list[str], bool]:
    from core import config
    if provider not in _PROVIDERS:
        return [f"Unknown provider: {provider!r}  ({', '.join(_PROVIDERS)})"], False
    model_key = _MODEL_KEY.get(provider, "anthropic.model")
    current = config.get(model_key, "")

    if provider == "bedrock":
        model_ids = list(_BEDROCK_MODELS)
        source = "static list"
    elif provider == "anthropic-sub":
        from core.llm_client import load_sub_token
        token = load_sub_token()
        model_ids = _fetch_anthropic_models(bearer_token=token) if token else []
        source = "live from API" if model_ids else "not logged in — run: sidesaddle login"
    elif provider == "anthropic":
        key = config.get_api_key("anthropic")
        model_ids = _fetch_anthropic_models(api_key=key) if key else []
        source = "live from API" if model_ids else "no key — /key set anthropic <key>"
    elif provider in ("openrouter", "nvidia", "local"):
        from core.llm_client import PROVIDERS as _PROV, resolve_provider_key, _models_url_for
        spec = _PROV.get(provider)
        if spec:
            api_key = resolve_provider_key(spec)
            model_ids = _fetch_openai_compat_models(spec, api_key)
            source = "live from API" if model_ids else "no key or server not reachable"
        else:
            model_ids, source = [], "unknown provider"
    else:
        model_ids, source = [], "unknown provider"

    lines = [f"Models for [bold]{provider}[/bold]  [{source}]",
             f"  Current: [cyan]{current or '(not set)'}[/cyan]", ""]
    for m in model_ids:
        marker = "  [yellow]← active[/yellow]" if m == current else ""
        lines.append(f"  {m}{marker}")
    if not model_ids:
        lines.append("  [dim](none retrieved)[/dim]")
    lines += ["", "  Set: /provider model set <model-id>"]
    return lines, True


def _model_set(model_id: str) -> tuple[list[str], bool]:
    from core import config
    provider = config.get("active_provider", "anthropic")
    key = _MODEL_KEY.get(provider, "anthropic.model")
    config.set_value(key, model_id)
    return [f"[green]Model → {model_id}[/green]  (provider: {provider})"], True


def _fetch_openai_compat_models(spec, api_key: str | None) -> list[str]:
    """Fetch model IDs from an OpenAI-compat /models endpoint."""
    import json, urllib.request
    from core.llm_client import _models_url_for, _auth_headers
    url = _models_url_for(spec)
    if not url:
        return []
    hdrs = {**_auth_headers(spec, api_key), **spec.extra_headers}
    try:
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        items = data.get("data", data) if isinstance(data, dict) else data
        return [m.get("id", "") for m in items if isinstance(m, dict) and m.get("id")]
    except Exception:
        return []


def _fetch_anthropic_models(*, api_key: str | None = None, bearer_token: str | None = None) -> list[str]:
    import json, urllib.request
    if not api_key and not bearer_token:
        return []
    headers = {"anthropic-version": "2023-06-01"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    else:
        headers["x-api-key"] = api_key
    try:
        req = urllib.request.Request("https://api.anthropic.com/v1/models", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return [m["id"] for m in data.get("data", []) if m.get("id")]
    except Exception:
        return []


def handle_analyst(args: list[str]) -> tuple[list[str], bool]:
    from core import config
    if not args:
        return _command_help("/analyst") or [], False
    sub = args[0]

    if sub == "interval":
        if len(args) < 2:
            return [f"  analyst.interval = {config.get('analyst.interval', 10)}s",
                    "  Usage: /analyst interval <seconds>  (minimum 3)"], True
        try:
            v = int(args[1])
        except ValueError:
            return ["Expected an integer"], False
        if v < 3:
            return ["Minimum interval is 3 seconds"], False
        config.set_value("analyst.interval", v)
        return [f"[green]Poll interval → {v}s[/green]"], True

    if sub == "debounce":
        if len(args) < 2:
            return [f"  analyst.debounce = {config.get('analyst.debounce', 15)}s",
                    "  Usage: /analyst debounce <seconds>  (minimum 5)"], True
        try:
            v = int(args[1])
        except ValueError:
            return ["Expected an integer"], False
        if v < 5:
            return ["Minimum debounce is 5 seconds"], False
        config.set_value("analyst.debounce", v)
        return [f"[green]Debounce → {v}s[/green]"], True

    if sub == "debug":
        if len(args) < 2:
            cur = config.get("debug", False)
            return [f"  debug = {'on' if cur else 'off'}",
                    "  Usage: /analyst debug on|off"], True
        val = args[1].lower()
        if val not in ("on", "off", "true", "false"):
            return ["Expected on or off"], False
        config.set_value("debug", val in ("on", "true"))
        return [f"[green]Debug → {val}[/green]"], True

    return [f"Unknown: /analyst {sub}  (interval | debounce | debug)"], False


def handle_key(args: list[str]) -> tuple[list[str], bool]:
    from core import config
    if not args:
        return _command_help("/key") or [], False
    sub = args[0]

    if sub == "list":
        lines = ["API key status:", ""]
        for p in _KEY_PROVIDERS:
            k = config.get_api_key(p)
            if k:
                masked = k[:4] + "…" + k[-4:] if len(k) > 8 else "****"
                lines.append(f"  {p:<16} [green]set[/green]  ({masked})")
            else:
                lines.append(f"  {p:<16} [dim]not set[/dim]")
        return lines, True

    if sub == "set" and len(args) >= 3:
        provider, key_val = args[1], args[2]
        if provider not in _KEY_PROVIDERS:
            return [f"Unknown provider: {provider!r}  ({', '.join(_KEY_PROVIDERS)})"], False
        persisted = config.set_api_key(provider, key_val)
        masked = key_val[:4] + "…" + key_val[-4:] if len(key_val) > 8 else "****"
        lines = [f"[green]{provider} key stored[/green]  ({masked})"]
        if not persisted:
            lines.append("[yellow]Warning: keyring unavailable — key is session-only and will not persist[/yellow]")
        return lines, True

    if sub == "clear":
        import keyring
        targets = [args[1]] if len(args) > 1 else list(_KEY_PROVIDERS)
        results = []
        for p in targets:
            try:
                keyring.delete_password("sidesaddle", p)
                results.append(f"{p} key removed")
            except Exception:
                results.append(f"{p} key not found")
        return results, True

    return ["Usage: /key set <provider> <key>  |  /key list  |  /key clear [provider]"], False


def handle_config(args: list[str]) -> tuple[list[str], bool]:
    from core import config, settings
    if not args:
        return _command_help("/config") or [], False
    sub = args[0]

    if sub == "list":
        group_filter = args[1].capitalize() if len(args) > 1 else None
        lines = ["Settings  ([yellow]*[/yellow] = changed from default)", ""]
        for g in settings.GROUPS:
            if group_filter and g != group_filter:
                continue
            grp_settings = settings.settings_in_group(g)
            if not grp_settings:
                continue
            lines.append(f"[bold]{g}[/bold]")
            for s in grp_settings:
                val = settings.current_value(s)
                marker = "[yellow]*[/yellow] " if settings.is_changed(s) else "  "
                lines.append(f"  {marker}{s.key:<30} {settings.format_value(val)}")
                lines.append(f"      [dim]{s.desc}[/dim]")
            lines.append("")
        return lines, True

    if sub == "get" and len(args) >= 2:
        s = settings.get_setting(args[1])
        if not s:
            return [f"Unknown setting: {args[1]!r}  (see /config list)"], False
        val = settings.current_value(s)
        lines = [
            f"[cyan]{s.key}[/cyan]  [{s.type}]  group: {s.group}",
            f"  Value:   {settings.format_value(val)}",
            f"  Default: {settings.format_value(s.default)}",
            f"  {s.desc}",
        ]
        if s.choices:
            lines.append(f"  Choices: {', '.join(s.choices)}")
        return lines, True

    if sub == "set" and len(args) >= 3:
        s = settings.get_setting(args[1])
        if not s:
            return [f"Unknown setting: {args[1]!r}  (see /config list)"], False
        raw = " ".join(args[2:])
        val, err = settings.coerce(s, raw)
        if err:
            return [f"[red]{err}[/red]"], False
        config.set_value(s.key, val)
        return [f"[green]{s.key} → {settings.format_value(val)}[/green]"], True

    if sub == "reset" and len(args) >= 2:
        s = settings.get_setting(args[1])
        if not s:
            return [f"Unknown setting: {args[1]!r}  (see /config list)"], False
        config.set_value(s.key, s.default)
        return [f"[green]{s.key} reset to default: {settings.format_value(s.default)}[/green]"], True

    return _command_help("/config") or [], False


def handle_persona(args: list[str]) -> tuple[list[str], bool]:
    from core import config
    from pathlib import Path
    _PERSONAS = ("redteam", "pentest", "ctf")
    if not args:
        return _command_help("/persona") or [], False
    sub = args[0]

    if sub == "show":
        current = config.get("persona", "redteam")
        persona_path = Path(__file__).parent.parent / "agents" / current / "persona.md"
        if persona_path.exists():
            import re
            text = persona_path.read_text(encoding="utf-8")
            text = re.sub(r"^---\s*\n.*?\n---\s*\n", "", text, flags=re.DOTALL).strip()
            return [f"Active persona: [bold]{current}[/bold]", ""] + text.splitlines()[:50], True
        return [f"Active persona: [bold]{current}[/bold]", "  (persona file not found)"], True

    if sub == "set" and len(args) >= 2:
        persona = args[1].lower()
        if persona not in _PERSONAS:
            return [f"Unknown persona: {persona!r}  ({', '.join(_PERSONAS)})"], False
        config.set_value("persona", persona)
        return [f"[green]Persona → {persona}[/green]"], True

    return _command_help("/persona") or [], False


def handle_scope(args: list[str]) -> tuple[list[str], bool]:
    from core import config
    if not args:
        return _command_help("/scope") or [], False
    sub = args[0]

    if sub == "list":
        targets = config.get("scope.targets", []) or []
        excl    = config.get("scope.exclusions", []) or []
        lines   = ["Scope targets:", ""]
        lines  += [f"  {t}" for t in targets] or ["  (none)"]
        lines  += ["", "Exclusions:"]
        lines  += [f"  {e}" for e in excl] or ["  (none)"]
        return lines, True

    if sub == "add" and len(args) >= 2:
        targets = list(config.get("scope.targets", []) or [])
        t = args[1]
        if t not in targets:
            targets.append(t)
            config.set_value("scope.targets", targets)
        return [f"[green]Added:[/green] {t}"], True

    if sub == "remove" and len(args) >= 2:
        targets = list(config.get("scope.targets", []) or [])
        t = args[1]
        if t in targets:
            targets.remove(t)
            config.set_value("scope.targets", targets)
            return [f"[green]Removed:[/green] {t}"], True
        return [f"[yellow]{t} not in scope[/yellow]"], False

    return ["Usage: /scope add <target>  |  /scope remove <target>  |  /scope list"], False


# ── Main dispatcher ───────────────────────────────────────────────────────────

def dispatch(text: str) -> tuple[list[str], bool] | None:
    """Returns (lines, ok) for stateless commands, None for app-state commands
    (/op new/load, /c2 connect/disconnect/status, /export, /status, /clear, /exit)."""
    parsed = parse(text)
    if parsed is None:
        return None
    cmd, args = parsed

    if cmd == "/help":
        return handle_help(args)
    if cmd == "/info":
        return handle_info()

    if cmd in ("/provider", "/provider list", "/provider set",
               "/provider model", "/provider model list", "/provider model set"):
        sub = cmd.replace("/provider", "").strip()
        return handle_provider((sub.split() + args) if sub else args)

    if cmd in ("/analyst", "/analyst interval", "/analyst debounce", "/analyst debug"):
        sub = cmd.replace("/analyst", "").strip()
        return handle_analyst((sub.split() + args) if sub else args)

    if cmd in ("/key", "/key set", "/key list", "/key clear"):
        sub = cmd.replace("/key", "").strip()
        return handle_key((sub.split() + args) if sub else args)

    if cmd in ("/scope", "/scope add", "/scope remove", "/scope list"):
        sub = cmd.replace("/scope", "").strip()
        return handle_scope((sub.split() + args) if sub else args)

    if cmd in ("/config", "/config list", "/config get", "/config set", "/config reset"):
        sub = cmd.replace("/config", "").strip()
        return handle_config((sub.split() + args) if sub else args)

    if cmd in ("/persona", "/persona set", "/persona show"):
        sub = cmd.replace("/persona", "").strip()
        return handle_persona((sub.split() + args) if sub else args)

    # /op dir is stateless (config only); new/list/load are app-state
    if cmd == "/op dir":
        from core import config
        path = args[0] if args else ""
        if not path or path.lower() in ("none", "clear", ""):
            config.set_value("op.working_directory", "")
            return ["[green]Working directory cleared[/green]  (using ~/.local/share/sidesaddle/<op>)"], True
        config.set_value("op.working_directory", path)
        return [f"[green]Working directory → {path}[/green]"], True

    # /c2 url and /c2 auth are stateless; connect/disconnect/status are app-state
    if cmd == "/c2 url":
        from core import config
        url = args[0] if args else ""
        config.set_value("c2.nighthawk.url", url)
        return [f"[green]Nighthawk URL → {url or '(cleared)'}[/green]"], True

    if cmd == "/c2 auth":
        from core import config
        if not args or args[0] in ("status", ""):
            user = config.get("c2.nighthawk.username", "") or "(not set)"
            has_pass = bool(config.get_api_key("nighthawk_pass"))
            return [
                f"  username: {user}",
                f"  password: {'[green]set[/green]' if has_pass else '[dim]not set[/dim]'}",
                "  Usage: /c2 auth <username> <password>  |  /c2 auth clear",
            ], True
        if args[0] == "clear":
            import keyring
            config.set_value("c2.nighthawk.username", "")
            try:
                keyring.delete_password("sidesaddle", "nighthawk_pass")
            except Exception:
                pass
            return ["[green]Nighthawk credentials cleared[/green]"], True
        if len(args) < 2:
            return ["Usage: /c2 auth <username> <password>"], False
        config.set_value("c2.nighthawk.username", args[0])
        config.set_api_key("nighthawk_pass", args[1])
        return [f"[green]Credentials stored[/green]  (user: {args[0]})",
                "  Run /c2 connect to start polling"], True

    # /frontier set — modifies engagement state, handled by app.py
    if cmd in ("/frontier", "/frontier set"):
        return None

    # App-state commands — handled by app.py
    return None
