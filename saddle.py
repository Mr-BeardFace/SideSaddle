#!/usr/bin/env python3
"""saddle — SideSaddle shell-native CLI.

All TUI functionality available as subcommands.
Most data commands open the DB directly (no daemon required).
`saddle ai` and `saddle status --badge` need the daemon running.
"""
from __future__ import annotations
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

_console = Console()
_SS_BASE = Path.home() / ".local" / "share" / "sidesaddle"
_SESSIONS_DIR = _SS_BASE / "sessions"
_ACTIVE_LOG_DIR_FILE = _SS_BASE / ".active_log_dir"
_PROJECT_DIR = Path(__file__).parent

_LEAD_STATUSES   = ("open", "active", "confirmed", "refuted", "exhausted")
_FRONTIER_LEVELS = ("recon", "service", "vuln", "exploited", "foothold", "user", "privesc", "root")
_SEV_COLOR = {"info": "dim", "low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
_OPSEC_COLOR = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _active_op() -> str | None:
    if _ACTIVE_LOG_DIR_FILE.exists():
        text = _ACTIVE_LOG_DIR_FILE.read_text().strip()
        if text:
            return Path(text).parent.name
    return None


def _socket_path(op: str) -> Path:
    return _SS_BASE / op / ".daemon.sock"


def _daemon_running(op: str) -> bool:
    sock = _socket_path(op)
    if not sock.exists():
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(str(sock))
        s.close()
        return True
    except Exception:
        return False


def _socket_request(op: str, msg: dict, timeout: float = 120.0) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(_socket_path(op)))
    s.sendall(json.dumps(msg).encode() + b"\n")
    data = b""
    while b"\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data.split(b"\n")[0])


def _register_pid(pid: int) -> None:
    _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    (_SESSIONS_DIR / str(pid)).touch()


def _unregister_pid(pid: int) -> None:
    try:
        (_SESSIONS_DIR / str(pid)).unlink(missing_ok=True)
    except Exception:
        pass


def _open_store(op: str | None = None):
    """Open EngagementStore for op. Returns (store, op_name)."""
    sys.path.insert(0, str(_PROJECT_DIR))
    from core import config
    from core.auth import resolve_passphrase
    from core.store import BadPassphrase, EngagementStore

    if op:
        config.set_value("op.name", op)
    else:
        active = _active_op()
        if active and not config.get("op.name"):
            config.set_value("op.name", active)
        if not config.get("op.name"):
            raise click.ClickException("no active op — use --op <name> or: saddle start --op <name>")

    op_name = config.op_name()
    db_path = config.op_dir() / "engagement.db"
    if not db_path.exists():
        raise click.ClickException(f"no engagement DB for op '{op_name}'")

    env_pw = os.environ.get("SIDESADDLE_PASSPHRASE", "").strip()
    if env_pw:
        passphrase = env_pw
        os.environ.pop("SIDESADDLE_PASSPHRASE", None)
    else:
        try:
            passphrase, _ = resolve_passphrase(op_name, force_prompt=False)
        except Exception:
            passphrase = ""

    if not passphrase:
        raise click.ClickException(
            f"no cached passphrase for '{op_name}' — run: saddle start --op {op_name}"
        )
    try:
        return EngagementStore(db_path, passphrase), op_name
    except BadPassphrase:
        raise click.ClickException("incorrect passphrase")


def _print_lines(lines: list[str]) -> None:
    for line in lines:
        _console.print(line)


# ── Root group ────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """SideSaddle shell-native CLI — full op management without the TUI."""


# ── Daemon lifecycle ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--op", required=True, help="Op name")
def start(op: str) -> None:
    """Start the SideSaddle daemon for an op."""
    sys.path.insert(0, str(_PROJECT_DIR))
    from core import config
    from core.auth import cache_passphrase, resolve_passphrase
    from core.store import BadPassphrase, EngagementStore

    config.set_value("op.name", op)

    if _daemon_running(op):
        _register_pid(os.getppid())
        _console.print(f"saddle: daemon already running for [bold]{op}[/bold]")
        return

    env_pw = os.environ.get("SIDESADDLE_PASSPHRASE", "").strip()
    if env_pw:
        passphrase, was_prompted = env_pw, False
        os.environ.pop("SIDESADDLE_PASSPHRASE", None)
    else:
        passphrase, was_prompted = resolve_passphrase(op, force_prompt=False)

    db_path = config.op_dir() / "engagement.db"
    try:
        store = EngagementStore(db_path, passphrase)
        store.close()
    except BadPassphrase:
        raise click.ClickException("incorrect passphrase")

    if was_prompted:
        cache_passphrase(op, passphrase)

    _register_pid(os.getppid())

    daemon_env = {**os.environ, "SIDESADDLE_PASSPHRASE": passphrase,
                  "PYTHONPATH": str(_PROJECT_DIR)}
    subprocess.Popen(
        [sys.executable, "-m", "core.daemon", "--op", op],
        start_new_session=True,
        env=daemon_env,
        cwd=str(_PROJECT_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    for _ in range(30):
        if _daemon_running(op):
            _console.print(f"saddle: started op [bold]{op}[/bold]")
            return
        time.sleep(0.5)
    _console.print("saddle: daemon started (socket not yet ready)", style="yellow")


@cli.command()
@click.option("--op", default=None, help="Op name (default: active op)")
def stop(op: str | None) -> None:
    """Stop the daemon for the active op."""
    op = op or _active_op()
    if not op:
        raise click.ClickException("no active op")
    _unregister_pid(os.getppid())
    if _daemon_running(op):
        try:
            _socket_request(op, {"type": "stop"}, timeout=5.0)
        except Exception:
            pass
    _console.print(f"saddle: stopped [bold]{op}[/bold]")


@cli.command(hidden=True)
@click.argument("pid", type=int)
def register(pid: int) -> None:
    """Register a shell PID (called by shell hooks)."""
    _register_pid(pid)


@cli.command(hidden=True)
@click.argument("pid", type=int)
def unregister(pid: int) -> None:
    """Unregister a shell PID (called by shell EXIT trap)."""
    _unregister_pid(pid)


# ── Op status ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--op", default=None, help="Op name (default: active op)")
@click.option("--clear", "clear_badge", is_flag=True, default=False, help="Clear the current badge")
def status(op: str | None, clear_badge: bool) -> None:
    """Show op summary — frontier, counts, badge."""
    op = op or _active_op()
    if not op:
        raise click.ClickException("no active op")

    # Try daemon first for live badge
    if _daemon_running(op):
        try:
            resp = _socket_request(op, {"type": "status"}, timeout=5.0)
            _console.print(f"op:       [bold]{resp.get('op', op)}[/bold]")
            _console.print(f"frontier: [cyan]{resp.get('frontier', '?')}[/cyan]")
            badge = resp.get("badge")
            if badge:
                _console.print(f"badge:    [yellow][{badge}][/yellow]  ({resp.get('badge_type', '?')})")
            if clear_badge:
                _socket_request(op, {"type": "clear_badge"}, timeout=5.0)
            return
        except Exception:
            pass

    # Fall back to DB
    store, op_name = _open_store(op)
    try:
        summary = store.summary()
        _console.print(f"op:       [bold]{op_name}[/bold]")
        _console.print(f"chunks:   {summary.get('chunks', 0)}")
        _console.print(f"leads:    {summary.get('leads', 0)}")
        _console.print(f"findings: {summary.get('findings', 0)}")
        _console.print(f"creds:    {summary.get('credentials', 0)}")
    finally:
        store.close()


# ── Data views ────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--op", default=None)
@click.option("--status", "filter_status", default=None,
              type=click.Choice(_LEAD_STATUSES), help="Filter by status")
@click.option("--reach", default=None, type=click.Choice(_FRONTIER_LEVELS),
              help="Filter by reach level")
@click.option("--notable", is_flag=True, default=False, help="Show only notable leads")
def leads(op: str | None, filter_status: str | None, reach: str | None, notable: bool) -> None:
    """List leads."""
    store, _ = _open_store(op)
    try:
        rows = store.get_leads(status=filter_status)
    finally:
        store.close()

    if reach:
        rows = [r for r in rows if r.get("reach_level") == reach]
    if notable:
        rows = [r for r in rows if r.get("insight") == "notable"]

    if not rows:
        _console.print("[dim]no leads[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("#", style="dim", width=4)
    t.add_column("Status", width=10)
    t.add_column("Reach", width=10)
    t.add_column("Prior", width=5)
    t.add_column("Opsec", width=8)
    t.add_column("I", width=1)  # insight indicator
    t.add_column("Description")

    for r in rows:
        sev_color = _OPSEC_COLOR.get(r.get("opsec", "medium"), "white")
        insight_mark = "[cyan]*[/cyan]" if r.get("insight") == "notable" else ""
        status_color = "green" if r.get("status") == "confirmed" else \
                       "dim" if r.get("status") in ("refuted", "exhausted") else "white"
        t.add_row(
            str(r["id"]),
            f"[{status_color}]{r.get('status', 'open')}[/{status_color}]",
            r.get("reach_level", ""),
            f"{float(r.get('prior', 0.5)):.2f}",
            f"[{sev_color}]{r.get('opsec', 'medium')}[/{sev_color}]",
            insight_mark,
            r.get("description", ""),
        )
        if r.get("command"):
            t.add_row("", "", "", "", "", "", f"[dim]cmd: {r['command']}[/dim]")
        if r.get("target"):
            t.add_row("", "", "", "", "", "", f"[dim]target: {r['target']}[/dim]")

    _console.print(t)
    _console.print(f"[dim]{len(rows)} lead(s)  — [cyan]*[/cyan] = notable  — saddle lead <#> confirm|exhaust|refute[/dim]")


@cli.command()
@click.argument("lead_id", type=int)
@click.argument("action", type=click.Choice(("confirm", "exhaust", "refute", "active", "open")))
@click.option("--op", default=None)
def lead(lead_id: int, action: str, op: str | None) -> None:
    """Update a lead's status.  saddle lead <#> confirm|exhaust|refute"""
    status_map = {"confirm": "confirmed", "exhaust": "exhausted", "refute": "refuted",
                  "active": "active", "open": "open"}
    new_status = status_map[action]
    store, _ = _open_store(op)
    try:
        store.update_lead_status(lead_id, new_status)
    finally:
        store.close()
    _console.print(f"lead [bold]#{lead_id}[/bold] → [cyan]{new_status}[/cyan]")


@cli.command()
@click.option("--op", default=None)
def creds(op: str | None) -> None:
    """List credentials."""
    store, _ = _open_store(op)
    try:
        rows = store.get_credentials(decrypt=True)
    finally:
        store.close()

    if not rows:
        _console.print("[dim]no credentials[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Type", width=10)
    t.add_column("Username")
    t.add_column("Secret")
    t.add_column("Format", width=12)
    t.add_column("Location")
    t.add_column("Service", width=8)
    t.add_column("Source Host")

    for r in rows:
        secret = r.get("secret", "")
        masked = (secret[:2] + "…" + secret[-2:]) if len(secret or "") > 6 else (secret or "(none)")
        t.add_row(
            r.get("cred_type", ""),
            r.get("username", ""),
            masked,
            r.get("cred_format", ""),
            r.get("location", ""),
            r.get("service", ""),
            r.get("source_host", ""),
        )
    _console.print(t)
    _console.print(f"[dim]{len(rows)} credential(s)[/dim]")


@cli.command()
@click.option("--op", default=None)
@click.option("--severity", default=None,
              type=click.Choice(("info", "low", "medium", "high", "critical")))
def findings(op: str | None, severity: str | None) -> None:
    """List findings."""
    store, _ = _open_store(op)
    try:
        rows = store.get_findings()
    finally:
        store.close()

    if severity:
        rows = [r for r in rows if r.get("severity") == severity]
    if not rows:
        _console.print("[dim]no findings[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Sev", width=8)
    t.add_column("Title")
    t.add_column("Target")
    t.add_column("Technique", width=18)
    t.add_column("V", width=1)

    for r in rows:
        sev = r.get("severity", "info")
        color = _SEV_COLOR.get(sev, "white")
        t.add_row(
            f"[{color}]{sev.upper()}[/{color}]",
            r.get("title", ""),
            r.get("target", ""),
            r.get("technique", ""),
            "[green]✓[/green]" if r.get("verified") else "",
        )
    _console.print(t)
    _console.print(f"[dim]{len(rows)} finding(s)[/dim]")


@cli.command()
@click.option("--op", default=None)
def hosts(op: str | None) -> None:
    """List discovered hosts."""
    store, _ = _open_store(op)
    try:
        rows = store.get_hosts()
    finally:
        store.close()

    if not rows:
        _console.print("[dim]no hosts[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("IP")
    t.add_column("Hostname")
    t.add_column("OS")
    t.add_column("Open Ports")
    t.add_column("Notes")

    for r in rows:
        ports = json.loads(r["open_ports"]) if r.get("open_ports") else []
        t.add_row(
            r.get("ip", ""),
            r.get("hostname", ""),
            r.get("os", ""),
            ", ".join(ports[:8]),
            r.get("notes", ""),
        )
    _console.print(t)


@cli.command()
@click.option("--op", default=None)
def surfaces(op: str | None) -> None:
    """List attack surfaces."""
    store, _ = _open_store(op)
    try:
        rows = store.get_surfaces()
    finally:
        store.close()

    if not rows:
        _console.print("[dim]no surfaces[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Host")
    t.add_column("Service", width=10)
    t.add_column("Port", width=6)
    t.add_column("Fingerprint")
    t.add_column("Status", width=10)

    for r in rows:
        t.add_row(
            r.get("host", ""),
            r.get("service", ""),
            str(r.get("port") or ""),
            r.get("fingerprint", ""),
            r.get("status", ""),
        )
    _console.print(t)


@cli.command()
@click.option("--op", default=None)
def beacons(op: str | None) -> None:
    """List C2 beacons."""
    store, _ = _open_store(op)
    try:
        rows = store.get_beacons()
    finally:
        store.close()

    if not rows:
        _console.print("[dim]no beacons[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("ID")
    t.add_column("Host")
    t.add_column("IP")
    t.add_column("User")
    t.add_column("OS")
    t.add_column("Arch", width=6)
    t.add_column("Last Seen")

    for r in rows:
        t.add_row(
            r.get("beacon_id", ""),
            r.get("host", ""),
            r.get("ip", ""),
            r.get("user", ""),
            r.get("os", ""),
            r.get("arch", ""),
            r.get("last_seen", ""),
        )
    _console.print(t)


@cli.command()
@click.option("--op", default=None)
def facts(op: str | None) -> None:
    """List confirmed operational facts."""
    store, _ = _open_store(op)
    try:
        rows = store.get_facts()
    finally:
        store.close()

    if not rows:
        _console.print("[dim]no facts[/dim]")
        return

    for r in rows:
        scope = f"  [dim][{r['scope']}][/dim]" if r.get("scope") else ""
        _console.print(f"  {r.get('statement', '')}{scope}")
        if r.get("evidence"):
            _console.print(f"    [dim]evidence: {r['evidence'][:80]}[/dim]")


@cli.command()
@click.option("--op", default=None)
@click.option("--op-only", is_flag=True, default=False, help="Show only op-tagged activities")
@click.option("--limit", default=50, show_default=True, help="Max rows to show")
def activities(op: str | None, op_only: bool, limit: int) -> None:
    """List logged activities."""
    store, _ = _open_store(op)
    try:
        rows = store.get_activities()
    finally:
        store.close()

    if op_only:
        rows = [r for r in rows if r.get("ioc_type") == "op"]
    rows = rows[-limit:]  # most recent N

    if not rows:
        _console.print("[dim]no activities[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Time", width=16)
    t.add_column("Tag", width=7)
    t.add_column("Host", width=14)
    t.add_column("User", width=12)
    t.add_column("Command")

    for r in rows:
        tag = r.get("ioc_type", "")
        color = "green" if tag == "op" else "dim"
        ts = (r.get("timestamp") or "")[:16]
        t.add_row(
            ts,
            f"[{color}]{tag}[/{color}]",
            r.get("execution_host", ""),
            r.get("user_context", ""),
            (r.get("command_action") or r.get("command", ""))[:80],
        )
    _console.print(t)
    _console.print(f"[dim]showing {len(rows)} of {limit} max — use --op-only to filter[/dim]")


# ── Frontier ──────────────────────────────────────────────────────────────────

@cli.group()
def frontier() -> None:
    """View or override the kill-chain frontier."""


@frontier.command("show")
@click.option("--op", default=None)
def frontier_show(op: str | None) -> None:
    """Show current frontier level."""
    store, op_name = _open_store(op)
    try:
        state = store.load_state()
    finally:
        store.close()
    _console.print(f"[bold]{op_name}[/bold] frontier: [cyan]{state.frontier}[/cyan]")


@frontier.command("set")
@click.argument("level", type=click.Choice(_FRONTIER_LEVELS))
@click.option("--op", default=None)
def frontier_set(level: str, op: str | None) -> None:
    """Manually override the frontier level."""
    store, op_name = _open_store(op)
    try:
        state = store.load_state()
        state.frontier = level
        store.save_cursors(state.log_cursors)
        # Persist frontier in meta
        store._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('frontier', ?)", (level,)
        )
        store._conn.commit()
    finally:
        store.close()
    _console.print(f"[bold]{op_name}[/bold] frontier → [cyan]{level}[/cyan]")


# ── Config / provider / key / scope / analyst / persona ───────────────────────
# Delegate to the existing stateless handlers in ui/commands.py

def _dispatch_tui_command(text: str) -> None:
    sys.path.insert(0, str(_PROJECT_DIR))
    from ui.commands import dispatch
    result = dispatch(text)
    if result is None:
        _console.print(f"[dim](no output for '{text}')[/dim]")
        return
    lines, _ = result
    _print_lines(lines)


@cli.group()
def config() -> None:
    """View or change configuration settings."""


@config.command("list")
@click.argument("group", default="")
def config_list(group: str) -> None:
    """List all settings."""
    _dispatch_tui_command(f"/config list {group}".strip())


@config.command("get")
@click.argument("key")
def config_get(key: str) -> None:
    """Show one setting's value."""
    _dispatch_tui_command(f"/config get {key}")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Change a setting."""
    _dispatch_tui_command(f"/config set {key} {value}")


@config.command("reset")
@click.argument("key")
def config_reset(key: str) -> None:
    """Reset a setting to its default."""
    _dispatch_tui_command(f"/config reset {key}")


@cli.group()
def provider() -> None:
    """Switch provider or manage models."""


@provider.command("list")
def provider_list() -> None:
    _dispatch_tui_command("/provider list")


@provider.command("set")
@click.argument("name")
def provider_set(name: str) -> None:
    _dispatch_tui_command(f"/provider set {name}")


@provider.group("model")
def provider_model() -> None:
    """Manage models for the active provider."""


@provider_model.command("list")
@click.argument("provider_name", default="")
def model_list(provider_name: str) -> None:
    _dispatch_tui_command(f"/provider model list {provider_name}".strip())


@provider_model.command("set")
@click.argument("model_id")
def model_set(model_id: str) -> None:
    _dispatch_tui_command(f"/provider model set {model_id}")


@cli.group()
def key() -> None:
    """Manage API keys (stored in system keychain)."""


@key.command("list")
def key_list() -> None:
    _dispatch_tui_command("/key list")


@key.command("set")
@click.argument("provider_name")
@click.argument("api_key")
def key_set(provider_name: str, api_key: str) -> None:
    _dispatch_tui_command(f"/key set {provider_name} {api_key}")


@key.command("clear")
@click.argument("provider_name", default="")
def key_clear(provider_name: str) -> None:
    _dispatch_tui_command(f"/key clear {provider_name}".strip())


@cli.group()
def scope() -> None:
    """Engagement scope — aids IOC tagging."""


@scope.command("list")
def scope_list() -> None:
    _dispatch_tui_command("/scope list")


@scope.command("add")
@click.argument("target")
def scope_add(target: str) -> None:
    _dispatch_tui_command(f"/scope add {target}")


@scope.command("remove")
@click.argument("target")
def scope_remove(target: str) -> None:
    _dispatch_tui_command(f"/scope remove {target}")


@cli.group()
def analyst() -> None:
    """Tune the background analyst."""


@analyst.command("interval")
@click.argument("seconds", type=int)
def analyst_interval(seconds: int) -> None:
    _dispatch_tui_command(f"/analyst interval {seconds}")


@analyst.command("debounce")
@click.argument("seconds", type=int)
def analyst_debounce(seconds: int) -> None:
    _dispatch_tui_command(f"/analyst debounce {seconds}")


@analyst.command("debug")
@click.argument("state", type=click.Choice(("on", "off")))
def analyst_debug(state: str) -> None:
    _dispatch_tui_command(f"/analyst debug {state}")


@cli.group()
def persona() -> None:
    """Switch the analyst persona."""


@persona.command("show")
def persona_show() -> None:
    _dispatch_tui_command("/persona show")


@persona.command("set")
@click.argument("name", type=click.Choice(("redteam", "pentest", "ctf")))
def persona_set(name: str) -> None:
    _dispatch_tui_command(f"/persona set {name}")


@cli.command()
def info() -> None:
    """Show op configuration, provider, keys, analyst state."""
    _dispatch_tui_command("/info")


# ── AI chat (requires daemon) ─────────────────────────────────────────────────

@cli.command()
@click.argument("message", nargs=-1, required=True)
@click.option("--op", default=None)
def ai(message: tuple[str, ...], op: str | None) -> None:
    """Chat with the analyst AI (daemon must be running)."""
    op = op or _active_op()
    if not op:
        raise click.ClickException("no active op — run: saddle start --op <name>")
    if not _daemon_running(op):
        raise click.ClickException(f"daemon not running for '{op}' — run: saddle start --op {op}")
    try:
        resp = _socket_request(op, {"type": "chat", "message": " ".join(message)})
        _console.print(resp.get("text", ""))
    except Exception as e:
        raise click.ClickException(str(e))


# ── Export ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--op", default=None)
def export(op: str | None) -> None:
    """Export IOC activities + beacons to xlsx."""
    sys.path.insert(0, str(_PROJECT_DIR))
    from core import config
    from core.analyst import Analyst
    from core.engagement_state import EngagementState

    store, op_name = _open_store(op)
    try:
        state = store.load_state()
        analyst_obj = Analyst(
            state=state,
            on_activity=lambda m: None,
            on_state_update=lambda s: None,
            store=store,
        )
        path = analyst_obj.export_ioc()
        _console.print(f"[green]Exported:[/green] {path}")
    finally:
        store.close()


# ── Op management ─────────────────────────────────────────────────────────────

@cli.command("ops")
def list_ops() -> None:
    """List all saved operations."""
    sys.path.insert(0, str(_PROJECT_DIR))
    from core.config import _SS_BASE
    ops = sorted(p.name for p in _SS_BASE.iterdir()
                 if p.is_dir() and (p / "engagement.db").exists())
    if not ops:
        _console.print("[dim]no saved ops[/dim]")
        return
    active = _active_op()
    for name in ops:
        marker = " [yellow]← active[/yellow]" if name == active else ""
        _console.print(f"  {name}{marker}")


if __name__ == "__main__":
    cli()
