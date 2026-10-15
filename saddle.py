#!/usr/bin/env python3
"""saddle — SideSaddle shell-native CLI."""
from __future__ import annotations
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import click

_SS_BASE = Path.home() / ".local" / "share" / "sidesaddle"
_SESSIONS_DIR = _SS_BASE / "sessions"
_ACTIVE_LOG_DIR_FILE = _SS_BASE / ".active_log_dir"
_PROJECT_DIR = Path(__file__).parent


def _active_op() -> str | None:
    if _ACTIVE_LOG_DIR_FILE.exists():
        log_dir_text = _ACTIVE_LOG_DIR_FILE.read_text().strip()
        if log_dir_text:
            # log_dir = <op_dir>/logs  →  op_dir = parent
            return Path(log_dir_text).parent.name
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


@click.group()
def cli() -> None:
    """SideSaddle shell-native CLI."""


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
        click.echo(f"saddle: daemon already running for '{op}'")
        return

    # Resolve passphrase
    env_pw = os.environ.get("SIDESADDLE_PASSPHRASE", "").strip()
    if env_pw:
        passphrase, was_prompted = env_pw, False
        os.environ.pop("SIDESADDLE_PASSPHRASE", None)
    else:
        passphrase, was_prompted = resolve_passphrase(op, force_prompt=False)

    # Validate before spawning daemon
    db_path = config.op_dir() / "engagement.db"
    try:
        store = EngagementStore(db_path, passphrase)
        store.close()
    except BadPassphrase:
        click.echo("Error: incorrect passphrase.", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error opening DB: {e}", err=True)
        sys.exit(1)

    if was_prompted:
        cache_passphrase(op, passphrase)

    # Register calling shell
    _register_pid(os.getppid())

    # Spawn daemon (detached)
    daemon_env = {
        **os.environ,
        "SIDESADDLE_PASSPHRASE": passphrase,
        "PYTHONPATH": str(_PROJECT_DIR),
    }
    subprocess.Popen(
        [sys.executable, "-m", "core.daemon", "--op", op],
        start_new_session=True,
        env=daemon_env,
        cwd=str(_PROJECT_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait up to 15s for socket
    for _ in range(30):
        if _daemon_running(op):
            click.echo(f"saddle: started op '{op}'")
            return
        time.sleep(0.5)
    click.echo("saddle: daemon started (socket not yet ready)", err=True)


@cli.command()
@click.option("--op", default=None, help="Op name (default: active op)")
def stop(op: str | None) -> None:
    """Stop the daemon for the active op."""
    op = op or _active_op()
    if not op:
        click.echo("saddle: no active op", err=True)
        sys.exit(1)
    _unregister_pid(os.getppid())
    if _daemon_running(op):
        try:
            _socket_request(op, {"type": "stop"}, timeout=5.0)
        except Exception:
            pass
    click.echo(f"saddle: stopped op '{op}'")


@cli.command()
@click.argument("pid", type=int)
def register(pid: int) -> None:
    """Register a shell PID with the active daemon (called by shell hooks)."""
    _register_pid(pid)


@cli.command()
@click.argument("pid", type=int)
def unregister(pid: int) -> None:
    """Unregister a shell PID from the daemon (called by shell EXIT trap)."""
    _unregister_pid(pid)


@cli.command()
@click.argument("message", nargs=-1, required=True)
@click.option("--op", default=None, help="Op name (default: active op)")
def ai(message: tuple[str, ...], op: str | None) -> None:
    """Chat with the analyst AI daemon."""
    op = op or _active_op()
    if not op:
        click.echo("saddle: no active op (run: saddle start --op <name>)", err=True)
        sys.exit(1)
    if not _daemon_running(op):
        click.echo(f"saddle: daemon not running for '{op}' (run: saddle start --op {op})", err=True)
        sys.exit(1)
    try:
        resp = _socket_request(op, {"type": "chat", "message": " ".join(message)})
        if resp.get("type") == "reply":
            click.echo(resp.get("text", ""))
        else:
            click.echo(f"saddle: unexpected response: {resp}", err=True)
    except Exception as e:
        click.echo(f"saddle: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--op", default=None, help="Op name (default: active op)")
@click.option("--clear", "clear_badge", is_flag=True, default=False,
              help="Clear the current badge after displaying")
def status(op: str | None, clear_badge: bool) -> None:
    """Show daemon status and current badge."""
    op = op or _active_op()
    if not op:
        click.echo("saddle: no active op")
        return
    if not _daemon_running(op):
        click.echo(f"saddle: daemon not running for '{op}'")
        return
    try:
        resp = _socket_request(op, {"type": "status"}, timeout=5.0)
        click.echo(f"op:       {resp.get('op', op)}")
        click.echo(f"frontier: {resp.get('frontier', '?')}")
        badge = resp.get("badge")
        if badge:
            click.echo(f"badge:    [{badge}] ({resp.get('badge_type', '?')})")
        if clear_badge:
            _socket_request(op, {"type": "clear_badge"}, timeout=5.0)
    except Exception as e:
        click.echo(f"saddle: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
