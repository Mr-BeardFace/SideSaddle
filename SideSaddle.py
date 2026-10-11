#!/usr/bin/env python3
"""
SideSaddle — Red Team Operator Companion
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from core import config
from core.analyst import Analyst
from core.auth import cache_passphrase, expiry_warning, resolve_passphrase
from core.engagement_state import EngagementState
from core.log_watcher import LogWatcher
from core.store import EngagementStore, BadPassphrase


@click.group(invoke_without_command=True)
@click.option("--op", default=None, help="Op name; prompted if omitted")
@click.option("--c2", is_flag=True, default=False, help="Enable C2 polling on start")
@click.option("--passphrase", is_flag=True, default=False,
              help="Prompt for passphrase (forces re-entry and renews 72h cache)")
@click.pass_context
def cli(ctx: click.Context, op: str | None, c2: bool, passphrase: bool) -> None:
    """SideSaddle — Red Team Operator Companion

    Run without a subcommand to start a live operation.
    """
    if ctx.invoked_subcommand is not None:
        return  # subcommand handles everything

    # ── Op name ───────────────────────────────────────────────────────────────
    if op:
        config.set_value("op.name", op)
    else:
        name = click.prompt("Op name", default=config.op_name())
        config.set_value("op.name", name)

    op_name = config.op_name()

    # ── Load or create engagement state ──────────────────────────────────────
    state_path = config.op_dir() / "session_state.json"
    state = EngagementState.load(state_path) if state_path.exists() else EngagementState(op_name=op_name)

    # ── Passphrase resolution ─────────────────────────────────────────────────
    # Order: SIDESADDLE_PASSPHRASE env var → keyring cache (72h) → interactive prompt
    env_pw = os.environ.get("SIDESADDLE_PASSPHRASE", "").strip()
    store: EngagementStore | None = None
    pw_warning: str | None = None

    if env_pw:
        pw, was_prompted = env_pw, False
    else:
        pw, was_prompted = resolve_passphrase(op_name, force_prompt=passphrase)

    if pw:
        db_path = config.op_dir() / "engagement.db"

        # New engagement: confirm to avoid typo footgun
        if not db_path.exists():
            if not click.confirm(f"Create new engagement '{op_name}'?", default=True):
                click.echo("Aborted.")
                sys.exit(0)

        try:
            store = EngagementStore(db_path, pw)
        except BadPassphrase:
            click.echo("Error: incorrect passphrase.", err=True)
            sys.exit(1)

        # Cache only after successful open — wrong passphrase is never stored
        if was_prompted and not env_pw:
            cache_passphrase(op_name, pw)

        # Startup status
        summary = store.summary()
        if summary["chunks"] > 0:
            last = store.get_last_cycles(1)
            last_ts = last[-1]["ts"] if last else "unknown"
            click.echo(f"Resuming: {op_name}  ({summary['chunks']} chunks, {summary['leads']} leads, last active: {last_ts})")
        else:
            click.echo(f"New engagement: {op_name}")

        # Expiry warning (CLI) — only relevant when using cached passphrase
        if not was_prompted and not env_pw:
            pw_warning = expiry_warning(op_name)
            if pw_warning:
                click.echo(f"[!] {pw_warning}")
    else:
        click.echo("No passphrase — running without DB (use --passphrase to enable)")

    analyst = Analyst(
        state=state,
        on_activity=lambda m: None,
        on_state_update=lambda s: None,
        store=store,
    )
    log_watcher = LogWatcher(on_new_content=analyst.queue_new_content)

    from ui.app import SideSaddleApp
    app = SideSaddleApp(state=state, analyst=analyst, log_watcher=log_watcher,
                        passphrase_warning=pw_warning)

    if c2:
        from core.c2.nighthawk import NighthawkC2
        NighthawkC2(config.op_dir(), on_activity=lambda m: None)

    app.run()


@cli.command()
@click.argument("op_name")
@click.option("--passphrase", is_flag=True, default=False,
              help="Prompt for passphrase (forces re-entry)")
def review(op_name: str, passphrase: bool) -> None:
    """Load a previous op in read-only mode (browse state + export IOC)."""
    bases = [Path.home() / ".local" / "share" / "sidesaddle"]
    wd = config.get("op.working_directory", "")
    if wd:
        bases.append(Path(wd).expanduser())

    op_dir_path = next((b / op_name for b in bases if (b / op_name).exists()), None)
    if not op_dir_path:
        click.echo(f"No saved state found for op '{op_name}'. Use `list` to see available ops.")
        sys.exit(1)

    db_path = op_dir_path / "engagement.db"
    state_path = op_dir_path / "session_state.json"

    store: EngagementStore | None = None
    if db_path.exists():
        env_pw = os.environ.get("SIDESADDLE_PASSPHRASE", "").strip()
        pw = env_pw if env_pw else resolve_passphrase(op_name, force_prompt=passphrase)[0]
        try:
            store = EngagementStore(db_path, pw)
        except BadPassphrase:
            click.echo("Error: incorrect passphrase.", err=True)
            sys.exit(1)

    state = EngagementState.load(state_path) if state_path.exists() else EngagementState(op_name=op_name)
    click.echo(f"Loading op '{op_name}' in read-only mode")

    analyst = Analyst(state=state, on_activity=lambda m: None, on_state_update=lambda s: None, store=store)
    log_watcher = LogWatcher(on_new_content=lambda p, d: None)

    from ui.app import SideSaddleApp
    app = SideSaddleApp(state=state, analyst=analyst, log_watcher=log_watcher, read_only=True)
    app.run()


@cli.command("list")
def list_ops() -> None:
    """List all saved operations."""
    import datetime
    bases = [Path.home() / ".local" / "share" / "sidesaddle"]
    wd = config.get("op.working_directory", "")
    if wd:
        bases.append(Path(wd).expanduser())
    found = False
    seen: set[str] = set()
    for base in bases:
        if not base.exists():
            continue
        for d in sorted(base.iterdir()):
            if not d.is_dir() or d.name in seen:
                continue
            seen.add(d.name)
            db = d / "engagement.db"
            json_state = d / "session_state.json"
            if db.exists():
                mtime = datetime.datetime.fromtimestamp(db.stat().st_mtime)
                click.echo(f"  {d.name:30s}  last active: {mtime.strftime('%Y-%m-%d %H:%M')}")
                found = True
            elif json_state.exists():
                state = EngagementState.load(json_state)
                click.echo(
                    f"  {d.name:30s}  [legacy] beacons={len(state.beacons)}  "
                    f"hosts={len(state.hosts)}  creds={len(state.credentials)}  "
                    f"last={state.last_analysis.strftime('%Y-%m-%d %H:%M') if state.last_analysis else 'never'}"
                )
                found = True
    if not found:
        click.echo("No saved ops found.")


@cli.command()
def login() -> None:
    """Authenticate with Claude subscription (anthropic-sub provider)."""
    from core.llm_client import sub_login_url, sub_login_exchange, _SUB_CLIENT_ID

    if not _SUB_CLIENT_ID:
        click.echo(
            "No CLIENT_ID found.\n"
            "Create ~/.config/sidesaddle/providers_local.py with:\n\n"
            "    CLIENT_ID = 'your-client-id'\n\n"
            "    def register(api):\n"
            "        api.set_sub_client_id(CLIENT_ID)\n\n"
            "Or if pdtmj-ai is set up, its providers_local.py will be used automatically."
        )
        return

    url, verifier = sub_login_url()
    click.echo(f"\nOpen this URL in your browser:\n\n  {url}\n")
    click.echo("After authorizing, you'll be redirected to a page with a code in the URL.")
    code_state = click.prompt("Paste the code#state value from the redirect URL")
    try:
        msg = sub_login_exchange(code_state.strip(), verifier)
        click.echo(f"\n{msg}")
    except Exception as e:
        click.echo(f"\nLogin failed: {e}")


@cli.command("key")
@click.argument("action", type=click.Choice(["set", "get"]))
@click.argument("provider")
def key_cmd(action: str, provider: str) -> None:
    """Set or display an API key."""
    if action == "set":
        value = click.prompt(f"Enter key for {provider}", hide_input=True)
        config.set_api_key(provider, value)
        click.echo(f"Key saved for {provider}")
    elif action == "get":
        k = config.get_api_key(provider)
        if k:
            masked = k[:4] + "*" * max(0, len(k) - 8) + k[-4:] if len(k) > 8 else "****"
            click.echo(f"{provider}: {masked}")
        else:
            click.echo(f"No key found for {provider}")


@cli.command()
def install() -> None:
    """Print setup instructions."""
    here = Path(__file__).parent
    click.echo(f"Run: bash {here}/install.sh")


if __name__ == "__main__":
    cli()
