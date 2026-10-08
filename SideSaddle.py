"""SideSaddle — red team op logger and tactical advisor.

TUI mode (default):   python3 SideSaddle.py
Batch mode:           python3 SideSaddle.py --analyze [--log-dir <path>] [--output-dir <path>]
Subscribe login:      python3 SideSaddle.py --login
"""
from __future__ import annotations
import argparse
import os
import sys
from collections import deque
from datetime import datetime
from pathlib import Path

from rich.markup import escape
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Input, RichLog, Static, Checkbox, Select, TextArea

from core.llm_client import (
    cfg, resolve_key, LLMClient,
    load_sub_token, sub_login_url, sub_login_exchange,
)
from core.log_watcher import LogWatcher
from core.analyst import Analyst
from core.c2_client import C2Client
from core.preprocessor import preprocess
import core.commands as commands
from core.commands import resolve_op


# ── Chat input widget ─────────────────────────────────────────────────────────

class ChatInput(TextArea):
    """TextArea where Enter submits and Shift+Enter inserts a newline."""

    class Submit(Message):
        def __init__(self, text: str) -> None:
            self.text = text; super().__init__()

    def _on_key(self, event: events.Key) -> None:
        if event.key == "enter":
            event.prevent_default()
            text = self.text.strip()
            if text:
                self.post_message(ChatInput.Submit(text))
                self.load_text("")
        elif event.key == "tab":
            event.prevent_default()
            suggestion = commands.best_suggestion(self.text.strip())
            if suggestion:
                self.load_text(suggestion)
                self.action_cursor_line_end()
        else:
            super()._on_key(event)


# ── Advisory modal ───────────────────────────────────────────────────────────

class AdvisoryScreen(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, entries: list[tuple[str, str]]) -> None:
        self._entries = entries
        super().__init__()

    def compose(self) -> ComposeResult:
        with Vertical(id="adv-modal"):
            yield Static("[bold #58a6ff]⬡  Op Intelligence[/bold #58a6ff]", id="adv-title", markup=True)
            yield RichLog(id="adv-log", markup=True, highlight=False, wrap=True, auto_scroll=False)
            yield Static("[dim]ESC  close[/dim]", id="adv-footer", markup=True)

    def on_mount(self) -> None:
        log = self.query_one("#adv-log", RichLog)
        if not self._entries:
            log.write("[dim]No analysis results yet.[/dim]")
            return
        for i, (ts, text) in enumerate(reversed(self._entries)):
            if i > 0:
                log.write(f"[dim]{'─' * 60}[/dim]")
            log.write(f"[dim][{ts}][/dim]")
            for line in text.splitlines():
                s = line.strip()
                if not s:
                    continue
                if s.startswith("[OPSEC]"):
                    log.write(f"[bold red]{escape(s)}[/bold red]")
                elif s.startswith("[TACTICAL]"):
                    log.write(f"[cyan]{escape(s)}[/cyan]")
                elif s.startswith("[STATE]"):
                    log.write(f"[blue]{escape(s)}[/blue]")
                else:
                    log.write(f"[dim]{escape(s)}[/dim]")


# ── Date prompt modal ────────────────────────────────────────────────────────

class DatePromptScreen(ModalScreen):
    """Ask for an optional start date before building the IOC log."""
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, last_ioc_time: "datetime | None" = None) -> None:
        self._last = last_ioc_time
        super().__init__()

    def compose(self) -> ComposeResult:
        with Vertical(id="date-modal"):
            yield Static("[bold #58a6ff]Build IOC Log[/bold #58a6ff]", markup=True)
            if self._last:
                desc = (f"[dim]Last run: {self._last.strftime('%Y-%m-%d %H:%M')} — "
                        f"blank = since then · 'all' = full re-run[/dim]")
                ph = "YYYY-MM-DD, 'all', or blank (since last run)"
            else:
                desc = "[dim]Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM) — blank = all logs[/dim]"
                ph = "e.g. 2025-09-28  or  blank for everything"
            yield Static(desc, markup=True)
            yield Input(placeholder=ph, id="date-input")
            yield Static("[dim]Enter  confirm · ESC  cancel[/dim]", markup=True)

    def on_mount(self) -> None:
        self.query_one("#date-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        if raw.lower() == "all":
            self.dismiss((None, True))   # force full run
            return
        if not raw:
            self.dismiss((None, False))  # use default (last_ioc_time or all)
            return
        for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                self.dismiss((datetime.strptime(raw, fmt), False))
                return
            except ValueError:
                continue
        self.query_one("#date-input", Input).border_title = "Invalid date"


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
Screen {
    background: #0d1117;
    color: #e6edf3;
    layout: vertical;
}

#status-bar {
    height: 1;
    background: #161b22;
    color: #58a6ff;
    text-style: bold;
    padding: 0 1;
}

#toolbar {
    height: 3;
    background: #161b22;
    padding: 0 1;
    align: left middle;
    border-bottom: solid #30363d;
}

#brand {
    color: #58a6ff;
    text-style: bold;
    width: auto;
    padding: 0 2 0 0;
}

Checkbox {
    background: #161b22;
    border: none;
    width: auto;
    color: #3fb950;
    padding: 0 1;
}

#verb-select {
    width: 16;
    height: 1;
    margin: 0 1;
    border: none;
    padding: 0;
}

#verb-select SelectCurrent {
    border: none;
    padding: 0 1;
    height: 1;
}

Button {
    width: auto;
    min-width: 14;
    height: 1;
    border: none;
    margin: 0 1;
}

#btn-analyze {
    background: #1f6feb;
    color: white;
}

#btn-analyze:hover {
    background: #388bfd;
}

#btn-intel {
    background: #388bfd;
    color: white;
}

#btn-intel:hover {
    background: #58a6ff;
}

#btn-export {
    background: #21262d;
    color: #e6edf3;
}

#btn-export:hover {
    background: #30363d;
}

#btn-copy {
    background: #21262d;
    color: #e6edf3;
}

#btn-copy:hover {
    background: #30363d;
}

#intel-panel {
    height: 7;
    background: #0d1117;
    border: none;
    border-bottom: solid #1f6feb;
    scrollbar-color: #30363d #0d1117;
    padding: 0 1;
}

#activity-log {
    height: 1fr;
    background: #0d1117;
    border: none;
    scrollbar-color: #30363d #0d1117;
    padding: 0 1 0 1;
}

TextArea {
    height: 4;
    background: #0d1117;
    border: tall #30363d;
    border-top: tall #58a6ff;
    color: #e6edf3;
    padding: 0 1;
}

TextArea:focus {
    border: tall #58a6ff;
}

TextArea .text-area--cursor {
    background: #58a6ff;
    color: #0d1117;
}

AdvisoryScreen {
    align: center middle;
}

#adv-modal {
    width: 82%;
    height: 82%;
    background: #161b22;
    border: double #1f6feb;
    padding: 0;
}

#adv-title {
    height: 1;
    padding: 0 2;
    background: #0d1117;
    border-bottom: solid #30363d;
    text-align: center;
}

#adv-log {
    height: 1fr;
    background: #161b22;
    padding: 0 1;
}

#adv-footer {
    height: 1;
    padding: 0 2;
    background: #0d1117;
    border-top: solid #30363d;
    text-align: center;
}

#date-modal {
    width: 60;
    height: auto;
    background: #161b22;
    border: solid #30363d;
    padding: 1 2;
}

#date-modal Static {
    margin-bottom: 1;
}

#date-input {
    margin-bottom: 1;
}
"""


# ── App ───────────────────────────────────────────────────────────────────────

class SideSaddleApp(App[None]):
    CSS   = _CSS
    TITLE = "SideSaddle"

    def __init__(self, env_warnings: list[str] | None = None,
                 c2_client: "C2Client | None" = None) -> None:
        self._env_warnings = env_warnings or []
        self._c2_client    = c2_client
        super().__init__()

    BINDINGS = [
        Binding("ctrl+n",    "create_ioc",    "IOC Log",  show=True),
        Binding("ctrl+i",    "show_intel",    "History",  show=True),
        Binding("ctrl+up",   "intel_grow",    "Intel+",   show=False),
        Binding("ctrl+down", "intel_shrink",  "Intel-",   show=False),
        Binding("ctrl+e",    "export_csv",    "Export",   show=True),
        Binding("ctrl+y",    "copy_log",      "Copy Log", show=True),
        Binding("ctrl+c",    "request_quit",  "Quit",     show=True),
    ]

    # ── Messages ──────────────────────────────────────────────────────────────

    class Advisory(Message):
        def __init__(self, text: str) -> None:
            self.text = text; super().__init__()

    class Response(Message):
        def __init__(self, text: str) -> None:
            self.text = text; super().__init__()

    class Status(Message):
        def __init__(self, text: str) -> None:
            self.text = text; super().__init__()

    class Error(Message):
        def __init__(self, text: str) -> None:
            self.text = text; super().__init__()

    class NewLog(Message):
        def __init__(self, text: str) -> None:
            self.text = text; super().__init__()

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Static("⬡ SideSaddle", id="status-bar")
        yield Horizontal(
            Static("⬡ SideSaddle", id="brand"),
            Checkbox("AUTO", value=bool(cfg("auto_analysis", True)), id="auto-check"),
            Select(
                [("brief", "brief"), ("verbose", "verbose")],
                value=str(cfg("verbosity", "brief")),
                id="verb-select",
                allow_blank=False,
            ),
            Button("IOC Log", id="btn-analyze"),
            Button("Intel",       id="btn-intel"),
            Button("Export CSV",  id="btn-export"),
            Button("Copy Log",    id="btn-copy"),
            id="toolbar",
        )
        yield RichLog(
            id="intel-panel",
            markup=True, highlight=False,
            wrap=True, auto_scroll=False,
            max_lines=500,
        )
        yield RichLog(
            id="activity-log",
            markup=True, highlight=False,
            wrap=True, auto_scroll=True,
            max_lines=5000,
        )
        yield ChatInput(id="cmd-input", language=None, show_line_numbers=False)

    def on_mount(self) -> None:
        self._log_buf: deque[str] = deque(maxlen=5000)
        self._cmd_history: list[str] = []
        self._hist_idx: int = 0
        self._advisory_entries: list[tuple[str, str]] = []
        self._intel_height: int = 7
        self._syncing: bool = False
        self.query_one("#intel-panel", RichLog).write("[dim]No analysis yet[/dim]")

        self.query_one("#cmd-input", ChatInput).focus()

        try:
            llm = LLMClient()

            # Op is guaranteed by main() — resolve_op() will always return a value here
            op, log_dir_path, output_dir_path = resolve_op()
            log_dir_path.mkdir(parents=True, exist_ok=True)
            output_dir_path.mkdir(parents=True, exist_ok=True)
            self._log_dir_path = log_dir_path
            self._ioc_acc_path = log_dir_path / "ioc_acc.log"
            self._analyst = Analyst(
                llm,
                output_dir=str(output_dir_path),
                log_dir=str(log_dir_path),
                on_advisory=lambda t: self.post_message(SideSaddleApp.Advisory(t)),
                on_response=lambda t: self.post_message(SideSaddleApp.Response(t)),
                on_status=lambda s: self.post_message(SideSaddleApp.Status(s)),
                on_error=lambda e: self.post_message(SideSaddleApp.Error(e)),
                c2_client=self._c2_client,
            )
            self._watcher = LogWatcher(
                log_dir=str(log_dir_path),
                callback=lambda text: self.post_message(SideSaddleApp.NewLog(text)),
                glob=cfg("log_glob", "raw_*.log"),
            )
            self._watcher.start()
            self._write(f"[dim]Op: [bold]{op}[/bold]  Watching {log_dir_path}[/dim]  Enter submits · Shift+Enter newline")

            resumed = self._analyst.load_session()
            if resumed:
                self._write(f"[green]{escape(resumed)}[/green]")

            for w in self._env_warnings:
                self._write(f"[bold yellow][WARN][/bold yellow] [yellow]{escape(w)}[/yellow]")
            if self._c2_client:
                self._write(f"[dim]C2 backend: {escape(self._c2_client._url)}  (push not yet implemented)[/dim]")
            if not _has_auth():
                self._write("[red]No credentials.[/red] Run [bold]--login[/bold] or set [bold]ANTHROPIC_API_KEY[/bold].")
        except Exception as e:
            self._write(f"[bold red][ERR][/bold red] [red]{escape(str(e))}[/red]")

    def on_unmount(self) -> None:
        if hasattr(self, "_watcher"):
            self._watcher.stop()
        self._save_session_silent()

    def _save_session_silent(self) -> None:
        if not hasattr(self, "_analyst"):
            return
        try:
            path = self._analyst.save_session()
            if path:
                self._analyst.export_csv()
        except Exception:
            pass

    # ── Message handlers ──────────────────────────────────────────────────────

    def on_side_saddle_app_advisory(self, event: Advisory) -> None:
        ts = self._ts()
        self._advisory_entries.append((ts, event.text))
        panel = self.query_one("#intel-panel", RichLog)
        panel.clear()
        panel.write(f"[dim][{ts}][/dim]")
        for line in event.text.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("[OPSEC]"):
                panel.write(f"[bold red]{escape(s)}[/bold red]")
            elif s.startswith("[TACTICAL]"):
                panel.write(f"[cyan]{escape(s)}[/cyan]")
            elif s.startswith("[STATE]"):
                panel.write(f"[blue]{escape(s)}[/blue]")
            else:
                panel.write(f"[dim]{escape(s)}[/dim]")

    def on_side_saddle_app_response(self, event: Response) -> None:
        log = self.query_one("#activity-log", RichLog)
        ts = self._ts()
        log.write(f"[dim]\\[{ts}][/dim] [bold #9cdcfe]\\[AI][/bold #9cdcfe]")
        log.write(escape(event.text))
        self._log_buf.append(f"[{ts}] [AI]")
        self._log_buf.append(event.text)

    def on_side_saddle_app_status(self, event: Status) -> None:
        self.query_one("#status-bar", Static).update(
            f"[bold #58a6ff]⬡ SideSaddle[/bold #58a6ff]  [dim]{escape(event.text)}[/dim]"
        )

    def on_side_saddle_app_error(self, event: Error) -> None:
        self._write(f"[bold red]\\[ERR][/bold red] [red]{escape(event.text)}[/red]")

    def on_side_saddle_app_new_log(self, event: NewLog) -> None:
        ioc_chunk, session_chunk = preprocess(
            event.text,
            ioc_body_lines=cfg("ioc_output_lines", 20),
        )
        if ioc_chunk.strip() and hasattr(self, "_ioc_acc_path"):
            try:
                with open(self._ioc_acc_path, "a", encoding="utf-8") as f:
                    f.write(ioc_chunk)
            except OSError:
                pass
        lines = session_chunk.count("\n") + 1
        self.query_one("#status-bar", Static).update(
            f"[bold #58a6ff]⬡ SideSaddle[/bold #58a6ff]  "
            f"[dim]New log content ({lines} lines) — queued for analysis[/dim]"
        )
        if hasattr(self, "_analyst"):
            self._analyst.add_raw(session_chunk)

    # ── Widget events ─────────────────────────────────────────────────────────

    def on_chat_input_submit(self, event: ChatInput.Submit) -> None:
        self._submit(event.text)

    def on_key(self, event: events.Key) -> None:
        inp = self.query_one("#cmd-input", ChatInput)
        if self.focused is not inp or not self._cmd_history:
            return
        if event.key == "up" and inp.cursor_location[0] == 0:
            event.prevent_default()
            self._hist_idx = max(0, self._hist_idx - 1)
            inp.load_text(self._cmd_history[self._hist_idx])
        elif event.key == "down" and inp.cursor_location[0] >= inp.document.line_count - 1:
            event.prevent_default()
            self._hist_idx = min(len(self._cmd_history), self._hist_idx + 1)
            inp.load_text(
                self._cmd_history[self._hist_idx]
                if self._hist_idx < len(self._cmd_history) else ""
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-analyze": self.action_create_ioc()
        elif bid == "btn-intel":   self.action_show_intel()
        elif bid == "btn-export":  self.action_export_csv()
        elif bid == "btn-copy":    self.action_copy_log()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.control.id == "auto-check" and hasattr(self, "_analyst") and not self._syncing:
            self._analyst.auto_analysis = event.value
            self._write(f"[dim]Auto-analysis {'enabled' if event.value else 'disabled'}[/dim]")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.control.id == "verb-select" and event.value is not Select.BLANK and not self._syncing:
            if hasattr(self, "_analyst"):
                self._analyst.verbosity = str(event.value)
            self._write(f"[dim]Verbosity: {event.value}[/dim]")

    # ── Actions ───────────────────────────────────────────────────────────────

    def action_create_ioc(self) -> None:
        last = getattr(self._analyst, "_last_ioc_time", None) if hasattr(self, "_analyst") else None
        def _run(result: tuple) -> None:
            since, full = result
            if full:
                label = "all logs"
            elif since:
                label = f"from {since.strftime('%Y-%m-%d %H:%M')}"
            elif last:
                label = f"since {last.strftime('%Y-%m-%d %H:%M')}"
            else:
                label = "all logs"
            self._write(f"[dim]Building IOC log ({label})…[/dim]")
            if hasattr(self, "_analyst"):
                self._analyst.create_ioc_log(since=since, full=full)
        self.push_screen(DatePromptScreen(last_ioc_time=last), _run)

    def action_show_intel(self) -> None:
        self.push_screen(AdvisoryScreen(self._advisory_entries))

    def action_intel_grow(self) -> None:
        self._intel_height = min(self._intel_height + 3, 30)
        self.query_one("#intel-panel", RichLog).styles.height = self._intel_height

    def action_intel_shrink(self) -> None:
        self._intel_height = max(self._intel_height - 3, 3)
        self.query_one("#intel-panel", RichLog).styles.height = self._intel_height

    def action_export_csv(self) -> None:
        if not hasattr(self, "_analyst"):
            return
        try:
            bp, ap = self._analyst.export_csv()
            self._write(f"[green]Exported:[/green]\n  {bp}\n  {ap}")
        except Exception as e:
            self._write(f"[bold red]\\[ERR][/bold red] [red]{escape(str(e))}[/red]")

    def action_copy_log(self) -> None:
        path = Path("/tmp/ss_copy.txt")
        path.write_text("\n".join(self._log_buf), encoding="utf-8")
        self._write(f"[green]Log copied →[/green] [dim]{path}[/dim]")

    def action_request_quit(self) -> None:
        self._save_session_silent()
        self.exit()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _submit(self, text: str) -> None:
        if text.lower() in ("exit", "quit", "/exit", "/quit"):
            self._save_session_silent()
            self.exit()
            return

        # Slash commands
        if text.startswith("/") and hasattr(self, "_analyst"):
            result = commands.dispatch(text, self._analyst)
            if result is not None:
                for line in result.lines:
                    self._write(f"[dim]{escape(line)}[/dim]")
                if result.lines:
                    self.query_one("#activity-log", RichLog).write("")
                action = result.action
                if action == "exit":
                    self._save_session_silent()
                    self.exit()
                elif action.startswith("ioc:"):
                    rest = action[4:]
                    iso, _, full_flag = rest.rpartition(":")
                    full = full_flag == "1"
                    since = datetime.fromisoformat(iso) if iso else None
                    last = getattr(self._analyst, "_last_ioc_time", None)
                    if full:
                        label = "all logs"
                    elif since:
                        label = f"from {since.strftime('%Y-%m-%d %H:%M')}"
                    elif last:
                        label = f"since {last.strftime('%Y-%m-%d %H:%M')}"
                    else:
                        label = "all logs"
                    self._write(f"[dim]Building IOC log ({label})…[/dim]")
                    self._analyst.create_ioc_log(since=since, full=full)
                elif action == "export":
                    self.action_export_csv()
                self._sync_widgets()
                return

        if not self._cmd_history or self._cmd_history[-1] != text:
            self._cmd_history.append(text)
            if len(self._cmd_history) > 15:
                self._cmd_history = self._cmd_history[-15:]
        self._hist_idx = len(self._cmd_history)
        self._write(
            f"[bold yellow]\\[OP][/bold yellow] [yellow]{escape(text)}[/yellow]"
        )
        if hasattr(self, "_analyst"):
            self._analyst.chat(text)

    def _sync_widgets(self) -> None:
        """Push analyst live state to toolbar widgets without echoing change messages."""
        if not hasattr(self, "_analyst"):
            return
        self._syncing = True
        try:
            self.query_one("#auto-check", Checkbox).value = self._analyst.auto_analysis
            sel = self.query_one("#verb-select", Select)
            if sel.value != self._analyst.verbosity:
                sel.value = self._analyst.verbosity
        except Exception:
            pass
        finally:
            self._syncing = False

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _write(self, markup: str) -> None:
        ts = self._ts()
        self.query_one("#activity-log", RichLog).write(
            f"[dim]\\[{ts}][/dim]  {markup}"
        )
        self._log_buf.append(f"[{ts}]  {markup}")


# ── Env check ────────────────────────────────────────────────────────────────

def check_env() -> list[str]:
    """Return warning strings for missing or misconfigured environment pieces."""
    import shutil
    warnings: list[str] = []

    # script binary — required for TTY-level capture
    if not shutil.which("script"):
        warnings.append(
            "WARNING: 'script' binary not found — TTY session logging will not work.\n"
            "  Run configure.sh on your Linux/WSL op station."
        )

    # zshrc configured
    zshrc = Path.home() / ".zshrc"
    if zshrc.exists():
        try:
            if "SideSaddle session logging" not in zshrc.read_text(errors="replace"):
                warnings.append(
                    "WARNING: ~/.zshrc does not contain the SideSaddle logging block.\n"
                    "  Run configure.sh to set up automatic session capture."
                )
        except OSError:
            pass
    else:
        warnings.append(
            "WARNING: ~/.zshrc not found — logging hooks not installed.\n"
            "  Run configure.sh on your Linux/WSL op station."
        )

    return warnings


# ── Auth ──────────────────────────────────────────────────────────────────────

def _has_auth() -> bool:
    if cfg("active_provider", "anthropic") == "anthropic-sub":
        return bool(load_sub_token())
    return bool(resolve_key())


# ── Login ─────────────────────────────────────────────────────────────────────

def run_login() -> None:
    import webbrowser
    if load_sub_token():
        print("Found existing subscription token.\nSet active_provider: anthropic-sub in config.yaml")
        return
    url, verifier = sub_login_url()
    print(f"\nOpening browser…\n  {url}\n")
    webbrowser.open(url)
    print("After approving, paste as:  <code>#<state>")
    code_state = input("Code#State: ").strip()
    if not code_state:
        print("Aborted."); return
    try:
        print(f"\n{sub_login_exchange(code_state, verifier)}")
    except Exception as e:
        print(f"\nLogin failed: {e}"); sys.exit(1)


# ── Batch ─────────────────────────────────────────────────────────────────────

def run_batch(log_dir: Path | None, output_dir: Path | None) -> None:
    if not _has_auth():
        print("Error: no credentials.\n"
              "  API key:      export ANTHROPIC_API_KEY=sk-ant-…\n"
              "  Subscription: python3 SideSaddle.py --login")
        sys.exit(1)
    # Resolve dirs: explicit args > op-scoped > error
    if log_dir is None or output_dir is None:
        op, op_log_dir, op_out_dir = resolve_op()
        if not op:
            print("Error: no op set and no --log-dir given.\n"
                  "  Set SS_OP env var or pass --log-dir / --output-dir explicitly.")
            sys.exit(1)
        log_dir    = log_dir    or op_log_dir
        output_dir = output_dir or op_out_dir
    log_dir = log_dir.expanduser()
    if not log_dir.is_dir():
        print(f"Error: log directory not found: {log_dir}"); sys.exit(1)
    log_glob = cfg("log_glob", "raw_*.log")
    log_files = sorted(log_dir.glob(log_glob))
    if not log_files:
        print(f"No {log_glob} files in {log_dir}"); sys.exit(0)
    raw_combined = "\n".join(p.read_text(errors="replace") for p in log_files)
    _, raw = preprocess(raw_combined)  # use session log content for batch analysis
    print(f"Loaded {len(log_files)} file(s)")
    analyst = Analyst(
        LLMClient(), output_dir=output_dir,
        on_advisory=lambda _: None,
        on_response=lambda _: None,
        on_status=lambda s: print(f"  {s}"),
        on_error=lambda e: print(f"  Error: {e}", file=sys.stderr),
    )
    print("Analyzing…")
    print("\n── Advisory ──")
    print(analyst.analyze_sync(raw))
    bp, ap = analyst.export_csv()
    print(f"\nExported:\n  Beacons    ({len(analyst.beacons)}): {bp}")
    print(f"  Activities ({len(analyst.activities)}): {ap}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="SideSaddle — red team op logger")
    parser.add_argument("--op",         metavar="NAME",  help="Operation name (required unless SS_OP env var or current_op config is set)")
    parser.add_argument("--c2",         metavar="URL",   help="C2 teamserver URL for activity forwarding (template — not yet implemented)")
    parser.add_argument("--analyze",    action="store_true")
    parser.add_argument("--login",      action="store_true")
    parser.add_argument("--log-dir",    type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()

    if args.login:
        run_login()
        return

    # Set SS_OP from --op flag so resolve_op() picks it up everywhere
    if args.op:
        os.environ["SS_OP"] = args.op

    # Validate op is set (--op flag, SS_OP env var, or current_op in config)
    op, _, _ = resolve_op()
    if not op:
        parser.error(
            "no operation set — use --op <name>\n"
            "  Example:  python3 SideSaddle.py --op op1\n"
            "  Or set:   SS_OP=op1  (env var)  |  current_op: op1  (config.yaml)"
        )

    # Build C2 client if --c2 given (or c2_url in config)
    c2_url = args.c2 or cfg("c2_url", None)
    c2_client = C2Client(c2_url) if c2_url else None

    env_warnings = check_env()

    if args.analyze:
        for w in env_warnings:
            print(w)
        run_batch(args.log_dir, args.output_dir)
        return

    if not sys.stdout.isatty():
        try:
            fd = os.open("/dev/tty", os.O_RDWR)
            os.dup2(fd, sys.stdout.fileno())
            os.dup2(fd, sys.stderr.fileno())
            os.close(fd)
        except OSError:
            pass

    SideSaddleApp(env_warnings=env_warnings, c2_client=c2_client).run()


if __name__ == "__main__":
    main()
