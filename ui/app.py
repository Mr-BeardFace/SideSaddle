from __future__ import annotations
import threading
from collections import deque
from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)
from textual.reactive import reactive
from textual.screen import ModalScreen

from core import config
from core.analyst import Analyst
from core.engagement_state import EngagementState
from core.log_watcher import LogWatcher
from ui import commands as cmd_mod

_ACTIVITY_HISTORY_MAX = 50_000  # lines kept for Ctrl+L modal / copy

_CSS = """
Screen {
    background: #0d1117;
    color: #c9d1d9;
}

#status-bar {
    height: 1;
    background: #161b22;
    color: #8b949e;
    padding: 0 1;
}

#main-split {
    height: 1fr;
}

#left-pane {
    width: 35%;
    border-right: solid #30363d;
}

#right-pane {
    width: 1fr;
}

#left-tabs {
    height: 1fr;
}

#next-steps-container {
    height: 10;
    border-top: solid #30363d;
    padding: 0 1;
    background: #0d1117;
    overflow-y: auto;
}

#next-steps-label {
    color: #58a6ff;
    text-style: bold;
    padding-top: 1;
}

#next-steps-content {
    color: #8b949e;
    padding-bottom: 1;
}

#activity-label {
    height: 1;
    background: #161b22;
    color: #58a6ff;
    text-style: bold;
    padding: 0 1;
}

#activity-log {
    height: 7fr;
    scrollbar-color: #30363d #0d1117;
}

#cmd-dialogue {
    height: 3fr;
    border-top: dashed #30363d;
    display: none;
}

#cmd-log {
    height: 1fr;
    background: #0d1117;
    scrollbar-color: #30363d #0d1117;
    padding: 0 1;
}

#cmd-header {
    height: 1;
    background: #161b22;
    color: #3fb950;
    text-style: bold;
    padding: 0 1;
}

#input-container {
    height: 5;
    border-top: solid #30363d;
    background: #0d1117;
}

#chat-input {
    background: #0d1117;
    border: none;
    color: #c9d1d9;
    height: 5;
    scrollbar-size: 0 0;
}

#chat-input:focus {
    border: none;
}

DataTable {
    background: #0d1117;
    color: #c9d1d9;
}

DataTable > .datatable--header {
    background: #161b22;
    color: #58a6ff;
}

DataTable > .datatable--cursor {
    background: #1f2937;
}

TabbedContent > TabPane {
    padding: 0;
}

Tabs {
    background: #161b22;
}

Tab {
    color: #8b949e;
}

Tab.-active {
    color: #58a6ff;
}

.masked {
    color: #3d444d;
}

Footer {
    background: #161b22;
    color: #8b949e;
}
"""


class ActivityLogModal(ModalScreen):
    """Full-screen activity log viewer — Escape to close."""

    CSS = """
    ActivityLogModal {
        align: center middle;
    }
    #activity-modal-outer {
        width: 95%;
        height: 90%;
        background: #0d1117;
        border: solid #30363d;
        padding: 1 2;
    }
    #activity-modal-body {
        height: 1fr;
        background: #0d1117;
    }
    """

    BINDINGS = [("escape", "dismiss", "Close"), ("q", "dismiss", "Close")]

    def __init__(self, lines: list[str]) -> None:
        super().__init__()
        self._text = "\n".join(lines) if isinstance(lines, list) else lines

    def compose(self) -> ComposeResult:
        from textual.widgets import TextArea
        with Vertical(id="activity-modal-outer"):
            yield Static("[bold cyan]ACTIVITY LOG[/bold cyan]", markup=True)
            yield TextArea(self._text, id="activity-modal-body", read_only=True)
            yield Static("[dim]Esc / q — close  ·  select + Ctrl+C to copy[/dim]", markup=True)


class FindingDetailModal(ModalScreen):
    """Full-detail view for a finding — Escape or Enter to close."""

    CSS = """
    FindingDetailModal {
        align: center middle;
    }
    #finding-detail-container {
        width: 80%;
        max-height: 80%;
        background: #161b22;
        border: solid #30363d;
        padding: 1 2;
    }
    #finding-detail-scroll {
        height: 1fr;
    }
    """

    BINDINGS = [("escape", "dismiss", "Close"), ("enter", "dismiss", "Close")]

    def __init__(self, finding) -> None:
        super().__init__()
        self._finding = finding

    def compose(self) -> ComposeResult:
        f = self._finding
        _SEV_COLORS = {"critical": "red", "high": "red1", "medium": "yellow",
                       "low": "cyan", "info": "dim"}
        col = _SEV_COLORS.get(f.severity, "white")
        lines = [
            f"[bold][{col}]{f.severity.upper()}[/{col}]  {f.title}[/bold]",
            f"[dim]Target:[/dim] {f.target or '—'}  [dim]Technique:[/dim] {f.technique or '—'}",
            f"[dim]Verified:[/dim] {'[green]yes[/green]' if f.verified else '[dim]no[/dim]'}",
            "",
        ]
        if f.description:
            lines += ["[bold]Description[/bold]", f.description, ""]
        if f.evidence:
            lines += ["[bold]Evidence[/bold]", f"[dim]{f.evidence}[/dim]", ""]
        text = "\n".join(lines)
        with Vertical(id="finding-detail-container"):
            with ScrollableContainer(id="finding-detail-scroll"):
                yield Static(text, markup=True)
            yield Static("[dim]Escape / Enter to close[/dim]", markup=True)


class SideSaddleApp(App):
    CSS = _CSS
    TITLE = "SideSaddle"

    BINDINGS = [
        Binding("ctrl+left",  "shrink_left",         "Shrink left pane",  show=False),
        Binding("ctrl+right", "grow_left",            "Grow left pane",    show=False),
        Binding("ctrl+up",    "resize_vertical_up",   "Resize up",          show=False, priority=True),
        Binding("ctrl+down",  "resize_vertical_down", "Resize down",        show=False, priority=True),
        Binding("ctrl+l",     "show_log",             "Full Log"),
        Binding("ctrl+d",     "toggle_cmd_pane",      "Commands",          show=False),
        Binding("ctrl+e",     "export",               "Export IOC"),
        Binding("ctrl+y",     "copy_log",             "Copy Log"),
        Binding("ctrl+q",     "app.quit",             "Quit"),
        Binding("enter",       "submit_input",         "Send",              show=False, priority=True),
        Binding("shift+enter", "insert_newline",      "Newline",           show=False, priority=True),
        Binding("tab",        "accept_completion",    "Complete",          show=False, priority=True),
        Binding("ctrl+p",     "history_prev",         "History ↑",         show=False),
        Binding("ctrl+n",     "history_next",         "History ↓",         show=False),
    ]

    _left_width: reactive[int] = reactive(35)
    _next_steps_height: reactive[int] = reactive(10)
    _right_act_fr: int = 7  # activity-log fraction out of 10; cmd-dialogue gets the rest
    _revealed_creds: set[int]

    def __init__(self, state: EngagementState, analyst: Analyst, log_watcher: LogWatcher,
                 read_only: bool = False, passphrase_warning: str | None = None,
                 debug: bool = False, verbose: bool = False) -> None:
        super().__init__()
        self._state = state
        self._analyst = analyst
        self._log_watcher = log_watcher
        self._read_only = read_only
        self._passphrase_warning = passphrase_warning
        self._debug = debug
        self._verbose = verbose
        self._cmd_history: list[str] = []
        self._hist_idx: int = -1
        self._revealed_creds: set[int] = set()
        self._activity_lines: deque = deque(maxlen=_ACTIVITY_HISTORY_MAX)
        self._pane_at_blank: bool = True
        self._cmd_lines: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._status_text(), id="status-bar")
        with Horizontal(id="main-split"):
            with Vertical(id="left-pane"):
                with TabbedContent(id="left-tabs"):
                    with TabPane("Beacons", id="tab-beacons"):
                        yield DataTable(id="beacons-table", cursor_type="row")
                    with TabPane("Hosts", id="tab-hosts"):
                        yield DataTable(id="hosts-table", cursor_type="row")
                    with TabPane("Credentials", id="tab-creds"):
                        yield DataTable(id="creds-table", cursor_type="cell")
                    with TabPane("Findings", id="tab-findings"):
                        yield DataTable(id="findings-table", cursor_type="row")
                with Vertical(id="next-steps-container"):
                    yield Label("SUGGESTED COMMANDS", id="next-steps-label")
                    yield Static("", id="next-steps-content")
            with Vertical(id="right-pane"):
                yield Label("ACTIVITY LOG", id="activity-label")
                yield RichLog(id="activity-log", highlight=True, markup=True, wrap=True)
                with Vertical(id="cmd-dialogue"):
                    yield Static(
                        "● COMMANDS  [dim](Ctrl+D hide)[/dim]",
                        id="cmd-header",
                    )
                    yield RichLog(id="cmd-log", highlight=True, markup=True, wrap=True)
        with Vertical(id="input-container"):
            placeholder = "> chat or /command  (Ctrl+Enter to send" + (", Tab to complete)" if True else ")")
            if self._read_only:
                placeholder += "  [READ ONLY]"
            yield TextArea(id="chat-input", soft_wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        from core import debug as dbg
        dbg.init(config.op_dir(), debug=self._debug, verbose=self._verbose)
        self._init_tables()
        self._refresh_state(self._state)
        config.publish_log_dir()
        self.set_interval(1.0, self._update_status_bar)

        if not self._read_only:
            # wire analyst callbacks
            self._analyst._on_activity = self._post_activity
            self._analyst._on_state_update = self._post_state_update

            self._log_watcher.start(self._state.log_cursors)
            self._analyst.start()

        if self._read_only:
            store = getattr(self._analyst, "_store", None)
            if store is not None:
                try:
                    log = self.query_one("#activity-log", RichLog)
                    for entry in store.get_activity_log():
                        line = f"[dim]{entry['ts']}[/dim] {entry['message']}"
                        log.write(line)
                        self._activity_lines.append(f"{entry['ts']} {entry['message']}")
                    self._pane_at_blank = False
                    log.write("")
                    log.write(f"[dim]─── end of stored log ───[/dim]")
                    log.write("")
                except Exception:
                    pass

        ts = datetime.utcnow().strftime("%H:%M:%S")
        mode = "READ ONLY" if self._read_only else "LIVE"
        self._write_activity(f"[bold cyan]SideSaddle[/bold cyan] [{ts}] Op: [bold]{self._state.op_name}[/bold] — {mode}")

        if not self._read_only:
            hooks = Path(__file__).parent.parent / "shell" / "sidesaddle-hooks.zsh"
            if hooks.exists():
                self._write_activity(f"[dim]Shell hooks: source {hooks}[/dim]")
            log_dir = config.log_dir()
            self._write_activity(f"[dim]Log dir: {log_dir}[/dim]")

        if self._passphrase_warning:
            self._write_activity(f"[bold yellow]⚠ {self._passphrase_warning}[/bold yellow]")

    def _init_tables(self) -> None:
        t = self.query_one("#beacons-table", DataTable)
        t.add_columns("ID", "Host", "IP", "User", "OS", "Last Seen")

        t = self.query_one("#hosts-table", DataTable)
        t.add_columns("IP", "Hostname", "OS", "Ports")

        t = self.query_one("#creds-table", DataTable)
        t.add_column("Type",     key="type")
        t.add_column("Username", key="username")
        t.add_column("Secret",   key="secret")
        t.add_column("Format",   key="format")
        t.add_column("Location", key="location")

        t = self.query_one("#findings-table", DataTable)
        t.add_column("Sev",     key="sev")
        t.add_column("Title",   key="title")
        t.add_column("Target",  key="target")
        t.add_column("Technique", key="technique")

    def _refresh_state(self, state: EngagementState) -> None:
        self._state = state
        self.title = f"SideSaddle — {state.op_name}"

        t = self.query_one("#beacons-table", DataTable)
        t.clear()
        for b in state.beacons:
            t.add_row(b.id, b.host, b.ip, b.user, b.os,
                      b.last_seen.strftime("%H:%M:%S") if b.last_seen else "")

        t = self.query_one("#hosts-table", DataTable)
        t.clear()
        for h in state.hosts:
            t.add_row(h.ip, h.hostname, h.os, ", ".join(h.open_ports[:6]))

        t = self.query_one("#creds-table", DataTable)
        t.clear()
        self._revealed_creds.clear()
        for i, c in enumerate(state.credentials):
            masked = "[dim]••••••[/dim]" if c.secret else "[dim]—[/dim]"
            location = c.location or c.source_host
            t.add_row(c.type, c.username, masked, c.format, location, key=str(i))

        _SEV_COLORS = {"critical": "red", "high": "red1", "medium": "yellow", "low": "cyan", "info": "dim"}
        t = self.query_one("#findings-table", DataTable)
        t.clear()
        for i, f in enumerate(sorted(state.findings,
                key=lambda x: -{"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(x.severity,0))):
            col = _SEV_COLORS.get(f.severity, "white")
            sev_cell = f"[{col}]{f.severity.upper()}[/{col}]"
            t.add_row(sev_cell, f.title, f.target, f.technique, key=str(i))

        _REACH_ORDER = {"recon":0,"service":1,"vuln":2,"exploited":3,
                        "foothold":4,"user":5,"privesc":6,"root":7}
        _OPSEC_CLR = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
        _OPSEC_LBL = {"low": "LOW", "medium": "MED", "high": "HIGH", "critical": "CRIT"}
        ns = self.query_one("#next-steps-content", Static)
        from rich.markup import escape as _esc
        open_leads = [l for l in state.open_leads() if l.command]
        if open_leads:
            # best (highest prior) lead per technique, sorted by frontier relevance
            best: dict[str, object] = {}
            for l in open_leads:
                key = (l.technique or l.reach_level).lower()
                if key not in best or l.prior > best[key].prior:
                    best[key] = l
            sorted_leads = sorted(best.values(),
                key=lambda l: (-_REACH_ORDER.get(l.reach_level, 0), -l.prior))[:10]
            lines = []
            for l in sorted_leads:
                clr = _OPSEC_CLR.get(l.opsec, "yellow")
                lbl = _OPSEC_LBL.get(l.opsec, "MED")
                tech = _esc((l.technique or l.reach_level)[:14])
                cmd  = _esc(l.command)
                lines.append(f"[dim]{tech:<14}[/dim]  [{clr}]{lbl}[/{clr}]  {cmd}")
            ns.update("\n".join(lines))
        else:
            ns.update("[dim]No suggested commands yet[/dim]")

        self.query_one("#status-bar", Static).update(self._status_text())

    def _status_text(self) -> str:
        provider = config.get("active_provider", "?")
        last = self._state.last_analysis
        last_str = last.strftime("%H:%M:%S") if last else "never"
        inp, out, cached = self._analyst.token_counts()
        cost, is_est = self._analyst.cost_info()
        tok_str = f"  │  tok: {inp:,}↑ {out:,}↓" + (f" {cached:,}⚡" if cached else "")
        cost_str = f"  │  ~${cost:.4f}" if is_est else f"  │  ${cost:.4f}"
        analyst_str = f"  │  [dim]{self._analyst.analyst_status}[/dim]" if self._analyst.analyst_status else ""
        return (
            f"op: [bold]{self._state.op_name}[/bold]  │  frontier: {self._state.frontier}  │  "
            f"last: {last_str}  │  {provider}{tok_str}{cost_str}{analyst_str}  │  "
            f"beacons: {len(self._state.beacons)}  hosts: {len(self._state.hosts)}  "
            f"creds: {len(self._state.credentials)}  findings: {len(self._state.findings)}  "
            f"leads: {len(self._state.open_leads())}/{len(self._state.leads)}"
        )

    def _write_activity(self, message: str, sep: bool = False) -> None:
        log = self.query_one("#activity-log", RichLog)
        ts = datetime.utcnow().strftime("%H:%M:%S")
        if sep and not self._pane_at_blank:
            log.write("")
            self._activity_lines.append("")
        line = f"[dim]{ts}[/dim] {message}"
        log.write(line)
        self._activity_lines.append(f"{ts} {message}")
        self._pane_at_blank = False
        store = getattr(self._analyst, "_store", None)
        if store is not None:
            try:
                store.add_activity_log(ts, message)
            except Exception:
                pass

    def _update_status_bar(self) -> None:
        try:
            self.query_one("#status-bar", Static).update(self._status_text())
        except Exception:
            pass

    def _flash_status(self, msg: str) -> None:
        try:
            self.query_one("#status-bar", Static).update(msg)
            self.set_timer(2.0, self._update_status_bar)
        except Exception:
            pass

    def _show_cmd_output(self, lines: list[str], success: bool = True) -> None:
        dlg = self.query_one("#cmd-dialogue")
        dlg.display = True
        log = self.query_one("#cmd-log", RichLog)
        ts = datetime.utcnow().strftime("%H:%M:%S")
        color = "green" if success else "yellow"
        icon = "✓" if success else "!"
        log.write(f"[dim]{ts}[/dim]  [{color}]{icon}[/{color}]")
        self._cmd_lines.append(f"{ts}  {icon}")
        for line in lines:
            log.write(f"  {line}")
            self._cmd_lines.append(f"  {line}")
        log.write("")
        self._cmd_lines.append("")

    def _post_activity(self, message: str) -> None:
        """Thread-safe: post activity from analyst background thread."""
        self.call_from_thread(self._write_activity, message, True)

    def _post_state_update(self, state: EngagementState) -> None:
        """Thread-safe: refresh UI from analyst background thread."""
        self.call_from_thread(self._refresh_state, state)

    # --- Input handling ---

    def _get_input(self) -> TextArea:
        return self.query_one("#chat-input", TextArea)

    def action_submit_input(self) -> None:
        ta = self._get_input()
        text = ta.text.strip()
        ta.clear()
        ta.focus()
        self._hist_idx = -1
        if not text:
            return
        if text.startswith("/"):
            self._cmd_history.append(text)
            self._handle_command(text)
        elif not self._read_only:
            lines = text.splitlines()
            preview = lines[0] + (f" [dim]…+{len(lines)-1} lines[/dim]" if len(lines) > 1 else "")
            self._write_activity(f"[bold white]You:[/bold white] {preview}", sep=True)
            threading.Thread(target=self._chat, args=(text,), daemon=True).start()
        else:
            self._write_activity("[dim]Chat disabled in read-only mode[/dim]")

    def _chat(self, message: str) -> None:
        reply = self._analyst.chat(message)
        self.call_from_thread(self._write_activity, f"[bold cyan]Analyst:[/bold cyan] {reply}", True)

    def _copy_to_clipboard(self, text: str) -> bool:
        """Best-effort OS clipboard copy. Returns True on success."""
        import shutil, subprocess, sys
        if sys.platform == "win32":
            candidates = [["clip"]]
        elif sys.platform == "darwin":
            candidates = [["pbcopy"]]
        else:
            candidates = [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
        for cmd in candidates:
            if not shutil.which(cmd[0]):
                continue
            try:
                proc = subprocess.run(cmd, input=text.encode("utf-8"),
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                if proc.returncode == 0:
                    return True
            except Exception:
                continue
        try:
            self.copy_to_clipboard(text)
            return True
        except Exception:
            return False

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        tid = event.data_table.id
        if tid == "findings-table":
            row_idx = int(event.row_key.value)
            findings = sorted(
                self._state.findings,
                key=lambda x: -{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(x.severity, 0),
            )
            if row_idx < len(findings):
                self.push_screen(FindingDetailModal(findings[row_idx]))
        elif tid == "hosts-table":
            try:
                row = event.data_table.get_row(event.row_key)
                text = "  ".join(str(c) for c in row if str(c).strip())
                if text and self._copy_to_clipboard(text):
                    self._flash_status("[green]Host row copied to clipboard[/green]")
            except Exception:
                pass

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        if event.data_table.id != "creds-table":
            return
        col_key = event.cell_key.column_key
        row_key = event.cell_key.row_key
        if col_key.value != "secret":
            return
        row_idx = int(row_key.value)
        if row_idx >= len(self._state.credentials):
            return
        cred = self._state.credentials[row_idx]
        if not cred.secret:
            return
        t = self.query_one("#creds-table", DataTable)
        if row_idx in self._revealed_creds:
            self._revealed_creds.discard(row_idx)
            t.update_cell(row_key, col_key, "[dim]••••••[/dim]")
        else:
            self._revealed_creds.add(row_idx)
            t.update_cell(row_key, col_key, cred.secret)
            if self._copy_to_clipboard(cred.secret):
                self._flash_status("[green]Secret copied to clipboard[/green]")

    def _handle_command(self, text: str) -> None:
        # Try the stateless dispatcher first (info, config, key, provider, scope, help)
        result = cmd_mod.dispatch(text)
        if result is not None:
            lines, ok = result
            self._show_cmd_output(lines, ok)
            config.publish_log_dir()
            live_name = config.op_name()
            if live_name != self._state.op_name:
                self._state.op_name = live_name
                self.title = f"SideSaddle — {live_name}"
        else:
            # App-state commands that need access to self
            parsed = cmd_mod.parse(text)
            if parsed is None:
                return
            cmd, args = parsed

            if cmd in ("/exit", "/quit", "/q"):
                self.exit()

            elif cmd == "/frontier":
                sub = args[0] if args else ""
                level = args[1] if len(args) > 1 else ""
                if sub == "set" and level:
                    from core.engagement_state import FRONTIER_LEVELS
                    if level not in FRONTIER_LEVELS:
                        self._show_cmd_output([f"Unknown level '{level}'. Choose: {', '.join(FRONTIER_LEVELS)}"], False)
                    else:
                        self._state.frontier = level
                        self._analyst._save_state()
                        self._show_cmd_output([f"Frontier set to: {level}"], True)
                else:
                    self._show_cmd_output([f"Usage: /frontier set <{'|'.join(['recon','service','vuln','exploited','foothold','user','privesc','root'])}>"], False)

            elif cmd == "/export":
                if self._read_only:
                    self._show_cmd_output(["Exporting from saved state..."], True)
                threading.Thread(target=self._do_export, daemon=True).start()

            elif cmd == "/endop":
                self._analyst.stop()
                self._log_watcher.stop()
                threading.Thread(target=self._do_endop, daemon=True).start()

            elif cmd == "/clear":
                self.query_one("#activity-log", RichLog).clear()
                self._activity_lines.clear()
                self._pane_at_blank = True

            elif cmd == "/status":
                lines = self._analyst._state_summary().splitlines()
                self._show_cmd_output(lines, True)

            elif cmd in ("/c2", "/c2 connect", "/c2 disconnect", "/c2 status"):
                # /c2 url and /c2 auth are handled by the stateless dispatcher above
                self._handle_c2(cmd, args)

            elif cmd in ("/op", "/op new", "/op list", "/op load"):
                self._handle_op(cmd, args)

            else:
                lines, _ = cmd_mod.handle_help()
                self._show_cmd_output([f"Unknown command: {cmd}", ""] + lines, False)

        # Always refresh status bar — any command may have changed config
        self._update_status_bar()

    def _do_export(self) -> None:
        try:
            path = self._analyst.export_ioc()
            self.call_from_thread(self._write_activity, f"[green]Exported:[/green] {path.name}")
        except Exception as e:
            self.call_from_thread(self._write_activity, f"[red]Export failed:[/red] {e}")

    def _do_endop(self) -> None:
        try:
            self._analyst._store.set_op_ended()
            self.call_from_thread(self._write_activity, "[bold yellow]Op ended — generating IOC report…[/bold yellow]")
            ioc_path = self._analyst.export_ioc()
            self.call_from_thread(self._write_activity, f"[bold green]IOC report saved:[/bold green] {ioc_path.name}")

            self.call_from_thread(self._write_activity, "[bold yellow]Generating HTML report — running report agent…[/bold yellow]")
            from core.report import generate_report
            report_path = generate_report(self._analyst._store, self._analyst._state, config.op_dir())
            self.call_from_thread(self._write_activity, f"[bold green]HTML report saved:[/bold green] {report_path.name}")
            self.call_from_thread(self._flash_status, f"[green]Reports: {ioc_path.name}  {report_path.name}[/green]")
        except Exception as e:
            import traceback
            self.call_from_thread(self._write_activity, f"[red]Endop failed:[/red] {e}\n{traceback.format_exc()[:400]}")

    def _handle_c2(self, cmd: str, args: list[str]) -> None:
        from core.c2.nighthawk import NighthawkC2
        sub = cmd.split("/c2")[-1].strip() or (args[0] if args else "")
        if sub == "connect":
            c2 = NighthawkC2(config.log_dir(), self._post_activity)
            c2.start()
            self._c2_backend = c2
            self._show_cmd_output(["C2 connected"], True)
        elif sub == "disconnect":
            if hasattr(self, "_c2_backend"):
                self._c2_backend.stop()
                self._show_cmd_output(["C2 disconnected"], True)
            else:
                self._show_cmd_output(["No active C2 connection"], False)
        elif sub == "status":
            url   = config.get("c2.nighthawk.url", "") or "(not set)"
            user  = config.get("c2.nighthawk.username", "") or "(not set)"
            has_p = bool(config.get_api_key("nighthawk_pass"))
            conn  = "connected" if hasattr(self, "_c2_backend") else "not connected"
            self._show_cmd_output([
                f"C2 Nighthawk: {conn}",
                f"  url:  {url}",
                f"  user: {user}  pass: {'set' if has_p else 'not set'}",
            ], True)
        else:
            self._show_cmd_output(["Usage: /c2 connect | /c2 disconnect | /c2 status"], False)

    def _handle_op(self, cmd: str, args: list[str]) -> None:
        sub = cmd.split("/op")[-1].strip() or (args[0] if args else "")

        if sub == "list":
            import datetime as _dt
            base = config._SS_BASE
            lines = ["Saved ops:", ""]
            if base.exists():
                for d in sorted(base.iterdir()):
                    if not d.is_dir():
                        continue
                    if (d / "engagement.db").exists():
                        mtime = _dt.datetime.fromtimestamp((d / "engagement.db").stat().st_mtime)
                        lines.append(f"  {d.name}  ({mtime.strftime('%Y-%m-%d %H:%M')})")
                    elif (d / "session_state.json").exists():
                        lines.append(f"  {d.name}  [legacy]")
            if len(lines) == 2:
                lines.append("  none")
            self._show_cmd_output(lines, True)

        elif sub == "new":
            new_name = args[0] if args else (cmd.split()[-1] if len(cmd.split()) > 2 else None)
            if not new_name:
                self._show_cmd_output(["Usage: /op new <name>"], False)
                return
            self._analyst.stop()
            self._log_watcher.stop()
            self._state.log_cursors = self._log_watcher.get_cursors()
            self._analyst._save_state()

            config.set_value("op.name", new_name)
            new_state = EngagementState(op_name=new_name)
            self._state = new_state
            self._analyst._state = new_state
            self._analyst._chat_history.clear()
            self._analyst._pending.clear()

            self._log_watcher._cursors.clear()
            self._log_watcher.start()
            self._analyst.start()
            config.publish_log_dir()

            self._refresh_state(new_state)
            self.query_one("#activity-log", RichLog).clear()
            self._activity_lines.clear()
            self._pane_at_blank = True
            self._write_activity(f"[bold green]Switched to new op:[/bold green] {new_name}  (logs → {config.log_dir()})")

        elif sub == "load":
            name = args[0] if args else None
            if not name:
                self._show_cmd_output(["Usage: /op load <name>"], False)
                return
            self._show_cmd_output([f"Restart with: python SideSaddle.py review {name}"], True)

    # --- Completion & history ---

    def action_insert_newline(self) -> None:
        self._get_input().insert("\n")

    def action_accept_completion(self) -> None:
        ta = self._get_input()
        # Only complete on the first line (command line); multiline = no completion
        first_line = ta.text.split("\n")[0]
        suggestion = cmd_mod.complete(first_line)
        if suggestion and "\n" not in ta.text:
            ta.load_text(suggestion)
            ta.move_cursor(ta.get_cursor_line_end_location())
        else:
            self.action_focus_next()

    def action_history_prev(self) -> None:
        if not self._cmd_history:
            return
        self._hist_idx = min(self._hist_idx + 1, len(self._cmd_history) - 1)
        ta = self._get_input()
        ta.load_text(self._cmd_history[-(self._hist_idx + 1)])
        ta.move_cursor(ta.get_cursor_line_end_location())

    def action_history_next(self) -> None:
        ta = self._get_input()
        if self._hist_idx <= 0:
            self._hist_idx = -1
            ta.clear()
            return
        self._hist_idx -= 1
        ta.load_text(self._cmd_history[-(self._hist_idx + 1)])
        ta.move_cursor(ta.get_cursor_line_end_location())

    # --- Keybindings ---

    def action_shrink_left(self) -> None:
        self._left_width = max(20, self._left_width - 5)
        self.query_one("#left-pane").styles.width = f"{self._left_width}%"

    def action_grow_left(self) -> None:
        self._left_width = min(60, self._left_width + 5)
        self.query_one("#left-pane").styles.width = f"{self._left_width}%"

    def action_shrink_next_steps(self) -> None:
        self._next_steps_height = max(3, self._next_steps_height - 2)
        self.query_one("#next-steps-container").styles.height = self._next_steps_height

    def action_grow_next_steps(self) -> None:
        self._next_steps_height = min(20, self._next_steps_height + 2)
        self.query_one("#next-steps-container").styles.height = self._next_steps_height

    def _in_right_pane(self) -> bool:
        w = self.focused
        while w is not None:
            if getattr(w, "id", None) == "right-pane":
                return True
            w = getattr(w, "parent", None)
        return False

    def _resize_right_split(self, delta: int) -> None:
        self._right_act_fr = max(2, min(9, self._right_act_fr + delta))
        self.query_one("#activity-log").styles.height = f"{self._right_act_fr}fr"
        dlg = self.query_one("#cmd-dialogue")
        if delta < 0 and not dlg.display:
            dlg.display = True
        if dlg.display:
            dlg.styles.height = f"{10 - self._right_act_fr}fr"

    def action_resize_vertical_up(self) -> None:
        if self._in_right_pane():
            self._resize_right_split(+1)
        else:
            self.action_shrink_next_steps()

    def action_resize_vertical_down(self) -> None:
        if self._in_right_pane():
            self._resize_right_split(-1)
        else:
            self.action_grow_next_steps()

    def action_export(self) -> None:
        threading.Thread(target=self._do_export, daemon=True).start()

    def action_toggle_cmd_pane(self) -> None:
        dlg = self.query_one("#cmd-dialogue")
        dlg.display = not dlg.display
        if not dlg.display:
            self._get_input().focus()

    def action_show_log(self) -> None:
        text = "\n".join(self._activity_lines)
        self.push_screen(ActivityLogModal([text] if text else []))

    def action_copy_log(self) -> None:
        text = "\n".join(self._activity_lines)
        n = len(self._activity_lines)
        if self._copy_to_clipboard(text):
            self._flash_status(f"[green]Copied {n} lines to clipboard[/green]")
        else:
            self._flash_status("[yellow]Copy failed: no clipboard backend available[/yellow]")

    def on_unmount(self) -> None:
        self._log_watcher.stop()
        self._analyst.stop()
        # save cursor positions on exit
        self._state.log_cursors = self._log_watcher.get_cursors()
        self._analyst._save_state()
