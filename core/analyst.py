"""Op state, LLM analysis, and operator chat for SideSaddle."""
from __future__ import annotations
import csv
import json
import re
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable

from core.llm_client import LLMClient, cfg
from core.c2_client import C2Backend as C2Client

_TS_PAT = re.compile(r"### (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ")


@dataclass
class Beacon:
    beacon_id: str
    c2_type: str = ""        # NH | Sliver | CS | Havoc | etc.
    first_seen: str = ""
    last_seen: str = ""
    hostname: str = ""       # machine the implant runs on
    user_context: str = ""   # OS user the implant runs as
    external_ip: str = ""    # internet-facing IP of target
    internal_ips: str = ""   # comma-separated internal IPs
    process: str = ""        # hosting process + PID
    listener: str = ""       # listener / callback name or URL


@dataclass
class Activity:
    activity_id: str
    beacon_id: str = ""
    timestamp_utc: str = ""
    execution_context: str = ""
    execution_host: str = ""
    user_context: str = ""
    remote_host: str = ""
    command_action: str = ""
    result: str = ""
    observable_artifacts: str = ""


# ── Tool definitions ──────────────────────────────────────────────────────────

_ANALYSIS_TOOLS = [
    {
        "name": "analyze_session",
        "description": "Record all findings from a log batch. Called ONCE per analysis with everything populated.",
        "input_schema": {
            "type": "object",
            "properties": {
                "beacons": {
                    "type": "array",
                    "description": "C2 implants found. Empty array if none.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "beacon_id":     {"type": "string", "description": "C2-N identifier (e.g. C2-1) or NH clientId short form"},
                            "c2_type":       {"type": "string", "description": "NH | Sliver | CS | Havoc | unknown"},
                            "first_seen":    {"type": "string", "description": "ISO timestamp"},
                            "last_seen":     {"type": "string", "description": "ISO timestamp"},
                            "hostname":      {"type": "string", "description": "Machine the implant runs on"},
                            "user_context":  {"type": "string", "description": "OS user the implant runs as"},
                            "external_ip":   {"type": "string", "description": "Internet-facing IP of target"},
                            "internal_ips":  {"type": "string", "description": "Comma-separated internal IPs"},
                            "process":       {"type": "string", "description": "Hosting process name + PID, e.g. notepad.exe (1234)"},
                            "listener":      {"type": "string", "description": "Listener / callback name or URL"},
                        },
                        "required": ["beacon_id"],
                    },
                },
                "activities": {
                    "type": "array",
                    "description": "All executed commands. One entry per command. Skip commands that never ran.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "activity_id":          {"type": "string", "description": "ACT-N identifier"},
                            "beacon_id":            {"type": "string"},
                            "timestamp_utc":        {"type": "string"},
                            "execution_context":    {"type": "string", "description": "C2 > HOST | Proxychains > C2 > HOST | <local> (direct, no C2) | SSH > HOST"},
                            "execution_host":       {"type": "string", "description": "Host the command ran ON. Use 'OpStation' for the attack box."},
                            "user_context":         {"type": "string"},
                            "remote_host":          {"type": "string", "description": "Target host if action was directed outward"},
                            "command_action":       {"type": "string", "description": "Exact command text with secrets redacted: passwords/keys/tokens in flags replaced with <REDACTED>, e.g. -p <REDACTED>"},
                            "result":               {"type": "string", "description": "One-line interpretation — not raw output. E.g. 'Identified 12 live hosts on /24'."},
                            "observable_artifacts": {"type": "string", "description": "Max 4, newline-separated. What the TARGET system would log: processes spawned ON target, network connections FROM target's perspective (src:port→dst:port seen by target), files/registry written ON target, DNS queries FROM target. NOT OpStation-local artifacts. Never log credential values."},
                        },
                        "required": ["activity_id", "command_action", "timestamp_utc"],
                    },
                },
                "op_picture": {
                    "type": "object",
                    "description": "Full living op picture — all previously known info plus new findings.",
                    "properties": {
                        "access": {
                            "type": "array",
                            "description": "All hosts with active access.",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "host":       {"type": "string"},
                                    "user":       {"type": "string"},
                                    "priv_level": {"type": "string", "description": "user | local_admin | domain_admin | SYSTEM"},
                                    "beacon_id":  {"type": "string"},
                                    "notes":      {"type": "string"},
                                },
                                "required": ["host", "user", "priv_level"],
                            },
                        },
                        "discovered_assets": {
                            "type": "array",
                            "description": "Hosts/services discovered (not necessarily compromised).",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "asset":    {"type": "string"},
                                    "services": {"type": "string"},
                                    "notes":    {"type": "string"},
                                },
                                "required": ["asset"],
                            },
                        },
                        "credential_material": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Note THAT creds exist, never values. Format: '<type> — <DOMAIN\\\\user> (<context>)'.",
                        },
                        "attack_paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Viable lateral movement or escalation paths.",
                        },
                        "environment_notes": {
                            "type": "string",
                            "description": "Domain, DCs, EDR/AV, subnet layout, other useful context.",
                        },
                    },
                },
                "advisory": {
                    "type": "object",
                    "properties": {
                        "opsec":    {"type": "array", "items": {"type": "string"}, "description": "Noisy/detection-prone actions. Reference ACT-ID."},
                        "tactical": {"type": "array", "items": {"type": "string"}, "description": "Actionable next steps. Only when clear."},
                        "state":    {"type": "string", "description": "One-sentence current op status."},
                    },
                    "required": ["state"],
                },
            },
            "required": ["activities", "advisory"],
        },
    },
]

_IOC_TOOLS = [
    {
        "name": "log_ioc_activities",
        "description": "Record every executed command as an IOC entry. Called once per chunk with all activities found.",
        "input_schema": {
            "type": "object",
            "properties": {
                "activities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "timestamp_utc":      {"type": "string"},
                            "beacon_id":          {"type": "string", "description": "C2-N or short clientId of the beacon this activity ran through. Empty only for <local> commands."},
                            "execution_context":  {"type": "string", "description": "C2 > HOST | Proxychains > C2 > HOST | <local> (direct OpStation→target, no C2)"},
                            "execution_host":     {"type": "string", "description": "Machine command ran ON (the target, not the proxy hop)"},
                            "command_action":     {"type": "string", "description": "Exact command, secrets replaced with <REDACTED>"},
                            "result":             {"type": "string", "description": "One-line result summary"},
                            "observable_artifacts": {"type": "string", "description": "What TARGET system would log: processes spawned on target, inbound connections, files written on target. Max 4, newline-separated. NOT OpStation artifacts."},
                        },
                        "required": ["command_action"],
                    },
                },
            },
            "required": ["activities"],
        },
    }
]

_IOC_SYSTEM = """\
You are an IOC extractor for red team operations. Extract every executed command from \
these logs into structured activity records.

LOG SECTIONS — you may receive two sections:
- Terminal session logs (default): raw operator TTY capture from the attack box.
- C2 CONSOLE LOGS (=== C2 CONSOLE LOGS ===): beacon metadata + commands.
  BEACON ARTIFACT BLOCKS (# BEACON … #───) appear once per beacon:
    fields: c2_type, beacon_id, hostname, user, external_ip, internal_ips,
            process PID, listener, first_seen, last_seen.
  BEACON COMMANDS: ### timestamp NH:operator  command  [C2: HOSTNAME\\user]
    execution_context = "C2 > HOSTNAME", execution_host = HOSTNAME

EXECUTION CONTEXT — use exactly one of:
- C2 > HOSTNAME       — command sent through a beacon
- Proxychains > C2 > HOSTNAME — local command routed through beacon's SOCKS proxy
- <local>             — direct connection from OpStation with no C2 (rare; flag as OPSEC risk)

BEACON CORRELATION:
- Every activity that ran through a beacon must have beacon_id populated.
- Derive beacon_id from the # BEACON block (beacon_id field) or from the [C2: HOSTNAME]
  annotation in the ### header.
- Proxychains commands: use beacon_id of the beacon whose socks-start preceded them.
  If multiple beacons are active, match by hostname/subnet from the SOCKS port used.

CROSS-SOURCE CORRELATION:
- If C2 logs show socks/socks-start/socks5 on a beacon, and terminal logs later show
  proxychains on the same or downstream subnet: those proxychains commands ran through
  that beacon. Set execution_context = "Proxychains > C2 > HOSTNAME" and beacon_id
  to that beacon. Use timestamps — proxychains must come AFTER the socks-start.

SKIP — do NOT record:
- Local tool setup: pip install, apt install, apt-get, brew, npm, gem, cargo, go install
- Local config changes: /etc/hosts edits, local SSH config, local file management on OpStation
- Repeated identical failures: record once with result "Failed repeatedly (<error>)"
- Commands that never executed (syntax errors, typos)

RECORD — always log:
- Any command directed at or run ON a target
- Network connections to targets (failed ones too — once per unique error)
- Credential use or discovery
- File operations on target systems
- Privilege escalation attempts
- C2 beacon commands (from C2 CONSOLE LOGS section)

REDACTION — replace inline secrets in command_action with <REDACTED>:
- Passwords in flags: -p password → -p <REDACTED>
- API keys, tokens, hashes passed as arguments
- --password=, -pass, :password@, Basic auth strings

Call log_ioc_activities ONCE with every activity found. \
No advisory, no op state analysis — extraction only.
"""

_CHAT_TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from the operator's filesystem. Use when the operator asks about file contents or wants you to analyze something on disk.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path":      {"type": "string",  "description": "Absolute or ~ path to the file"},
                "max_lines": {"type": "integer", "description": "Max lines to return (default 150)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_directory",
        "description": "List files and directories at a path. Supports glob patterns (e.g. *.txt). Use to explore the filesystem.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path":    {"type": "string", "description": "Directory path to list"},
                "pattern": {"type": "string", "description": "Glob pattern to filter entries (default: *)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "find_files",
        "description": "Recursively find files matching a glob pattern under a directory (like find -name).",
        "input_schema": {
            "type": "object",
            "properties": {
                "directory":   {"type": "string",  "description": "Root directory to search from"},
                "pattern":     {"type": "string",  "description": "Glob pattern, e.g. '*.conf' or 'id_rsa*'"},
                "max_results": {"type": "integer", "description": "Cap results (default 50)"},
            },
            "required": ["directory", "pattern"],
        },
    },
    {
        "name": "grep_file",
        "description": "Search for a regex pattern inside a file and return matching lines with line numbers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path":        {"type": "string",  "description": "File to search"},
                "pattern":     {"type": "string",  "description": "Regex or literal string to search for"},
                "max_matches": {"type": "integer", "description": "Cap matches returned (default 50)"},
            },
            "required": ["path", "pattern"],
        },
    },
    {
        "name": "web_search",
        "description": "Search the public internet for CVEs, tools, techniques, or general research. Do NOT use this to probe or interact with any target system — queries go to Brave Search only.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query":       {"type": "string",  "description": "Search query"},
                "max_results": {"type": "integer", "description": "Number of results to return (default 5, max 10)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch the content of a URL from the public internet to read an article, advisory, or documentation page. Only use URLs returned by web_search. Never use this to contact target systems — private/internal IPs are automatically blocked.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to fetch (http/https only)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "write_file",
        "description": "Write (create or overwrite) a file inside the configured working_dir. Fails if working_dir is not set or the path resolves outside it.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path":    {"type": "string", "description": "Absolute or ~ path to write"},
                "content": {"type": "string", "description": "Full file content to write"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "append_file",
        "description": "Append text to a file inside the configured working_dir. Creates the file if it doesn't exist. Fails if working_dir is not set or the path resolves outside it.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path":    {"type": "string", "description": "Absolute or ~ path to append to"},
                "content": {"type": "string", "description": "Text to append"},
            },
            "required": ["path", "content"],
        },
    },
]


# ── System prompts ────────────────────────────────────────────────────────────

_ANALYSIS_SYSTEM = """\
You are SideSaddle, a red team operations logger. Analyze raw terminal session log output \
and maintain structured records for operator awareness and SOC handoff.

EXECUTION CONTEXTS — use exactly one of:
- C2 > HOST: command sent through a beacon (host from [C2: ...] annotation)
- Proxychains > C2 > HOST: local command routed through a beacon's SOCKS proxy
- <local>: direct OpStation→target with no C2 (rare; always note as OPSEC risk)
- SSH > HOST: SSH session (set beacon_id if the SSH connection itself went through a beacon)
Populate beacon_id on every activity that touched a C2 beacon.

LOG SECTIONS — you may receive two sections:
  Terminal session logs: raw operator TTY capture.
  === C2 CONSOLE LOGS ===: beacon metadata and commands.

  BEACON ARTIFACT BLOCKS (# BEACON … #───) appear once per beacon and contain:
    c2_type, beacon_id, hostname, user, external_ip, internal_ips, process PID,
    listener name, first_seen, last_seen.
  Extract these into beacon records with all fields populated.

  BEACON COMMANDS follow beacon blocks:
    ### timestamp NH:operator  command  [C2: HOSTNAME\\user]
    execution_context = "C2 > HOSTNAME", execution_host = HOSTNAME

CROSS-SOURCE CORRELATION:
  When C2 logs show a SOCKS listener opened (socks, socks-start, socks5) and terminal
  logs later show proxychains on the same or downstream subnet, the proxychains
  commands are routing through that beacon. Set execution_context to
  "Proxychains > C2 > HOSTNAME". Use timestamps to establish ordering.

Call analyze_session ONCE with all findings populated:
- beacons: C2 implants found (empty array if none); for each include c2_type, hostname,
  user_context, external_ip, internal_ips, process, listener, first_seen, last_seen
- activities: operational commands only (see SKIP LIST below)
- op_picture: full living knowledge base — previously known info plus new findings
- advisory: opsec warnings, tactical next steps, one-sentence state

SKIP — do NOT record these as activities:
- Local tool setup: pip install, apt install, apt-get, brew, npm, gem, cargo, go install
- Local config changes: /etc/hosts edits, ~/.bashrc edits, SSH config changes on OpStation
- Local file management on OpStation: mkdir, touch, chmod on the attack box itself
- Repeated identical failures: if the same connection error appears multiple times, \
record it ONCE with result "Failed repeatedly (<error>)"
- Commands that never executed (typos caught before Enter, syntax errors with no effect)

RECORD — these always get logged regardless of execution host:
- Any command directed at or run ON a target (recon, exploitation, post-ex, lateral movement)
- Network connections to targets (even failed ones — once per unique error)
- Credential use or discovery
- File operations on target systems
- Privilege escalation attempts

REDACTION — in command_action, replace inline secrets with <REDACTED>:
- Passwords in flags: -p password123 → -p <REDACTED>
- API keys, tokens, hashes passed as arguments
- Anything matching --password=, -pass, :password@, Basic auth strings
- Keep the flag name, redact only the value: --password <REDACTED> not --<REDACTED>

ACTIVITY RULES:
- execution_context: infer from command and output
- execution_host: machine the command ran ON ("OpStation" for the attack box)
- command_action: exact command with secrets redacted per REDACTION rules above
- result: one-line INTERPRETATION — not raw output. "Identified 12 live hosts on /24", \
"Confirmed running as mrbeardface on kali", "Dumped LSASS — credential material retrieved"
- observable_artifacts: what the TARGET system would log — process names spawned on target, \
network connections seen FROM the target (src IP:port → dst IP:port), files created/modified \
on target, registry keys touched on target, DNS queries issued from target. \
NOT what the OpStation sees. Max 4, newline-separated. Never log credential values.

ADVISORY VERBOSITY: {verbosity}
  brief   — one-line items; state in one sentence
  verbose — items with brief explanation; tactical with reasoning
"""

_CHAT_SYSTEM = """\
You are SideSaddle, a red team tactical advisor. Answer operator questions, \
suggest next steps, flag OPSEC concerns, and help interpret command output. \
Be concise and actionable. Do not re-state what the operator already knows.

The operator may be running commands directly from their attack box, pivoting via SSH/proxychains, \
or using a C2 implant — or all three. There may be no C2 beacon at all; that is normal.

You can read files from the operator's filesystem using the read_file tool when relevant.

CURRENT OP STATE:
{state_summary}
"""


# ── Analyst ───────────────────────────────────────────────────────────────────

class Analyst:
    def __init__(
        self,
        llm: LLMClient,
        output_dir: str | Path,
        on_advisory: Callable[[str], None],
        on_response: Callable[[str], None],
        on_status:   Callable[[str], None],
        on_error:    Callable[[str], None],
        log_dir: str | Path | None = None,
        c2_client: C2Client | None = None,
    ):
        self._llm = llm
        self._output_dir = Path(output_dir).expanduser()
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._log_dir   = Path(log_dir).expanduser() if log_dir else None
        self._c2        = c2_client
        _nd = cfg("notes_dir", None)
        self._notes_dir = Path(_nd).expanduser() if _nd else None
        _ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._session_ioc_path = self._output_dir / f"ioc_session_{_ts}.csv"
        self._session_ioc_initialized = False

        self.on_advisory = on_advisory
        self.on_response = on_response
        self.on_status   = on_status
        self.on_error    = on_error

        self.beacons:    dict[str, Beacon] = {}
        self.activities: list[Activity]    = []
        self._op_picture: dict             = {}
        self._next_beacon_n   = 1
        self._next_activity_n = 1

        self._history: list[dict] = []

        self._pending: list[str] = []   # raw log text chunks awaiting analysis
        self._all_raw: list[str] = []   # every chunk ever seen (for Analyze Now replay)
        self._debounce: threading.Timer | None = None
        self._lock = threading.Lock()
        self._analysis_lock = threading.Lock()  # serializes LLM analysis calls
        self._ioc_stop = threading.Event()      # set to abort _run_ioc_bg
        self._last_ioc_time: datetime | None = None

        self.verbosity:     str  = cfg("verbosity", "brief")
        self.auto_analysis: bool = cfg("auto_analysis", True)

    # ── Public ────────────────────────────────────────────────────────────────

    def add_raw(self, text: str) -> None:
        """Called by LogWatcher with a raw log text chunk."""
        with self._lock:
            self._all_raw.append(text)
            if self.auto_analysis:
                self._pending.append(text)
        if not self.auto_analysis:
            return
        if self._debounce:
            self._debounce.cancel()
        secs = cfg("debounce_seconds", 30)
        self._debounce = threading.Timer(secs, self._run_analysis_bg)
        self._debounce.daemon = True
        self._debounce.start()

    def create_ioc_log(self, since: "datetime | None" = None, full: bool = False) -> None:
        effective = since if (since is not None or full) else self._last_ioc_time
        threading.Thread(target=self._run_ioc_bg, args=(effective,), daemon=True).start()

    def stop_ioc(self) -> None:
        self._ioc_stop.set()

    def _read_logs_from_disk(self, since: "datetime | None") -> str:
        """Read IOC log(s) from log_dir, optionally filtered to lines after `since`.

        Prefers preprocessed ioc_acc.log if present; falls back to *.log for
        backward compat and batch mode with un-preprocessed logs.
        """
        if not self._log_dir or not self._log_dir.is_dir():
            return ""
        ioc_acc = self._log_dir / "ioc_acc.log"
        if ioc_acc.exists():
            candidates = [ioc_acc]
        else:
            candidates = sorted(self._log_dir.glob(cfg("log_glob", "raw_*.log")))
        parts: list[str] = []
        for path in candidates:
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if since is not None:
                filtered: list[str] = []
                include = False
                for line in text.splitlines(keepends=True):
                    m = _TS_PAT.match(line)
                    if m:
                        try:
                            line_dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                            include = line_dt >= since
                        except ValueError:
                            pass
                    if include:
                        filtered.append(line)
                text = "".join(filtered)
            if text.strip():
                parts.append(text)
        c2_files = sorted(self._log_dir.glob("c2_events_*.log"))
        c2_parts: list[str] = []
        for c2_log in c2_files:
            try:
                c2_text = c2_log.read_text(errors="replace")
            except OSError:
                continue
            if since is not None:
                filtered_c2: list[str] = []
                include = False
                for line in c2_text.splitlines(keepends=True):
                    m = _TS_PAT.match(line)
                    if m:
                        try:
                            include = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S") >= since
                        except ValueError:
                            pass
                    if include:
                        filtered_c2.append(line)
                c2_text = "".join(filtered_c2)
            if c2_text.strip():
                c2_parts.append(c2_text.strip())
        if c2_parts:
            parts.append("\n=== C2 CONSOLE LOGS ===\n" + "\n\n".join(c2_parts))

        if self._notes_dir and self._notes_dir.is_dir():
            globs = cfg("notes_glob", "*.md,*.txt").split(",")
            note_parts: list[str] = []
            for g in globs:
                for p in sorted(self._notes_dir.glob(g.strip())):
                    try:
                        t = p.read_text(errors="replace").strip()
                        if t:
                            note_parts.append(f"--- {p.name} ---\n{t}")
                    except OSError:
                        pass
            if note_parts:
                parts.append("\n=== ANALYST NOTES ===\n" + "\n\n".join(note_parts))
        return "\n".join(parts)

    def _run_ioc_bg(self, since: "datetime | None" = None) -> None:
        """Build IOC log: extract activities from disk logs → dedicated CSV. No op state."""
        raw = self._read_logs_from_disk(since)
        if not raw.strip():
            with self._lock:
                raw = "\n".join(self._all_raw)
        if not raw.strip():
            self.on_status("No log content found")
            return
        since_str = f" (from {since.strftime('%Y-%m-%d %H:%M')})" if since else ""
        max_out = cfg("ioc_output_lines", 20)
        raw = self._truncate_ioc_entries(raw, max_lines=max_out)
        if cfg("debug", False):
            self._debug_dump("debug_ioc_input.txt", raw)
        chunks = self._split_chunks(raw)
        total = len(chunks)
        collected: list[Activity] = []
        n = self._next_activity_n
        self._ioc_stop.clear()
        stopped = False
        try:
            with self._analysis_lock:
                for i, chunk in enumerate(chunks, 1):
                    if self._ioc_stop.is_set():
                        stopped = True
                        break
                    pct = int(i / total * 100)
                    self.on_status(
                        f"Building IOC log{since_str}  {i}/{total}  [{pct}%]  ({len(chunk):,} chars)…"
                    )
                    acts = self._do_ioc_chunk(chunk, start_n=n)
                    collected.extend(acts)
                    n += len(acts)
            if collected:
                act_path, bcn_path, xlsx_path = self._write_ioc_outputs(collected, since)
            else:
                act_path = bcn_path = xlsx_path = None
            if stopped:
                self.on_status(f"IOC log stopped — {len(collected)} activities")
                msg = f"IOC log stopped. {len(collected)} activities extracted."
                if act_path:
                    msg += f"\nPartial: {act_path}"
                self.on_response(msg)
            else:
                self._last_ioc_time = datetime.now()
                lines = [f"IOC log: {len(collected)} activities"]
                if act_path:
                    lines.append(f"  Activities CSV: {act_path}")
                    lines.append(f"  Beacons CSV:    {bcn_path}")
                if xlsx_path:
                    lines.append(f"  Excel:          {xlsx_path}")
                self.on_status(f"IOC log: {len(collected)} activities")
                self.on_response("\n".join(lines))
        except Exception as e:
            self.on_error(str(e))
            self.on_status("Error")

    def _do_ioc_chunk(self, raw_text: str, start_n: int = 1) -> list[Activity]:
        messages: list[dict] = [
            {"role": "user", "content": f"Extract all IOC activities from these logs:\n\n{raw_text}"}
        ]
        resp = self._llm.call(_IOC_SYSTEM, messages, tools=_IOC_TOOLS, max_tokens=8192,
                               model=cfg("ioc_model", None))
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "log_ioc_activities":
                inp = block.input
                if isinstance(inp, str):
                    inp = json.loads(inp)
                acts = []
                for i, a in enumerate(inp.get("activities") or []):
                    acts.append(Activity(
                        activity_id=f"ACT-{start_n + i:04d}",
                        beacon_id=a.get("beacon_id", ""),
                        timestamp_utc=a.get("timestamp_utc", ""),
                        execution_context=a.get("execution_context", ""),
                        execution_host=a.get("execution_host", ""),
                        command_action=a.get("command_action", ""),
                        result=a.get("result", ""),
                        observable_artifacts=a.get("observable_artifacts", ""),
                    ))
                return acts
        return []

    _IOC_FIELDS = [
        "activity_id", "beacon_id", "timestamp_utc", "execution_context",
        "execution_host", "command_action", "result", "observable_artifacts",
    ]

    def _append_ioc_rows(self, activities: list[Activity]) -> None:
        """Append newly extracted activities to the running session IOC CSV."""
        try:
            mode = "a" if self._session_ioc_initialized else "w"
            with open(self._session_ioc_path, mode, newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=self._IOC_FIELDS)
                if not self._session_ioc_initialized:
                    w.writeheader()
                    self._session_ioc_initialized = True
                for a in activities:
                    w.writerow({k: getattr(a, k, "") for k in self._IOC_FIELDS})
        except Exception:
            pass

    _BEACON_IOC_FIELDS = [
        "beacon_id", "c2_type", "hostname", "user", "external_ip",
        "internal_ips", "process", "listener", "first_seen", "last_seen",
    ]

    def _parse_beacon_blocks(self) -> list[dict]:
        """Parse # BEACON artifact blocks from all c2_events_*.log files."""
        if not self._log_dir or not self._log_dir.is_dir():
            return []
        seen: dict[str, dict] = {}
        block_re = re.compile(r'# BEACON ─+\n(.*?)# ─+', re.DOTALL)
        field_re = re.compile(r'#\s+([\w_]+):\s*(.*)')
        for path in sorted(self._log_dir.glob("c2_events_*.log")):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for match in block_re.finditer(text):
                b: dict[str, str] = {}
                for line in match.group(1).splitlines():
                    m = field_re.match(line.strip())
                    if m:
                        b[m.group(1).strip()] = m.group(2).strip()
                bid = b.get("beacon_id", "")
                if bid:
                    seen[bid] = b  # last-seen block wins (freshest last_seen)
        return list(seen.values())

    def _write_ioc_outputs(
        self, activities: list[Activity], since: "datetime | None"
    ) -> tuple[Path, Path, Path | None]:
        """Write activities CSV, beacons CSV, and (if openpyxl available) xlsx.
        Returns (activities_path, beacons_path, xlsx_path_or_None).
        """
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = f"_from_{since.strftime('%Y%m%d')}" if since else ""
        base   = self._output_dir / f"ioc{suffix}_{ts}"

        act_path = Path(str(base) + "_activities.csv")
        with open(act_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self._IOC_FIELDS)
            w.writeheader()
            for a in activities:
                w.writerow({k: getattr(a, k, "") for k in self._IOC_FIELDS})

        beacons  = self._parse_beacon_blocks()
        bcn_path = Path(str(base) + "_beacons.csv")
        with open(bcn_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self._BEACON_IOC_FIELDS)
            w.writeheader()
            for b in beacons:
                w.writerow({k: b.get(k, "") for k in self._BEACON_IOC_FIELDS})

        xlsx_path: Path | None = None
        try:
            import openpyxl
            wb  = openpyxl.Workbook()
            ws_b = wb.active
            ws_b.title = "Beacons"
            ws_b.append(self._BEACON_IOC_FIELDS)
            for b in beacons:
                ws_b.append([b.get(k, "") for k in self._BEACON_IOC_FIELDS])
            ws_a = wb.create_sheet("Activities")
            ws_a.append(self._IOC_FIELDS)
            for a in activities:
                ws_a.append([getattr(a, k, "") for k in self._IOC_FIELDS])
            xlsx_path = Path(str(base) + ".xlsx")
            wb.save(str(xlsx_path))
        except ImportError:
            pass

        return act_path, bcn_path, xlsx_path

    def _load_screenshot_blocks(self) -> list[dict]:
        """Load image files from notes_dir as base64 vision blocks."""
        import base64 as _b64
        if not self._notes_dir or not self._notes_dir.is_dir():
            return []
        _mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                 "gif": "image/gif", "webp": "image/webp"}
        blocks: list[dict] = []
        for p in sorted(self._notes_dir.iterdir()):
            mime = _mime.get(p.suffix.lstrip(".").lower())
            if not mime:
                continue
            try:
                data = _b64.standard_b64encode(p.read_bytes()).decode()
                blocks.append({"type": "image", "source": {"type": "base64", "media_type": mime, "data": data}})
            except Exception:
                pass
        return blocks

    def chat(self, message: str) -> None:
        threading.Thread(target=self._run_chat_bg, args=(message,), daemon=True).start()

    def save_session(self) -> Path | None:
        """Persist current state to session_state.json. Returns path or None if nothing to save."""
        if not self.activities and not self.beacons:
            return None
        path = self._output_dir / "session_state.json"
        data = {
            "saved_at": datetime.now().isoformat(),
            "activities": [asdict(a) for a in self.activities],
            "beacons": {k: asdict(v) for k, v in self.beacons.items()},
            "op_picture": self._op_picture,
            "next_beacon_n": self._next_beacon_n,
            "next_activity_n": self._next_activity_n,
            "last_ioc_time": self._last_ioc_time.isoformat() if self._last_ioc_time else None,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def load_session(self) -> str | None:
        """Load session_state.json if present. Returns a summary string or None."""
        path = self._output_dir / "session_state.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.activities      = [Activity(**a) for a in data.get("activities", [])]
            self.beacons         = {k: Beacon(**v) for k, v in data.get("beacons", {}).items()}
            self._op_picture     = data.get("op_picture", {})
            self._next_beacon_n  = data.get("next_beacon_n", 1)
            self._next_activity_n = data.get("next_activity_n", 1)
            raw_lit = data.get("last_ioc_time")
            self._last_ioc_time = datetime.fromisoformat(raw_lit) if raw_lit else None
            saved = data.get("saved_at", "unknown")[:16].replace("T", " ")
            return f"Resumed session from {saved} — {len(self.activities)} activities, {len(self.beacons)} beacons"
        except Exception as e:
            return f"Could not load session: {e}"

    def export_csv(self) -> tuple[Path, Path, Path | None]:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        bcn_fields = list(Beacon.__dataclass_fields__.keys())
        act_fields = list(Activity.__dataclass_fields__.keys())

        bp = self._output_dir / f"beacons_{ts}.csv"
        with open(bp, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=bcn_fields)
            w.writeheader()
            for b in self.beacons.values():
                w.writerow(asdict(b))

        ap = self._output_dir / f"activities_{ts}.csv"
        with open(ap, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=act_fields)
            w.writeheader()
            for a in self.activities:
                w.writerow(asdict(a))

        xp: Path | None = None
        try:
            import openpyxl
            wb   = openpyxl.Workbook()
            ws_b = wb.active
            ws_b.title = "Beacons"
            ws_b.append(bcn_fields)
            for b in self.beacons.values():
                ws_b.append([getattr(b, k, "") for k in bcn_fields])
            ws_a = wb.create_sheet("Activities")
            ws_a.append(act_fields)
            for a in self.activities:
                ws_a.append([getattr(a, k, "") for k in act_fields])
            xp = self._output_dir / f"session_{ts}.xlsx"
            wb.save(str(xp))
        except ImportError:
            pass

        return bp, ap, xp

    # ── Internal ──────────────────────────────────────────────────────────────

    def _next_bid(self) -> str:
        bid = f"C2-{self._next_beacon_n}"; self._next_beacon_n += 1; return bid

    def _next_aid(self) -> str:
        aid = f"ACT-{self._next_activity_n}"; self._next_activity_n += 1; return aid

    def _state_summary(self) -> str:
        if not self.beacons and not self._op_picture and not self.activities:
            return "No beacons or activities logged yet."
        parts: list[str] = []
        pic = self._op_picture
        if self.beacons:
            parts.append("BEACONS:")
            for b in self.beacons.values():
                line = f"  {b.beacon_id} [{b.c2_type or '?'}]: {b.user_context or '?'} on {b.hostname or '?'}"
                if b.external_ip:  line += f"  ext:{b.external_ip}"
                if b.internal_ips: line += f"  int:{b.internal_ips}"
                if b.process:      line += f"  proc:{b.process}"
                if b.listener:     line += f"  → {b.listener}"
                parts.append(line)
        if pic.get("access"):
            parts.append("ACCESS INVENTORY:")
            for a in pic["access"]:
                line = f"  {a.get('host','?')} — {a.get('user','?')} [{a.get('priv_level','?')}]"
                if a.get("beacon_id"): line += f"  beacon:{a['beacon_id']}"
                if a.get("notes"):     line += f"  | {a['notes']}"
                parts.append(line)
        if pic.get("discovered_assets"):
            parts.append("DISCOVERED ASSETS:")
            for d in pic["discovered_assets"]:
                line = f"  {d.get('asset','?')}"
                if d.get("services"): line += f"  — {d['services']}"
                if d.get("notes"):    line += f"  | {d['notes']}"
                parts.append(line)
        if pic.get("credential_material"):
            parts.append("CREDENTIAL MATERIAL:")
            for c in pic["credential_material"]: parts.append(f"  {c}")
        if pic.get("attack_paths"):
            parts.append("IDENTIFIED ATTACK PATHS:")
            for p in pic["attack_paths"]: parts.append(f"  → {p}")
        if pic.get("environment_notes"):
            parts.append("ENVIRONMENT:")
            parts.append(f"  {pic['environment_notes']}")
        parts.append(f"ACTIVITIES LOGGED: {len(self.activities)}")
        if self.activities:
            last = self.activities[-1]
            parts.append(f"  Last: {last.activity_id} — {last.command_action} ({last.timestamp_utc})")
        return "\n".join(parts)

    def _handle_batch(self, data: dict) -> str:
        for b in data.get("beacons") or []:
            bid = b.get("beacon_id") or self._next_bid()
            if bid not in self.beacons:
                self.beacons[bid] = Beacon(beacon_id=bid)
            beacon = self.beacons[bid]
            for k, v in b.items():
                if k != "beacon_id" and v and hasattr(beacon, k):
                    setattr(beacon, k, str(v))

        new_activities: list[Activity] = []
        for a in data.get("activities") or []:
            aid = a.get("activity_id") or self._next_aid()
            act = Activity(
                activity_id=aid,
                beacon_id=a.get("beacon_id", ""),
                timestamp_utc=a.get("timestamp_utc", ""),
                execution_context=a.get("execution_context", ""),
                execution_host=a.get("execution_host", ""),
                user_context=a.get("user_context", ""),
                remote_host=a.get("remote_host", ""),
                command_action=a.get("command_action", ""),
                result=a.get("result", ""),
                observable_artifacts=a.get("observable_artifacts", ""),
            )
            self.activities.append(act)
            new_activities.append(act)
        if new_activities:
            self._append_ioc_rows(new_activities)
            if self._c2:
                try:
                    self._c2.push_activities(new_activities)
                except NotImplementedError:
                    pass
                except Exception as e:
                    self.on_error(f"C2 push failed: {e}")

        if data.get("op_picture"):
            self._op_picture = data["op_picture"]

        adv = data.get("advisory") or {}
        parts: list[str] = []
        for item in adv.get("opsec") or []:    parts.append(f"[OPSEC] {item}")
        for item in adv.get("tactical") or []: parts.append(f"[TACTICAL] {item}")
        if adv.get("state"):                   parts.append(f"[STATE] {adv['state']}")
        return "\n".join(parts) or "[STATE] Log processed."

    @staticmethod
    def _truncate_ioc_entries(text: str, max_lines: int = 15) -> str:
        """Per ### block, keep only the first max_lines of output. Command header always kept."""
        sections = re.split(r"(?m)(?=^### )", text)
        out: list[str] = []
        for sec in sections:
            lines = sec.splitlines(keepends=True)
            if len(lines) <= max_lines + 1:
                out.append(sec)
                continue
            kept   = lines[:max_lines + 1]  # ## header line + max_lines of output
            dropped = len(lines) - len(kept)
            out.append("".join(kept) + f"[... {dropped} lines truncated]\n")
        return "".join(out)

    def _split_chunks(self, text: str) -> list[str]:
        """Split text at ### command log boundaries, grouping into chunks near analyze_chunk_size."""
        size = cfg("analyze_chunk_size", 40_000)
        if len(text) <= size:
            return [text]

        # Find all ## boundary positions (start of each command log entry)
        boundaries = [m.start() for m in re.finditer(r"^### ", text, re.MULTILINE)]

        if not boundaries:
            # No ### markers — fall back to line-aligned splitting
            chunks: list[str] = []
            while text:
                if len(text) <= size:
                    chunks.append(text)
                    break
                cut = text.rfind("\n", 0, size)
                if cut == -1:
                    cut = size
                chunks.append(text[:cut])
                text = text[cut:].lstrip("\n")
            return chunks

        chunks = []
        chunk_start = 0      # byte offset where current chunk starts
        chunk_size  = 0      # accumulated size of current chunk

        for i, pos in enumerate(boundaries):
            next_pos   = boundaries[i + 1] if i + 1 < len(boundaries) else len(text)
            entry_size = next_pos - pos

            # Anything before the first ## goes into the first chunk for free
            if pos == boundaries[0] and chunk_start < pos:
                chunk_size += pos - chunk_start

            if chunk_size + entry_size > size and chunk_size > 0:
                # Flush — split right before this entry
                chunks.append(text[chunk_start:pos])
                chunk_start = pos
                chunk_size  = entry_size
            else:
                chunk_size += entry_size

        # Flush remainder
        if chunk_start < len(text):
            chunks.append(text[chunk_start:])

        return chunks or [text]

    def _debug_dump(self, filename: str, content: str) -> None:
        try:
            path = self._output_dir / filename
            path.write_text(content, encoding="utf-8")
        except Exception:
            pass

    def _do_analysis(self, raw_text: str, images: list[dict] | None = None) -> str:
        system = _ANALYSIS_SYSTEM.format(verbosity=self.verbosity)
        content: list = [
            {"type": "text", "text": f"CURRENT OP STATE:\n{self._state_summary()}"},
            {"type": "text", "text": f"New log content to process:\n\n{raw_text}"},
        ]
        if images:
            for img in images:
                content.append(img)
            content.append({"type": "text", "text": "\nThe images above are analyst screenshots referenced in the op notes — treat them as additional evidence when populating activities and op_picture."})
        messages: list[dict] = [{"role": "user", "content": content}]
        if cfg("debug", False):
            import json as _json
            self._debug_dump("debug_request.json", _json.dumps(
                {"system": system, "messages": messages}, indent=2
            ))
        resp = self._llm.call(system, messages, tools=_ANALYSIS_TOOLS, max_tokens=8192)
        if cfg("debug", False):
            import json as _json
            try:
                self._debug_dump("debug_response.json", _json.dumps(
                    [{"type": b.type, **({
                        "name": b.name, "input": b.input
                    } if getattr(b, "type", None) == "tool_use" else {
                        "text": getattr(b, "text", "")
                    })} for b in resp.content], indent=2
                ))
            except Exception:
                pass
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "analyze_session":
                inp = block.input
                if isinstance(inp, str):
                    import json as _j
                    inp = _j.loads(inp)
                return self._handle_batch(inp)
        return "[STATE] Log processed. No structured findings returned."

    def _run_analysis_bg(self) -> None:
        with self._lock:
            chunks = list(self._pending)
            self._pending.clear()
        if not chunks:
            return
        raw = "\n".join(chunks)
        self.on_status("Analyzing…")
        try:
            with self._analysis_lock:
                advisory = self._do_analysis(raw)
            self.on_advisory(advisory)
            self.on_status("Ready")
        except Exception as e:
            self.on_error(str(e))
            self.on_status("Error")

    def _run_chat_bg(self, message: str) -> None:
        state = self._state_summary()
        with self._lock:
            pending = list(self._pending)
        if pending:
            max_chars = cfg("max_output_chars", 800)
            raw = "\n".join(pending)
            state += f"\n\nPENDING (queued, not yet analyzed):\n{raw[:max_chars * 10]}"

        system = _CHAT_SYSTEM.format(state_summary=state)
        self._history.append({"role": "user", "content": message})
        history = self._history[-20:]

        try:
            # Tool loop — AI may call read_file
            messages = list(history)
            while True:
                resp = self._llm.call(system, messages, tools=_CHAT_TOOLS,
                                     model=cfg("chat_model", None))
                tool_calls = [b for b in resp.content if b.type == "tool_use"]
                if not tool_calls:
                    text = "".join(b.text for b in resp.content if hasattr(b, "text"))
                    break
                messages.append({"role": "assistant", "content": resp.content})
                results = []
                for tc in tool_calls:
                    i = tc.input
                    if tc.name == "read_file":
                        result = _read_file(i.get("path", ""), i.get("max_lines", 150))
                    elif tc.name == "list_directory":
                        result = _list_directory(i.get("path", ""), i.get("pattern", "*"))
                    elif tc.name == "find_files":
                        result = _find_files(i.get("directory", ""), i.get("pattern", "*"), i.get("max_results", 50))
                    elif tc.name == "grep_file":
                        result = _grep_file(i.get("path", ""), i.get("pattern", ""), i.get("max_matches", 50))
                    elif tc.name == "write_file":
                        result = _write_file(i.get("path", ""), i.get("content", ""))
                    elif tc.name == "append_file":
                        result = _append_file(i.get("path", ""), i.get("content", ""))
                    elif tc.name == "fetch_url":
                        result = _fetch_url(i.get("url", ""))
                    elif tc.name == "web_search":
                        result = _web_search(i.get("query", ""), i.get("max_results", 5))
                    else:
                        result = "unknown tool"
                    results.append({"type": "tool_result", "tool_use_id": tc.id, "content": result})
                messages.append({"role": "user", "content": results})

            self._history.append({"role": "assistant", "content": text})
            if len(self._history) > 20:
                self._history = self._history[-20:]
            self.on_response(text)

        except Exception as e:
            self.on_error(str(e))

    def analyze_sync(self, raw_text: str) -> str:
        """Blocking — for batch/CLI mode."""
        return self._do_analysis(raw_text)


def _read_file(path: str, max_lines: int = 150) -> str:
    try:
        p = Path(path).expanduser()
        lines = p.read_text(errors="replace").splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n[... {len(lines) - max_lines} more lines truncated]"
        return "\n".join(lines)
    except Exception as e:
        return f"Error reading {path}: {e}"


def _list_directory(path: str, pattern: str = "*") -> str:
    try:
        p = Path(path).expanduser()
        entries = sorted(p.glob(pattern))
        lines = []
        for e in entries[:200]:
            try:
                size = e.stat().st_size
            except OSError:
                size = 0
            lines.append(f"{'d' if e.is_dir() else 'f'}  {size:>10}  {e.name}")
        if len(entries) > 200:
            lines.append(f"[... {len(entries) - 200} more entries]")
        return "\n".join(lines) if lines else "(empty)"
    except Exception as e:
        return f"Error listing {path}: {e}"


def _find_files(directory: str, pattern: str, max_results: int = 50) -> str:
    try:
        p = Path(directory).expanduser()
        results = sorted(p.rglob(pattern))[:max_results]
        lines = [str(r) for r in results]
        if len(results) == max_results:
            lines.append(f"[results capped at {max_results}]")
        return "\n".join(lines) if lines else "(no matches)"
    except Exception as e:
        return f"Error finding files: {e}"


def _grep_file(path: str, pattern: str, max_matches: int = 50) -> str:
    import re as _re
    try:
        p = Path(path).expanduser()
        lines = p.read_text(errors="replace").splitlines()
        try:
            rx = _re.compile(pattern, _re.IGNORECASE)
        except _re.error:
            rx = _re.compile(_re.escape(pattern), _re.IGNORECASE)
        matches = [(i + 1, line) for i, line in enumerate(lines) if rx.search(line)]
        out = [f"{n:6}: {line}" for n, line in matches[:max_matches]]
        if len(matches) > max_matches:
            out.append(f"[... {len(matches) - max_matches} more matches]")
        return "\n".join(out) if out else "(no matches)"
    except Exception as e:
        return f"Error searching {path}: {e}"


def _check_write_allowed(path: str) -> "tuple[Path, str | None]":
    """Return (resolved_path, error_string). error_string is None if write is allowed."""
    from core.llm_client import cfg as _cfg
    wd = _cfg("working_dir", "")
    if not wd:
        return Path(path), "Write blocked: working_dir is not set. Use /config set working_dir <path> to enable writes."
    try:
        target = Path(path).expanduser().resolve()
        base   = Path(wd).expanduser().resolve()
        target.relative_to(base)  # raises ValueError if outside
        return target, None
    except ValueError:
        return Path(path), f"Write blocked: {path} is outside working_dir ({wd})."
    except Exception as e:
        return Path(path), f"Write blocked: {e}"


def _write_file(path: str, content: str) -> str:
    target, err = _check_write_allowed(path)
    if err:
        return err
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"Written {len(content)} bytes to {target}"
    except Exception as e:
        return f"Error writing {path}: {e}"


def _append_file(path: str, content: str) -> str:
    target, err = _check_write_allowed(path)
    if err:
        return err
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as f:
            f.write(content)
        return f"Appended {len(content)} bytes to {target}"
    except Exception as e:
        return f"Error appending to {path}: {e}"


def _fetch_url(url: str) -> str:
    import urllib.request, urllib.parse, ipaddress, socket, re as _re
    from core.llm_client import cfg as _cfg
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return "Blocked: only http/https URLs are allowed."
        hostname = parsed.hostname or ""
    except Exception as e:
        return f"Invalid URL: {e}"
    # Block private / loopback / reserved addresses
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return f"Blocked: {hostname} resolves to a private/internal address ({ip})."
    except socket.gaierror as e:
        return f"DNS resolution failed for {hostname}: {e}"
    # Block configured target hosts
    blocked = _cfg("blocked_hosts", "")
    if blocked:
        for pattern in (p.strip() for p in blocked.split(",") if p.strip()):
            if hostname == pattern or hostname.endswith("." + pattern):
                return f"Blocked: {hostname} matches blocked_hosts entry '{pattern}'."
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(65536).decode("utf-8", errors="replace")
        # Strip tags and collapse whitespace for readable output
        text = _re.sub(r"<[^>]+>", " ", raw)
        text = _re.sub(r"\s+", " ", text).strip()
        if len(text) > 4000:
            text = text[:4000] + "\n[... truncated]"
        return text
    except Exception as e:
        return f"Error fetching {url}: {e}"


def _web_search(query: str, max_results: int = 5) -> str:
    import urllib.request, urllib.parse, json as _json
    from core.llm_client import cfg as _cfg
    key = os.environ.get("BRAVE_API_KEY") or _cfg("brave_api_key", "")
    if not key:
        return "Web search unavailable: set BRAVE_API_KEY env var or /config set brave_api_key <key>"
    url = "https://api.search.brave.com/res/v1/web/search?" + urllib.parse.urlencode({
        "q": query,
        "count": max(1, min(max_results, 10)),
    })
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "X-Subscription-Token": key,
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read())
    except Exception as e:
        return f"Search error: {e}"
    results = data.get("web", {}).get("results", [])
    if not results:
        return "(no results)"
    lines = []
    for r in results:
        lines.append(r.get("title", ""))
        lines.append(r.get("url", ""))
        desc = r.get("description", "").strip()
        if desc:
            lines.append(desc)
        lines.append("")
    return "\n".join(lines).strip()
