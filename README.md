# SideSaddle

> ⚠️ **Work in progress** — functional but actively developed. Interfaces, log formats, and C2 integration are subject to change.

A red team op logger and tactical advisor. Captures terminal sessions at the TTY level, pulls C2 console logs, extracts IOCs, and provides an AI-powered operator assistant to track state, flag OPSEC issues, and suggest next steps — all without leaving your terminal.

---

## What it does

- **TTY-level capture** via `script` — catches everything typed, including inside SSH, evil-winrm, and other interactive shells
- **C2 log polling** — pulls Nighthawk console logs per-beacon, correlates with terminal activity; stubs ready for Cobalt Strike / Sliver / Havoc
- **AI advisor** — Sonnet-powered chat that tracks your op picture: hosts, credentials found, attack paths, live OPSEC warnings; sees both terminal and C2 activity
- **IOC extraction** — structured export of every executed command with beacon attribution, execution context (`C2 > HOST` / `Proxychains > C2 > HOST` / `<local>`), and observable artifacts
- **IOC export** — activities CSV + beacons CSV + Excel workbook (two sheets) per run
- **Op-scoped logging** — all logs and outputs go to `<root>/<op>/`; multiple ops, no mixing

---

## Requirements

- Python 3.11+
- Linux or WSL (TTY capture uses `script`)
- Anthropic API key **or** Claude Pro/Max subscription

```bash
pip install -r requirements.txt
```

---

## Quick start

**1. Set up your op station (Linux/WSL — run once):**

```bash
bash configure.sh
```

This installs the zsh hooks, sets up `script` auto-start, and writes the evil-winrm prompt override.

**2. Set your op and open a new terminal:**

```bash
ssop op1          # sets SS_OP, creates log dir
# open a new terminal — script starts automatically
```

**3. Run SideSaddle:**

```bash
python3 SideSaddle.py --op op1
```

The `--op` flag is required. Alternatives:

```bash
SS_OP=op1 python3 SideSaddle.py          # env var
# or set current_op: op1 in config.yaml  # persistent
```

**4. (First time) Set your API key:**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or for Claude subscription:
python3 SideSaddle.py --login
```

---

## Configuration

Copy `config.yaml.example` to `config.yaml` and edit:

```bash
cp config.yaml.example config.yaml
```

Key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `log_root` | `~/.local/share/sidesaddle` | Root for op log folders |
| `output_root` | `~/sidesaddle-output` | Root for CSV/Excel exports |
| `model` | `claude-sonnet-4-6` | Default model |
| `ioc_model` | *(uses model)* | Model for IOC extraction — Haiku recommended |
| `chat_model` | *(uses model)* | Model for advisor chat |
| `debounce_seconds` | `30` | Seconds to wait before auto-analysis |
| `auto_analysis` | `true` | Auto-analyze on new log entries |

### C2 backend

```yaml
c2:
  type: nighthawk          # nighthawk | cobalt_strike | sliver | havoc | generic
  url: https://teamserver:4443
  auth:
    username: operator
    password: changeme
  poll_seconds: 30         # how often to pull console logs
  verify_tls: true         # set false for self-signed certs
```

The `--c2 <url>` flag overrides `c2.url` at runtime. NH session token is cached to `~/.config/sidesaddle/nh_state.json`; per-agent poll state persists across restarts.

---

## Usage

```
python3 SideSaddle.py --op <name>            # TUI mode
python3 SideSaddle.py --op <name> --analyze  # batch analysis of existing logs
python3 SideSaddle.py --op <name> --c2 <url> # override C2 URL at runtime
python3 SideSaddle.py --login                # subscription auth flow
```

### TUI commands

| Command | Description |
|---------|-------------|
| `/ioc [YYYY-MM-DD \| all]` | Build IOC log — writes activities CSV, beacons CSV, and Excel |
| `/export` | Export live session state to CSV + Excel |
| `/info` | Session state snapshot |
| `/config` | View/change settings live |
| `/op` | Show current op and log paths |
| `/stop` | Cancel in-progress IOC analysis |
| `/help` | Full command reference |

`Tab` autocompletes commands. `Ctrl+N` → IOC log, `Ctrl+E` → export, `Ctrl+I` → advisory history.

---

## Architecture

```
script (TTY capture)
  └─ raw_*.log
       └─ LogWatcher (5s poll)
            └─ preprocessor.preprocess()
                 ├─ ioc_acc.log  → IOC agent (Haiku) → ioc_*_activities.csv
                 └─ session chunk → Advisor agent (Sonnet) → TUI + session_state.json

NH teamserver (or other C2)
  └─ NighthawkBackend (poll_seconds interval)
       └─ Console/list per agent
            ├─ c2_events_{clientId}.log  ─┐
            │    # BEACON artifact block  │→ /ioc reads both → ioc_*_beacons.csv
            │    ### commands             │                  → ioc_*.xlsx
            └────────────────────────────┘
            └─ NewLog → Advisor agent (live C2 context)
```

- **Preprocessor** — pure Python, no LLM; strips ANSI, collapses TUI sessions, annotates targets, redacts credentials
- **IOC agent** — extracts structured activity records with `beacon_id` and execution context; one LLM call per chunk
- **Advisor agent** — maintains living op picture; correlates C2 and terminal activity; answers operator questions
- **C2 backend** — `build_c2_client()` factory reads `c2.type` from config; NH pull implemented; push stubs for CS/Sliver/Havoc in `core/c2_client.py`

### IOC output files

`/ioc` produces three files per run (all in `output_root/<op>/`):

| File | Purpose |
|------|---------|
| `ioc_{ts}_activities.csv` | Every executed command — `beacon_id`, `execution_context`, `execution_host`, `command_action`, `result`, `observable_artifacts` |
| `ioc_{ts}_beacons.csv` | C2 artifacts — `c2_type`, `hostname`, `external_ip`, `internal_ips`, `process`, `listener`, `first_seen`, `last_seen` |
| `ioc_{ts}.xlsx` | Both sheets in one workbook (requires `openpyxl`) |

### Execution contexts

| Context | Meaning |
|---------|---------|
| `C2 > HOST` | Command sent directly through a beacon |
| `Proxychains > C2 > HOST` | Local command routed through a beacon's SOCKS proxy |
| `<local>` | Direct connection from OpStation with no C2 (flag as OPSEC risk) |

---

## Evil-WinRM target attribution

The `configure.sh` script installs a PowerShell prompt override that injects `$env:COMPUTERNAME` into every evil-winrm prompt line. This lets the preprocessor attribute commands to the correct target without any extra tooling.

```powershell
# Loaded automatically via: evil-winrm -s ~/.local/share/evil-winrm-scripts/
function prompt {
    "*Evil-WinRM* PS [$env:COMPUTERNAME] $PWD> "
}
```

---

## Status / roadmap

- [x] TTY capture via `script`
- [x] Two-log pipeline (IOC + session)
- [x] Target annotation and credential redaction in preprocessor
- [x] Op-scoped logging with `--op` flag
- [x] Per-agent model split (ioc_model / chat_model)
- [x] Env check on startup
- [x] Nighthawk C2 — per-beacon log polling, beacon artifacts, cross-source correlation
- [x] IOC export — activities CSV + beacons CSV + Excel workbook
- [ ] C2 push implementation (Cobalt Strike / Havoc / Sliver / generic)
- [ ] Prompt caching for API-key path
- [ ] Web UI / multi-operator support

---

## License

MIT
