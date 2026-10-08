# SideSaddle

> ⚠️ **Work in progress** — functional but actively developed. Interfaces, log formats, and C2 integration are subject to change.

A red team op logger and tactical advisor. Captures terminal sessions at the TTY level, extracts IOCs, and provides an AI-powered operator assistant to track state, flag OPSEC issues, and suggest next steps — all without leaving your terminal.

---

## What it does

- **TTY-level capture** via `script` — catches everything typed, including inside SSH, evil-winrm, and other interactive shells
- **Two-log pipeline** — raw capture preprocessed into an IOC log (commands only) and a session log (cleaned output for the advisor)
- **AI advisor** — Sonnet-powered chat that tracks your op picture: hosts, credentials found, attack paths, live OPSEC warnings
- **IOC extraction** — structured CSV export of every executed command with target attribution, execution context, and observable artifacts
- **Op-scoped logging** — all logs and outputs go to `<root>/<op>/`; multiple ops, no mixing
- **C2 backend stub** — plumbing for forwarding activities to a teamserver (format TBD — see `core/c2_client.py`)

---

## Requirements

- Python 3.11+
- Linux or WSL (TTY capture uses `script`)
- Anthropic API key **or** Claude Pro/Max subscription

```
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
| `output_root` | `~/sidesaddle-output` | Root for CSV exports |
| `model` | `claude-sonnet-4-6` | Default model |
| `ioc_model` | *(uses model)* | Model for IOC extraction — Haiku recommended |
| `chat_model` | *(uses model)* | Model for advisor chat |
| `debounce_seconds` | `30` | Seconds to wait before auto-analysis |
| `auto_analysis` | `true` | Auto-analyze on new log entries |

---

## Usage

```
python3 SideSaddle.py --op <name>           # TUI mode
python3 SideSaddle.py --op <name> --analyze # batch analysis of existing logs
python3 SideSaddle.py --op <name> --c2 <url> # with C2 backend (stub — not yet implemented)
python3 SideSaddle.py --login               # subscription auth flow
```

### TUI commands

| Command | Description |
|---------|-------------|
| `/ioc [YYYY-MM-DD \| all]` | Build IOC log from disk logs |
| `/export` | Export activities and beacons to CSV |
| `/info` | Session state snapshot |
| `/config` | View/change settings live |
| `/op` | Show current op and log paths |
| `/stop` | Cancel in-progress IOC analysis |
| `/help` | Full command reference |

`Tab` autocompletes commands. `Ctrl+N` → IOC log, `Ctrl+E` → export CSV, `Ctrl+I` → advisory history.

---

## Architecture

```
script (TTY capture)
  └─ raw_*.log
       └─ LogWatcher (5s poll)
            └─ preprocessor.preprocess()
                 ├─ ioc_acc.log  → IOC agent (Haiku) → ioc_log_*.csv
                 └─ session chunk → Advisor agent (Sonnet) → TUI + session_state.json
```

- **Preprocessor** — pure Python, no LLM; strips ANSI, collapses TUI sessions, annotates targets, redacts credentials
- **IOC agent** — extracts structured activity records; one call per chunk
- **Advisor agent** — maintains living op picture; answers operator questions; can read files via tool use
- **C2 client** — stub for forwarding to a teamserver (see `core/c2_client.py`)

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
- [x] C2 backend plumbing (stub)
- [ ] C2 push format implementation (Cobalt Strike / Havoc / Sliver / generic)
- [ ] Prompt caching for API-key path
- [ ] Web UI / multi-operator support

---

## License

MIT
