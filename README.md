# SideSaddle

Red team operator companion. Captures PTY sessions, watches logs in real time, and runs an LLM analyst that maintains a live tactical picture — findings, credentials, leads, and advisories — stored in an encrypted SQLite engagement database.

> **Authorized use only.** This tool is designed for professional red team engagements and penetration tests conducted with explicit written permission.

---

## What it does

- **Live log capture** — zsh hooks wrap `ssh`, `evil-winrm`, and raw TTY sessions via `script`, stripping ANSI and writing timestamped logs to the op directory
- **LLM analyst** — processes new log batches on a debounce loop; extracts commands, credentials, findings, hosts, surfaces, and persistence changes into structured state
- **Encrypted DB** — per-engagement SQLite with PBKDF2-SHA256 + AES-GCM; passphrase cached in system keyring for 72 hours
- **Suggested Commands panel** — top-10 open leads ranked by kill-chain frontier and prior probability, each with a literal runnable command and OPSEC severity badge
- **Actionable advisories** — structured analyst notes triggered only by direct log evidence; deduplicated across cycles; OPSEC-annotated
- **HTML report** — LLM report agent enriches findings with CVSS scores, impact, and remediation; renders a client-ready HTML deliverable sorted by severity
- **IOC export** — Excel workbook with Credentials, Findings, Leads, and Persistence sheets

---

## Requirements

- Python 3.11+
- An Anthropic API key (or Claude subscription via `sidesaddle login`)
- Linux / macOS for shell hooks (`script`, zsh); Windows supported for the TUI only

---

## Installation

```bash
git clone https://github.com/Mr-BeardFace/SideSaddle.git
cd SideSaddle
pip install -r requirements.txt
```

Set your API key:

```bash
python SideSaddle.py key set anthropic
```

Install the zsh hooks (optional — required for live TTY capture):

```bash
# Add to ~/.zshrc:
source /path/to/SideSaddle/shell/sidesaddle-hooks.zsh
```

---

## Usage

**Start a new op:**

```bash
python SideSaddle.py --op <op-name>
```

**Resume an existing op:**

```bash
python SideSaddle.py --op <op-name>
# select [C]ontinue at the prompt
```

**Read-only review:**

```bash
python SideSaddle.py review <op-name>
```

**List saved ops:**

```bash
python SideSaddle.py list
```

**Start TTY capture** (after sourcing the hooks):

```bash
ss_op
```

SSH sessions are captured automatically when the hooks are sourced.

---

## TUI commands

| Command | Description |
|---|---|
| `/op new <name>` | Create a new op |
| `/op list` | List saved ops |
| `/scope <target>` | Add a scope target |
| `/report` | Generate HTML report for current op |
| `/ioc` | Export IOC workbook (.xlsx) |
| `/key set <provider>` | Set an API key |
| `/help` | Show all commands |

---

## Architecture

```
SideSaddle.py          CLI entry point (Click)
core/
  analyst.py           LLM analyst loop + tool execution
  preprocessor.py      Log parser — PTY echo reconstruction, chunk extraction
  engagement_state.py  Pydantic models (Lead, Finding, Credential, …)
  store.py             SQLite engagement DB with AES-GCM encryption
  report.py            Report agent — finding enrichment + HTML render
  auth.py              Passphrase resolution + keyring cache
  llm_client.py        Anthropic client (API key + subscription paths)
  config.py            Op directory + API key management
  debug.py             Structured trace logger (--debug / --verbose)
ui/
  app.py               Textual TUI application
  commands.py          /command handler
shell/
  sidesaddle-hooks.zsh zsh hooks for ssh, evil-winrm, ss_op
  log_processor.py     ANSI stripper / real-time log writer
agents/redteam/        Phase-specific analyst guidance (persona, recon, …)
reporting/templates/   Jinja2 HTML report template
```

---

## Security notes

- Engagement DBs are encrypted at rest (AES-GCM, PBKDF2-SHA256 at 600k iterations)
- Credentials are stored in the DB only — never in plaintext logs or debug output
- The LLM analyst runs entirely within your infrastructure; no engagement data is sent to external services except the LLM provider API
- `web_search` (when enabled) filters against scope targets, beacon hosts, and known credentials before executing
- The analyst never executes commands on target systems; it reads logs only
