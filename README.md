# SideSaddle

LLM-assisted red team companion. Run it alongside an engagement — it watches your terminal logs, maintains a live tactical picture, and surfaces findings, credentials, suggested commands, and OPSEC-annotated advisories as you work. Everything is stored in an encrypted per-op database.

**Authorized use only.**

---

## How it works

SideSaddle has two parts: shell hooks that capture your terminal sessions to log files, and a TUI that watches those files and runs an LLM analyst in the background.

The analyst reads each new log batch, extracts structured data (commands, credentials, findings, hosts, persistence changes), and updates the engagement state. It surfaces actionable next steps in the Suggested Commands panel — each with a literal runnable command and an OPSEC severity rating — and posts advisory notes directly to the activity feed when there's something worth acting on.

At the end of an op, generate an HTML report. The report agent enriches every finding with CVSS scores, impact, and remediation, then writes an executive summary and full attack narrative.

---

## Requirements

- Python 3.11+
- Anthropic API key (or Claude subscription — `python SideSaddle.py login`)
- zsh + `script` for live TTY capture (Linux/macOS); the TUI runs on Windows without capture

---

## Setup

```bash
git clone https://github.com/Mr-BeardFace/SideSaddle.git
cd SideSaddle
pip install -r requirements.txt
python SideSaddle.py key set anthropic
```

Add the shell hooks to `~/.zshrc`:

```bash
source /path/to/SideSaddle/shell/sidesaddle-hooks.zsh
```

Once sourced, `ssh` and `evil-winrm` sessions are captured automatically. Run `ss_op` to capture a raw TTY session.

---

## Usage

```bash
# New op
python SideSaddle.py --op <name>

# Resume
python SideSaddle.py --op <name>   # select [C]ontinue

# Read-only review
python SideSaddle.py review <name>

# List ops
python SideSaddle.py list
```

---

## TUI commands

| Command | Description |
|---|---|
| `/op new <name>` | Create a new op |
| `/scope <target>` | Add a scope target |
| `/report` | Generate HTML report |
| `/ioc` | Export IOC workbook (.xlsx) |
| `/key set <provider>` | Set an API key |
| `/help` | Show all commands |

---

## Storage

Each op gets its own directory under `~/.local/share/sidesaddle/<op-name>/`:

- `engagement.db` — AES-GCM encrypted SQLite (PBKDF2-SHA256, 600k iterations)
- `*.log` — timestamped terminal logs watched by the analyst
- `report_*.html` — generated reports
- `ioc_*.xlsx` — IOC exports
- `ai_workspace/` — files written by the LLM analyst

The passphrase is cached in the system keyring for 72 hours. Set `SIDESADDLE_PASSPHRASE` to skip the prompt in automated contexts.
