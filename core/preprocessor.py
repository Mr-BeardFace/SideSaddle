"""Preprocess raw script captures into IOC and session logs.

Reads raw TTY output (from `script`) and produces two cleaned versions:
  ioc_text     — commands only; interactive sessions keep a truncated body
  session_text — full stripped output; TUI blocks collapsed to [TUI session]
"""
from __future__ import annotations
import re

# ── Patterns ──────────────────────────────────────────────────────────────────

_ANSI     = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-9;]*[ -/]*[@-~])')
_TUI_CHAR = re.compile(r'\x1b\[(?:2J|H|\d+;\d+H)')
_PROMPT   = re.compile(r'^(?:\*\S+\*\s+)?(?:PS\s+)?[\w:\\/~.\[\]-]{2,}[>#$%]\s*$', re.MULTILINE)
_BLOCK    = re.compile(r'(?m)(?=^### )')
# Matches any prompt line (bare or with command) — used to strip trailing echo from section bodies
_PROMPT_LINE = re.compile(r'^(?:\*\S+\*\s+)?(?:PS\s+)?[\w:\\/~.\[\]-]{2,}[>#$%]\s*')

# Extract just the command part from a ### header line
_HEADER_CMD = re.compile(r'^### \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+\s+(.+)$')

# Target extraction (applied to command portion only)
_IP       = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_HOST     = re.compile(r'(?:@|://)([a-zA-Z0-9][\w.-]{2,}(?:\.[a-zA-Z]{2,}))')
_S3_URL   = re.compile(r'(s3://[\w.-]+(?:/[\w./-]*)?)')
_GH_REPO  = re.compile(r'(?:github\.com/|/repos?/)([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)')
_CLOUD_RE = re.compile(r'^(aws|gcloud|gh|git|az|terraform|kubectl)\b', re.IGNORECASE)
_CLOUD_NAMES = {
    'aws': 'AWS API', 'gcloud': 'GCP API', 'gh': 'GitHub API',
    'git': 'GitHub/VCS', 'az': 'Azure API', 'terraform': 'Cloud API', 'kubectl': 'K8s API',
}

# Credential redaction
_CREDS = re.compile(
    r'(?<=-[pP] )(\S+)'
    r'|(?<=-pass )(\S+)'
    r'|(?<=--password )(\S+)'
    r'|(?<=--password=)(\S+)'
    r'|(?<=[^a-zA-Z]:)([^/@\s]+)(?=@[\w.-])',  # :password@host
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_ansi(text: str) -> str:
    return _ANSI.sub('', text)


def _is_tui(body_raw: str) -> bool:
    return bool(_TUI_CHAR.search(body_raw))


def _is_interactive(body_clean: str) -> bool:
    """Multiple prompt-like lines in the body means an interactive session."""
    return len(_PROMPT.findall(body_clean)) > 2


def _get_cmd(header_clean: str) -> str:
    """Extract the command portion from a ### header line."""
    m = _HEADER_CMD.match(header_clean.strip())
    return m.group(1) if m else ''


def _extract_target(cmd: str) -> str | None:
    m = _IP.search(cmd)
    if m:
        return m.group(1)
    m = _HOST.search(cmd)
    if m:
        return m.group(1)
    return None


def _cloud_target(cmd: str) -> str | None:
    if not _CLOUD_RE.match(cmd.lstrip()):
        return None
    m = _S3_URL.search(cmd) or _GH_REPO.search(cmd)
    if m:
        return m.group(1)
    tool = cmd.split()[0].lower() if cmd.split() else ''
    return _CLOUD_NAMES.get(tool)


def _annotate(header_clean: str) -> str:
    cmd = _get_cmd(header_clean)
    t   = _extract_target(cmd) or _cloud_target(cmd)
    return f"# [TARGET: {t or '<NEEDS ATTENTION>'}]\n"


def _redact(text: str) -> str:
    return _CREDS.sub('<REDACTED>', text)


def _strip_trailing_echo(body: str) -> str:
    """Remove trailing blank lines and prompt-echo lines from a section body."""
    lines = body.splitlines(keepends=True)
    while lines:
        last = lines[-1].rstrip('\r\n')
        if not last or _PROMPT_LINE.match(last):
            lines.pop()
        else:
            break
    return ''.join(lines)


def _truncate(lines: list[str], max_lines: int) -> list[str]:
    if len(lines) <= max_lines:
        return lines
    kept = lines[:max_lines]
    kept.append(f"[... {len(lines) - max_lines} lines truncated]\n")
    return kept


# ── Main entry point ──────────────────────────────────────────────────────────

def preprocess(
    raw: str,
    ioc_body_lines: int = 20,
    session_body_lines: int = 50,
) -> tuple[str, str]:
    """Transform raw script output → (ioc_text, session_text).

    ioc_text:     header + target annotation only; interactive sessions also keep
                  a truncated body so the LLM has remote-command context.
    session_text: header + target annotation + stripped output; TUI collapsed.
    """
    raw = _redact(raw)
    sections = _BLOCK.split(raw)
    ioc_parts:     list[str] = []
    session_parts: list[str] = []

    for sec in sections:
        if not sec.strip():
            continue
        lines       = sec.splitlines(keepends=True)
        header_raw  = lines[0] if lines else ''
        body_raw    = ''.join(lines[1:]) if len(lines) > 1 else ''

        header_clean = _strip_ansi(header_raw)
        # Skip pre-header noise (shell startup output before first ### marker)
        if not header_clean.startswith('### '):
            continue
        annotation   = _annotate(header_clean)
        body_clean   = _strip_trailing_echo(_strip_ansi(body_raw))

        # ── IOC log ──────────────────────────────────────────────────────────
        if _is_interactive(body_clean):
            body_lines = body_clean.splitlines(keepends=True)
            ioc_body   = ''.join(_truncate(body_lines, ioc_body_lines))
            ioc_parts.append(header_clean + annotation + ioc_body)
        else:
            ioc_parts.append(header_clean + annotation)

        # ── Session log ──────────────────────────────────────────────────────
        if _is_tui(body_raw):
            session_parts.append(header_clean + annotation + '[TUI session]\n')
        else:
            body_lines    = body_clean.splitlines(keepends=True)
            session_body  = ''.join(_truncate(body_lines, session_body_lines))
            session_parts.append(header_clean + annotation + session_body)

    return ''.join(ioc_parts), ''.join(session_parts)
