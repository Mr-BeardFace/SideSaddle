from __future__ import annotations
import re
from pathlib import Path
from datetime import datetime

_MAX_OUTPUT_LINES = 200

# ── ANSI / OSC stripping ──────────────────────────────────────────────────────
# Full OSC sequences (ESC ] ... BEL|ST) — stripped after title extraction
_ANSI = re.compile(
    r"\x1b(?:"
    r"\].*?(?:\x07|\x1b\\)"   # OSC: ESC ] ... BEL | ESC \
    r"|\[[0-9;?]*[@-~]"        # CSI: ESC [ ... final
    r"|[@-Z\\-_]"              # Fe: ESC single-byte
    r")"
    r"|\r|\x07|\x08"           # bare CR, BEL, and BS (backspace corrections)
)

def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


# ── prompt patterns ───────────────────────────────────────────────────────────

# Local zsh — two forms:
#   with timestamp:    [2026-10-11 23:15:07][user@host]:path$
#   without timestamp: [user@host]:path$
# Group 1 = timestamp (may be None), group 2 = user@host, group 3 = path
_LOCAL_PROMPT = re.compile(
    r"^(?:\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\])?"  # optional timestamp
    r"\[([^\]]+)\]:([^\$\n]*)\$"                           # [user@host]:path$
)

# Remote shell prompt: [user@host dir]$ or [user@host dir]#
# May be prefixed with stripped OSC remnant like "0;hostname:~"
_REMOTE_PROMPT = re.compile(
    r"^(?:[0-9];[^\[]*)?\[[\w\-\.]+@[\w\-\.]+ [^\]]+\][$#]\s*$"
)

# ── OSC title classification ──────────────────────────────────────────────────
# After the ESC] prefix is stripped, title lines look like:
#   "2;CMD_TEXT1;SHORT"    — command is running (window title = command)
#   "2;user@host:path1;..." — shell idle (window title = cwd)
# The presence of "7;file://" on the same OSC group means shell idle.

_SHELL_IDLE_OSC = re.compile(
    r"^2;[\w\-\.]+@[\w\-\.]+[:/]"  # 2;user@host:path = shell at prompt
)

def _parse_osc_title(line: str) -> tuple[str | None, str]:
    """
    Given a line starting with '2;', extract (command, trailing_output).
    Returns (None, '') when it's a shell-idle title (should be discarded).
    trailing_output is non-empty when output appears on the same line as the title
    (e.g. '2;cat file1;catfile_contents_here').
    """
    if not line.startswith("2;"):
        return None, ""
    # Shell-idle: "2;user@host:path..." — skip
    if _SHELL_IDLE_OSC.match(line):
        return None, ""
    # Also skip if it contains 7; (CWD indicator = shell idle group)
    if "7;file://" in line:
        return None, ""

    content = line[2:]  # strip "2;"
    trailing = ""

    if "1;" in content:
        cmd_part = content[:content.index("1;")].strip()
        rest = content[content.index("1;") + 2:]      # after "1;"
        # Short name is the first word of the full command
        short = cmd_part.split()[0] if cmd_part else ""
        # If rest starts with the short name, everything after it is output
        if short and rest.startswith(short):
            trailing = rest[len(short):]
        cmd = cmd_part
    else:
        cmd = content.strip()

    return (cmd if cmd else None), trailing


# ── assembled-command detection (no-PTY / char-echo) ─────────────────────────

def _reconstruct_from_echo(lines: list[str]) -> tuple[str, list[str]]:
    """
    In a no-PTY shell (nc reverse shell), each character is echoed individually
    and then the COMPLETE assembled command is echoed on its own line before output.

    Algorithm: running-concatenate the lines (whitespace-stripped); when we hit a
    line whose no-whitespace content equals the running concat's no-whitespace
    content, that's the assembled command.

    Returns (assembled_command, output_lines_after_it).
    Falls back to ("", all_lines) when no assembled command is found.
    """
    concat = ""
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        s_nows = re.sub(r"\s+", "", s)
        concat_nows = re.sub(r"\s+", "", concat)

        # This line equals what we've assembled so far → assembled command
        if concat_nows and s_nows == concat_nows:
            return s, [l for l in lines[i + 1:] if l.strip()]

        # This line starts with the running concat and is longer →
        # also an assembled command (happens when final chars came in a bigger chunk)
        if (concat_nows and len(s_nows) > len(concat_nows)
                and s_nows.startswith(concat_nows)):
            return s, [l for l in lines[i + 1:] if l.strip()]

        concat += s

    # Concat-match failed (terminal artifacts in char echo).
    # Fallback: scan from the BEGINNING for the first full-command-looking line
    # — in no-PTY sessions the assembled command appears AFTER the single-char
    # fragments but BEFORE the output; single chars (len≤2) are never commands.
    # ponytail: O(n), fine for log chunks; heuristic ceiling documented below
    for j, line in enumerate(lines):
        s = line.strip()
        # skip single/double char echo fragments
        if not s or len(s) <= 2:
            continue
        if _looks_like_full_command(s):
            return s, [l for l in lines[j + 1:] if l.strip()]

    return "", [l for l in lines if l.strip()]


def _looks_like_full_command(line: str) -> bool:
    """Heuristic: does this line look like a complete shell command (PTY mode)?"""
    s = line.strip()
    if not s or len(s) < 2:
        return False
    # Starts with a common command name
    return bool(re.match(
        r"^(ls|cd|cat|grep|find|ps|id|whoami|netstat|ss|uname|python[23]?|"
        r"bash|sh|sudo|wget|curl|nc|ssh|export|echo|mkdir|chmod|chown|"
        r"rm|cp|mv|tar|unzip|which|file|strings|head|tail|less|more|"
        r"script|env|set|printenv|history|ping|nmap|John|hydra|"
        r"perl|ruby|php|java|./)\b",
        s,
        re.IGNORECASE,
    )) or (" " in s and len(s) > 4)


# ── block ─────────────────────────────────────────────────────────────────────

_NOISE_LINES = re.compile(r"^[=>%\s]*$")  # pure prompt-suffix noise
_OSC_REMNANT = re.compile(r"^[0-9];")     # any stripped OSC remnant


class _Block:
    def __init__(self, timestamp: str | None, context: str):
        self.timestamp = timestamp        # from local prompt, or None
        self.context = context            # "local" | "remote"
        self.command_title: str | None = None  # from OSC 2 title
        self.lines: list[str] = []        # raw content lines
        self.extra_output: list[str] = [] # output fragments found inline with title
        self._title_at: int = -1          # len(lines) when title was set

    def add(self, line: str) -> None:
        s = line.strip()
        if s and not _NOISE_LINES.match(s):
            self.lines.append(s)

    def set_title(self, cmd: str, trailing: str = "") -> None:
        if not self.command_title:  # first title wins
            self.command_title = cmd
            self._title_at = len(self.lines)  # lines before this are char-echo noise
            if trailing.strip():
                self.extra_output.append(trailing.strip())

    def finalize(self) -> dict | None:
        # Filter OSC remnants and blank lines from content
        content = [l for l in self.lines if l.strip() and not _OSC_REMNANT.match(l)]
        if not content and not self.command_title and not self.extra_output:
            return None

        ts = self.timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        if self.command_title:
            # Lines before _title_at are char-echo noise; after = real output
            if self._title_at >= 0:
                post = [l for l in self.lines[self._title_at:]
                        if l.strip() and not _OSC_REMNANT.match(l)]
            else:
                post = content
            output_lines = self.extra_output + post
            return {
                "timestamp": ts,
                "command": self.command_title,
                "output": "\n".join(output_lines[:_MAX_OUTPUT_LINES]).strip(),
                "context": self.context,
            }

        if not content:
            return None

        if self.context == "local":
            # Local shell without title — shouldn't happen often, treat first line as cmd
            return {
                "timestamp": ts,
                "command": content[0],
                "output": "\n".join(content[1:_MAX_OUTPUT_LINES]).strip(),
                "context": self.context,
            }

        # Remote — try assembled-command reconstruction first
        cmd, output = _reconstruct_from_echo(content)
        if cmd:
            return {
                "timestamp": ts,
                "command": cmd,
                "output": "\n".join(output[:_MAX_OUTPUT_LINES]).strip(),
                "context": "remote-nc",
            }

        # PTY mode: check if first line looks like a full command
        if _looks_like_full_command(content[0]):
            return {
                "timestamp": ts,
                "command": content[0],
                "output": "\n".join(content[1:_MAX_OUTPUT_LINES]).strip(),
                "context": "remote-pty",
            }

        # Give up: return as raw blob so analyst still sees it
        return {
            "timestamp": ts,
            "command": "(remote session)",
            "output": "\n".join(content[:_MAX_OUTPUT_LINES]).strip(),
            "context": "remote-raw",
        }


# ── main entry points ─────────────────────────────────────────────────────────

def parse_chunks(raw: bytes) -> list[dict]:
    """
    Parse raw script/tty log bytes into [{timestamp, command, output, context}].

    Handles:
    - Local zsh prompts with timestamps + xterm OSC command titles (exact)
    - Remote PTY sessions after shell stabilization (full-line commands)
    - Remote no-PTY sessions (char-echo reconstruction)
    - Partial OSC strips: '2;CMD1;SHORT' lines from script-captured sessions
    """
    text = strip_ansi(raw.decode("utf-8", errors="replace"))
    lines = text.splitlines()

    chunks: list[dict] = []
    current: _Block | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # ── skip script header / footer ──────────────────────────────────────
        if stripped.startswith("Script started") or stripped.startswith("Script done"):
            continue

        # ── OSC title remnant: "2;..." ────────────────────────────────────────
        if stripped.startswith("2;"):
            cmd, trailing = _parse_osc_title(stripped)
            if cmd and current is not None:
                current.set_title(cmd, trailing)
            # Always skip the OSC line itself (don't add to content)
            continue

        # ── skip other OSC remnants: "0;...", "1;...", "7;..." ───────────────
        if _OSC_REMNANT.match(stripped) and "[$#]" not in stripped:
            continue

        # ── local prompt ──────────────────────────────────────────────────────
        m = _LOCAL_PROMPT.match(stripped)
        if m:
            if current is not None:
                chunk = current.finalize()
                if chunk:
                    chunks.append(chunk)
            # group(1) is None when the prompt has no embedded timestamp —
            # finalize() will use utcnow() as the fallback (replaced by DB
            # write-time once the storage layer is wired in)
            current = _Block(timestamp=m.group(1), context="local")
            continue

        # ── remote prompt ─────────────────────────────────────────────────────
        if _REMOTE_PROMPT.match(stripped):
            if current is not None:
                chunk = current.finalize()
                if chunk:
                    chunks.append(chunk)
            current = _Block(timestamp=None, context="remote")
            continue

        # ── content line ──────────────────────────────────────────────────────
        if current is not None:
            current.add(stripped)

    # finalize trailing block
    if current is not None:
        chunk = current.finalize()
        if chunk:
            chunks.append(chunk)

    # fallback: unrecognised format → single blob
    if not chunks:
        clean_lines = [l for l in lines if l.strip()]
        if clean_lines:
            chunks = [{
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "command": "(raw session — format unrecognised)",
                "output": "\n".join(clean_lines[:_MAX_OUTPUT_LINES]),
                "context": "raw",
            }]

    return chunks


def chunks_to_text(chunks: list[dict]) -> str:
    """Format parsed chunks into a clean, LLM-readable string."""
    parts = []
    for c in chunks:
        ctx = f"[{c.get('context', '?')}] " if c.get("context") else ""
        block = f"[{c['timestamp']}] {ctx}$ {c['command']}"
        if c.get("output"):
            out_lines = c["output"].splitlines()
            if len(out_lines) > 100:
                block += "\n" + "\n".join(out_lines[:100])
                block += f"\n... ({len(out_lines) - 100} more lines truncated)"
            else:
                block += "\n" + c["output"]
        parts.append(block)
    return "\n\n".join(parts)


def read_all_logs(op_dir: Path) -> str:
    """Read and parse ALL log files in op_dir for review."""
    all_chunks: list[dict] = []
    for log_file in sorted(op_dir.glob("*.log")):
        try:
            all_chunks.extend(parse_chunks(log_file.read_bytes()))
        except OSError:
            continue
    all_chunks.sort(key=lambda c: c["timestamp"])
    return chunks_to_text(all_chunks)
