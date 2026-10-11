from __future__ import annotations

SLASH_COMMANDS = [
    "/export",
    "/key set ",
    "/key get ",
    "/config set ",
    "/config get ",
    "/c2 connect",
    "/c2 disconnect",
    "/op new ",
    "/op list",
    "/op load ",
    "/clear",
    "/status",
    "/help",
]


def complete(text: str) -> str | None:
    """Return the first matching slash command completion, or None."""
    if not text.startswith("/"):
        return None
    for cmd in SLASH_COMMANDS:
        if cmd.startswith(text) and cmd != text:
            return cmd
    return None


def parse_command(text: str) -> tuple[str, list[str]]:
    """Parse '/cmd arg1 arg2' -> ('cmd', ['arg1', 'arg2'])"""
    if not text.startswith("/"):
        return ("", [])
    parts = text[1:].split()
    if not parts:
        return ("", [])
    return (parts[0], parts[1:])
