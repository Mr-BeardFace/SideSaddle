"""
Debug trace logger.
Enable with --debug flag (traces) or --verbose (traces + LLM calls + DB writes + all actions).
Writes to <op_dir>/debug.log — tail -f it in a separate terminal.
"""
from __future__ import annotations
import os
import threading
from datetime import datetime
from pathlib import Path

_enabled = False
_verbose = False
_lock = threading.Lock()
_log_path: Path | None = None


def init(op_dir: Path, debug: bool = False, verbose: bool = False) -> None:
    """Call once on startup to set the log file path and enable level."""
    global _log_path, _enabled, _verbose
    _enabled = debug or verbose
    _verbose = verbose
    if _enabled:
        _log_path = op_dir / "debug.log"
        _log_path.parent.mkdir(parents=True, exist_ok=True)
        level = "verbose" if verbose else "debug"
        _write(f"=== SideSaddle {level} trace started pid={os.getpid()} ===")


def trace(component: str, msg: str) -> None:
    """Debug-level trace — emitted with --debug or --verbose."""
    if not _enabled:
        return
    _write(f"[{component}] {msg}")


def verbose(component: str, msg: str) -> None:
    """Verbose-level trace — emitted only with --verbose."""
    if not _verbose:
        return
    _write(f"[{component}:V] {msg}")


def is_verbose() -> bool:
    return _verbose


def _write(msg: str) -> None:
    ts = datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
    line = f"{ts}  {msg}\n"
    with _lock:
        if _log_path:
            try:
                with open(_log_path, "a") as f:
                    f.write(line)
            except Exception:
                pass
        else:
            import sys
            sys.stderr.write(line)
