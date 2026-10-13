from __future__ import annotations
import threading
import time
from pathlib import Path
from typing import Callable

from core import config
from core import debug as dbg


class LogWatcher:
    """
    Polls log files in the op directory for new content.
    Calls on_new_content(path, new_bytes) for each file that grew.
    """

    def __init__(self, on_new_content: Callable[[Path, bytes], None]) -> None:
        self._on_new = on_new_content
        self._cursors: dict[Path, int] = {}
        self._running = False
        self._thread: threading.Thread | None = None
        self._interval = config.get("analyst.interval", 10)

    def start(self, cursors: dict[str, int] | None = None) -> None:
        if cursors:
            self._cursors = {Path(k): v for k, v in cursors.items()}
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def get_cursors(self) -> dict[str, int]:
        return {str(k): v for k, v in self._cursors.items()}

    def _run(self) -> None:
        while self._running:
            self._poll()
            time.sleep(self._interval)

    # ponytail: simple substring ignore — extend to glob/regex if more patterns needed
    _IGNORE = {"sidesaddle", "debug", "pdtmj"}

    def _should_ignore(self, name: str) -> bool:
        n = name.lower()
        extra = config.get("analyst.ignore_logs", "")
        patterns = self._IGNORE | {p.strip() for p in extra.split(",") if p.strip()}
        return any(p in n for p in patterns)

    def _poll(self) -> None:
        op = config.log_dir()
        log_files = [f for f in op.glob("*.log") if not self._should_ignore(f.name)]
        dbg.trace("watcher", f"poll  dir={op}  files={[f.name for f in log_files]}")
        for log_file in log_files:
            size = log_file.stat().st_size
            cursor = self._cursors.get(log_file, 0)
            dbg.trace("watcher", f"  {log_file.name}  size={size}  cursor={cursor}  new={size - cursor}b")
            if size > cursor:
                with open(log_file, "rb") as f:
                    f.seek(cursor)
                    new_bytes = f.read()
                self._cursors[log_file] = size
                if new_bytes:
                    dbg.trace("watcher", f"  → queuing {len(new_bytes)}b from {log_file.name}")
                    self._on_new(log_file, new_bytes)
