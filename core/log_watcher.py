"""Poll ~/.local/share/session-logs/*.log for new content.

Instead of hard-coded regex parsing, raw text chunks are passed to the caller
so the LLM can intelligently extract entries from any log format.
"""
from __future__ import annotations
import threading
from pathlib import Path
from typing import Callable


class LogWatcher:
    """Polls log_dir/*.log every `poll` seconds, passes new raw text to callback.

    Buffers partial content per file so a read that lands mid-entry doesn't
    lose data — the buffered remainder is prepended to the next read.
    """

    def __init__(
        self,
        log_dir: str | Path,
        callback: Callable[[str], None],
        poll: float = 5.0,
        glob: str = "raw_*.log",
    ):
        self._dir  = Path(log_dir).expanduser()
        self._callback = callback
        self._poll = poll
        self._glob = glob
        self._offsets: dict[Path, int] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._dir.is_dir():
                chunks: list[str] = []
                for path in sorted(self._dir.glob(self._glob)):
                    offset = self._offsets.get(path, 0)
                    try:
                        with path.open("rb") as f:
                            f.seek(offset)
                            raw = f.read()
                            self._offsets[path] = f.tell()
                    except OSError:
                        continue
                    if raw:
                        chunks.append(raw.decode("utf-8", errors="replace"))
                if chunks:
                    self._callback("\n".join(chunks))
            self._stop.wait(self._poll)
