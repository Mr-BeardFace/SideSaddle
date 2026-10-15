"""
SideSaddle headless daemon.

Spawned by `saddle start --op <name>`. Runs LogWatcher + Analyst without a TUI.
Writes <op_dir>/.badge for RPROMPT and serves a Unix socket for `saddle ai`.
Exits when all registered shell sessions are gone (ref-count via sessions/<pid> files).
"""
from __future__ import annotations
import json
import os
import re
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

_SS_BASE = Path.home() / ".local" / "share" / "sidesaddle"
_SESSIONS_DIR = _SS_BASE / "sessions"

_OPSEC_RE = re.compile(r"OPSEC\s*\[(high|critical)\]", re.IGNORECASE)


def _op_dir(op: str) -> Path:
    return _SS_BASE / op


def _socket_path(op: str) -> Path:
    return _op_dir(op) / ".daemon.sock"


def _badge_path(op: str) -> Path:
    return _op_dir(op) / ".badge"


def _write_badge(op: str, badge: str | None, badge_type: str | None) -> None:
    path = _badge_path(op)
    if badge:
        path.write_text(f"{badge}\n{badge_type or ''}\n")
    else:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


def _live_pids() -> set[int]:
    """Return PIDs in sessions dir that are still alive; prune dead ones."""
    _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    alive = set()
    for f in _SESSIONS_DIR.iterdir():
        try:
            pid = int(f.name)
            os.kill(pid, 0)  # signal 0 = liveness check, no signal sent
            alive.add(pid)
        except (ValueError, ProcessLookupError):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        except PermissionError:
            alive.add(int(f.name))  # process exists, we lack perms — still alive
    return alive


class _Daemon:
    def __init__(self, op: str, passphrase: str) -> None:
        self._op = op
        self._passphrase = passphrase
        self._analyst = None
        self._frontier_prev: str = "recon"
        self._notable_count_prev: int = 0
        self._badge: str | None = None
        self._badge_type: str | None = None
        self._stop_evt = threading.Event()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        from core import config
        from core.analyst import Analyst
        from core.engagement_state import EngagementState
        from core.log_watcher import LogWatcher
        from core.store import EngagementStore, BadPassphrase

        config.set_value("op.name", self._op)
        config.publish_log_dir()

        db_path = config.op_dir() / "engagement.db"
        try:
            store = EngagementStore(db_path, self._passphrase)
        except BadPassphrase:
            sys.exit("daemon: bad passphrase")
        except Exception as e:
            sys.exit(f"daemon: store open failed: {e}")
        finally:
            self._passphrase = ""  # clear immediately after use

        state = store.load_state()
        self._frontier_prev = state.frontier
        self._notable_count_prev = sum(1 for l in state.leads if l.insight == "notable")

        analyst = Analyst(
            state=state,
            on_activity=self._on_activity,
            on_state_update=self._on_state_update,
            store=store,
        )
        self._analyst = analyst

        log_watcher = LogWatcher(on_new_content=analyst.queue_new_content)
        log_watcher.start(cursors=store.get_cursors())
        analyst.start()

        _write_badge(self._op, None, None)

        # Unix socket
        sock_path = _socket_path(self._op)
        try:
            sock_path.unlink(missing_ok=True)
        except Exception:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(4)
        server.settimeout(1.0)
        threading.Thread(target=self._serve, args=(server, analyst), daemon=True).start()

        # Session watcher: stop when all PIDs gone
        while not self._stop_evt.is_set():
            time.sleep(30)
            if not _live_pids():
                break

        analyst.stop()
        log_watcher.stop()
        store.close()
        try:
            server.close()
        except Exception:
            pass
        try:
            sock_path.unlink(missing_ok=True)
        except Exception:
            pass
        _write_badge(self._op, None, None)

    # ── Analyst callbacks ─────────────────────────────────────────────────────

    def _on_state_update(self, state) -> None:
        """Called once per analysis cycle after merge_update. Resets badge for this cycle."""
        # Reset — badge reflects THIS cycle only
        self._badge = None
        self._badge_type = None

        if state.frontier != self._frontier_prev:
            self._badge = state.frontier
            self._badge_type = "frontier"
            self._frontier_prev = state.frontier

        notable_now = sum(1 for l in state.leads if l.insight == "notable")
        if notable_now > self._notable_count_prev and self._badge_type is None:
            self._badge = "lead"
            self._badge_type = "notable_lead"
        self._notable_count_prev = notable_now
        # Flush deferred — on_activity will flush with any opsec additions

    def _on_activity(self, msg: str) -> None:
        """Called once per advisory line (or 'no findings') after on_state_update."""
        m = _OPSEC_RE.search(msg)
        if m and self._badge_type not in ("frontier", "notable_lead"):
            self._badge = f"OPSEC {m.group(1).upper()}"
            self._badge_type = "opsec"
        _write_badge(self._op, self._badge, self._badge_type)

    # ── Socket server ─────────────────────────────────────────────────────────

    def _serve(self, server: socket.socket, analyst) -> None:
        while True:
            try:
                conn, _ = server.accept()
            except (socket.timeout, OSError):
                if self._stop_evt.is_set():
                    return
                continue
            threading.Thread(target=self._handle, args=(conn, analyst), daemon=True).start()

    def _handle(self, conn: socket.socket, analyst) -> None:
        try:
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            msg = json.loads(data.split(b"\n")[0])
            msg_type = msg.get("type")

            if msg_type == "chat":
                reply = analyst.chat(msg.get("message", ""))
                conn.sendall(json.dumps({"type": "reply", "text": reply}).encode() + b"\n")

            elif msg_type == "status":
                state = analyst._state
                conn.sendall(json.dumps({
                    "type": "status",
                    "running": True,
                    "op": self._op,
                    "frontier": state.frontier,
                    "badge": self._badge,
                    "badge_type": self._badge_type,
                }).encode() + b"\n")

            elif msg_type == "clear_badge":
                self._badge = None
                self._badge_type = None
                _write_badge(self._op, None, None)
                conn.sendall(json.dumps({"type": "ok"}).encode() + b"\n")

            elif msg_type == "stop":
                conn.sendall(json.dumps({"type": "ok"}).encode() + b"\n")
                self._stop_evt.set()

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="SideSaddle headless daemon")
    p.add_argument("--op", required=True, help="Op name")
    args = p.parse_args()

    passphrase = os.environ.pop("SIDESADDLE_PASSPHRASE", "")
    if not passphrase:
        try:
            from core.auth import resolve_passphrase
            passphrase, _ = resolve_passphrase(args.op, force_prompt=False)
        except Exception as e:
            sys.exit(f"daemon: no passphrase available — {e}")

    _Daemon(op=args.op, passphrase=passphrase).run()


if __name__ == "__main__":
    main()
