"""Nighthawk C2 backend for SideSaddle.

Pulls console logs from the NH teamserver and feeds them into the existing
### -format pipeline so the preprocessor and analyst handle them normally.

Polling strategy:
  - One request per agent per poll cycle so per-agent index tracking is exact.
  - Dead beacons (includeDisconnected=True) are polled until exhausted, then
    marked done — they won't be re-polled until restarted.
  - agent_index and agent_done are persisted to disk so restarts don't
    re-pull logs that were already processed.
"""
from __future__ import annotations
import json
import os
import ssl
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from core.c2_client import C2Backend

_POLL_COUNT  = 100               # entries per request
_STATE_FILE  = Path.home() / ".config" / "sidesaddle" / "nh_state.json"


class NighthawkBackend(C2Backend):
    """Pulls Nighthawk console logs on a timer, writes to c2_events.log."""

    c2_type = "NH"   # prefix used in ### headers; change for other NH-based backends

    def __init__(
        self,
        url: str,
        username: str | None = None,
        password: str | None = None,
        poll_seconds: int = 30,
        verify_tls: bool = True,
    ):
        super().__init__(url)
        self._username   = username
        self._password   = password
        self._poll_secs  = poll_seconds
        self._verify_tls = verify_tls

        self._session_id: str | None = None
        # per-agent log offset: {clientId: next_index_to_fetch}
        self._agent_index: dict[str, int] = {}
        # agents that are dead and fully drained — skip until restart
        self._agent_done: set[str] = set()
        # display name cache: clientId → "HOSTNAME\user"
        self._agent_names: dict[str, str] = {}
        # agents whose beacon artifact block has been written to c2_events.log
        self._agent_announced: set[str] = set()

        self._stop   = threading.Event()
        self._thread: threading.Thread | None = None

        self._load_state()

    # ── Public ────────────────────────────────────────────────────────────────

    def start_polling(self, callback: Callable[[str, str], None]) -> None:
        """callback(agent_id, text) — caller routes each agent to its own log file."""
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, args=(callback,), daemon=True, name="nh-poller"
        )
        self._thread.start()

    def stop_polling(self) -> None:
        self._stop.set()
        self._save_state()
        if self._session_id:
            try:
                self._logout()
            except Exception:
                pass

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _login(self) -> None:
        if not self._username or not self._password:
            raise ValueError(
                "Nighthawk auth: set c2.auth.username and c2.auth.password in config.yaml"
            )
        body = json.dumps({
            "username": self._username,
            "password": self._password,
        }).encode()
        resp = self._request("POST", "/api/v1.0/User/login", body=body)
        sid = resp.get("sessionId") or resp.get("session_id") or resp.get("id")
        if not sid:
            raise ValueError(f"NH login: no sessionId in response — got keys: {list(resp.keys())}")
        self._session_id = sid
        self._save_state()

    def _logout(self) -> None:
        if self._session_id:
            try:
                self._request("GET", f"/api/v1.0/User/logout/{self._session_id}")
            except Exception:
                pass
            self._session_id = None
            self._save_state()

    def _ensure_session(self) -> None:
        if not self._session_id:
            self._login()

    # ── State persistence ─────────────────────────────────────────────────────

    def _save_state(self) -> None:
        try:
            _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "url":         self._url,
                "session_id":  self._session_id,
                "agent_index": self._agent_index,
                "agent_done":  list(self._agent_done),
            }
            fd = os.open(str(_STATE_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
        except OSError:
            pass

    def _load_state(self) -> None:
        try:
            data = json.loads(_STATE_FILE.read_text())
            if data.get("url") != self._url:
                return  # different teamserver — start fresh
            self._session_id  = data.get("session_id")
            self._agent_index = data.get("agent_index") or {}
            self._agent_done  = set(data.get("agent_done") or [])
        except Exception:
            pass

    # ── NH API calls ──────────────────────────────────────────────────────────

    def get_agents(self, include_disconnected: bool = True) -> list[dict]:
        """Return list of AgentInfoResponse dicts (live + dead by default)."""
        self._ensure_session()
        qs = "?includeDisconnected=true" if include_disconnected else ""
        result = self._request("GET", f"/api/v1.0/Agent/list{qs}")
        # unwrap JsonRpcMethodResult wrapper if present
        if isinstance(result, dict):
            return result.get("innerResult") or result.get("result") or []
        if isinstance(result, list):
            return result
        return []

    def get_console_updates(
        self,
        client_id: str,
        index: int = 0,
        count: int = _POLL_COUNT,
        verb: str = "first",
    ) -> list[dict]:
        """POST /Console/list/{verb}/{count}/{index} for a single agent.

        verb="first" + ascending index = chronological replay from the start.
        """
        self._ensure_session()
        body = json.dumps([client_id]).encode()
        result = self._request(
            "POST",
            f"/api/v1.0/Console/list/{verb}/{count}/{index}",
            body=body,
        )
        if isinstance(result, dict):
            return result.get("innerResult") or result.get("result") or []
        if isinstance(result, list):
            return result
        return []

    # ── Poll loop ─────────────────────────────────────────────────────────────

    def _loop(self, callback: Callable[[str, str], None]) -> None:
        while not self._stop.is_set():
            try:
                self._poll_once(callback)
            except RuntimeError as e:
                msg = str(e)
                if "401" in msg or "403" in msg or "session" in msg.lower():
                    self._session_id = None
                    self._save_state()
            except Exception:
                pass
            self._stop.wait(self._poll_secs)

    def _poll_once(self, callback: Callable[[str, str], None]) -> None:
        agents = self.get_agents(include_disconnected=True)
        if not agents:
            return

        for agent in agents:
            cid = agent.get("clientId", "")
            if not cid:
                continue

            self._agent_names[cid] = self._agent_display_name(agent)
            connected = bool(agent.get("connected", True))

            # Write beacon artifact block on first ever contact with this agent
            if cid not in self._agent_announced:
                block = self._beacon_artifact_block(agent)
                if block:
                    callback(cid, block)
                self._agent_announced.add(cid)

            if cid in self._agent_done:
                continue  # fully drained dead beacon — skip

            idx     = self._agent_index.get(cid, 0)
            updates = self.get_console_updates(cid, index=idx)

            if updates:
                text = self._updates_to_log(updates, agent)
                if text.strip():
                    callback(cid, text)
                self._agent_index[cid] = idx + len(updates)

            # Fewer entries than requested + beacon is dead = fully drained
            if not connected and len(updates) < _POLL_COUNT:
                self._agent_done.add(cid)

        self._save_state()

    # ── Conversion ────────────────────────────────────────────────────────────

    def _updates_to_log(self, updates: list[dict], agent: dict) -> str:
        host  = self._agent_display_name(agent)
        lines: list[str] = []

        for u in updates:
            ts  = self._parse_ts(u.get("updateTime", ""))

            inp = u.get("inputUpdate") or {}
            if inp.get("inputText"):
                operator = inp.get("userName", "operator")
                cmd      = inp.get("inputText", "").strip()
                lines.append(f"### {ts} {self.c2_type}:{operator}  {cmd}  [C2: {host}]")

            txt = u.get("textUpdate") or {}
            if txt.get("consoleText"):
                lines.append(txt["consoleText"].rstrip())

            cr = (u.get("commandResponseUpdate") or {}).get("commandResponse") or {}
            if cr.get("output"):
                lines.append(str(cr["output"]).rstrip())

        return "\n".join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _agent_display_name(agent: dict) -> str:
        if agent.get("agentName"):
            return agent["agentName"]
        mi       = agent.get("detailedMachineInfo") or {}
        hostname = mi.get("machineName") or agent.get("externalIP", "")
        user     = mi.get("userName") or ""
        return f"{hostname}\\{user}" if user else hostname or (agent.get("clientId") or "")[:8]

    def _beacon_artifact_block(self, agent: dict) -> str:
        """Structured comment block written once per agent to c2_events.log."""
        mi       = agent.get("detailedMachineInfo") or {}
        hostname = mi.get("machineName", "")
        user     = mi.get("userName", "")
        pid      = mi.get("processId", "")
        pname    = mi.get("processName", "")
        ips_raw  = mi.get("ipAddresses") or []
        ips      = ", ".join(str(ip) for ip in ips_raw) if isinstance(ips_raw, list) else str(ips_raw)
        ext_ip   = agent.get("externalIP", "")
        listener = agent.get("listenerName", "")
        first    = self._parse_ts(agent.get("firstSeen", ""))
        last     = self._parse_ts(agent.get("lastActivity", ""))
        cid      = (agent.get("clientId") or "")[:8]
        proc     = f"{pname} (PID {pid})" if pname and pid else pname or (f"PID {pid}" if pid else "unknown")

        lines = [
            "# BEACON ─────────────────────────────────────────────",
            f"# c2_type:     {self.c2_type}",
            f"# beacon_id:   {cid}",
            f"# hostname:    {hostname}",
            f"# user:        {user}",
            f"# external_ip: {ext_ip}",
            f"# internal_ips: {ips}",
            f"# process:     {proc}",
            f"# listener:    {listener}",
            f"# first_seen:  {first}",
            f"# last_seen:   {last}",
            "# ─────────────────────────────────────────────────────",
        ]
        return "\n".join(lines)

    @staticmethod
    def _parse_ts(raw: str) -> str:
        if not raw:
            return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return raw[:19].replace("T", " ")

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, body: bytes | None = None) -> dict | list:
        url     = self._url + path
        # NH requires text/json — application/json returns 415
        headers = {"Content-Type": "text/json", "Accept": "text/json"}
        if self._session_id:
            headers["X-NHAPI-SESSION"] = self._session_id

        ctx = None
        if not self._verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"NH API {method} {path} → HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"NH API unreachable: {e.reason}") from e
