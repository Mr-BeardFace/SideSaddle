"""C2 teamserver backend — base class, format helpers, and factory.

Supported backends (configured via c2.type in config.yaml):
  nighthawk     — Nighthawk C2  (pull: polls console logs)
  cobalt_strike — Cobalt Strike (push: stub, format TBD)
  sliver        — Sliver C2     (push: stub, format TBD)
  havoc         — Havoc C2      (push: stub, format TBD)
  generic       — Custom REST   (push: generic JSON record)

config.yaml:
  c2:
    type: nighthawk
    url: https://teamserver:4443
    auth:
      username: operator
      password: changeme
      # token: xxx   # for token-based backends
    poll_seconds: 30   # pull backends only
"""
from __future__ import annotations
import json
import urllib.request
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from core.analyst import Activity


class C2Backend:
    """Base class for all C2 backends.

    Push backends: implement push_activities().
    Pull backends: implement start_polling() / stop_polling().
    """

    def __init__(self, url: str, token: str | None = None):
        self._url   = url.rstrip("/")
        self._token = token

    # ── Push interface (CS / Sliver / Havoc / generic) ────────────────────────

    def push_activities(self, activities: list["Activity"]) -> None:
        raise NotImplementedError(
            f"push_activities not implemented for {type(self).__name__}"
        )

    # ── Pull interface (Nighthawk, future pull backends) ──────────────────────

    def start_polling(self, callback: Callable[[str, str], None]) -> None:
        """Start background polling loop.
        callback(agent_id, text) — agent_id routes to the right log file."""

    def stop_polling(self) -> None:
        """Stop background polling loop."""

    # ── Format helpers (reuse in push implementations) ───────────────────────

    def _format_cobalt_strike(self, activity: "Activity") -> dict:
        return {
            "bid":       "",
            "ts":        activity.timestamp_utc,
            "host":      activity.execution_host,
            "user":      activity.user_context,
            "cmd":       activity.command_action,
            "result":    activity.result,
            "artifacts": activity.observable_artifacts,
        }

    def _format_havoc(self, activity: "Activity") -> dict:
        return {
            "timestamp":  activity.timestamp_utc,
            "demon_id":   activity.beacon_id,
            "operator":   "",
            "hostname":   activity.execution_host,
            "command":    activity.command_action,
            "output":     activity.result,
            "iocs":       activity.observable_artifacts,
        }

    def _format_sliver(self, activity: "Activity") -> dict:
        return {
            "time":    activity.timestamp_utc,
            "implant": activity.beacon_id,
            "host":    activity.execution_host,
            "user":    activity.user_context,
            "command": activity.command_action,
            "result":  activity.result,
            "ioc":     activity.observable_artifacts,
        }

    def _format_generic(self, activity: "Activity") -> dict:
        return {
            "timestamp":            activity.timestamp_utc,
            "activity_id":          activity.activity_id,
            "beacon_id":            activity.beacon_id,
            "execution_context":    activity.execution_context,
            "execution_host":       activity.execution_host,
            "user_context":         activity.user_context,
            "remote_host":          activity.remote_host,
            "command_action":       activity.command_action,
            "result":               activity.result,
            "observable_artifacts": activity.observable_artifacts,
        }

    # ── HTTP helper ───────────────────────────────────────────────────────────

    def _post(self, endpoint: str, payload: object, timeout: int = 10) -> None:
        url     = self._url + endpoint
        body    = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout):
            pass


# ── Factory ───────────────────────────────────────────────────────────────────

def build_c2_client(url_override: str | None = None) -> "C2Backend | None":
    """Build a C2 backend from config.yaml `c2:` block.

    url_override: value of --c2 CLI flag; overrides config c2.url.
    Returns None if no C2 is configured.
    """
    from core.llm_client import cfg

    c2_cfg = cfg("c2") or {}
    url    = url_override or c2_cfg.get("url") or cfg("c2_url")  # c2_url: legacy key
    if not url:
        return None

    kind = (c2_cfg.get("type") or "generic").lower().replace("-", "_")
    auth = c2_cfg.get("auth") or {}

    if kind == "nighthawk":
        from core.c2_nighthawk import NighthawkBackend
        return NighthawkBackend(
            url=url,
            username=auth.get("username"),
            password=auth.get("password"),
            poll_seconds=int(c2_cfg.get("poll_seconds", 30)),
        )

    # push-only stubs (implement push_activities when ready)
    token = auth.get("token")
    return C2Backend(url=url, token=token)
