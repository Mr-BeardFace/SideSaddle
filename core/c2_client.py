"""C2 teamserver backend client — activity forwarding stub.

Wire-up is complete; push_activities() raises NotImplementedError until
the teamserver log format is defined and implemented below.

Usage (once implemented):
    client = C2Client(url="http://teamserver:8080", token="...")
    client.push_activities(activities)
"""
from __future__ import annotations
import json
import urllib.request
from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.analyst import Activity


class C2Client:
    def __init__(self, url: str, token: str | None = None):
        self._url   = url.rstrip("/")
        self._token = token  # bearer token / API key for the teamserver

    # ── Public ────────────────────────────────────────────────────────────────

    def push_activities(self, activities: list["Activity"]) -> None:
        """Forward activities to the C2 teamserver.

        TODO: implement once teamserver log format is known.
        Pick one _format_* helper below (or write a new one), build the
        payload list, then call _post().
        """
        raise NotImplementedError(
            f"C2 push not yet implemented (target: {self._url})\n"
            "  1. Decide which _format_* helper fits your teamserver (or add one).\n"
            "  2. Build payload, call self._post(endpoint, payload).\n"
            "  3. Remove this raise."
        )

    # ── Format templates — pick / complete one ─────────────────────────────────

    def _format_cobalt_strike(self, activity: "Activity") -> dict:
        """Cobalt Strike external-C2 / aggressor log shape.
        CS teamserver HTTP API is not public — adapt to your aggressor script's
        listener endpoint schema.
        """
        # TODO: fill in fields once aggressor endpoint schema is known
        return {
            "bid":       "",          # beacon ID if relayed via C2
            "ts":        activity.timestamp_utc,
            "host":      activity.execution_host,
            "user":      activity.user_context,
            "cmd":       activity.command_action,
            "result":    activity.result,
            "artifacts": activity.observable_artifacts,
        }

    def _format_havoc(self, activity: "Activity") -> dict:
        """Havoc C2 teamserver REST log shape (Havoc >= 0.7 has an HTTP listener API).
        Endpoint: POST /api/v1/log  (or similar — check your Havoc build).
        """
        # TODO: confirm Havoc API schema from teamserver source
        return {
            "timestamp":  activity.timestamp_utc,
            "demon_id":   activity.beacon_id,
            "operator":   "",         # TODO: pull from config / SS_OP
            "hostname":   activity.execution_host,
            "command":    activity.command_action,
            "output":     activity.result,
            "iocs":       activity.observable_artifacts,
        }

    def _format_sliver(self, activity: "Activity") -> dict:
        """Sliver C2 — no native HTTP log API; typically forwarded via multiplayer
        event stream or a custom operator-side webhook.
        Shape below is a reasonable starting point for a custom listener.
        """
        # TODO: define webhook endpoint on Sliver teamserver side
        return {
            "time":     activity.timestamp_utc,
            "implant":  activity.beacon_id,
            "host":     activity.execution_host,
            "user":     activity.user_context,
            "command":  activity.command_action,
            "result":   activity.result,
            "ioc":      activity.observable_artifacts,
        }

    def _format_generic(self, activity: "Activity") -> dict:
        """Generic REST / SIEM-style log record — good starting point for any
        custom backend or log aggregator (Splunk HEC, Elastic, custom API).
        """
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
        """POST JSON payload to self._url + endpoint."""
        url  = self._url + endpoint
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout):
            pass  # raise on HTTP errors
