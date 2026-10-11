from __future__ import annotations
import getpass
import json
from datetime import datetime, timedelta

import keyring

_SERVICE = "sidesaddle"
_TTL_HOURS = 72
_WARN_HOURS = 24  # warn when < 24h remain


def _kr_key(op_name: str) -> str:
    return f"passphrase:{op_name}"


def cache_passphrase(op_name: str, passphrase: str) -> None:
    payload = json.dumps({
        "passphrase": passphrase,
        "stored_at": datetime.utcnow().isoformat(),
    })
    try:
        keyring.set_password(_SERVICE, _kr_key(op_name), payload)
    except Exception:
        pass  # keyring unavailable in some headless environments; silently skip


def clear_passphrase_cache(op_name: str) -> None:
    try:
        keyring.delete_password(_SERVICE, _kr_key(op_name))
    except Exception:
        pass


def cached_expires_at(op_name: str) -> datetime | None:
    """Returns UTC expiry time of cached passphrase, or None if not cached / expired."""
    raw = keyring.get_password(_SERVICE, _kr_key(op_name))
    if not raw:
        return None
    try:
        data = json.loads(raw)
        stored = datetime.fromisoformat(data["stored_at"])
        expires = stored + timedelta(hours=_TTL_HOURS)
        return expires if expires > datetime.utcnow() else None
    except Exception:
        return None


def resolve_passphrase(op_name: str, force_prompt: bool = False) -> tuple[str, bool]:
    """
    Returns (passphrase, was_prompted).

    Resolution order:
    1. Keyring cache (if within TTL and not force_prompt)
    2. Interactive getpass prompt

    The caller is responsible for calling cache_passphrase() after a successful
    DB open when was_prompted=True (so a wrong passphrase is never cached).
    """
    if not force_prompt:
        raw = keyring.get_password(_SERVICE, _kr_key(op_name))
        if raw:
            try:
                data = json.loads(raw)
                stored = datetime.fromisoformat(data["stored_at"])
                if datetime.utcnow() - stored < timedelta(hours=_TTL_HOURS):
                    return data["passphrase"], False
            except Exception:
                pass

    passphrase = getpass.getpass(f"Passphrase for '{op_name}': ")
    return passphrase, True


def expiry_warning(op_name: str) -> str | None:
    """
    Returns a warning string when the cached passphrase expires within _WARN_HOURS,
    or None if the cache is healthy or missing (missing = user just typed it).
    """
    expires = cached_expires_at(op_name)
    if expires is None:
        return None
    remaining = expires - datetime.utcnow()
    hours = int(remaining.total_seconds() / 3600)
    if hours <= _WARN_HOURS:
        return (
            f"Passphrase cache expires in {max(0, hours)}h "
            f"— run with --passphrase to renew (72h)"
        )
    return None
