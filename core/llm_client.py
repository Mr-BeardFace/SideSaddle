"""LLM client for SideSaddle — Anthropic API key or subscription OAuth.

active_provider in config.yaml:
  anthropic     — standard API key (ANTHROPIC_API_KEY env var or keyring)
  anthropic-sub — Claude Pro/Max subscription via OAuth

Auth is discovered automatically in priority order:
  API key:      ANTHROPIC_API_KEY env → keyring "sidesaddle" → keyring "pentest-ai"
  Sub tokens:   $SIDESADDLE_SUB_TOKENS → ~/.config/sidesaddle/... → ~/.config/pdtmj-ai/...
  OAuth client: ~/.config/sidesaddle/providers_local.py → ~/.config/pdtmj-ai/providers_local.py
"""
from __future__ import annotations
import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path

import anthropic
import yaml


# ── Config ────────────────────────────────────────────────────────────────────

_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"
_cfg: dict | None = None


def _load() -> dict:
    global _cfg
    if _cfg is None:
        try:
            _cfg = yaml.safe_load(_CONFIG_PATH.read_text()) or {}
        except FileNotFoundError:
            _cfg = {}
    return _cfg


def cfg(key: str, default=None):
    return _load().get(key, default)


def set_cfg(key: str, value) -> None:
    c = _load()
    c[key] = value
    _CONFIG_PATH.write_text(yaml.dump(c, default_flow_style=False))
    global _cfg
    _cfg = c


# ── Exceptions ────────────────────────────────────────────────────────────────

class APIAuthError(Exception):
    pass


class APIRateLimitError(Exception):
    pass


class APIConnectionError(Exception):
    pass


# ── API-key path ──────────────────────────────────────────────────────────────

_KEYRING_SVC = "sidesaddle"
# Checked in order: own service first, then pdtmj-ai fallback
_KEYRING_FALLBACKS = ("sidesaddle", "pentest-ai")


def resolve_key() -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    try:
        import keyring
        for svc in _KEYRING_FALLBACKS:
            k = keyring.get_password(svc, "anthropic_api_key")
            if k:
                return k
    except Exception:
        pass
    return None


def store_key(key: str) -> None:
    try:
        import keyring
        keyring.set_password(_KEYRING_SVC, "anthropic_api_key", key)
    except Exception:
        pass


# ── Subscription OAuth path ───────────────────────────────────────────────────

# Set by _load_external_providers() from ~/.config/sidesaddle/providers_local.py
_SUB_CLIENT_ID  = ""
_SUB_TOKEN_URL  = "https://platform.claude.com/v1/oauth/token"
_SUB_AUTH_URL   = "https://claude.ai/oauth/authorize"
_SUB_REDIRECT   = "https://platform.claude.com/oauth/code/callback"
_SUB_SCOPES     = "org:create_api_key user:profile user:inference user:sessions:claude_code"
_SUB_BETAS      = [
    "claude-code-20250219",
    "oauth-2025-04-20",
    "interleaved-thinking-2025-05-14",
    "context-management-2025-06-27",
]
_SUB_SYS_PREFIX = "You are a Claude agent, built on Anthropic's Claude Agent SDK."
_EXPIRY_BUFFER  = 5 * 60  # refresh 5 min before expiry

_SUB_TOKENS_DEFAULT = Path.home() / ".config" / "sidesaddle" / "anthropic_sub_tokens.json"
_SUB_TOKENS_PDTMJ   = Path.home() / ".config" / "pdtmj-ai"   / "anthropic_sub_tokens.json"

_SUB_TOKENS_OVERRIDE: Path | None = None  # set by providers_local.py via api.set_tokens_path()
_active_token_path:   Path | None = None  # the file we last read tokens from; write target


def _token_paths() -> list[Path]:
    """Ordered list of token files to check, highest priority first."""
    paths: list[Path] = []
    if _SUB_TOKENS_OVERRIDE is not None:
        paths.append(_SUB_TOKENS_OVERRIDE)
    env = os.environ.get("SIDESADDLE_SUB_TOKENS")
    if env:
        paths.append(Path(env).expanduser())
    paths.append(_SUB_TOKENS_DEFAULT)
    paths.append(_SUB_TOKENS_PDTMJ)  # auto-fallback to pdtmj-ai tokens
    return paths


def _tokens_read() -> dict:
    global _active_token_path
    for path in _token_paths():
        try:
            data = json.loads(path.read_text())
            if data.get("anthropic_sub_access"):
                _active_token_path = path
                return data
        except Exception:
            pass
    _active_token_path = _SUB_TOKENS_OVERRIDE or _SUB_TOKENS_DEFAULT
    return {}


def _tokens_write(data: dict) -> None:
    path = _active_token_path or _SUB_TOKENS_OVERRIDE or _SUB_TOKENS_DEFAULT
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass


def _sub_refresh(data: dict) -> str | None:
    """Attempt a token refresh. Returns new access token or None."""
    refresh = data.get("anthropic_sub_refresh")
    if not refresh:
        return None
    try:
        body = json.dumps({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": _SUB_CLIENT_ID,
        }).encode()
        req = urllib.request.Request(
            _SUB_TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            d = json.loads(resp.read())
        if not d.get("access_token"):
            return None
        data["anthropic_sub_access"]  = d["access_token"]
        data["anthropic_sub_expires"] = str(int(time.time()) + int(d.get("expires_in", 3600)))
        if d.get("refresh_token"):
            data["anthropic_sub_refresh"] = d["refresh_token"]
        _tokens_write(data)
        return d["access_token"]
    except Exception:
        return None


def load_sub_token() -> str | None:
    """Return a valid subscription access token, refreshing if needed."""
    data = _tokens_read()
    access  = data.get("anthropic_sub_access")
    try:
        expires = int(data.get("anthropic_sub_expires") or 0)
    except ValueError:
        expires = 0

    if access and expires > int(time.time()) + _EXPIRY_BUFFER:
        return access

    # Try refresh; fall back to whatever we have (may be stale)
    return _sub_refresh(data) or access


def sub_login_url() -> tuple[str, str]:
    """Generate a PKCE authorize URL. Returns (url, verifier)."""
    import hashlib, secrets
    from urllib.parse import urlencode
    from base64 import urlsafe_b64encode

    def b64url(raw: bytes) -> str:
        return urlsafe_b64encode(raw).decode().rstrip("=")

    verifier  = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    url = _SUB_AUTH_URL + "?" + urlencode({
        "code": "true", "client_id": _SUB_CLIENT_ID,
        "response_type": "code", "redirect_uri": _SUB_REDIRECT,
        "scope": _SUB_SCOPES, "code_challenge": challenge,
        "code_challenge_method": "S256", "state": verifier,
    })
    return url, verifier


def sub_login_exchange(code_state: str, verifier: str) -> str:
    """Exchange auth code for tokens. code_state is '<code>#<state>' from the page.
    Returns a success message or raises on failure."""
    code, _, state = code_state.partition("#")
    body = json.dumps({
        "grant_type": "authorization_code",
        "code": code, "state": state or verifier,
        "client_id": _SUB_CLIENT_ID,
        "redirect_uri": _SUB_REDIRECT,
        "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(
        _SUB_TOKEN_URL, data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        d = json.loads(resp.read())
    if not d.get("access_token"):
        raise ValueError(f"Token exchange returned no access_token: {d}")
    data = _tokens_read()
    data["anthropic_sub_access"]  = d["access_token"]
    data["anthropic_sub_expires"] = str(int(time.time()) + int(d.get("expires_in", 3600)))
    if d.get("refresh_token"):
        data["anthropic_sub_refresh"] = d["refresh_token"]
    _tokens_write(data)
    return "Logged in. Set active_provider: anthropic-sub in config.yaml."


# ── Model listing ────────────────────────────────────────────────────────────

def fetch_models() -> list[tuple[str, str]]:
    """Fetch available models from the active provider.
    Returns [(id, display_name), ...]. Raises APIAuthError / APIConnectionError."""
    provider = cfg("active_provider", "anthropic")
    if provider == "anthropic-sub":
        token = load_sub_token()
        if not token:
            raise APIAuthError("No subscription token — run --login first")
        headers = {"Authorization": f"Bearer {token}", "anthropic-version": "2023-06-01"}
    elif provider == "anthropic":
        key = resolve_key()
        if not key:
            raise APIAuthError("No API key set")
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    else:
        return []  # bedrock / unknown — no HTTP models endpoint
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/models", headers=headers,
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return [(m["id"], m.get("display_name", m["id"])) for m in data.get("data", [])]
    except urllib.error.URLError as e:
        raise APIConnectionError(f"Could not reach Anthropic API: {e}") from e


# ── Prompt caching helper ─────────────────────────────────────────────────────

def _cache_last_user_msg(messages: list[dict]) -> list[dict]:
    """Mark the last user message block for prompt caching (saves token costs on long turns)."""
    if not messages or messages[-1].get("role") != "user":
        return messages
    last    = messages[-1]
    content = last.get("content")
    if isinstance(content, str):
        new_content = [{"type": "text", "text": content,
                        "cache_control": {"type": "ephemeral"}}]
    elif isinstance(content, list) and content and isinstance(content[-1], dict):
        new_content    = list(content)
        blk            = dict(new_content[-1])
        blk["cache_control"] = {"type": "ephemeral"}
        new_content[-1] = blk
    else:
        return messages
    return messages[:-1] + [{**last, "content": new_content}]


# ── Client ────────────────────────────────────────────────────────────────────

class LLMClient:
    def __init__(self, api_key: str | None = None):
        self._model    = cfg("model", "claude-sonnet-4-6")
        self._sub_mode = cfg("active_provider", "anthropic") == "anthropic-sub"

        if not self._sub_mode:
            self._client = anthropic.Anthropic(api_key=api_key or resolve_key())

    def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
        *,
        model: str | None = None,
    ):
        m = model or self._model
        if self._sub_mode:
            return self._call_sub(system, messages, tools, max_tokens, model=m)
        return self._call_api(system, messages, tools, max_tokens, model=m)

    # ── Subscription path ─────────────────────────────────────────────────────

    def _call_sub(self, system, messages, tools, max_tokens, model=None):
        token = load_sub_token()
        if not token:
            raise APIAuthError(
                "No subscription token found.\n"
                "Run: python3 SideSaddle.py --login\n"
                "Or set active_provider: anthropic in config.yaml to use an API key."
            )

        system_blocks = [
            {"type": "text", "text": _SUB_SYS_PREFIX},
            {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}},
        ]
        cached_messages = _cache_last_user_msg(messages)
        cached_tools = None
        if tools:
            cached_tools = list(tools)
            last = dict(cached_tools[-1])
            last["cache_control"] = {"type": "ephemeral"}
            cached_tools[-1] = last

        kwargs: dict = {
            "model":      model or self._model,
            "max_tokens": max_tokens,
            "system":     system_blocks,
            "messages":   cached_messages,
            "betas":      _SUB_BETAS,
        }
        if cached_tools:
            kwargs["tools"] = cached_tools

        retries, wait = 5, 8.0
        for attempt in range(retries + 1):
            sdk = anthropic.Anthropic(auth_token=token)
            try:
                return sdk.beta.messages.create(**kwargs)
            except anthropic.AuthenticationError:
                # One refresh attempt on first auth failure
                if attempt == 0:
                    data   = _tokens_read()
                    fresh  = _sub_refresh(data)
                    if fresh:
                        token = fresh
                        continue
                raise APIAuthError(
                    "Subscription token rejected — re-run: python3 SideSaddle.py --login"
                )
            except anthropic.RateLimitError as e:
                if attempt >= retries:
                    raise APIRateLimitError(
                        f"Subscription rate limit exceeded — wait a minute and try again\n"
                        f"(detail: {e})"
                    )
                time.sleep(wait); wait = min(wait * 2, 60)
            except anthropic.BadRequestError as e:
                raise APIRateLimitError(
                    f"Request rejected by subscription API — likely too large or malformed\n"
                    f"(detail: {e})"
                )
            except anthropic.APIConnectionError as e:
                if attempt >= retries:
                    raise APIConnectionError("Connection to Anthropic failed") from e
                time.sleep(wait); wait = min(wait * 2, 30)

    # ── API-key path ──────────────────────────────────────────────────────────

    def _call_api(self, system, messages, tools, max_tokens, model=None):
        kwargs: dict = {
            "model":      model or self._model,
            "max_tokens": max_tokens,
            "system":     system,
            "messages":   messages,
        }
        if tools:
            kwargs["tools"] = tools

        retries, wait = 3, 4.0
        for attempt in range(retries + 1):
            try:
                return self._client.messages.create(**kwargs)
            except anthropic.RateLimitError:
                if attempt >= retries:
                    raise APIRateLimitError("Rate limit exceeded — try again shortly")
                time.sleep(wait); wait = min(wait * 2, 30)
            except anthropic.AuthenticationError as e:
                raise APIAuthError("API key rejected — set ANTHROPIC_API_KEY or use /key") from e
            except anthropic.APIConnectionError as e:
                if attempt >= retries:
                    raise APIConnectionError("Connection to Anthropic failed") from e
                time.sleep(wait); wait = min(wait * 2, 30)
            except anthropic.BadRequestError:
                raise


# ── External providers (operator-private) ─────────────────────────────────────
# Drop ~/.config/sidesaddle/providers_local.py exposing register(api) to
# override _SUB_CLIENT_ID or the full subscription handler. Never committed.

def _ext_providers_path() -> Path:
    override = os.environ.get("SIDESADDLE_LOCAL_PROVIDERS")
    return Path(override) if override else Path.home() / ".config" / "sidesaddle" / "providers_local.py"


def _load_external_providers() -> None:
    import importlib.util, sys as _sys
    # 1. sidesaddle-specific providers_local.py (highest priority)
    path = _ext_providers_path()
    if path.is_file():
        try:
            spec = importlib.util.spec_from_file_location("sidesaddle_providers_local", str(path))
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            reg = getattr(mod, "register", None)
            if callable(reg):
                reg(_external_api())
        except Exception as e:
            print(f"[providers_local] failed to load {path}: {e}", file=_sys.stderr)

    # 2. Auto-discover OAuth CLIENT_ID from pdtmj-ai's providers_local.py if still unset
    if not _SUB_CLIENT_ID:
        _autodiscover_client_id()


def _autodiscover_client_id() -> None:
    """Read CLIENT_ID from pdtmj-ai's providers_local.py by text scan (no import needed)."""
    global _SUB_CLIENT_ID
    path = Path.home() / ".config" / "pdtmj-ai" / "providers_local.py"
    if not path.is_file():
        return
    try:
        import re
        text = path.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^CLIENT_ID\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
        if m:
            _SUB_CLIENT_ID = m.group(1)
    except Exception:
        pass


def _external_api():
    """Minimal API surface passed to providers_local.register()."""
    import types
    ns = types.SimpleNamespace()
    ns.set_sub_client_id = _set_sub_client_id
    ns.set_tokens_path   = _set_tokens_path
    return ns


def _set_sub_client_id(client_id: str) -> None:
    global _SUB_CLIENT_ID
    _SUB_CLIENT_ID = client_id


def _set_tokens_path(path) -> None:
    global _SUB_TOKENS_OVERRIDE
    _SUB_TOKENS_OVERRIDE = Path(path).expanduser()


_load_external_providers()
