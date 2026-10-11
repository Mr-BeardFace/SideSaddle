from __future__ import annotations
import importlib.util
import json
import os
import re
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

import anthropic
from core import config

# ── Subscription constants ────────────────────────────────────────────────────

_SUB_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
_SUB_AUTH_URL  = "https://claude.ai/oauth/authorize"
_SUB_REDIRECT  = "https://platform.claude.com/oauth/code/callback"
_SUB_SCOPES    = "org:create_api_key user:profile user:inference user:sessions:claude_code"
_SUB_BETAS     = [
    "claude-code-20250219",
    "oauth-2025-04-20",
    "interleaved-thinking-2025-05-14",
    "context-management-2025-06-27",
]
# Must be prepended to every system prompt on the subscription path
_SUB_SYS_PREFIX = "You are a Claude agent, built on Anthropic's Claude Agent SDK."
_EXPIRY_BUFFER  = 5 * 60  # refresh 5 min before expiry

_SUB_CLIENT_ID: str = ""

_TOKENS_DEFAULT = Path.home() / ".config" / "sidesaddle" / "anthropic_sub_tokens.json"
_TOKENS_PDTMJ   = Path.home() / ".config" / "pdtmj-ai"   / "anthropic_sub_tokens.json"
_TOKENS_OVERRIDE: Path | None = None
_active_token_path: Path | None = None

_MAX_RETRIES = 4


# ── Token helpers ─────────────────────────────────────────────────────────────

def _token_paths() -> list[Path]:
    paths: list[Path] = []
    if _TOKENS_OVERRIDE is not None:
        paths.append(_TOKENS_OVERRIDE)
    if env := os.environ.get("SIDESADDLE_SUB_TOKENS"):
        paths.append(Path(env).expanduser())
    paths.append(_TOKENS_DEFAULT)
    paths.append(_TOKENS_PDTMJ)
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
    _active_token_path = _TOKENS_OVERRIDE or _TOKENS_DEFAULT
    return {}


def _tokens_write(data: dict) -> None:
    path = _active_token_path or _TOKENS_OVERRIDE or _TOKENS_DEFAULT
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)


def _sub_refresh(data: dict) -> str | None:
    refresh = data.get("anthropic_sub_refresh")
    if not refresh or not _SUB_CLIENT_ID:
        return None
    try:
        body = json.dumps({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": _SUB_CLIENT_ID,
        }).encode()
        req = urllib.request.Request(
            _SUB_TOKEN_URL, data=body,
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
    data    = _tokens_read()
    access  = data.get("anthropic_sub_access")
    try:
        expires = int(data.get("anthropic_sub_expires") or 0)
    except ValueError:
        expires = 0
    if access and expires > int(time.time()) + _EXPIRY_BUFFER:
        return access
    return _sub_refresh(data) or access


# ── Login flow (PKCE) ─────────────────────────────────────────────────────────

def sub_login_url() -> tuple[str, str]:
    """Generate PKCE authorize URL. Returns (url, verifier)."""
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
    """Exchange auth code for tokens. code_state is '<code>#<state>'."""
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
    return "Logged in successfully. Set active_provider: anthropic-sub in config.yaml."


# ── External providers (providers_local.py) ───────────────────────────────────

def _set_sub_client_id(client_id: str) -> None:
    global _SUB_CLIENT_ID
    _SUB_CLIENT_ID = client_id


def _set_tokens_path(path) -> None:
    global _TOKENS_OVERRIDE
    _TOKENS_OVERRIDE = Path(path).expanduser()


def _external_api():
    import types
    ns = types.SimpleNamespace()
    ns.set_sub_client_id = _set_sub_client_id
    ns.set_tokens_path   = _set_tokens_path
    return ns


def _load_external_providers() -> None:
    global _SUB_CLIENT_ID
    # 1. sidesaddle providers_local.py
    local_path = Path(
        os.environ.get("SIDESADDLE_LOCAL_PROVIDERS", "")
    ) or Path.home() / ".config" / "sidesaddle" / "providers_local.py"

    if local_path.is_file():
        try:
            spec = importlib.util.spec_from_file_location("ss_providers_local", str(local_path))
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if callable(getattr(mod, "register", None)):
                mod.register(_external_api())
        except Exception:
            pass

    # 2. Auto-discover CLIENT_ID from pdtmj-ai's providers_local.py if still unset
    if not _SUB_CLIENT_ID:
        pdtmj_path = Path.home() / ".config" / "pdtmj-ai" / "providers_local.py"
        if pdtmj_path.is_file():
            try:
                text = pdtmj_path.read_text(encoding="utf-8", errors="replace")
                m = re.search(r'^CLIENT_ID\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
                if m:
                    _SUB_CLIENT_ID = m.group(1)
            except Exception:
                pass


_load_external_providers()


# ── Main call interface ───────────────────────────────────────────────────────

def _model() -> str:
    provider = config.get("active_provider", "anthropic")
    if provider == "bedrock":
        return config.get("bedrock.model", "us.anthropic.claude-opus-4-5-v1:0")
    return config.get("anthropic.model", "claude-opus-4-5-20251101")


def call(
    system: str,
    messages: list[dict],
    tools: list[dict] | None = None,
    max_tokens: int = 4096,
    extra_kwargs: dict[str, Any] | None = None,
) -> anthropic.types.Message:
    provider = config.get("active_provider", "anthropic")

    if provider == "bedrock":
        return _call_bedrock(system, messages, tools, max_tokens)
    if provider == "anthropic-sub":
        return _call_sub(system, messages, tools, max_tokens)
    return _call_api(system, messages, tools, max_tokens)


def _call_api(system, messages, tools, max_tokens):
    key = config.get_api_key("anthropic")
    client = anthropic.Anthropic(api_key=key)
    kwargs: dict[str, Any] = dict(model=_model(), max_tokens=max_tokens,
                                   system=system, messages=messages)
    if tools:
        kwargs["tools"] = tools
    return _retry(lambda: client.messages.create(**kwargs))


def _call_bedrock(system, messages, tools, max_tokens):
    client = anthropic.AnthropicBedrock(
        aws_profile=config.get("bedrock.profile", "default"),
        aws_region=config.get("bedrock.region", "us-east-1"),
    )
    kwargs: dict[str, Any] = dict(model=_model(), max_tokens=max_tokens,
                                   system=system, messages=messages)
    if tools:
        kwargs["tools"] = tools
    return _retry(lambda: client.messages.create(**kwargs))


def _call_sub(system, messages, tools, max_tokens):
    token = load_sub_token()
    if not token:
        raise anthropic.AuthenticationError(
            message="No subscription token. Run: python SideSaddle.py login",
            response=None, body=None,
        )

    system_blocks = [
        {"type": "text", "text": _SUB_SYS_PREFIX},
        {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}},
    ]
    kwargs: dict[str, Any] = dict(
        model=_model(), max_tokens=max_tokens,
        system=system_blocks, messages=messages,
        betas=_SUB_BETAS,
    )
    if tools:
        cached = list(tools)
        last   = dict(cached[-1])
        last["cache_control"] = {"type": "ephemeral"}
        cached[-1] = last
        kwargs["tools"] = cached

    attempt = 0
    while True:
        sdk = anthropic.Anthropic(auth_token=token)
        try:
            return sdk.beta.messages.create(**kwargs)
        except anthropic.AuthenticationError:
            if attempt == 0:
                data  = _tokens_read()
                fresh = _sub_refresh(data)
                if fresh:
                    token = fresh
                    attempt += 1
                    continue
            raise
        except (anthropic.RateLimitError, anthropic.APIConnectionError, anthropic.InternalServerError):
            if attempt >= _MAX_RETRIES:
                raise
            time.sleep(min(5 * 2 ** attempt, 60))
            attempt += 1


def _retry(fn):
    delay = 5
    for attempt in range(_MAX_RETRIES):
        try:
            return fn()
        except (anthropic.RateLimitError, anthropic.APIConnectionError, anthropic.InternalServerError):
            if attempt == _MAX_RETRIES - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 60)
