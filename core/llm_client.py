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


# ── Provider registry ────────────────────────────────────────────────────────
# Adding a provider = one entry here. /provider set, /provider model list,
# and the OAI-compat HTTP backend all derive from this table.

from dataclasses import dataclass, field as _dc_field


@dataclass(frozen=True)
class ProviderSpec:
    name:          str
    label:         str
    keyring_key:   str
    env_var:       str
    key_prefixes:  tuple[str, ...]
    native:        bool = False        # True → Anthropic SDK; False → OpenAI-compat HTTP
    chat_url:      str  = ""
    models_url:    str  = ""
    auth_style:    str  = "bearer"     # "bearer" | "x-api-key"
    free_only:     bool = False        # /models list shows only free models
    extra_headers: dict = _dc_field(default_factory=dict)
    key_optional:  bool = False
    base_url_config: str = ""          # config key for a runtime base URL (local provider)


PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        name="anthropic", label="Anthropic",
        keyring_key="anthropic_api_key", env_var="ANTHROPIC_API_KEY",
        key_prefixes=("sk-ant-",), native=True,
        models_url="https://api.anthropic.com/v1/models", auth_style="x-api-key",
    ),
    "openrouter": ProviderSpec(
        name="openrouter", label="OpenRouter",
        keyring_key="openrouter_api_key", env_var="OPENROUTER_API_KEY",
        key_prefixes=("sk-or-",),
        chat_url="https://openrouter.ai/api/v1/chat/completions",
        models_url="https://openrouter.ai/api/v1/models", free_only=True,
        extra_headers={"HTTP-Referer": "https://sidesaddle", "X-Title": "SideSaddle"},
    ),
    "nvidia": ProviderSpec(
        name="nvidia", label="NVIDIA",
        keyring_key="nvidia_api_key", env_var="NVIDIA_API_KEY",
        key_prefixes=("nvapi-",),
        chat_url="https://integrate.api.nvidia.com/v1/chat/completions",
        models_url="https://integrate.api.nvidia.com/v1/models",
    ),
    "local": ProviderSpec(
        name="local", label="Local (OpenAI-compatible)",
        keyring_key="local_api_key", env_var="LOCAL_API_KEY",
        key_prefixes=(), key_optional=True,
        base_url_config="local_base_url",
    ),
}

_NATIVE_PROVIDERS = {"anthropic", "bedrock", "anthropic-sub"}


def get_provider(name: str | None) -> ProviderSpec | None:
    return PROVIDERS.get((name or "").lower())


def _base_url_for(spec: ProviderSpec) -> str:
    if not spec.base_url_config:
        return ""
    return (config.get(spec.base_url_config, "") or "").rstrip("/")


def _chat_url_for(spec: ProviderSpec) -> str:
    base = _base_url_for(spec)
    return f"{base}/chat/completions" if base else spec.chat_url


def _models_url_for(spec: ProviderSpec) -> str:
    base = _base_url_for(spec)
    return f"{base}/models" if base else spec.models_url


def resolve_provider_key(spec: ProviderSpec) -> str | None:
    env = os.environ.get(spec.env_var)
    if env:
        return env
    return config.get_api_key(spec.name)


def _auth_headers(spec: ProviderSpec, key: str | None) -> dict:
    if not key:
        return {}
    if spec.auth_style == "x-api-key":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    return {"Authorization": f"Bearer {key}"}


def _is_temperature_rejected(msg: str) -> bool:
    low = msg.lower()
    return "temperature" in low and any(
        kw in low for kw in ("deprecat", "not support", "unsupported",
                             "not allowed", "cannot", "invalid")
    )


# ── OpenAI-compat format converters ──────────────────────────────────────────

def _block_as_dict(block) -> dict:
    if isinstance(block, dict):
        return block
    return {
        "type":  getattr(block, "type",  ""),
        "text":  getattr(block, "text",  ""),
        "id":    getattr(block, "id",    ""),
        "name":  getattr(block, "name",  ""),
        "input": getattr(block, "input", {}),
    }


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    result: list[dict] = []
    for msg in messages:
        role, content = msg["role"], msg["content"]
        if isinstance(content, str):
            result.append({"role": role, "content": content})
            continue
        if role == "assistant":
            text_parts, tool_calls = [], []
            for raw in content:
                b = _block_as_dict(raw)
                if b.get("type") == "text" and b.get("text"):
                    text_parts.append(b["text"])
                elif b.get("type") == "tool_use":
                    tool_calls.append({
                        "id": b["id"], "type": "function",
                        "function": {"name": b["name"],
                                     "arguments": json.dumps(b.get("input", {}))},
                    })
            out: dict = {"role": "assistant", "content": " ".join(text_parts) or None}
            if tool_calls:
                out["tool_calls"] = tool_calls
            result.append(out)
        elif role == "user":
            text_parts = []
            for raw in content:
                b = _block_as_dict(raw)
                btype = b.get("type", "")
                if btype == "tool_result":
                    body = b.get("content", "")
                    if isinstance(body, list):
                        body = " ".join(_block_as_dict(x).get("text", "") for x in body)
                    result.append({"role": "tool", "tool_call_id": b.get("tool_use_id", ""),
                                   "content": str(body)})
                elif btype == "text" and b.get("text"):
                    text_parts.append(b["text"])
            if text_parts:
                result.append({"role": "user", "content": "\n\n".join(text_parts)})
    return result


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    result = []
    for tool in tools:
        params = dict(tool.get("input_schema", {}))
        params.pop("cache_control", None)
        result.append({"type": "function", "function": {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "parameters": params,
        }})
    return result


from dataclasses import dataclass as _dc, field as _dcf


@_dc
class _TextBlock:
    type: str = "text"
    text: str = ""


@_dc
class _ToolUseBlock:
    type:  str  = "tool_use"
    id:    str  = ""
    name:  str  = ""
    input: dict = _dcf(default_factory=dict)


@_dc
class _Usage:
    input_tokens:  int = 0
    output_tokens: int = 0
    cache_read_input_tokens:     int = 0
    cache_creation_input_tokens: int = 0


@_dc
class _OAIMessage:
    stop_reason: str   = "end_turn"
    content:     list  = _dcf(default_factory=list)
    usage:       _Usage = _dcf(default_factory=_Usage)


def _openai_response_to_anthropic(data: dict) -> "_OAIMessage":
    choice   = data.get("choices", [{}])[0]
    finish   = choice.get("finish_reason", "stop")
    message  = choice.get("message", {})
    stop     = {"tool_calls": "tool_use", "length": "max_tokens"}.get(finish, "end_turn")
    content: list = []
    text = message.get("content")
    if text:
        content.append(_TextBlock(type="text", text=text))
    for tc in message.get("tool_calls") or []:
        fn = tc.get("function", {})
        try:
            inputs = json.loads(fn.get("arguments", "{}"))
        except Exception:
            inputs = {}
        content.append(_ToolUseBlock(type="tool_use", id=tc.get("id", ""),
                                     name=fn.get("name", ""), input=inputs))
    ud = data.get("usage", {})
    usage = _Usage(input_tokens=ud.get("prompt_tokens", 0),
                   output_tokens=ud.get("completion_tokens", 0))
    return _OAIMessage(stop_reason=stop, content=content, usage=usage)


# ── OAI-compat HTTP call (OpenRouter / NVIDIA / local) ───────────────────────

# Per-session set of model IDs that rejected `temperature` (populated once, avoids repeated 400s)
_no_temperature: set[str] = set()


def _call_openai_compat(spec: ProviderSpec, model: str, system: str,
                        messages: list[dict], tools: list[dict] | None,
                        max_tokens: int) -> "_OAIMessage":
    import httpx

    key = resolve_provider_key(spec)
    if not key and not spec.key_optional:
        raise RuntimeError(f"{spec.label}: no API key — run /key set {spec.name} <key>")
    if spec.base_url_config and not _base_url_for(spec):
        raise RuntimeError(f"{spec.label}: no base URL — run /provider set local <url>")

    oai_messages = [{"role": "system", "content": system}] + _to_openai_messages(messages)
    payload: dict[str, Any] = {"model": model, "messages": oai_messages, "max_tokens": max_tokens}
    temp = config.get("temp")
    if temp is not None and model not in _no_temperature:
        payload["temperature"] = temp
    if tools:
        payload["tools"] = _to_openai_tools(tools)
        payload["tool_choice"] = "auto"

    headers = {"Content-Type": "application/json",
               **_auth_headers(spec, key), **spec.extra_headers}

    delay = 4.0
    for attempt in range(_MAX_RETRIES + 2):
        try:
            resp = httpx.post(_chat_url_for(spec), headers=headers, json=payload, timeout=120)
            if resp.status_code == 200:
                return _openai_response_to_anthropic(resp.json())
            try:
                err = resp.json().get("error", {}).get("message", resp.text)
            except Exception:
                err = resp.text
            err = str(err)[:200]
            if resp.status_code == 401:
                raise anthropic.AuthenticationError(
                    message=f"{spec.label} key rejected", response=None, body=None)
            if resp.status_code in (429, 402) or "quota" in err.lower():
                if attempt < _MAX_RETRIES:
                    time.sleep(delay); delay = min(delay * 2, 60); continue
                raise anthropic.RateLimitError(message=err, response=None, body=None)
            if resp.status_code in (500, 502, 503):
                if attempt < _MAX_RETRIES:
                    time.sleep(delay); delay = min(delay * 2, 60); continue
                raise anthropic.InternalServerError(message=err, response=None, body=None)
            if resp.status_code == 400 and "temperature" in payload and _is_temperature_rejected(err):
                _no_temperature.add(model)
                payload.pop("temperature", None)
                continue
            raise RuntimeError(f"{spec.label} error {resp.status_code}: {err}")
        except (anthropic.AuthenticationError, anthropic.RateLimitError,
                anthropic.InternalServerError, RuntimeError):
            raise
        except Exception as e:
            if attempt < _MAX_RETRIES:
                time.sleep(delay); delay = min(delay * 2, 60); continue
            raise RuntimeError(f"{spec.label} connection failed: {e}") from e
    raise RuntimeError("OAI-compat retry loop exhausted")


# ── Custom exceptions ─────────────────────────────────────────────────────────

class APIAuthError(Exception):
    """API key rejected or access denied — not retryable."""

class APIAccountLimitError(Exception):
    """Account credit / quota exhausted — not retryable."""

class APIConnectionError(Exception):
    """Network failure after all retries — resumable once connectivity returns."""

class ModelRefusalError(Exception):
    """Model refused the request content — looping won't help, switch models."""


_QUOTA_KEYWORDS = ("quota", "credit", "billing", "balance", "insufficient",
                   "exceeded your", "monthly", "daily limit", "account limit",
                   "out of tokens")


def _is_quota_exhaustion(msg: str) -> bool:
    lower = msg.lower()
    return any(kw in lower for kw in _QUOTA_KEYWORDS)


# ── LLMClient class ───────────────────────────────────────────────────────────

class LLMClient:
    """Session-scoped LLM client.

    Tracks per-session state (which models have rejected `temperature`) and adds
    conversation prompt caching on the Anthropic native path. Re-reads the active
    provider from config on each run() call so mid-session `/provider set` takes
    effect immediately.
    """
    def __init__(self, on_retry: "Callable[[int, float, str], None] | None" = None):
        self.on_retry = on_retry
        self._no_temperature_models: set[str] = set()

    def run(
        self,
        model: str,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 8192,
    ) -> Any:
        provider = config.get("active_provider", "anthropic")
        if provider == "bedrock":
            return _call_bedrock(system, messages, tools, max_tokens)
        if provider == "anthropic-sub":
            return _call_sub(system, messages, tools, max_tokens)
        spec = get_provider(provider)
        if spec and not spec.native:
            try:
                return _call_openai_compat(spec, model, system, messages, tools, max_tokens)
            except Exception as e:
                if model not in self._no_temperature_models and _is_temperature_rejected(str(e)):
                    self._no_temperature_models.add(model)
                    return _call_openai_compat(spec, model, system, messages, tools, max_tokens)
                raise
        return self._run_anthropic(model, system, messages, tools, max_tokens)

    @staticmethod
    def _with_conversation_cache(messages: list[dict]) -> list[dict]:
        """Mark the last user message block with cache_control so the growing
        conversation prefix is cached and re-read cheaply on subsequent turns."""
        if not messages or messages[-1].get("role") != "user":
            return messages
        last = messages[-1]
        content = last.get("content")
        if isinstance(content, str):
            new_content = [{"type": "text", "text": content,
                            "cache_control": {"type": "ephemeral"}}]
        elif isinstance(content, list) and content and isinstance(content[-1], dict):
            new_content = list(content)
            blk = dict(new_content[-1])
            blk["cache_control"] = {"type": "ephemeral"}
            new_content[-1] = blk
        else:
            return messages
        return messages[:-1] + [{**last, "content": new_content}]

    def _run_anthropic(self, model: str, system: str, messages: list[dict],
                       tools: list[dict] | None, max_tokens: int) -> Any:
        key = config.get_api_key("anthropic")
        client = anthropic.Anthropic(api_key=key)

        system_blocks = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        cached_tools = None
        if tools:
            cached_tools = list(tools)
            last = dict(cached_tools[-1])
            last["cache_control"] = {"type": "ephemeral"}
            cached_tools[-1] = last

        kwargs: dict[str, Any] = {
            "model": model, "max_tokens": max_tokens,
            "system": system_blocks,
            "messages": self._with_conversation_cache(messages),
        }
        temp = config.get("temp")
        if temp is not None and model not in self._no_temperature_models:
            kwargs["temperature"] = temp
        if cached_tools:
            kwargs["tools"] = cached_tools

        wait = 4.0
        for attempt in range(_MAX_RETRIES + 2):
            try:
                return client.messages.create(**kwargs)
            except anthropic.RateLimitError as e:
                if _is_quota_exhaustion(str(e)):
                    raise APIAccountLimitError("Request quota exhausted") from e
                if attempt >= _MAX_RETRIES:
                    raise APIAccountLimitError("Rate limit persists — quota may be exhausted") from e
                if self.on_retry:
                    self.on_retry(attempt + 1, wait, "Rate limited")
                time.sleep(wait); wait = min(wait * 2, 60)
            except anthropic.InternalServerError:
                if attempt >= _MAX_RETRIES:
                    raise
                if self.on_retry:
                    self.on_retry(attempt + 1, wait, "Server error")
                time.sleep(wait); wait = min(wait * 2, 60)
            except anthropic.APIConnectionError as e:
                if attempt >= _MAX_RETRIES:
                    raise APIConnectionError("Connection to Anthropic failed after retries") from e
                if self.on_retry:
                    self.on_retry(attempt + 1, wait, "Connection error")
                time.sleep(wait); wait = min(wait * 2, 60)
            except anthropic.AuthenticationError as e:
                raise APIAuthError("API key rejected — run /key set anthropic <key>") from e
            except anthropic.BadRequestError as e:
                if "temperature" in kwargs and _is_temperature_rejected(str(e)):
                    self._no_temperature_models.add(model)
                    kwargs.pop("temperature", None)
                    continue
                raise
        raise RuntimeError("LLMClient retry loop exhausted")


# ── Main call interface ───────────────────────────────────────────────────────

def _model() -> str:
    provider = config.get("active_provider", "anthropic")
    if provider == "bedrock":
        return config.get("bedrock.model", "us.anthropic.claude-opus-4-5-v1:0")
    if provider == "openrouter":
        return config.get("openrouter.model", "anthropic/claude-sonnet-4-5")
    if provider == "nvidia":
        return config.get("nvidia.model", "meta/llama-3.1-405b-instruct")
    if provider == "local":
        return config.get("local.model", "")
    return config.get("anthropic.model", "claude-opus-4-5-20251101")


def call(
    system: str,
    messages: list[dict],
    tools: list[dict] | None = None,
    max_tokens: int = 4096,
    extra_kwargs: dict[str, Any] | None = None,
) -> Any:
    provider = config.get("active_provider", "anthropic")

    if provider == "bedrock":
        return _call_bedrock(system, messages, tools, max_tokens)
    if provider == "anthropic-sub":
        return _call_sub(system, messages, tools, max_tokens)
    # OpenAI-compat providers
    spec = get_provider(provider)
    if spec and not spec.native:
        return _call_openai_compat(spec, _model(), system, messages, tools, max_tokens)
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
