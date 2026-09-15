"""Runtime configuration.

Keys come from `.env` / process env, and can be changed at runtime from the UI
(persisted to `config.local.json`, which is gitignored so secrets never get
committed). Nothing here is ever written to logs.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

try:  # python-dotenv is optional at runtime
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore

from .providers.registry import BY_ID, default_model_for, resolve_api_key

ROOT = Path(__file__).resolve().parent.parent
LOCAL_CONFIG = ROOT / "config.local.json"
VERSION = "1.0.0"

_lock = threading.RLock()
_runtime: Dict[str, Any] = {
    "provider": None,
    "model": None,
    "api_keys": {},
    "base_urls": {},
    "effort": "standard",
    "temperature": 0.2,
}


def _load_dotenv_once() -> None:
    global load_dotenv
    if load_dotenv is None:
        return
    for candidate in (ROOT / ".env", ROOT.parent / ".env"):
        if candidate.exists():
            load_dotenv(candidate, override=False)
    load_dotenv = None  # only once


def _read_local() -> Dict[str, Any]:
    if not LOCAL_CONFIG.exists():
        return {}
    try:
        with LOCAL_CONFIG.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_local(patch: Dict[str, Any]) -> None:
    data = _read_local()
    data.update(patch)
    # Drop keys that were explicitly cleared so a stale value is never reloaded.
    data = {k: v for k, v in data.items() if v is not None or k == "model"}
    with _lock:
        try:
            with LOCAL_CONFIG.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            os.chmod(LOCAL_CONFIG, 0o600)
        except Exception:
            pass  # never fail a request because config could not be persisted


def load_runtime() -> None:
    """Hydrate runtime state from disk + env. Called once at import/startup."""
    _load_dotenv_once()
    saved = _read_local()
    with _lock:
        for key in ("provider", "model", "effort", "temperature"):
            if saved.get(key) is not None:
                _runtime[key] = saved[key]
        if isinstance(saved.get("api_keys"), dict):
            _runtime["api_keys"].update(saved["api_keys"])
        if isinstance(saved.get("base_urls"), dict):
            _runtime["base_urls"].update(saved["base_urls"])
        if _runtime["effort"] is None:
            _runtime["effort"] = os.getenv("REVIEW_EFFORT", "standard")


def get_provider_id() -> str:
    with _lock:
        chosen = _runtime.get("provider") or os.getenv("REVIEW_PROVIDER")
        if chosen and chosen in BY_ID:
            return chosen
        # auto-select: first provider that actually has a key, else offline engine
        for provider_id in ("groq", "gemini", "openrouter", "cerebras", "together",
                            "deepinfra", "mistral", "sambanova", "xai"):
            if resolve_api_key(provider_id, _runtime["api_keys"].get(provider_id)):
                return provider_id
        if os.getenv("OLLAMA_AUTOSTART", "").lower() in {"1", "true", "yes"}:
            return "ollama"
        return "demo"


def get_model(provider_id: Optional[str] = None) -> str:
    provider_id = provider_id or get_provider_id()
    with _lock:
        if _runtime.get("model") and _runtime.get("provider") == provider_id:
            stored = _runtime["model"]
            # Guard against a stale model id that does not belong to this
            # provider (e.g. left over in config.local.json from an earlier run).
            valid = {m.id for m in BY_ID[provider_id].models} if provider_id in BY_ID else set()
            if not valid or stored in valid:
                return stored
        env_model = os.getenv("REVIEW_MODEL")
        if env_model and provider_id == (_runtime.get("provider") or get_provider_id()):
            return env_model
    return default_model_for(provider_id)


def get_api_key(provider_id: str, override: Optional[str] = None) -> Optional[str]:
    if override:
        return override.strip()
    with _lock:
        runtime_key = _runtime["api_keys"].get(provider_id)
    return resolve_api_key(provider_id, runtime_key)


def get_base_url(provider_id: str) -> Optional[str]:
    with _lock:
        override = _runtime["base_urls"].get(provider_id)
    if override:
        return override
    spec = BY_ID.get(provider_id)
    return spec.base_url if spec else None


def get_effort() -> str:
    with _lock:
        return _runtime.get("effort") or "standard"


def get_temperature() -> float:
    with _lock:
        value = _runtime.get("temperature")
    try:
        return float(value if value is not None else os.getenv("REVIEW_TEMPERATURE", 0.2))
    except (TypeError, ValueError):
        return 0.2


def update(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    api_keys: Optional[Dict[str, str]] = None,
    base_urls: Optional[Dict[str, str]] = None,
    effort: Optional[str] = None,
    temperature: Optional[float] = None,
) -> Dict[str, Any]:
    patch: Dict[str, Any] = {}
    with _lock:
        if provider is not None:
            if provider not in BY_ID:
                raise ValueError(f"unknown provider '{provider}'")
            _runtime["provider"] = provider
            patch["provider"] = provider
            if model is None:
                # Clearing the model must be persisted too, otherwise the previous
                # provider's model id is reloaded from disk against a new provider.
                _runtime["model"] = None
                patch["model"] = None
        if model is not None:
            _runtime["model"] = model
            patch["model"] = model
        if api_keys:
            for key, value in api_keys.items():
                if key in BY_ID:
                    if value:
                        _runtime["api_keys"][key] = value.strip()
                    else:
                        _runtime["api_keys"].pop(key, None)
            patch["api_keys"] = _runtime["api_keys"]
        if base_urls:
            for key, value in base_urls.items():
                if value:
                    _runtime["base_urls"][key] = value.strip()
                else:
                    _runtime["base_urls"].pop(key, None)
            patch["base_urls"] = _runtime["base_urls"]
        if effort is not None:
            _runtime["effort"] = effort
            patch["effort"] = effort
        if temperature is not None:
            _runtime["temperature"] = float(temperature)
            patch["temperature"] = _runtime["temperature"]
    if patch:
        _write_local(patch)
    return snapshot()


def runtime_api_keys() -> Dict[str, str]:
    """Copy of runtime-supplied keys (never exposed to the browser)."""
    with _lock:
        return dict(_runtime["api_keys"])


def snapshot() -> Dict[str, Any]:
    """Config view safe to return to the browser (keys are masked)."""
    from .providers.registry import provider_status

    provider_id = get_provider_id()
    with _lock:
        masked = {k: _mask(v) for k, v in _runtime["api_keys"].items()}
        base_urls = dict(_runtime["base_urls"])
        keys = dict(_runtime["api_keys"])
    return {
        "provider": provider_id,
        "model": get_model(provider_id),
        "effort": get_effort(),
        "temperature": get_temperature(),
        "api_keys_masked": masked,
        "base_urls": base_urls,
        "providers": provider_status(runtime_keys=keys),
        "github_token_set": bool(os.getenv("GITHUB_TOKEN")),
        "version": VERSION,
    }


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * 12}{value[-4:]}"


load_runtime()
