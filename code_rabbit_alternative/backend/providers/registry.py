"""Provider catalog and resolution.

Only backends with a genuine free tier are enabled by default, plus local
runtimes (Ollama / LM Studio) and the offline engine.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .base import LLMProvider, ModelSpec, ProviderError
from .demo import DemoProvider
from .gemini import GeminiProvider
from .openai_compat import OpenAICompatProvider


@dataclass
class ProviderSpec:
    id: str
    label: str
    kind: str                      # demo | gemini | openai-compat
    env_key: str
    base_url: str
    docs_url: str
    signup_url: str
    free_note: str
    models: List[ModelSpec] = field(default_factory=list)
    requires_key: bool = True
    local: bool = False


GROQ_MODELS = [
    ModelSpec("llama-3.3-70b-versatile", "Llama 3.3 70B Versatile", 128_000, True, True, True, 4096),
    ModelSpec("llama-3.1-8b-instant", "Llama 3.1 8B Instant", 128_000, True, False, True, 4096),
    ModelSpec("meta-llama/llama-4-scout-17b-16e-instruct", "Llama 4 Scout 17B", 128_000, True, False, True, 4096),
    ModelSpec("qwen/qwen3-32b", "Qwen3 32B", 32_000, True, False, True, 4096),
    ModelSpec("deepseek-r1-distill-llama-70b", "DeepSeek R1 Distill 70B", 128_000, True, False, True, 4096),
]

OPENROUTER_MODELS = [
    ModelSpec("meta-llama/llama-3.3-70b-instruct:free", "Llama 3.3 70B (free)", 128_000, True, True, True, 4096),
    ModelSpec("deepseek/deepseek-chat-v3-0324:free", "DeepSeek V3 (free)", 128_000, True, False, True, 4096),
    ModelSpec("qwen/qwen3-coder:free", "Qwen3 Coder (free)", 128_000, True, False, True, 4096),
    ModelSpec("google/gemini-2.0-flash-exp:free", "Gemini 2.0 Flash Exp (free)", 128_000, True, False, True, 4096),
    ModelSpec("mistralai/mistral-small-3.1-24b-instruct:free", "Mistral Small 3.1 (free)", 128_000, True, False, True, 4096),
]

CEREBRAS_MODELS = [
    ModelSpec("llama3.1-70b", "Llama 3.1 70B", 128_000, True, True, True, 4096),
    ModelSpec("qwen-3-coder-480b", "Qwen3 Coder 480B", 256_000, True, False, True, 4096),
    ModelSpec("llama3.1-8b", "Llama 3.1 8B", 128_000, True, False, True, 4096),
]

TOGETHER_MODELS = [
    ModelSpec("meta-llama/Llama-3.3-70B-Instruct-Turbo-Free", "Llama 3.3 70B Turbo (free)", 128_000, True, True, True, 4096),
    ModelSpec("Qwen/Qwen2.5-Coder-32B-Instruct", "Qwen2.5 Coder 32B", 32_000, True, False, True, 4096),
    ModelSpec("deepseek-ai/DeepSeek-R1-Distill-Llama-70B-free", "DeepSeek R1 70B (free)", 128_000, True, False, True, 4096),
]

DEEPINFRA_MODELS = [
    ModelSpec("meta-llama/Llama-3.3-70B-Instruct", "Llama 3.3 70B", 128_000, True, True, True, 4096),
    ModelSpec("Qwen/Qwen2.5-Coder-32B-Instruct", "Qwen2.5 Coder 32B", 32_000, True, False, True, 4096),
]

MISTRAL_MODELS = [
    ModelSpec("mistral-small-latest", "Mistral Small", 128_000, True, True, True, 4096),
    ModelSpec("codestral-latest", "Codestral", 128_000, True, False, True, 4096),
    ModelSpec("ministral-3-8b-latest", "Ministral 8B", 128_000, True, False, True, 4096),
]

SAMBANOVA_MODELS = [
    ModelSpec("DeepSeek-R1-0528", "DeepSeek R1", 32_000, True, True, True, 4096),
    ModelSpec("Llama-3.3-70B-Instruct", "Llama 3.3 70B", 128_000, True, False, True, 4096),
]

XAI_MODELS = [
    ModelSpec("grok-4-fast-reasoning", "Grok 4 Fast Reasoning", 256_000, True, True, True, 4096),
]

OLLAMA_MODELS = [
    ModelSpec("qwen2.5-coder:7b", "Qwen2.5 Coder 7B (local)", 32_000, True, True, True, 4096),
    ModelSpec("llama3.1:8b", "Llama 3.1 8B (local)", 128_000, True, False, True, 4096),
    ModelSpec("deepseek-coder-v2:16b", "DeepSeek Coder V2 16B (local)", 128_000, True, False, True, 4096),
    ModelSpec("codellama:13b", "Code Llama 13B (local)", 16_000, True, False, True, 2048),
]

LMSTUDIO_MODELS = [
    ModelSpec("local-model", "Whatever is loaded in LM Studio", 128_000, True, True, True, 4096),
]


PROVIDERS: List[ProviderSpec] = [
    ProviderSpec(
        id="demo", label="Offline static engine", kind="demo", env_key="", base_url="",
        docs_url="", signup_url="", requires_key=False,
        free_note="No key, no network, no cost. Rule-based review that always works.",
        models=DemoProvider.models, local=True,
    ),
    ProviderSpec(
        id="groq", label="Groq", kind="openai-compat", env_key="GROQ_API_KEY",
        base_url="https://api.groq.com/openai/v1",
        docs_url="https://console.groq.com/docs", signup_url="https://console.groq.com/keys",
        free_note="Free tier, no card required. Fastest inference of the group (~500 tok/s).",
        models=GROQ_MODELS,
    ),
    ProviderSpec(
        id="gemini", label="Google Gemini", kind="gemini", env_key="GEMINI_API_KEY",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        docs_url="https://ai.google.dev/gemini-api/docs", signup_url="https://aistudio.google.com/app/apikey",
        free_note="Generous free tier, 1M-token context — great for whole-repo reviews.",
        models=GeminiProvider.models,
    ),
    ProviderSpec(
        id="openrouter", label="OpenRouter", kind="openai-compat", env_key="OPENROUTER_API_KEY",
        base_url="https://openrouter.ai/api/v1",
        docs_url="https://openrouter.ai/docs", signup_url="https://openrouter.ai/keys",
        free_note="Routes to hundreds of models; the `:free` variants cost nothing.",
        models=OPENROUTER_MODELS,
    ),
    ProviderSpec(
        id="cerebras", label="Cerebras", kind="openai-compat", env_key="CEREBRAS_API_KEY",
        base_url="https://api.cerebras.ai/v1",
        docs_url="https://inference-docs.cerebras.ai", signup_url="https://cloud.cerebras.ai/",
        free_note="Free inference tier, extremely high tokens/second.",
        models=CEREBRAS_MODELS,
    ),
    ProviderSpec(
        id="together", label="Together AI", kind="openai-compat", env_key="TOGETHER_API_KEY",
        base_url="https://api.together.xyz/v1",
        docs_url="https://docs.together.ai", signup_url="https://api.together.xyz/settings/api-keys",
        free_note="Free credits on signup plus permanently free `-Free` models.",
        models=TOGETHER_MODELS,
    ),
    ProviderSpec(
        id="deepinfra", label="DeepInfra", kind="openai-compat", env_key="DEEPINFRA_API_KEY",
        base_url="https://api.deepinfra.com/v1/openai",
        docs_url="https://deepinfra.com/docs", signup_url="https://deepinfra.com/dash/api_keys",
        free_note="Free trial credits; many open models are cheap enough to be effectively free.",
        models=DEEPINFRA_MODELS,
    ),
    ProviderSpec(
        id="mistral", label="Mistral AI", kind="openai-compat", env_key="MISTRAL_API_KEY",
        base_url="https://api.mistral.ai/v1",
        docs_url="https://docs.mistral.ai", signup_url="https://console.mistral.ai/api-keys/",
        free_note="Free experimentation tier for most models.",
        models=MISTRAL_MODELS,
    ),
    ProviderSpec(
        id="sambanova", label="SambaNova", kind="openai-compat", env_key="SAMBANOVA_API_KEY",
        base_url="https://api.sambanova.ai/v1",
        docs_url="https://docs.sambanova.ai", signup_url="https://cloud.sambanova.ai/",
        free_note="Free tier for hosted open models.",
        models=SAMBANOVA_MODELS,
    ),
    ProviderSpec(
        id="xai", label="xAI", kind="openai-compat", env_key="XAI_API_KEY",
        base_url="https://api.x.ai/v1",
        docs_url="https://docs.x.ai", signup_url="https://console.x.ai/",
        free_note="Monthly free credit allowance.",
        models=XAI_MODELS,
    ),
    ProviderSpec(
        id="ollama", label="Ollama (local)", kind="openai-compat", env_key="",
        base_url="http://localhost:11434/v1",
        docs_url="https://github.com/ollama/ollama", signup_url="https://ollama.com/download",
        requires_key=False, local=True,
        free_note="100% local and free. Run `ollama pull qwen2.5-coder:7b` first.",
        models=OLLAMA_MODELS,
    ),
    ProviderSpec(
        id="lmstudio", label="LM Studio (local)", kind="openai-compat", env_key="",
        base_url="http://localhost:1234/v1",
        docs_url="https://lmstudio.ai/docs", signup_url="https://lmstudio.ai",
        requires_key=False, local=True,
        free_note="Local server, free. Enable the local server in LM Studio.",
        models=LMSTUDIO_MODELS,
    ),
]

BY_ID: Dict[str, ProviderSpec] = {spec.id: spec for spec in PROVIDERS}

# Extra env aliases people actually use.
ENV_ALIASES: Dict[str, List[str]] = {
    "gemini": ["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_AI_API_KEY"],
    "groq": ["GROQ_API_KEY"],
    "openrouter": ["OPENROUTER_API_KEY"],
}


def spec_for(provider_id: str) -> ProviderSpec:
    if provider_id not in BY_ID:
        raise ProviderError(
            f"Unknown provider '{provider_id}'. Available: {', '.join(BY_ID)}"
        )
    return BY_ID[provider_id]


def resolve_api_key(provider_id: str, override: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Key precedence: explicit override > provider env var > aliases."""
    if override:
        return override.strip()
    env = env if env is not None else os.environ
    spec = BY_ID.get(provider_id)
    if not spec or not spec.env_key:
        return None
    value = env.get(spec.env_key)
    if value:
        return value.strip()
    for alias in ENV_ALIASES.get(provider_id, []):
        if env.get(alias):
            return env[alias].strip()
    return None


def build_provider(
    provider_id: str,
    *,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: float = 90.0,
    env: Optional[Dict[str, str]] = None,
) -> LLMProvider:
    spec = spec_for(provider_id)
    key = resolve_api_key(provider_id, api_key, env)
    url = base_url or spec.base_url or None

    if spec.kind == "demo":
        return DemoProvider()
    if spec.kind == "gemini":
        return GeminiProvider(api_key=key, base_url=url, timeout=timeout)

    extra_headers: Dict[str, str] = {}
    if provider_id == "openrouter":
        # OpenRouter asks for attribution headers; they are optional but polite.
        extra_headers = {
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "Code Review Agent",
        }
    return OpenAICompatProvider(
        api_key=key,
        base_url=url,
        timeout=timeout,
        provider_id=spec.id,
        label=spec.label,
        models=spec.models,
        extra_headers=extra_headers,
        docs_url=spec.docs_url,
        requires_key=spec.requires_key,
    )


def default_model_for(provider_id: str) -> str:
    spec = spec_for(provider_id)
    for model in spec.models:
        if model.recommended:
            return model.id
    return spec.models[0].id if spec.models else ""


def provider_status(env: Optional[Dict[str, str]] = None, runtime_keys: Optional[Dict[str, str]] = None) -> List[Dict]:
    """Catalog with live 'do I have a key for this?' state, for the UI."""
    env = env if env is not None else os.environ
    runtime_keys = runtime_keys or {}
    out = []
    for spec in PROVIDERS:
        key = resolve_api_key(spec.id, runtime_keys.get(spec.id), env)
        out.append({
            "id": spec.id,
            "label": spec.label,
            "kind": spec.kind,
            "local": spec.local,
            "requires_key": spec.requires_key,
            "configured": (not spec.requires_key) or bool(key),
            "key_source": "runtime" if runtime_keys.get(spec.id) else ("env" if key and spec.requires_key else None),
            "base_url": spec.base_url,
            "docs_url": spec.docs_url,
            "signup_url": spec.signup_url,
            "free_note": spec.free_note,
            "models": [m.__dict__ for m in spec.models],
            "default_model": default_model_for(spec.id),
        })
    # configured providers first, then free cloud, then local
    out.sort(key=lambda p: (not p["configured"], p["local"], p["label"]))
    return out
