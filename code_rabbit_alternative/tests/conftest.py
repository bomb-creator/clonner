"""Shared test fixtures.

Runtime config is process-global and persists to `config.local.json`, so tests
that set an API key would leak into tests that assert "no key configured".
These fixtures isolate and reset that state per test.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import config  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_runtime_config(tmp_path, monkeypatch):
    """Point config at a temp file and clear in-memory keys for every test."""
    monkeypatch.setattr(config, "LOCAL_CONFIG", tmp_path / "config.local.json")
    with config._lock:  # noqa: SLF001 - test isolation only
        config._runtime["api_keys"].clear()
        config._runtime["base_urls"].clear()
        config._runtime["provider"] = None
        config._runtime["model"] = None
        config._runtime["effort"] = "standard"
        config._runtime["temperature"] = 0.2
    yield
    with config._lock:  # noqa: SLF001
        config._runtime["api_keys"].clear()
        config._runtime["base_urls"].clear()
        config._runtime["provider"] = None
        config._runtime["model"] = None


@pytest.fixture(autouse=True)
def clear_provider_env(monkeypatch):
    """Tests assert on 'unconfigured' states, so no ambient keys may be present."""
    for name in (
        "GROQ_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_AI_API_KEY",
        "OPENROUTER_API_KEY", "CEREBRAS_API_KEY", "TOGETHER_API_KEY",
        "DEEPINFRA_API_KEY", "MISTRAL_API_KEY", "SAMBANOVA_API_KEY", "XAI_API_KEY",
        "GITHUB_TOKEN", "REVIEW_PROVIDER", "REVIEW_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
