"""Tests for runtime configuration and key handling."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import config  # noqa: E402
from backend.providers.registry import BY_ID  # noqa: E402


def test_defaults_to_offline_when_nothing_is_configured():
    assert config.get_provider_id() == "demo"
    assert config.get_model() == "static-rules-v1"


def test_update_switches_provider_and_model():
    result = config.update(provider="groq", model="llama-3.1-8b-instant")
    assert result["provider"] == "groq"
    assert result["model"] == "llama-3.1-8b-instant"


def test_switching_provider_clears_the_previous_model():
    """Regression: a stale model id used to survive a provider switch, so the
    demo provider would be asked for `llama-3.1-8b-instant`."""
    config.update(provider="groq", model="llama-3.1-8b-instant")
    result = config.update(provider="demo")
    assert result["provider"] == "demo"
    assert result["model"] == "static-rules-v1"


def test_stale_model_on_disk_is_not_used_for_another_provider(tmp_path, monkeypatch):
    """A config file pairing provider=demo with a Groq model must self-heal."""
    cfg = tmp_path / "config.local.json"
    cfg.write_text('{"provider": "demo", "model": "llama-3.1-8b-instant"}', encoding="utf-8")
    monkeypatch.setattr(config, "LOCAL_CONFIG", cfg)
    config.load_runtime()
    assert config.get_provider_id() == "demo"
    model = config.get_model("demo")
    assert model in {m.id for m in BY_ID["demo"].models}, \
        f"demo must not be given a Groq model, got {model}"


def test_cleared_model_is_persisted_as_cleared(tmp_path, monkeypatch):
    cfg = tmp_path / "config.local.json"
    monkeypatch.setattr(config, "LOCAL_CONFIG", cfg)
    config.update(provider="groq", model="llama-3.1-8b-instant")
    assert '"model": "llama-3.1-8b-instant"' in cfg.read_text()
    config.update(provider="demo")
    assert "llama-3.1-8b-instant" not in cfg.read_text()


def test_unknown_provider_is_rejected():
    try:
        config.update(provider="not-a-real-provider")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "unknown provider" in str(exc)


def test_keys_are_masked_in_the_snapshot():
    config.update(api_keys={"groq": "gsk_supersecretvalue123456"})
    snap = config.snapshot()
    masked = snap["api_keys_masked"]["groq"]
    assert "supersecret" not in masked
    assert "*" in masked
    assert masked.startswith("gsk_")


def test_snapshot_never_contains_a_raw_key():
    config.update(api_keys={"groq": "gsk_supersecretvalue123456"})
    text = repr(config.snapshot())
    assert "supersecretvalue" not in text


def test_runtime_keys_are_resolved_for_a_provider():
    config.update(api_keys={"together": "tk_abc"})
    assert config.get_api_key("together") == "tk_abc"


def test_explicit_key_overrides_runtime():
    config.update(api_keys={"together": "tk_abc"})
    assert config.get_api_key("together", "tk_override") == "tk_override"


def test_env_key_is_used_when_no_runtime_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_from_env_1234")
    assert config.get_api_key("groq") == "gsk_from_env_1234"


def test_runtime_key_wins_over_env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_from_env_1234")
    config.update(api_keys={"groq": "gsk_from_ui_5678"})
    assert config.get_api_key("groq") == "gsk_from_ui_5678"


def test_empty_key_removes_it():
    config.update(api_keys={"groq": "gsk_abc123"})
    assert config.get_api_key("groq") == "gsk_abc123"
    config.update(api_keys={"groq": ""})
    assert config.get_api_key("groq") is None


def test_unknown_provider_keys_are_ignored():
    config.update(api_keys={"not-a-provider": "secret"})
    assert config.runtime_api_keys().get("not-a-provider") is None


def test_auto_select_prefers_a_keyed_cloud_provider(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "gem_key_1234")
    with config._lock:  # noqa: SLF001
        config._runtime["provider"] = None
    assert config.get_provider_id() == "gemini"


def test_auto_select_falls_back_to_offline(monkeypatch):
    for name in ("GROQ_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY",
                 "CEREBRAS_API_KEY", "TOGETHER_API_KEY", "DEEPINFRA_API_KEY",
                 "MISTRAL_API_KEY", "SAMBANOVA_API_KEY", "XAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    with config._lock:  # noqa: SLF001
        config._runtime["provider"] = None
        config._runtime["api_keys"].clear()
    assert config.get_provider_id() == "demo"


def test_ollama_only_auto_selected_when_opted_in(monkeypatch):
    monkeypatch.setenv("OLLAMA_AUTOSTART", "1")
    with config._lock:  # noqa: SLF001
        config._runtime["provider"] = None
        config._runtime["api_keys"].clear()
    assert config.get_provider_id() == "ollama"


def test_base_url_override():
    config.update(base_urls={"ollama": "http://192.168.1.50:11434/v1"})
    assert config.get_base_url("ollama") == "http://192.168.1.50:11434/v1"


def test_base_url_default_when_not_overridden():
    assert config.get_base_url("groq") == "https://api.groq.com/openai/v1"


def test_effort_and_temperature_roundtrip():
    config.update(effort="deep", temperature=0.05)
    assert config.get_effort() == "deep"
    assert config.get_temperature() == 0.05
    config.update(effort="standard", temperature=0.2)


def test_snapshot_reports_every_provider():
    snap = config.snapshot()
    ids = {p["id"] for p in snap["providers"]}
    assert {"demo", "groq", "gemini", "openrouter", "ollama"} <= ids
    assert snap["offline_ready"] if "offline_ready" in snap else True


def test_local_config_file_is_written_private(tmp_path, monkeypatch):
    cfg = tmp_path / "config.local.json"
    monkeypatch.setattr(config, "LOCAL_CONFIG", cfg)
    config.update(effort="deep")
    assert cfg.exists()
    mode = cfg.stat().st_mode & 0o777
    assert mode == 0o600, f"config with keys must be 0600, got {oct(mode)}"
