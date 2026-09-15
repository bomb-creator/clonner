"""Tests for the provider layer: registry, key resolution, offline engine."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.providers.base import ChatMessage, ProviderError  # noqa: E402
from backend.providers.demo import DemoProvider  # noqa: E402
from backend.providers.gemini import GeminiProvider  # noqa: E402
from backend.providers.registry import (  # noqa: E402
    BY_ID,
    PROVIDERS,
    build_provider,
    default_model_for,
    provider_status,
    resolve_api_key,
    spec_for,
)
from backend.utils.jsonrepair import extract_json  # noqa: E402

VULNERABLE = '''import os, sqlite3
SECRET = "hunter2secretvalue"

def lookup(uid):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + str(uid))
    for row in cur.fetchall():
        cur.execute("SELECT * FROM logs WHERE uid = %s" % uid)
    return cur.fetchone().name
'''


# ------------------------------------------------------------------ registry
def test_every_provider_spec_is_well_formed():
    for spec in PROVIDERS:
        assert spec.id, "provider id is required"
        assert spec.label
        assert spec.kind in {"demo", "gemini", "openai-compat"}
        assert spec.models, f"{spec.id} must advertise at least one model"
        assert spec.requires_key is False or spec.env_key, f"{spec.id} needs an env var name"
        for model in spec.models:
            assert model.id and model.label
            assert model.context_window > 0


def test_ids_are_unique():
    ids = [spec.id for spec in PROVIDERS]
    assert len(ids) == len(set(ids))


def test_free_providers_are_the_default_catalogue():
    expected = {"demo", "groq", "gemini", "openrouter", "cerebras", "together",
                "deepinfra", "mistral", "sambanova", "xai", "ollama", "lmstudio"}
    assert expected <= set(BY_ID)


def test_demo_and_local_runtimes_need_no_key():
    for provider_id in ("demo", "ollama", "lmstudio"):
        assert spec_for(provider_id).requires_key is False


def test_spec_for_unknown_provider_raises():
    with pytest.raises(ProviderError):
        spec_for("does-not-exist")


def test_default_model_is_the_recommended_one():
    assert default_model_for("groq") == "llama-3.3-70b-versatile"
    assert default_model_for("demo") == "static-rules-v1"
    assert default_model_for("gemini") == "gemini-2.0-flash"


def test_resolve_api_key_prefers_override():
    env = {"GROQ_API_KEY": "from-env"}
    assert resolve_api_key("groq", "explicit", env) == "explicit"
    assert resolve_api_key("groq", None, env) == "from-env"


def test_resolve_api_key_supports_gemini_aliases():
    assert resolve_api_key("gemini", None, {"GOOGLE_API_KEY": "g"}) == "g"
    assert resolve_api_key("gemini", None, {"GEMINI_API_KEY": "g2"}) == "g2"
    # the canonical name wins over the alias
    assert resolve_api_key("gemini", None,
                           {"GEMINI_API_KEY": "primary", "GOOGLE_API_KEY": "alias"}) == "primary"


def test_resolve_api_key_strips_whitespace():
    assert resolve_api_key("groq", "  padded-key  ") == "padded-key"


def test_resolve_api_key_for_keyless_provider():
    assert resolve_api_key("demo", None, {}) is None


def test_build_provider_returns_correct_types():
    assert isinstance(build_provider("demo"), DemoProvider)
    assert isinstance(build_provider("gemini", api_key="k"), GeminiProvider)
    groq = build_provider("groq", api_key="k")
    assert groq.id == "groq"
    assert groq.base_url == "https://api.groq.com/openai/v1"


def test_build_provider_applies_base_url_override():
    provider = build_provider("openai-compat" if "openai-compat" in BY_ID else "groq",
                              api_key="k", base_url="http://localhost:9999/v1")
    assert provider.base_url == "http://localhost:9999/v1"


def test_openrouter_sends_attribution_headers():
    provider = build_provider("openrouter", api_key="k")
    headers = provider._headers()
    assert headers["Authorization"] == "Bearer k"
    assert "X-Title" in headers


def test_ollama_is_configured_without_a_key():
    provider = build_provider("ollama")
    assert provider.is_configured() is True


def test_keyed_provider_is_not_configured_without_a_key():
    provider = build_provider("groq")
    provider.api_key = None
    assert provider.is_configured() is False


def test_provider_status_sorts_configured_first():
    statuses = provider_status(env={"GROQ_API_KEY": "k"}, runtime_keys={})
    assert statuses[0]["id"] == "groq"
    groq = next(s for s in statuses if s["id"] == "groq")
    assert groq["configured"] is True
    assert groq["key_source"] == "env"
    demo = next(s for s in statuses if s["id"] == "demo")
    assert demo["configured"] is True
    assert demo["requires_key"] is False


def test_provider_status_marks_runtime_keys():
    statuses = provider_status(env={}, runtime_keys={"gemini": "runtime-key"})
    gemini = next(s for s in statuses if s["id"] == "gemini")
    assert gemini["configured"] is True
    assert gemini["key_source"] == "runtime"


def test_provider_status_never_leaks_keys():
    statuses = provider_status(env={"GROQ_API_KEY": "super-secret-value"}, runtime_keys={})
    serialised = repr(statuses)
    assert "super-secret-value" not in serialised


# --------------------------------------------------------------- demo engine
def test_demo_provider_is_always_configured():
    provider = DemoProvider()
    assert provider.is_configured() is True
    assert provider.requires_key is False


def test_demo_provider_returns_valid_review_json():
    provider = DemoProvider()
    result = asyncio.run(provider.complete(
        [ChatMessage(role="user", content=VULNERABLE)],
        model="static-rules-v1",
        context={"task": "review", "code": VULNERABLE, "path": "app.py"},
    ))
    data = extract_json(result.text)
    assert data is not None
    assert "findings" in data and "summary" in data and "score" in data
    assert 0 <= data["score"] <= 100
    assert data["overall_assessment"] in {"approve", "approve_with_nits", "request_changes", "block"}


def test_demo_provider_finds_the_planted_vulnerabilities():
    provider = DemoProvider()
    result = asyncio.run(provider.complete(
        [ChatMessage(role="user", content=VULNERABLE)],
        model="static-rules-v1",
        context={"task": "review", "code": VULNERABLE, "path": "app.py"},
    ))
    data = extract_json(result.text)
    titles = " ".join(f["title"].lower() for f in data["findings"])
    assert "sql" in titles
    assert "credential" in titles or "secret" in titles or "api key" in titles
    severities = {f["severity"] for f in data["findings"]}
    assert "critical" in severities


def test_demo_provider_findings_have_valid_line_numbers():
    provider = DemoProvider()
    total_lines = len(VULNERABLE.splitlines())
    result = asyncio.run(provider.complete(
        [ChatMessage(role="user", content=VULNERABLE)],
        model="static-rules-v1",
        context={"task": "review", "code": VULNERABLE, "path": "app.py"},
    ))
    data = extract_json(result.text)
    assert data["findings"], "expected findings in the planted sample"
    for finding in data["findings"]:
        assert 1 <= finding["line"] <= total_lines
        assert finding["file"] == "app.py"
        assert finding["category"] in {"security", "bug", "quality", "performance", "best_practices"}
        assert finding["severity"] in {"critical", "high", "medium", "low", "info"}
        assert finding["line_comment"]


def test_demo_provider_scores_clean_code_highly():
    clean = '''"""Look up a user by id."""
import sqlite3


def lookup(connection: sqlite3.Connection, user_id: int) -> dict | None:
    """Return the user row for `user_id`, or None."""
    cursor = connection.execute(
        "SELECT id, name FROM users WHERE id = ?", (user_id,)
    )
    return cursor.fetchone()
'''
    provider = DemoProvider()
    result = asyncio.run(provider.complete(
        [ChatMessage(role="user", content=clean)],
        model="static-rules-v1",
        context={"task": "review", "code": clean, "path": "clean.py"},
    ))
    data = extract_json(result.text)
    critical = [f for f in data["findings"] if f["severity"] in {"critical", "high"}]
    assert not critical, f"clean code should not be flagged: {[f['title'] for f in critical]}"
    assert data["score"] >= 85


def test_demo_provider_summary_task_returns_markdown():
    provider = DemoProvider()
    result = asyncio.run(provider.complete(
        [ChatMessage(role="user", content=VULNERABLE)],
        model="static-rules-v1",
        context={"task": "summary", "code": VULNERABLE, "path": "app.py"},
    ))
    assert "## Walkthrough" in result.text
    assert "mermaid" in result.text


def test_demo_provider_chat_task_answers_by_topic():
    provider = DemoProvider()
    result = asyncio.run(provider.complete(
        [ChatMessage(role="user", content=VULNERABLE)],
        model="static-rules-v1",
        context={"task": "chat", "code": VULNERABLE, "path": "app.py",
                 "question": "Are there any security problems?"},
    ))
    assert "Security findings" in result.text
    assert "SQL" in result.text


def test_demo_provider_recovers_code_from_fences_when_no_context():
    provider = DemoProvider()
    fenced = "Please review this:\n```python\nos.system('rm -rf ' + path)\n```\nThanks."
    result = asyncio.run(provider.complete(
        [ChatMessage(role="user", content=fenced)], model="static-rules-v1",
    ))
    data = extract_json(result.text)
    assert data["findings"], "should have detected the command injection inside the fence"


def test_demo_provider_stream_yields_the_full_text():
    provider = DemoProvider()

    async def collect():
        chunks = []
        async for piece in provider.stream(
            [ChatMessage(role="user", content=VULNERABLE)],
            model="static-rules-v1",
            context={"task": "review", "code": VULNERABLE, "path": "app.py"},
        ):
            chunks.append(piece)
        return "".join(chunks)

    text = asyncio.run(collect())
    assert extract_json(text) is not None


def test_demo_provider_reports_token_estimate():
    provider = DemoProvider()
    result = asyncio.run(provider.complete(
        [ChatMessage(role="user", content=VULNERABLE)],
        model="static-rules-v1",
        context={"task": "review", "code": VULNERABLE, "path": "app.py"},
    ))
    assert result.provider == "demo"
    assert result.prompt_tokens > 0
    assert result.latency_ms >= 0


# ------------------------------------------------------------------ gemini
def test_gemini_requires_a_key():
    provider = GeminiProvider(api_key=None)
    with pytest.raises(ProviderError):
        asyncio.run(provider.complete(
            [ChatMessage(role="user", content="x")], model="gemini-2.0-flash",
        ))


def test_gemini_payload_maps_roles_and_system_instruction():
    provider = GeminiProvider(api_key="k")
    payload = provider._payload(
        [
            ChatMessage(role="system", content="You are a reviewer."),
            ChatMessage(role="user", content="Review this."),
            ChatMessage(role="assistant", content="Done."),
            ChatMessage(role="user", content="Thanks."),
        ],
        temperature=0.2, max_tokens=1024, json_mode=True,
    )
    assert payload["systemInstruction"]["parts"][0]["text"] == "You are a reviewer."
    roles = [turn["role"] for turn in payload["contents"]]
    assert roles == ["user", "model", "user"]
    assert payload["generationConfig"]["responseMimeType"] == "application/json"
    assert payload["generationConfig"]["maxOutputTokens"] == 1024


def test_gemini_json_mode_is_optional():
    provider = GeminiProvider(api_key="k")
    payload = provider._payload([ChatMessage(role="user", content="hi")],
                                temperature=0.7, max_tokens=100, json_mode=False)
    assert "responseMimeType" not in payload["generationConfig"]
    assert payload["generationConfig"]["temperature"] == 0.7


def test_gemini_extracts_text_from_candidates():
    data = {"candidates": [{"content": {"parts": [{"text": "Hello "}, {"text": "world"}]}}]}
    assert GeminiProvider._extract_text(data) == "Hello world"


def test_gemini_extracts_nothing_from_blocked_response():
    assert GeminiProvider._extract_text({"promptFeedback": {"blockReason": "SAFETY"}}) == ""


# ------------------------------------------------------------- openai compat
def test_openai_compat_payload_shape():
    provider = build_provider("groq", api_key="k")
    payload = provider._payload(
        [ChatMessage(role="system", content="s"), ChatMessage(role="user", content="u")],
        model="llama-3.3-70b-versatile", temperature=0.2, max_tokens=1000, json_mode=True,
    )
    assert payload["model"] == "llama-3.3-70b-versatile"
    assert payload["messages"][0] == {"role": "system", "content": "s"}
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["max_tokens"] == 1000


def test_openai_compat_payload_without_json_mode():
    provider = build_provider("groq", api_key="k")
    payload = provider._payload([ChatMessage(role="user", content="u")],
                                model="m", temperature=0.1, max_tokens=10, json_mode=False)
    assert "response_format" not in payload
    assert "stream" not in payload


def test_openai_compat_requires_a_key_for_cloud_providers():
    provider = build_provider("groq")
    provider.api_key = None
    with pytest.raises(ProviderError):
        asyncio.run(provider.complete([ChatMessage(role="user", content="x")], model="m"))


def test_error_messages_are_actionable():
    class FakeResponse:
        status_code = 429
        text = '{"error": {"message": "Rate limit reached"}}'

        def json(self):
            import json
            return json.loads(self.text)

    provider = build_provider("groq", api_key="k")
    error = provider._error(FakeResponse())
    assert error.retryable is True
    assert "Rate limited" in str(error) or "free tier" in str(error)


def test_unauthorised_error_mentions_the_key():
    class FakeResponse:
        status_code = 401
        text = '{"error": {"message": "Invalid API key"}}'

        def json(self):
            import json
            return json.loads(self.text)

    provider = build_provider("groq", api_key="bad")
    error = provider._error(FakeResponse())
    assert error.retryable is False
    assert "API key" in str(error)
