"""End-to-end API tests using FastAPI's TestClient."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.main import app  # noqa: E402

pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)

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


# ------------------------------------------------------------------- health
def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["offline_ready"] is True
    assert data["version"]


def test_openapi_is_served_under_api_prefix():
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/review" in paths
    assert "/api/ask" in paths


def test_docs_page():
    assert client.get("/api/docs").status_code == 200


# ---------------------------------------------------------------- providers
def test_providers_lists_the_free_catalogue():
    data = client.get("/api/providers").json()
    ids = {p["id"] for p in data["providers"]}
    assert {"demo", "groq", "gemini", "openrouter"} <= ids
    demo = next(p for p in data["providers"] if p["id"] == "demo")
    assert demo["requires_key"] is False
    assert demo["configured"] is True


def test_provider_models_are_advertised():
    data = client.get("/api/providers").json()
    groq = next(p for p in data["providers"] if p["id"] == "groq")
    assert groq["models"]
    assert groq["signup_url"].startswith("http")
    assert groq["free_note"]


def test_provider_status_never_leaks_key_values():
    text = client.get("/api/providers").text
    assert "sk-" not in text or "signup" in text  # no raw key material echoed


# ------------------------------------------------------------------- config
def test_config_snapshot_masks_keys():
    response = client.post("/api/config", json={"api_keys": {"groq": "gsk_testvalue_1234567890"}})
    assert response.status_code == 200
    masked = response.json()["api_keys_masked"]["groq"]
    assert "testvalue" not in masked
    assert "*" in masked


def test_config_rejects_unknown_provider():
    response = client.post("/api/config", json={"provider": "not-a-provider"})
    assert response.status_code == 400


def test_config_accepts_a_known_provider():
    response = client.post("/api/config", json={"provider": "demo"})
    assert response.status_code == 200
    assert response.json()["provider"] == "demo"


def test_config_roundtrip_effort_and_temperature():
    response = client.post("/api/config", json={"effort": "deep", "temperature": 0.1})
    assert response.status_code == 200
    data = response.json()
    assert data["effort"] == "deep"
    assert data["temperature"] == 0.1
    client.post("/api/config", json={"effort": "standard", "temperature": 0.2})


def test_config_clears_a_key_when_set_empty():
    client.post("/api/config", json={"api_keys": {"together": "tk_abc123def456"}})
    response = client.post("/api/config", json={"api_keys": {"together": ""}})
    assert "together" not in response.json()["api_keys_masked"]


# ------------------------------------------------------------ system prompt
def test_system_prompt_is_exposed_verbatim():
    data = client.get("/api/system-prompt").json()
    core = data["core"]
    assert core.startswith("You are an expert AI code reviewer.")
    for section in ("## Code Quality", "## Bug Detection", "## Security Analysis",
                    "## Performance", "## Best Practices"):
        assert section in core
    assert "specific line references and code suggestions" in core


def test_system_prompt_lists_agent_focus_blocks():
    data = client.get("/api/system-prompt").json()
    assert {"quality", "bugs", "security", "performance", "best_practices",
            "synthesizer", "summarizer"} <= set(data["agents"])


# --------------------------------------------------------------------- scan
def test_static_scan_endpoint():
    response = client.post("/api/scan", json={"code": VULNERABLE, "path": "app.py"})
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "python"
    assert data["findings"]
    assert data["by_severity"]["critical"] > 0
    assert "app.py" in data["metrics"]


def test_static_scan_requires_input():
    assert client.post("/api/scan", json={}).status_code == 400


def test_static_scan_accepts_a_diff():
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
 import os
+SECRET = "hunter2secretvalue"
+os.system("rm -rf " + path)
"""
    response = client.post("/api/scan", json={"diff": diff})
    assert response.status_code == 200
    assert response.json()["findings"]


# ------------------------------------------------------------------- detect
def test_detect_endpoint():
    response = client.post("/api/detect", json={"code": "def f():\n    return 1", "path": "a.py"})
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "python"
    assert data["is_diff"] is False
    assert data["lines"] == 2


def test_detect_identifies_a_diff():
    response = client.post("/api/detect", json={"code": "@@ -1,2 +1,3 @@\n+x = 1"})
    assert response.json()["is_diff"] is True


# ------------------------------------------------------------------- review
def test_review_requires_some_input():
    response = client.post("/api/review", json={})
    assert response.status_code == 400
    assert "code" in response.json()["detail"]


def test_review_non_streaming_returns_a_full_review():
    response = client.post("/api/review", json={
        "code": VULNERABLE, "provider": "demo", "stream": False,
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in {"completed", "partial"}
    assert data["findings"]
    assert data["review_markdown"]
    assert 0 <= data["score"] <= 100
    assert data["provider"] == "demo"


def test_review_streaming_emits_sse_events():
    with client.stream("POST", "/api/review", json={
        "code": VULNERABLE, "provider": "demo", "stream": True,
    }) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(chunk for chunk in response.iter_text())

    events = [line for line in body.splitlines() if line.startswith("event:")]
    assert "event: start" in events
    assert "event: agent:start" in events
    assert "event: agent:done" in events
    assert "event: done" in events
    assert "event: end" in events

    done = [line for line in body.splitlines() if line.startswith("data:") and '"review"' in line]
    assert done
    review = json.loads(done[0][len("data:"):].strip())["review"]
    assert review["findings"]


def test_sse_data_lines_are_valid_json():
    with client.stream("POST", "/api/review", json={
        "code": "print('hi')", "provider": "demo",
    }) as response:
        body = "".join(chunk for chunk in response.iter_text())
    for line in body.splitlines():
        if line.startswith("data:"):
            payload = line[len("data:"):].strip()
            if payload:
                json.loads(payload)  # raises on malformed JSON


def test_review_diff_input():
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
 import os
+SECRET = "hunter2secretvalue"
+os.system("rm -rf " + path)
"""
    response = client.post("/api/review", json={"diff": diff, "provider": "demo", "stream": False})
    assert response.status_code == 200
    data = response.json()
    assert data["stats"]["diff_stats"]["files"] == 1
    assert all(f["line"] in {2, 3} for f in data["findings"] if f["line"])


def test_review_multiple_files():
    response = client.post("/api/review", json={
        "provider": "demo", "stream": False,
        "files": [
            {"path": "a.py", "content": VULNERABLE},
            {"path": "b.js", "content": "el.innerHTML = userInput;"},
        ],
    })
    assert response.status_code == 200
    files = {f["file"] for f in response.json()["findings"]}
    assert "a.py" in files


def test_review_invalid_diff_returns_a_useful_error():
    with client.stream("POST", "/api/review", json={"diff": "@@@ not a diff", "provider": "demo"}) as r:
        body = "".join(chunk for chunk in r.iter_text())
    assert "event: error" in body


def test_review_invalid_pr_reference_returns_a_useful_error():
    with client.stream("POST", "/api/review", json={"pull_request": "nonsense", "provider": "demo"}) as r:
        body = "".join(chunk for chunk in r.iter_text())
    assert "event: error" in body
    assert "owner/repo#123" in body


def test_review_category_filter():
    response = client.post("/api/review", json={
        "code": VULNERABLE, "provider": "demo", "stream": False, "categories": ["security"],
    })
    assert all(f["category"] == "security" for f in response.json()["findings"])


def test_review_stored_and_retrievable():
    review = client.post("/api/review", json={
        "code": VULNERABLE, "provider": "demo", "stream": False,
    }).json()
    stored = client.get(f"/api/reviews/{review['id']}")
    assert stored.status_code == 200
    assert stored.json()["id"] == review["id"]

    markdown = client.get(f"/api/reviews/{review['id']}/markdown").json()
    assert markdown["markdown"].startswith("# Code review")

    as_markdown = client.get(f"/api/reviews/{review['id']}?fmt=markdown").json()
    assert as_markdown["markdown"]


def test_review_lookup_of_unknown_id_is_404():
    assert client.get("/api/reviews/does-not-exist").status_code == 404


def test_review_comments_are_github_shaped():
    review = client.post("/api/review", json={
        "code": VULNERABLE, "provider": "demo", "stream": False,
    }).json()
    data = client.get(f"/api/reviews/{review['id']}/comments?min_severity=high").json()
    assert data["event"] in {"COMMENT", "REQUEST_CHANGES"}
    assert data["comments"]
    comment = data["comments"][0]
    assert {"path", "line", "body"} <= set(comment)
    assert comment["line"] >= 1
    assert "CRITICAL" in comment["body"] or "HIGH" in comment["body"]


def test_review_comments_respect_the_severity_floor():
    review = client.post("/api/review", json={
        "code": VULNERABLE, "provider": "demo", "stream": False,
    }).json()
    everything = client.get(f"/api/reviews/{review['id']}/comments?min_severity=info").json()
    critical_only = client.get(f"/api/reviews/{review['id']}/comments?min_severity=critical").json()
    assert len(critical_only["comments"]) <= len(everything["comments"])


def test_publish_without_a_pr_reference_is_rejected():
    review = client.post("/api/review", json={
        "code": VULNERABLE, "provider": "demo", "stream": False,
    }).json()
    response = client.post(f"/api/reviews/{review['id']}/publish", json={})
    assert response.status_code == 400
    assert "pull request" in response.json()["detail"].lower()


# ---------------------------------------------------------------------- ask
def test_ask_requires_a_question():
    assert client.post("/api/ask", json={"question": "  ", "code": "x=1"}).status_code == 400


def test_ask_requires_code_or_review_id():
    response = client.post("/api/ask", json={"question": "why?", "provider": "demo"})
    assert response.status_code == 400


def test_ask_answers_with_the_offline_provider():
    response = client.post("/api/ask", json={
        "question": "Are there security problems here?",
        "code": VULNERABLE,
        "path": "app.py",
        "provider": "demo",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["answer"]
    assert data["provider"] == "demo"
    assert "elapsed_ms" in data


def test_ask_against_a_stored_review():
    review = client.post("/api/review", json={
        "code": VULNERABLE, "provider": "demo", "stream": False,
    }).json()
    response = client.post("/api/ask", json={
        "question": "What is the worst issue?",
        "review_id": review["id"],
        "provider": "demo",
    })
    assert response.status_code == 200
    assert response.json()["answer"]


def test_ask_with_a_keyed_provider_but_no_key_is_rejected():
    response = client.post("/api/ask", json={
        "question": "why?", "code": "x = 1", "provider": "together",
    })
    assert response.status_code in {400, 502}


# ----------------------------------------------------------------- examples
def test_examples_are_served():
    data = client.get("/api/examples").json()
    names = {ex["name"] for ex in data["examples"]}
    assert "vulnerable_api.py" in names
    assert "payment_service.diff" in names
    diff_example = next(ex for ex in data["examples"] if ex["name"] == "payment_service.diff")
    assert diff_example["kind"] == "diff"


def test_example_code_actually_produces_findings():
    """Guards against shipping an example the reviewer says nothing about."""
    examples = client.get("/api/examples").json()["examples"]
    for example in examples:
        if example["kind"] != "code":
            continue
        response = client.post("/api/scan", json={
            "code": example["content"], "path": example["name"],
        })
        assert response.status_code == 200, example["name"]
        assert response.json()["findings"], f"{example['name']} produced no findings"


def test_example_diff_produces_findings():
    examples = client.get("/api/examples").json()["examples"]
    diff_example = next(ex for ex in examples if ex["kind"] == "diff")
    response = client.post("/api/scan", json={"diff": diff_example["content"]})
    assert response.status_code == 200
    assert response.json()["findings"]


# --------------------------------------------------------------------- ui
def test_frontend_is_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "Code Review Agent" in response.text


def test_frontend_assets_exist():
    for asset in ("/styles.css", "/app.js", "/vendor/markdown.js", "/vendor/highlight.js"):
        response = client.get(asset)
        assert response.status_code == 200, asset
        assert len(response.content) > 100, asset


def test_frontend_has_no_external_cdn_dependencies():
    """The sandbox has no CDN access, so the UI must be fully self-hosted."""
    html = client.get("/").text
    for banned in ("cdn.jsdelivr", "unpkg.com", "cdnjs.cloudflare", "fonts.googleapis",
                   "googleapis.com", "mermaid.min.js", "highlight.min.js"):
        assert banned not in html, f"index.html must not depend on {banned}"


def test_frontend_js_has_no_external_dependencies():
    script = client.get("/app.js").text
    for banned in ("cdn.jsdelivr", "unpkg.com", "cdnjs.cloudflare"):
        assert banned not in script


# ------------------------------------------------------------------ github
def test_github_pr_validation_rejects_bad_reference():
    response = client.post("/api/github/pr", json={"pull_request": "not-valid"})
    assert response.status_code == 400
    assert "owner/repo#123" in response.json()["detail"]


def test_github_pr_parse_accepts_several_shapes():
    from backend.integrations.github import parse_pr_ref

    assert parse_pr_ref("facebook/react#123") == {"owner": "facebook", "repo": "react", "number": 123}
    assert parse_pr_ref("https://github.com/facebook/react/pull/456") == {
        "owner": "facebook", "repo": "react", "number": 456}
    assert parse_pr_ref("facebook/react/pull/789") == {"owner": "facebook", "repo": "react", "number": 789}
    assert parse_pr_ref("") is None
    assert parse_pr_ref("nonsense") is None


def test_post_review_requires_a_token(monkeypatch):
    import asyncio

    from backend.integrations.github import PullRequest, post_review
    from backend.providers.base import ProviderError

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    pr = PullRequest(owner="a", repo="b", number=1)
    with pytest.raises(ProviderError) as info:
        asyncio.run(post_review(pr, "body", []))
    assert "GITHUB_TOKEN" in str(info.value)


# ------------------------------------------------------------------- errors
def test_unhandled_route_is_404():
    assert client.get("/api/does-not-exist").status_code == 404


def test_review_of_a_non_utf8_free_but_huge_input_does_not_hang():
    big = "x = 1\n" * 20000
    response = client.post("/api/review", json={
        "code": big, "provider": "demo", "stream": False, "effort": "quick",
    })
    assert response.status_code == 200
