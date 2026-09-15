"""Tests for tolerant JSON extraction from model output."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.utils.jsonrepair import coerce_findings, extract_json  # noqa: E402


def test_plain_json():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_json_in_code_fence():
    text = 'Here is the review:\n```json\n{"findings": []}\n```\nHope that helps.'
    assert extract_json(text) == {"findings": []}


def test_json_in_bare_fence():
    text = '```\n{"score": 90}\n```'
    assert extract_json(text) == {"score": 90}


def test_json_embedded_in_prose():
    text = 'Sure! {"summary": "looks fine", "findings": []} Let me know if you need more.'
    data = extract_json(text)
    assert data["summary"] == "looks fine"


def test_trailing_comma_repaired():
    assert extract_json('{"a": 1, "b": [1, 2,],}') == {"a": 1, "b": [1, 2]}


def test_python_constants_repaired():
    data = extract_json('{"ok": True, "missing": None, "off": False}')
    assert data == {"ok": True, "missing": None, "off": False}


def test_bare_keys_repaired():
    data = extract_json('{severity: "high", title: "SQL injection"}')
    assert data["severity"] == "high"


def test_nested_braces_and_strings_with_braces():
    text = '{"code_after": "if (x) { return {a: 1}; }", "line": 4}'
    data = extract_json(text)
    assert data["line"] == 4
    assert "{a: 1}" in data["code_after"]


def test_escaped_quotes_in_strings():
    text = r'{"title": "He said \"hi\"", "n": 2}'
    data = extract_json(text)
    assert data["n"] == 2
    assert "hi" in data["title"]


def test_line_comments_stripped():
    text = '{\n// a comment\n"a": 1\n}'
    assert extract_json(text) == {"a": 1}


def test_top_level_array():
    assert extract_json('[{"a": 1}, {"b": 2}]') == [{"a": 1}, {"b": 2}]


def test_truncated_json_returns_none():
    assert extract_json('{"findings": [{"title": "x"') is None


def test_garbage_returns_none():
    assert extract_json("this is not json at all") is None
    assert extract_json("") is None
    assert extract_json(None) is None


def test_multiline_realistic_payload():
    text = """Based on my review:

```json
{
  "summary": "The handler concatenates user input into SQL.",
  "overall_assessment": "block",
  "score": 32,
  "positives": ["Clear function names"],
  "findings": [
    {
      "category": "security",
      "severity": "critical",
      "title": "SQL injection via string concatenation",
      "file": "app.py",
      "line": 12,
      "description": "User input is concatenated into the query.",
      "suggestion": "Use a parameterised query.",
      "code_after": "cur.execute(\\"SELECT * FROM users WHERE id = %s\\", (uid,))",
      "confidence": 0.95,
      "references": ["CWE-89"]
    }
  ],
  "test_recommendations": ["Add a test with a quote in the id."]
}
```
"""
    data = extract_json(text)
    assert data is not None
    assert data["score"] == 32
    assert len(data["findings"]) == 1
    assert data["findings"][0]["line"] == 12
    assert "%s" in data["findings"][0]["code_after"]


# ------------------------------------------------------------- coerce_findings
def test_coerce_from_findings_key():
    assert len(coerce_findings({"findings": [{"title": "a"}, {"title": "b"}]})) == 2


def test_coerce_from_issues_key():
    assert len(coerce_findings({"issues": [{"title": "a"}]})) == 1


def test_coerce_from_comments_key():
    assert len(coerce_findings({"comments": [{"title": "a"}]})) == 1


def test_coerce_from_bare_list():
    assert len(coerce_findings([{"title": "a"}, {"title": "b"}])) == 2


def test_coerce_single_finding_object():
    result = coerce_findings({"title": "SQL injection", "severity": "critical"})
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_coerce_ignores_non_dicts():
    assert coerce_findings({"findings": ["not a dict", {"title": "ok"}, 42]}) == [{"title": "ok"}]


def test_coerce_handles_unexpected_shape():
    assert coerce_findings({"something": "else"}) == []
    assert coerce_findings(None) == []
    assert coerce_findings("string") == []
    assert coerce_findings(42) == []


def test_coerce_review_key():
    assert len(coerce_findings({"review": [{"title": "a"}]})) == 1
