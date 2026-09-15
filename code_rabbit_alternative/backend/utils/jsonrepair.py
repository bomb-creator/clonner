"""Tolerant JSON extraction for LLM output.

Models wrap JSON in prose or ```json fences, emit trailing commas, or use
single quotes. We try progressively more aggressive repairs instead of
failing the whole review.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

_FENCE_RE = re.compile(r"```(?:json|json5|javascript)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
_PY_CONST_RE = re.compile(r"\b(True|False|None)\b")
_LINE_COMMENT_RE = re.compile(r"^\s*//.*$", re.MULTILINE)


def _balanced_slice(text: str, start: int) -> Optional[str]:
    """Return the substring of the first balanced {...} block starting at `start`."""
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def extract_json(text: str) -> Optional[Any]:
    """Best-effort parse of a JSON object embedded in free-form model output."""
    if not text or not text.strip():
        return None

    candidates: list[str] = []
    stripped = text.strip()
    candidates.append(stripped)
    for match in _FENCE_RE.findall(text):
        candidates.append(match.strip())
    # first balanced object anywhere in the text
    brace = stripped.find("{")
    if brace != -1:
        block = _balanced_slice(stripped, brace)
        if block:
            candidates.append(block)

    for candidate in candidates:
        for transform in (lambda s: s, _light_repair, _heavy_repair):
            try:
                parsed = json.loads(transform(candidate))
                if isinstance(parsed, (dict, list)):
                    return parsed
            except Exception:
                continue
    return None


def _light_repair(text: str) -> str:
    out = _LINE_COMMENT_RE.sub("", text)
    out = _TRAILING_COMMA_RE.sub(r"\1", out)
    return out.strip()


def _heavy_repair(text: str) -> str:
    out = _light_repair(text)
    out = _PY_CONST_RE.sub(lambda m: {"True": "true", "False": "false", "None": "null"}[m.group(1)], out)
    # quote bare object keys: {severity: "high"} -> {"severity": "high"}
    out = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:", r'\1"\2":', out)
    return out


def coerce_findings(payload: Any) -> list[dict]:
    """Normalise any plausible model shape into a list of finding dicts."""
    if payload is None:
        return []
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        for key in ("findings", "issues", "comments", "problems", "results", "review"):
            value = payload.get(key)
            if isinstance(value, list):
                items = value
                break
        else:
            # a single finding object
            if any(k in payload for k in ("title", "description", "issue", "severity")):
                items = [payload]
            else:
                items = []
    else:
        return []
    return [item for item in items if isinstance(item, dict)]
