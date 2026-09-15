"""Language detection and per-language metadata.

Pure stdlib so it can be unit tested and reused by the offline engine.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

EXTENSION_MAP: Dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "bash",
    ".bash": "bash",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".vue": "vue",
    ".svelte": "svelte",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".md": "markdown",
    ".tf": "terraform",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".lua": "lua",
    ".r": "r",
    ".pl": "perl",
}

CONTENT_SIGNATURES: List[tuple] = [
    (r"^\s*def\s+\w+\s*\(|^\s*import\s+\w+|^\s*from\s+[\w.]+\s+import", "python"),
    (r"^\s*func\s+\w+\(|^\s*package\s+main\b", "go"),
    (r"^\s*(public|private|protected)\s+class\s+\w+|System\.out\.print", "java"),
    (r"^\s*(const|let|var)\s+\w+\s*=|=>\s*{|console\.log", "javascript"),
    (r"^\s*(interface|type)\s+\w+\s*(=|\{)|:\s*(string|number|boolean)\b", "typescript"),
    (r"^\s*fn\s+\w+\s*\(|^\s*use\s+std::", "rust"),
    (r"^\s*class\s+\w+\s*<\s*ActiveRecord|puts\s+", "ruby"),
    (r"<\?php", "php"),
    (r"^\s*#\s*include\s*<|^\s*int\s+main\s*\(", "c"),
    (r"^\s*using\s+System;|namespace\s+\w+", "csharp"),
]


@dataclass
class LanguageProfile:
    """Syntax/idiom metadata used by the static rule engine."""

    name: str
    line_comment: str = "//"
    block_comment: Optional[tuple] = None
    dynamic: bool = True
    typed: bool = False
    families: List[str] = field(default_factory=list)

    @property
    def is_web(self) -> bool:
        return "web" in self.families

    @property
    def is_script(self) -> bool:
        return "script" in self.families


PROFILES: Dict[str, LanguageProfile] = {
    "python": LanguageProfile("python", "#", ('"""', '"""'), True, False, ["script", "backend"]),
    "javascript": LanguageProfile("javascript", "//", ("/*", "*/"), True, False, ["script", "web"]),
    "typescript": LanguageProfile("typescript", "//", ("/*", "*/"), True, True, ["script", "web"]),
    "java": LanguageProfile("java", "//", ("/*", "*/"), False, True, ["backend", "jvm"]),
    "kotlin": LanguageProfile("kotlin", "//", ("/*", "*/"), False, True, ["backend", "jvm"]),
    "go": LanguageProfile("go", "//", ("/*", "*/"), False, True, ["backend"]),
    "rust": LanguageProfile("rust", "//", ("/*", "*/"), False, True, ["systems"]),
    "ruby": LanguageProfile("ruby", "#", ("=begin", "=end"), True, False, ["script", "web"]),
    "php": LanguageProfile("php", "//", ("/*", "*/"), True, False, ["web", "backend"]),
    "csharp": LanguageProfile("csharp", "//", ("/*", "*/"), False, True, ["backend", "jvm"]),
    "c": LanguageProfile("c", "//", ("/*", "*/"), False, True, ["systems"]),
    "cpp": LanguageProfile("cpp", "//", ("/*", "*/"), False, True, ["systems"]),
    "swift": LanguageProfile("swift", "//", ("/*", "*/"), False, True, ["mobile"]),
    "bash": LanguageProfile("bash", "#", None, True, False, ["script"]),
    "sql": LanguageProfile("sql", "--", ("/*", "*/"), False, False, ["data"]),
    "html": LanguageProfile("html", None, ("<!--", "-->"), False, False, ["web", "markup"]),
    "css": LanguageProfile("css", None, ("/*", "*/"), False, False, ["web", "markup"]),
    "json": LanguageProfile("json", None, None, False, False, ["data", "config"]),
    "yaml": LanguageProfile("yaml", "#", None, False, False, ["config"]),
    "markdown": LanguageProfile("markdown", None, None, False, False, ["docs"]),
    "terraform": LanguageProfile("terraform", "#", ("/*", "*/"), False, False, ["config", "infra"]),
}

DEFAULT_PROFILE = LanguageProfile("plaintext")


def language_for_path(path: str) -> str:
    ext = os.path.splitext(path or "")[1].lower()
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]
    base = os.path.basename(path or "").lower()
    if base in {"makefile", "dockerfile"}:
        return "bash" if base == "dockerfile" else "make"
    return "plaintext"


def detect_language(code: str, path: Optional[str] = None) -> str:
    """Detect language from the file path first, then from content signatures."""
    if path:
        by_path = language_for_path(path)
        if by_path != "plaintext":
            return by_path
    sample = "\n".join((code or "").splitlines()[:60])
    scores: Dict[str, int] = {}
    for pattern, lang in CONTENT_SIGNATURES:
        hits = len(re.findall(pattern, sample, re.MULTILINE))
        if hits:
            scores[lang] = scores.get(lang, 0) + hits
    if not scores:
        return "plaintext"
    return max(scores.items(), key=lambda kv: kv[1])[0]


def profile_for(language: str) -> LanguageProfile:
    return PROFILES.get(language, DEFAULT_PROFILE)


def is_test_file(path: str) -> bool:
    base = os.path.basename(path or "").lower()
    return bool(
        re.search(r"(^test_|_test\.|\.test\.|\.spec\.|^tests?$)", base)
        or "/tests/" in f"/{(path or '').lower()}"
        or base.endswith("_tests.go")
    )


def is_binary_or_ignorable(path: str) -> bool:
    """Skip lockfiles, minified bundles, images and vendored noise."""
    lowered = (path or "").lower()
    skip_names = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
        "composer.lock", "cargo.lock", "gemfile.lock", "go.sum",
    }
    if os.path.basename(lowered) in skip_names:
        return True
    skip_suffix = (".min.js", ".min.css", ".map", ".png", ".jpg", ".jpeg", ".gif",
                   ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".svg",
                   ".lock", ".pb.go", ".g.dart")
    if lowered.endswith(skip_suffix):
        return True
    skip_dirs = ("/node_modules/", "/vendor/", "/dist/", "/build/", "/.git/", "/__snapshots__/")
    return any(d in f"/{lowered}" for d in skip_dirs)
