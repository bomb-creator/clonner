"""Unified diff parsing and code<->diff mapping.

CodeRabbit-style review comments must point at a real line in the *new* file,
and we also need to know which lines a PR actually touched so agents can be
told to focus there.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_DIFF_GIT_HEADER = re.compile(r"^diff --git a/(?P<old>.+?) b/(?P<new>.+)$")
_HUNK_HEADER = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<ctx>.*)$"
)
_FILE_HEADERS = {
    "---": "minus",
    "+++": "plus",
    "Index:": "index",
    "new file mode": "mode",
    "deleted file mode": "mode",
    "similarity index": "meta",
    "rename from": "meta",
    "rename to": "meta",
    "old mode": "mode",
    "new mode": "mode",
}


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    context: str = ""
    lines: List[str] = field(default_factory=list)

    @property
    def added_lines(self) -> List[Tuple[int, str]]:
        """(new-file line number, text) for every added line in this hunk."""
        out: List[Tuple[int, str]] = []
        new_line = self.new_start
        for raw in self.lines:
            if raw.startswith("+"):
                out.append((new_line, raw[1:]))
                new_line += 1
            elif raw.startswith("-"):
                continue
            else:
                new_line += 1
        return out

    @property
    def removed_lines(self) -> List[Tuple[int, str]]:
        out: List[Tuple[int, str]] = []
        old_line = self.old_start
        for raw in self.lines:
            if raw.startswith("-"):
                out.append((old_line, raw[1:]))
                old_line += 1
            elif raw.startswith("+"):
                continue
            else:
                old_line += 1
        return out


@dataclass
class FileDiff:
    path: str
    old_path: Optional[str] = None
    hunks: List[Hunk] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False
    is_rename: bool = False
    binary: bool = False

    @property
    def added(self) -> List[Tuple[int, str]]:
        return [pair for hunk in self.hunks for pair in hunk.added_lines]

    @property
    def removed(self) -> List[Tuple[int, str]]:
        return [pair for hunk in self.hunks for pair in hunk.removed_lines]

    @property
    def additions(self) -> int:
        return sum(len(h.added_lines) for h in self.hunks)

    @property
    def deletions(self) -> int:
        return sum(len(h.removed_lines) for h in self.hunks)

    @property
    def changed_line_numbers(self) -> set:
        return {n for n, _ in self.added}

    def patch_text(self) -> str:
        """Reconstruct the unified diff for just this file."""
        head = f"--- a/{self.old_path or self.path}\n+++ b/{self.path}\n"
        body = []
        for h in self.hunks:
            body.append(
                f"@@ -{h.old_start},{h.old_count} +{h.new_start},{h.new_count} @@{h.context}"
            )
            body.extend(h.lines)
        return head + "\n".join(body) + ("\n" if body else "")

    def added_source(self, indent_marker: bool = True) -> str:
        """The added code with absolute new-file line numbers, for the LLM."""
        rows = []
        for number, text in self.added:
            rows.append(f"{number:>5} | {text}" if indent_marker else text)
        return "\n".join(rows)


@dataclass
class DiffSet:
    files: List[FileDiff] = field(default_factory=list)

    @property
    def additions(self) -> int:
        return sum(f.additions for f in self.files)

    @property
    def deletions(self) -> int:
        return sum(f.deletions for f in self.files)

    @property
    def paths(self) -> List[str]:
        return [f.path for f in self.files]

    def file(self, path: str) -> Optional[FileDiff]:
        for f in self.files:
            if f.path == path or f.path.endswith("/" + path) or path.endswith("/" + f.path):
                return f
        return None


def parse_unified_diff(text: str) -> DiffSet:
    """Parse a git-style unified diff into structured files and hunks."""
    result = DiffSet()
    if not text or not text.strip():
        return result

    lines = text.replace("\r\n", "\n").split("\n")
    current: Optional[FileDiff] = None
    current_hunk: Optional[Hunk] = None
    i = 0

    def flush_hunk():
        nonlocal current_hunk
        if current_hunk is not None and current is not None:
            current.hunks.append(current_hunk)
        current_hunk = None

    def flush_file():
        nonlocal current
        flush_hunk()
        if current is not None and (current.hunks or current.binary or current.is_deleted):
            result.files.append(current)
        current = None

    while i < len(lines):
        line = lines[i]

        match = _DIFF_GIT_HEADER.match(line)
        if match:
            flush_file()
            old, new = match.group("old"), match.group("new")
            current = FileDiff(path=new, old_path=old, is_rename=(old != new))
            i += 1
            continue

        if line.startswith("Index:") and current is None:
            flush_file()
            current = FileDiff(path=line[len("Index:") :].strip())
            i += 1
            continue

        if current is not None:
            if line.startswith("new file mode"):
                current.is_new = True
                i += 1
                continue
            if line.startswith("deleted file mode"):
                current.is_deleted = True
                i += 1
                continue
            if line.startswith("Binary files"):
                current.binary = True
                i += 1
                continue
            if line.startswith(("similarity index", "rename from", "rename to", "old mode", "new mode")):
                if line.startswith("rename to"):
                    current.path = line[len("rename to") :].strip()
                i += 1
                continue

        if line.startswith("--- "):
            path = line[4:].strip()
            path = path[2:] if path.startswith("a/") else path
            if current is None:
                flush_file()
                current = FileDiff(path=path if path != "/dev/null" else "")
                current.is_new = path == "/dev/null"
            elif path != "/dev/null":
                current.old_path = path[2:] if path.startswith("a/") else path
            i += 1
            continue

        if line.startswith("+++ "):
            path = line[4:].strip()
            path = path[2:] if path.startswith("b/") else path
            if current is not None:
                if path == "/dev/null":
                    current.is_deleted = True
                elif not current.path:
                    current.path = path
                else:
                    current.path = path
                if current.is_new:
                    current.is_new = path != "/dev/null" and current.is_new
            i += 1
            continue

        hunk_match = _HUNK_HEADER.match(line)
        if hunk_match:
            flush_hunk()
            if current is None:
                current = FileDiff(path="unknown")
            current_hunk = Hunk(
                old_start=int(hunk_match.group("old_start")),
                old_count=int(hunk_match.group("old_count") or 1),
                new_start=int(hunk_match.group("new_start")),
                new_count=int(hunk_match.group("new_count") or 1),
                context=hunk_match.group("ctx") or "",
            )
            i += 1
            continue

        if current_hunk is not None:
            if line.startswith("\\"):  # "\ No newline at end of file" — a marker, not content
                i += 1
                continue
            if line.startswith(("+", "-", " ", "\t")) or line == "":
                current_hunk.lines.append(line if line != "" else " ")
                i += 1
                continue
            flush_hunk()

        i += 1

    flush_file()
    # drop files with no identifiable path
    result.files = [f for f in result.files if f.path and f.path != "/dev/null"]
    return result


def looks_like_diff(text: str) -> bool:
    """Cheap check: is this input a unified diff rather than plain source?"""
    if not text:
        return False
    head = "\n".join(text.splitlines()[:40])
    if re.search(r"^diff --git ", head, re.MULTILINE):
        return True
    if re.search(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", head, re.MULTILINE):
        return True
    return bool(re.search(r"^\+\+\+ ", head, re.MULTILINE) and re.search(r"^--- ", head, re.MULTILINE))


def number_source(code: str, start: int = 1, width: int = 5) -> str:
    """Render plain source with absolute line numbers so models can cite lines."""
    rows = []
    for offset, line in enumerate(code.splitlines()):
        rows.append(f"{start + offset:>{width}} | {line}")
    return "\n".join(rows)


def snippet_around(code: str, line: int, radius: int = 3) -> str:
    """Line-numbered context window centred on `line` (1-based)."""
    lines = code.splitlines()
    low = max(0, line - 1 - radius)
    high = min(len(lines), line + radius)
    return number_source("\n".join(lines[low:high]), start=low + 1)


def merge_line_maps(files: List[FileDiff]) -> Dict[str, set]:
    return {f.path: f.changed_line_numbers for f in files}
