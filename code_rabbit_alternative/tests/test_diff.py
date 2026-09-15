"""Tests for the unified diff parser."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.analysis.diff import (  # noqa: E402
    looks_like_diff,
    number_source,
    parse_unified_diff,
    snippet_around,
)

SIMPLE_DIFF = """diff --git a/app.py b/app.py
index 1234567..89abcde 100644
--- a/app.py
+++ b/app.py
@@ -1,4 +1,6 @@
 import os
+import sqlite3
+PASSWORD = "hunter2"
 
 def main():
-    print("hi")
+    print("hello")
"""


def test_parses_files_and_hunks():
    diffset = parse_unified_diff(SIMPLE_DIFF)
    assert len(diffset.files) == 1
    file_diff = diffset.files[0]
    assert file_diff.path == "app.py"
    assert file_diff.old_path == "app.py"
    assert len(file_diff.hunks) == 1


def test_added_lines_carry_absolute_new_file_numbers():
    diffset = parse_unified_diff(SIMPLE_DIFF)
    added = diffset.files[0].added
    numbers = [n for n, _ in added]
    # hunk starts at new line 1; two insertions then the modified print
    assert numbers == [2, 3, 6]
    texts = [t for _, t in added]
    assert texts[0] == "import sqlite3"
    assert texts[1] == 'PASSWORD = "hunter2"'
    assert texts[2] == '    print("hello")'


def test_removed_lines_carry_old_file_numbers():
    diffset = parse_unified_diff(SIMPLE_DIFF)
    removed = diffset.files[0].removed
    # old file: line 1 `import os`, 2 blank, 3 `def main():`, 4 the removed print
    assert removed == [(4, '    print("hi")')]


def test_addition_deletion_counts():
    diffset = parse_unified_diff(SIMPLE_DIFF)
    assert diffset.additions == 3
    assert diffset.deletions == 1


def test_multi_file_diff_with_new_and_deleted_files():
    text = """diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,3 @@
+def added():
+    return 1
+
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def removed():
-    return 2
diff --git a/old.py b/renamed.py
similarity index 80%
rename from old.py
rename to renamed.py
--- a/old.py
+++ b/renamed.py
@@ -1,2 +1,2 @@
-x = 1
+x = 2
 y = 3
"""
    diffset = parse_unified_diff(text)
    paths = diffset.paths
    assert "new.py" in paths
    assert "renamed.py" in paths

    new_file = diffset.file("new.py")
    assert new_file is not None
    assert new_file.is_new
    assert new_file.additions == 3   # two code lines plus the trailing blank

    gone = diffset.file("gone.py")
    assert gone is not None
    assert gone.is_deleted
    assert gone.deletions == 2

    renamed = diffset.file("renamed.py")
    assert renamed is not None
    assert renamed.is_rename


def test_reconstruct_patch_text():
    diffset = parse_unified_diff(SIMPLE_DIFF)
    patch = diffset.files[0].patch_text()
    assert patch.startswith("--- a/app.py\n+++ b/app.py\n")
    assert "@@ -1,4 +1,6 @@" in patch
    assert '+PASSWORD = "hunter2"' in patch


def test_no_newline_marker_is_skipped():
    text = """--- a/f.py
+++ b/f.py
@@ -1 +1 @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
"""
    diffset = parse_unified_diff(text)
    assert diffset.files[0].added == [(1, "new")]
    assert diffset.files[0].removed == [(1, "old")]


def test_looks_like_diff():
    assert looks_like_diff(SIMPLE_DIFF) is True
    assert looks_like_diff("def main():\n    return 1\n") is False
    assert looks_like_diff("") is False
    plain_plus = "a = 1 + 2\nb = c\n"
    assert looks_like_diff(plain_plus) is False


def test_bare_diff_without_git_header():
    text = """--- a/x.py
+++ b/x.py
@@ -0,0 +1,2 @@
+import os
+os.system("ls")
"""
    diffset = parse_unified_diff(text)
    assert len(diffset.files) == 1
    assert diffset.files[0].path == "x.py"
    assert diffset.files[0].additions == 2


def test_empty_and_garbage_input():
    assert parse_unified_diff("").files == []
    assert parse_unified_diff("not a diff at all").files == []
    assert parse_unified_diff(None).files == []


def test_number_source_and_snippet():
    code = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5"
    numbered = number_source(code)
    assert "    1 | a = 1" in numbered
    assert "    5 | e = 5" in numbered

    window = snippet_around(code, 3, radius=1)
    assert "b = 2" in window and "d = 4" in window
    assert "a = 1" not in window


def test_changed_line_numbers_set():
    diffset = parse_unified_diff(SIMPLE_DIFF)
    assert diffset.files[0].changed_line_numbers == {2, 3, 6}


def test_crlf_normalised():
    text = SIMPLE_DIFF.replace("\n", "\r\n")
    diffset = parse_unified_diff(text)
    assert len(diffset.files) == 1
    assert diffset.files[0].additions == 3
