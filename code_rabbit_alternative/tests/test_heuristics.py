"""Tests for the static rule engine."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.analysis.heuristics import (  # noqa: E402
    compute_metrics,
    scan_code,
    scan_diff,
    summarise_findings,
)
from backend.analysis.diff import parse_unified_diff  # noqa: E402


def ids(findings):
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------- security
def test_detects_sql_string_concatenation():
    code = '''
def lookup(name):
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
'''
    result = scan_code(code, path="db.py")
    assert "SEC-SQLI-CONCAT" in ids(result.findings)
    hit = next(f for f in result.findings if f.rule_id == "SEC-SQLI-CONCAT")
    assert hit.severity == "critical"
    assert hit.line == 3
    assert "CWE-89" in hit.references


def test_detects_hardcoded_secret():
    code = 'API_KEY = "not-a-real-secret-value-12345"\n'
    result = scan_code(code, path="config.py")
    assert "SEC-SECRET-HARDCODED" in ids(result.findings)


def test_detects_cloud_access_key_literal():
    """The vendor-format literal is assembled at runtime on purpose: committing
    a realistic key shape would trip GitHub push protection on this very repo."""
    prefix = "AK" + "IA"          # split so no vendor-format literal is committed
    body = ("EXAMPLE" * 3)[:16]   # 16 chars from [0-9A-Z], obviously not a real key
    key = prefix + body
    assert len(key) == 20 and key.startswith(prefix)

    code = f'aws_access = "{key}"\n'
    result = scan_code(code, path="cloud.py")
    assert "SEC-AWS-KEY" in ids(result.findings)
    hit = next(f for f in result.findings if f.rule_id == "SEC-AWS-KEY")
    assert hit.severity == "critical"


def test_detects_command_injection():
    code = 'import os\nos.system("rm -rf " + user_input)\n'
    result = scan_code(code, path="shell.py")
    assert "SEC-CMD-INJECTION" in ids(result.findings)


def test_detects_shell_true():
    code = 'subprocess.run(cmd, shell=True)\n'
    result = scan_code(code, path="shell.py")
    assert "SEC-SHELL-TRUE" in ids(result.findings)


def test_detects_weak_hash():
    code = 'import hashlib\ndigest = hashlib.md5(password.encode()).hexdigest()\n'
    result = scan_code(code, path="auth.py")
    assert "SEC-WEAK-HASH" in ids(result.findings)


def test_detects_unsafe_deserialization():
    code = 'import yaml\ndata = yaml.load(stream)\n'
    result = scan_code(code, path="cfg.py")
    assert "SEC-INSECURE-DESER" in ids(result.findings)

    safe = 'data = yaml.safe_load(stream)\n'
    assert "SEC-INSECURE-DESER" not in ids(scan_code(safe, path="cfg.py").findings)


def test_detects_xss_innerhtml():
    code = "el.innerHTML = userInput;\n"
    result = scan_code(code, path="ui.js")
    assert "SEC-XSS-INNERHTML" in ids(result.findings)


def test_detects_cors_wildcard_and_debug_mode():
    js = "app.use(cors({ origin: '*' }));\n"
    assert "SEC-CORS-WILDCARD" in ids(scan_code(js, path="server.js").findings)
    py = "app.run(debug=True)\n"
    assert "SEC-DEBUG-ON" in ids(scan_code(py, path="app.py").findings)


def test_detects_tls_verification_disabled():
    code = 'requests.get(url, verify=False)\n'
    assert "SEC-SSL-DISABLED" in ids(scan_code(code, path="client.py").findings)


# -------------------------------------------------------------------- bugs
def test_detects_mutable_default_argument():
    code = "def add(item, bucket=[]):\n    bucket.append(item)\n"
    result = scan_code(code, path="util.py")
    assert "BUG-MUTABLE-DEFAULT" in ids(result.findings)


def test_detects_swallowed_exception():
    code = "try:\n    do()\nexcept:\n    pass\n"
    result = scan_code(code, path="util.py")
    assert "BUG-BARE-EXCEPT" in ids(result.findings)


def test_detects_empty_catch_block_in_js():
    code = "try { run(); } catch (e) {}\n"
    result = scan_code(code, path="app.js")
    assert "BUG-EMPTY-CATCH" in ids(result.findings)


def test_detects_loop_off_by_one():
    code = "for (var i = 0; i <= items.length; i++) { use(items[i]); }\n"
    result = scan_code(code, path="app.js")
    assert "BUG-OFF-BY-ONE-RANGE" in ids(result.findings)
    assert "BUG-LOOP-VAR-CLOSURE" in ids(result.findings)


def test_detects_missing_timeout_on_requests():
    code = 'requests.get("https://example.com")\n'
    assert "BUG-TIMEOUT-MISSING" in ids(scan_code(code, path="c.py").findings)

    fixed = 'requests.get("https://example.com", timeout=5)\n'
    assert "BUG-TIMEOUT-MISSING" not in ids(scan_code(fixed, path="c.py").findings)


def test_detects_resource_without_context_manager():
    code = 'f = open("data.txt")\ndata = f.read()\n'
    assert "BUG-RESOURCE-LEAK" in ids(scan_code(code, path="io.py").findings)

    fixed = 'with open("data.txt") as f:\n    data = f.read()\n'
    assert "BUG-RESOURCE-LEAK" not in ids(scan_code(fixed, path="io.py").findings)


def test_detects_nan_comparison():
    code = "if (value == NaN) { reset(); }\n"
    assert "BUG-COMPARE-IS-NAN" in ids(scan_code(code, path="a.js").findings)


def test_detects_return_in_finally():
    code = "try:\n    x()\nexcept ValueError:\n    log()\nfinally:\n    return True\n"
    assert "BUG-RETURN-IN-FINALLY" in ids(scan_code(code, path="f.py").findings)

    clean = "try:\n    x()\nfinally:\n    close()\n"
    assert "BUG-RETURN-IN-FINALLY" not in ids(scan_code(clean, path="f.py").findings)


# ------------------------------------------------------------- performance
def test_detects_n_plus_one_query_in_loop():
    code = """
for order in orders:
    cur.execute("SELECT * FROM items WHERE order_id = ?", order.id)
    process(cur.fetchall())
"""
    result = scan_code(code, path="svc.py")
    assert "PERF-N-PLUS-1" in ids(result.findings)
    hit = next(f for f in result.findings if f.rule_id == "PERF-N-PLUS-1")
    assert hit.line == 3
    assert "loop" in hit.description.lower()


def test_no_n_plus_one_outside_a_loop():
    code = 'cur.execute("SELECT * FROM items WHERE order_id = ?", oid)\n'
    assert "PERF-N-PLUS-1" not in ids(scan_code(code, path="svc.py").findings)


def test_detects_blocking_io_in_async():
    code = """
async def fetch_all(urls):
    for url in urls:
        r = requests.get(url, timeout=5)
        yield r.json()
"""
    result = scan_code(code, path="async_svc.py")
    assert "PERF-SYNC-IO-IN-ASYNC" in ids(result.findings)


def test_no_blocking_io_flag_in_sync_function():
    code = """
def fetch_all(urls):
    for url in urls:
        r = requests.get(url, timeout=5)
        yield r.json()
"""
    assert "PERF-SYNC-IO-IN-ASYNC" not in ids(scan_code(code, path="svc.py").findings)


def test_detects_unbounded_cache():
    code = "@cache\ndef heavy(x):\n    return x * 2\n"
    assert "PERF-UNBOUNDED-CACHE" in ids(scan_code(code, path="c.py").findings)


def test_detects_select_star_and_missing_pagination():
    code = 'cur.execute("SELECT * FROM users")\n'
    result = scan_code(code, path="q.py")
    assert "PERF-SELECT-STAR" in ids(result.findings)
    assert "PERF-MISSING-PAGINATION" in ids(result.findings)


# ----------------------------------------------------------------- quality
def test_detects_debug_print_left_in_code():
    code = 'def f():\n    print("debug", x)\n'
    assert "QUA-DEBUG-LOG" in ids(scan_code(code, path="m.py").findings)


def test_debug_print_not_flagged_in_tests():
    code = 'def test_f():\n    print("debug")\n'
    result = scan_code(code, path="tests/test_m.py")
    assert "QUA-DEBUG-LOG" not in ids(result.findings)


def test_detects_todo_markers():
    code = "# TODO: handle the empty case\nx = 1\n"
    result = scan_code(code, path="m.py")
    assert "QUA-TODO" in ids(result.findings)
    assert result.metrics["m.py"].todo_count == 1


def test_detects_long_lines():
    code = "x = '" + "a" * 200 + "'\n"
    assert "QUA-GOD-LINE" in ids(scan_code(code, path="m.py").findings)


def test_detects_long_parameter_list():
    code = "def save(a, b, c, d, e, f, g, h):\n    pass\n"
    assert "QUA-LONG-PARAM-LIST" in ids(scan_code(code, path="m.py").findings)


def test_detects_var_declaration_in_js():
    code = "var total = 0;\n"
    assert "QUA-VAR-DECL" in ids(scan_code(code, path="a.js").findings)


def test_detects_duplicated_blocks():
    block = """def validate_email(value):
    if not value:
        return False
    if "@" not in value:
        return False
    return True
"""
    code = block + "\n\n" + block.replace("validate_email", "validate_phone")
    result = scan_code(code, path="v.py")
    assert "QUA-DUPLICATE-BLOCK" in ids(result.findings)


# ---------------------------------------------------------- best practices
def test_detects_print_instead_of_logger():
    code = 'def run():\n    print("started")\n'
    assert "BP-PRINT-NOT-LOGGER" in ids(scan_code(code, path="r.py").findings)


def test_detects_missing_input_validation():
    code = 'def handler(request):\n    name = request.json["name"]\n    return name\n'
    assert "BP-NO-INPUT-VALIDATION" in ids(scan_code(code, path="h.py").findings)


def test_detects_generic_exception():
    code = 'if bad:\n    raise Exception("failed")\n'
    assert "BP-GENERIC-EXCEPTION" in ids(scan_code(code, path="e.py").findings)


def test_detects_assert_in_production_code_but_not_tests():
    code = "def f(x):\n    assert x > 0\n    return x\n"
    assert "BP-ASSERT-IN-PROD" in ids(scan_code(code, path="f.py").findings)
    assert "BP-ASSERT-IN-PROD" not in ids(scan_code(code, path="test_f.py").findings)


# ---------------------------------------------------------- false positives
def test_ignores_sql_inside_a_comment():
    code = '# cur.execute("SELECT * FROM users WHERE id = " + uid)\nx = 1\n'
    result = scan_code(code, path="m.py")
    assert "SEC-SQLI-CONCAT" not in ids(result.findings)


def test_language_specific_rules_do_not_leak():
    # `var` is a JS rule; Python code containing the word should not match it
    code = "variance = compute_variance(samples)\n"
    assert "QUA-VAR-DECL" not in ids(scan_code(code, path="stats.py").findings)


def test_category_filter_limits_results():
    code = 'API_KEY = "secret123"\nprint("debug")\n'
    result = scan_code(code, path="m.py", include_categories=["security"])
    assert all(f.category == "security" for f in result.findings)
    assert "SEC-SECRET-HARDCODED" in ids(result.findings)
    assert "QUA-DEBUG-LOG" not in ids(result.findings)


def test_focus_lines_restricts_scan():
    code = 'API_KEY = "secret123"\nprint("debug")\n'
    result = scan_code(code, path="m.py", focus_lines={2})
    assert all(f.line == 2 for f in result.findings)


# ----------------------------------------------------------------- metrics
def test_compute_metrics():
    code = """# a comment
import os


def short():
    return 1


def very_long():
    x = 1
    y = 2
    z = 3
    return x + y + z
"""
    metrics = compute_metrics(code, "m.py", "python")
    assert metrics.lines == 13
    assert metrics.comment_lines == 1
    assert metrics.blank_lines == 4
    assert metrics.functions >= 2
    assert metrics.code_lines == 8
    assert metrics.longest_function == 4
    # branch-free code stays at the baseline complexity of 1
    assert metrics.complexity == 1


def test_complexity_grows_with_branching():
    branchy = """
def route(request):
    if request.ok:
        for item in request.items:
            if item.valid and item.count > 0:
                try:
                    save(item)
                except ValueError:
                    pass
            else:
                skip(item)
    else:
        return None
"""
    assert compute_metrics(branchy, "m.py", "python").complexity > 5


def test_metrics_flag_deep_nesting():
    code = "if a:\n    if b:\n        if c:\n            if d:\n                if e:\n                    if f:\n                        pass\n"
    metrics = compute_metrics(code, "m.py", "python")
    assert metrics.max_nesting >= 5


# --------------------------------------------------------------- scan_diff
def test_scan_diff_maps_line_numbers_to_new_file():
    diff_text = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,3 +10,5 @@
 def handler(request):
-    return ok()
+    query = "SELECT * FROM users WHERE id = " + str(request.args["id"])
+    cur.execute(query)
+    return cur.fetchone()
"""
    diffset = parse_unified_diff(diff_text)
    result = scan_diff(diffset)
    assert result.findings, "expected the added SQL concatenation to be flagged"
    # the query string is built on one line and executed on the next, so the
    # "assembled before execution" rule is the one that must fire
    sqli = {"SEC-SQLI-BUILD", "SEC-SQLI-CONCAT", "SEC-SQLI-FSTRING", "SEC-SQLI-TEMPLATE"}
    hits = [f for f in result.findings if f.rule_id in sqli]
    assert hits, f"no SQL injection rule fired: {[f.rule_id for f in result.findings]}"
    lines = {f.line for f in hits}
    # the added lines live at new-file lines 11-13
    assert lines and all(10 <= line <= 14 for line in lines)
    assert all(f.file == "app.py" for f in result.findings)
    assert any(f.severity == "critical" for f in hits)


def test_scan_diff_ignores_untouched_context():
    diff_text = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,4 +1,4 @@
-API_KEY = "leaked_secret_value"
+API_KEY = os.environ["API_KEY"]
 import os
"""
    result = scan_diff(parse_unified_diff(diff_text))
    assert "SEC-SECRET-HARDCODED" not in ids(result.findings)


def test_summarise_findings_is_compact():
    result = scan_code('os.system("rm " + p)\nAPI_KEY = "abc123456"\n', path="m.py")
    text = summarise_findings(result.findings)
    assert "### m.py" in text
    assert "L1" in text or "L2" in text
    assert "security/critical" in text


def test_results_sorted_by_severity_then_line():
    code = """print("debug")
API_KEY = "supersecret1"
cur.execute("SELECT * FROM t WHERE a = " + a)
os.system("ls " + p)
"""
    result = scan_code(code, path="m.py")
    weights = [{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f.severity] for f in result.findings]
    assert weights == sorted(weights, reverse=True)


def test_findings_are_json_serialisable():
    import json

    result = scan_code('os.system("rm -rf " + path)\n', path="m.py")
    payload = [f.to_dict() for f in result.findings]
    assert json.loads(json.dumps(payload))
    assert payload[0]["source"] == "static"
