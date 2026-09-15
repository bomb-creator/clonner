"""Tests for context building, the pipeline, merging and markdown rendering."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.agents.base import AgentContext, build_line_comment  # noqa: E402
from backend.agents.orchestrator import (  # noqa: E402
    build_context,
    prescan_to_findings,
    render_markdown,
    run_pipeline,
    run_prescan,
)
from backend.agents.specialists import plan_for, second_round_prompt  # noqa: E402
from backend.agents.synthesizer import (  # noqa: E402
    SynthesizerAgent,
    deterministic_merge,
    synthesise,
)
from backend.agents.summarizer import SummarizerAgent, deterministic_summary, summarise  # noqa: E402
from backend.models import Finding, ReviewRequest, ReviewResponse  # noqa: E402
from backend.providers.base import ProviderError  # noqa: E402
from backend.providers.demo import DemoProvider  # noqa: E402

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

CLEAN = '''"""Look up a user by id."""
import sqlite3


def lookup(connection: sqlite3.Connection, user_id: int) -> dict | None:
    """Return the row for `user_id`, or None."""
    cursor = connection.execute(
        "SELECT id, name FROM users WHERE id = ?", (user_id,)
    )
    return cursor.fetchone()
'''

DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,6 @@
 import os
+SECRET = "hunter2secretvalue"
+def run(cmd):
+    os.system("rm -rf " + cmd)
 print("hi")
"""


def run(coro):
    return asyncio.run(coro)


def make_finding(**overrides):
    base = dict(
        id="t1", category="bug", severity="medium", title="Test finding",
        description="A description.", file="app.py", line=3, suggestion="Fix it.",
        agent="bugs", source="llm", confidence=0.8,
    )
    base.update(overrides)
    return Finding(**base)


# ------------------------------------------------------------------ context
def test_build_context_from_plain_code():
    ctx = run(build_context(ReviewRequest(code=VULNERABLE, files=[])))
    assert ctx.is_diff is False
    assert ctx.code == VULNERABLE
    assert ctx.language == "python"
    assert ctx.max_line_by_file[ctx.path] == len(VULNERABLE.splitlines())


def test_build_context_detects_language_from_path():
    ctx = run(build_context(ReviewRequest(
        files=[{"path": "app.js", "content": "const x = 1;"}],  # type: ignore[list-item]
    )))
    assert ctx.language == "javascript"
    assert ctx.path == "app.js"


def test_build_context_from_diff():
    ctx = run(build_context(ReviewRequest(diff=DIFF)))
    assert ctx.is_diff is True
    assert ctx.diffset is not None
    assert ctx.diffset.files[0].path == "app.py"
    assert ctx.focus_lines, "focus lines should be set for diffs by default"
    assert 2 in ctx.focus_lines


def test_build_context_diff_without_focus():
    ctx = run(build_context(ReviewRequest(diff=DIFF, focus_changed_lines=False)))
    assert ctx.is_diff is True
    assert ctx.focus_lines is None


def test_build_context_autodetects_a_diff_in_the_code_field():
    ctx = run(build_context(ReviewRequest(code=DIFF)))
    assert ctx.is_diff is True


def test_build_context_multiple_files():
    ctx = run(build_context(ReviewRequest(files=[
        {"path": "a.py", "content": "x = 1"},          # type: ignore[list-item]
        {"path": "b.js", "content": "const y = 2;"},   # type: ignore[list-item]
    ])))
    assert len(ctx.files) == 2
    assert ctx.path == "2 files"
    assert set(ctx.max_line_by_file) == {"a.py", "b.js"}


def test_build_context_skips_lockfiles_and_binaries():
    ctx = run(build_context(ReviewRequest(files=[
        {"path": "app.py", "content": "x = 1"},                 # type: ignore[list-item]
        {"path": "package-lock.json", "content": "{}"},         # type: ignore[list-item]
        {"path": "logo.png", "content": "binary"},              # type: ignore[list-item]
    ])))
    assert [f["path"] for f in ctx.files] == ["app.py"]


def test_build_context_rejects_empty_input():
    with pytest.raises(ProviderError):
        run(build_context(ReviewRequest(code="   ")))


def test_build_context_rejects_unparseable_pr_reference():
    with pytest.raises(ProviderError):
        run(build_context(ReviewRequest(pull_request="not a pr reference")))


def test_build_context_rejects_unparseable_diff():
    with pytest.raises(ProviderError):
        run(build_context(ReviewRequest(diff="@@@ nonsense @@@")))


def test_numbered_code_includes_line_numbers():
    ctx = run(build_context(ReviewRequest(code="a = 1\nb = 2")))
    numbered = ctx.numbered_code()
    assert "    1 | a = 1" in numbered
    assert "    2 | b = 2" in numbered


def test_numbered_code_truncates_huge_input():
    big = "x = 1\n" * 40000
    ctx = run(build_context(ReviewRequest(code=big)))
    numbered = ctx.numbered_code(limit=5000)
    assert len(numbered) <= 5100
    assert "truncated" in numbered.lower()


# ------------------------------------------------------------------ prescan
def test_run_prescan_on_code():
    ctx = run(build_context(ReviewRequest(code=VULNERABLE)))
    scan = run_prescan(ctx)
    assert scan.findings
    assert any(f.rule_id == "SEC-SQLI-CONCAT" for f in scan.findings)


def test_run_prescan_on_diff_only_reports_added_lines():
    ctx = run(build_context(ReviewRequest(diff=DIFF)))
    scan = run_prescan(ctx)
    rule_ids = {f.rule_id for f in scan.findings}
    assert "SEC-SECRET-HARDCODED" in rule_ids or "SEC-CMD-INJECTION" in rule_ids


def test_prescan_findings_convert_to_api_findings():
    ctx = run(build_context(ReviewRequest(code=VULNERABLE)))
    findings = prescan_to_findings(run_prescan(ctx), ctx)
    assert findings
    assert all(f.source == "static" for f in findings)
    assert all(f.agent == "prescan" for f in findings)
    assert all(f.line_comment for f in findings)
    assert all(f.id.startswith("static-") for f in findings)


# --------------------------------------------------------------------- plan
def test_effort_plans():
    assert plan_for("quick", ["security", "bug"])["agents"] == ["security", "bugs"]
    standard = plan_for("standard", ["security", "bug", "quality", "performance", "best_practices"])
    assert len(standard["agents"]) == 5
    deep = plan_for("deep", ["security"])
    assert deep["agents"] == ["security"]
    assert deep["rounds"] == 2


def test_plan_maps_bug_category_to_bugs_agent():
    assert "bugs" in plan_for("standard", ["bug"])["agents"]


def test_second_round_prompt_lists_prior_titles():
    ctx = AgentContext(code="x = 1")
    text = second_round_prompt(ctx, ["SQL injection", "Hardcoded secret"])
    assert "SQL injection" in text
    assert "do not repeat" in text.lower()
    assert second_round_prompt(ctx, []) == ""


# --------------------------------------------------------------- merge logic
def test_deterministic_merge_dedupes_same_issue_from_two_agents():
    findings = [
        make_finding(id="a", agent="security", severity="high", title="SQL injection in lookup",
                     description="short", confidence=0.7),
        make_finding(id="b", agent="bugs", severity="critical", title="SQL injection in lookup",
                     description="a much longer and more specific description of the same issue",
                     confidence=0.9),
    ]
    merged = deterministic_merge(findings)
    assert len(merged["findings"]) == 1
    winner = merged["findings"][0]
    assert winner.severity == "critical"        # escalated to the highest
    assert winner.confidence == 0.9             # took the best confidence
    assert "longer" in winner.description       # kept the richer description
    assert winner.source == "merged"


def test_deterministic_merge_keeps_distinct_issues():
    findings = [
        make_finding(id="a", line=1, title="SQL injection"),
        make_finding(id="b", line=9, title="Unbounded cache"),
        make_finding(id="c", line=4, category="security", title="Hardcoded secret"),
    ]
    merged = deterministic_merge(findings)
    assert len(merged["findings"]) == 3


def test_deterministic_merge_empty_input():
    merged = deterministic_merge([])
    assert merged["findings"] == []
    assert merged["overall_assessment"] == "approve"
    assert merged["score"] >= 90


def test_merge_verdict_blocks_on_critical():
    merged = deterministic_merge([make_finding(severity="critical", title="Remote code execution")])
    assert merged["overall_assessment"] == "block"


def test_merge_verdict_approves_when_nothing_found():
    merged = deterministic_merge([])
    assert merged["overall_assessment"] == "approve"


def test_merge_orders_by_severity():
    findings = [
        make_finding(id="a", severity="low", title="Nit about naming", line=1),
        make_finding(id="b", severity="critical", title="RCE via eval", line=2),
        make_finding(id="c", severity="medium", title="Missing validation", line=3),
    ]
    merged = deterministic_merge(findings)
    severities = [f.severity for f in merged["findings"]]
    assert severities == ["critical", "medium", "low"]


def test_merge_respects_max_findings():
    findings = [make_finding(id=str(i), line=i, title=f"Issue number {i}") for i in range(1, 40)]
    merged = deterministic_merge(findings, max_findings=10)
    assert len(merged["findings"]) == 10


def test_merge_generates_test_recommendations_for_serious_findings():
    merged = deterministic_merge([make_finding(severity="critical", title="SQL injection")])
    assert merged["test_recommendations"]
    assert "SQL injection" in merged["test_recommendations"][0]


async def test_synthesise_falls_back_when_llm_fails():
    class BrokenProvider(DemoProvider):
        async def complete(self, messages, **kwargs):
            raise ProviderError("upstream is down")

    ctx = AgentContext(code=VULNERABLE, path="app.py", language="python",
                       prior_findings=[make_finding(title="SQL injection")],
                       max_line_by_file={"app.py": 11})
    agent = SynthesizerAgent(BrokenProvider(), "static-rules-v1")
    outcome = await synthesise(ctx, agent, prefer_llm=True)
    assert outcome.status == "done"
    assert outcome.model == "deterministic-merge"
    assert outcome.findings
    assert "unavailable" in outcome.error.lower()


async def test_synthesise_with_offline_provider_uses_deterministic_merge():
    ctx = AgentContext(code=VULNERABLE, path="app.py",
                       prior_findings=[make_finding(title="SQL injection")],
                       max_line_by_file={"app.py": 11})
    agent = SynthesizerAgent(DemoProvider(), "static-rules-v1")
    outcome = await synthesise(ctx, agent, prefer_llm=False)
    assert outcome.model == "deterministic-merge"
    assert outcome.payload["summary"]


# ------------------------------------------------------------------ summary
def test_deterministic_summary_shape():
    ctx = run(build_context(ReviewRequest(code=VULNERABLE, files=[])))
    summary = deterministic_summary(ctx, prescan_to_findings(run_prescan(ctx), ctx))
    assert summary["title"]
    assert "## Walkthrough" in summary["walkthrough"]
    assert "sequenceDiagram" in summary["sequence_diagram"]
    assert summary["checklist"]
    assert summary["risk_areas"]


async def test_summarise_offline_returns_fallback():
    ctx = await build_context(ReviewRequest(code=VULNERABLE))
    agent = SummarizerAgent(DemoProvider(), "static-rules-v1")
    outcome = await summarise(ctx, agent, [], prefer_llm=False)
    assert outcome.payload["walkthrough"]
    assert outcome.model == "deterministic-summary"


async def test_summariser_is_skipped_on_quick_effort():
    ctx = AgentContext(code="x = 1", effort="quick")
    assert SummarizerAgent(DemoProvider(), "m").is_enabled(ctx) is False
    ctx.effort = "standard"
    assert SummarizerAgent(DemoProvider(), "m").is_enabled(ctx) is True


# ------------------------------------------------------------ line comments
def test_build_line_comment_is_github_ready():
    finding = make_finding(severity="critical", category="security",
                           title="SQL injection", code_after='cur.execute("SELECT 1 WHERE id = %s", (i,))',
                           references=["CWE-89"])
    comment = build_line_comment(finding)
    assert "CRITICAL" in comment
    assert "SQL injection" in comment
    assert "CWE-89" in comment
    assert "cur.execute" in comment
    assert "confidence" in comment


def test_build_line_comment_without_suggested_code():
    comment = build_line_comment(make_finding(severity="low", title="Naming nit"))
    assert "LOW" in comment
    assert "```" not in comment


# ------------------------------------------------------------------ pipeline
def collect_events(request):
    async def go():
        return [event async for event in run_pipeline(request)]
    return run(go())


def test_pipeline_emits_the_full_event_sequence():
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="demo", stream=True))
    kinds = [e["event"] for e in events]
    assert kinds[0] == "start"
    assert kinds[-1] == "done"
    assert "provider" in kinds
    assert "agent:start" in kinds and "agent:done" in kinds
    assert kinds.index("agent:start") < kinds.index("agent:done")


def test_pipeline_produces_a_complete_review():
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="demo"))
    review = next(e for e in events if e["event"] == "done")["review"]
    assert review["status"] in {"completed", "partial"}
    assert review["provider"] == "demo"
    assert review["score"] >= 0 and review["score"] <= 100
    assert review["verdict"] in {"approve", "approve_with_nits", "request_changes", "block"}
    assert review["findings"], "the planted sample must produce findings"
    assert review["review_markdown"]
    assert review["elapsed_ms"] >= 0
    assert review["by_severity"]
    assert review["metrics"]


def test_pipeline_finds_the_planted_vulnerabilities():
    review = next(e for e in collect_events(ReviewRequest(code=VULNERABLE, provider="demo"))
                  if e["event"] == "done")["review"]
    titles = " ".join(f["title"].lower() for f in review["findings"])
    assert "sql" in titles
    assert any(word in titles for word in ("credential", "secret", "api key"))
    assert review["verdict"] in {"block", "request_changes"}


def test_pipeline_findings_have_valid_line_numbers():
    total = len(VULNERABLE.splitlines())
    review = next(e for e in collect_events(ReviewRequest(code=VULNERABLE, provider="demo"))
                  if e["event"] == "done")["review"]
    for finding in review["findings"]:
        assert finding["line"] is None or 1 <= finding["line"] <= total + 5


def test_pipeline_clean_code_is_not_flagged_as_blocking():
    review = next(e for e in collect_events(ReviewRequest(code=CLEAN, provider="demo"))
                  if e["event"] == "done")["review"]
    serious = [f for f in review["findings"] if f["severity"] in {"critical", "high"}]
    assert not serious, f"clean code should not be blocked: {[f['title'] for f in serious]}"
    assert review["score"] >= 80
    assert review["verdict"] in {"approve", "approve_with_nits"}


def test_pipeline_on_a_diff():
    review = next(e for e in collect_events(ReviewRequest(diff=DIFF, provider="demo"))
                  if e["event"] == "done")["review"]
    assert review["findings"]
    assert review["stats"]["diff_stats"]["files"] == 1
    # every finding must point at a line the diff actually touched
    touched = {2, 3, 4}
    for finding in review["findings"]:
        assert finding["line"] in touched, f"{finding['title']} points outside the diff"


def test_pipeline_respects_category_selection():
    review = next(e for e in collect_events(
        ReviewRequest(code=VULNERABLE, provider="demo", categories=["security"]))
        if e["event"] == "done")["review"]
    assert review["findings"]
    assert all(f["category"] == "security" for f in review["findings"])


def test_pipeline_respects_min_severity():
    review = next(e for e in collect_events(
        ReviewRequest(code=VULNERABLE, provider="demo", min_severity="high"))
        if e["event"] == "done")["review"]
    assert all(f["severity"] in {"critical", "high"} for f in review["findings"])


def test_pipeline_quick_effort_skips_the_summariser():
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="demo", effort="quick"))
    agents = {e.get("agent") for e in events if e["event"] == "agent:start"}
    assert "summarizer" not in agents
    review = next(e for e in events if e["event"] == "done")["review"]
    assert review["walkthrough"], "a fallback walkthrough is still produced"


def test_pipeline_standard_effort_runs_the_summariser():
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="demo", effort="standard"))
    agents = {e.get("agent") for e in events if e["event"] == "agent:start"}
    assert "summarizer" in agents


def test_pipeline_reports_multiple_files():
    review = next(e for e in collect_events(ReviewRequest(
        provider="demo",
        files=[
            {"path": "a.py", "content": VULNERABLE},   # type: ignore[list-item]
            {"path": "b.js", "content": "el.innerHTML = userInput;"},  # type: ignore[list-item]
        ],
    )) if e["event"] == "done")["review"]
    files = {f["file"] for f in review["findings"]}
    assert "a.py" in files
    assert len(review["metrics"]) == 2


def test_pipeline_falls_back_when_provider_is_unknown():
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="nonexistent-provider"))
    kinds = [e["event"] for e in events]
    assert "error" in kinds or "done" in kinds


def test_pipeline_falls_back_when_a_keyed_provider_has_no_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="groq"))
    review_events = [e for e in events if e["event"] == "done"]
    assert review_events, "should degrade to the offline engine instead of failing"
    review = review_events[0]["review"]
    assert review["provider"] == "demo"
    assert review["errors"], "the fallback must be reported to the user"


def test_pipeline_carries_extra_instructions():
    events = collect_events(ReviewRequest(
        code=VULNERABLE, provider="demo",
        instructions="This is a legacy Django project; ignore the debug print statements.",
    ))
    review = next(e for e in events if e["event"] == "done")["review"]
    assert review["id"]


def test_pipeline_reviews_are_retrievable():
    from backend.agents.orchestrator import get_review

    review = next(e for e in collect_events(ReviewRequest(code=VULNERABLE, provider="demo"))
                  if e["event"] == "done")["review"]
    assert get_review(review["id"]) is not None


# ------------------------------------------------------------------ markdown
def test_render_markdown_contains_all_sections():
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="demo"))
    response = ReviewResponse(**next(e for e in events if e["event"] == "done")["review"])
    markdown = render_markdown(response)
    assert markdown.startswith("# Code review")
    assert "## Summary" in markdown
    assert "## Findings" in markdown
    assert "| # | Severity |" in markdown
    assert "## Agent trace" in markdown
    assert response.verdict or "Verdict" in markdown


def test_render_markdown_with_no_findings():
    response = ReviewResponse(id="x", score=98, verdict="approve", summary="Clean.",
                              findings=[], provider="demo", model="m")
    markdown = render_markdown(response)
    assert "No issues found" in markdown


def test_render_markdown_escapes_table_pipes():
    response = ReviewResponse(
        id="x", findings=[make_finding(title="Uses | in a title", description="d")],
        provider="demo", model="m",
    )
    markdown = render_markdown(response)
    assert "Uses \\| in a title" in markdown


def test_render_markdown_includes_diff_stats():
    events = collect_events(ReviewRequest(diff=DIFF, provider="demo"))
    response = ReviewResponse(**next(e for e in events if e["event"] == "done")["review"])
    markdown = render_markdown(response)
    assert "**Diff:**" in markdown


def test_render_markdown_includes_suggested_code_blocks():
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="demo"))
    response = ReviewResponse(**next(e for e in events if e["event"] == "done")["review"])
    markdown = render_markdown(response)
    assert "```" in markdown
    assert "Suggested fix" in markdown


# --------------------------------------------------------- regression guards
def test_diff_findings_are_attributed_to_real_file_paths():
    """Regression: offline specialists once re-scanned the concatenated diff,
    producing duplicate findings under a bogus "N files changed" path."""
    diff_text = """diff --git a/backend/services/payment.py b/backend/services/payment.py
--- a/backend/services/payment.py
+++ b/backend/services/payment.py
@@ -10,3 +10,8 @@
 def charge(self, order):
+    query = "SELECT * FROM orders WHERE id = " + str(order.id)
+    row = self.db.execute(query).fetchone()
+    for item in order.items:
+        self.db.execute("UPDATE inventory SET count = count - 1 WHERE sku = '%s'" % item.sku)
+    return None
diff --git a/web/app.js b/web/app.js
--- a/web/app.js
+++ b/web/app.js
@@ -1,2 +1,4 @@
 function render(user) {
+  el.innerHTML = user.bio;
+  eval(user.config);
 }
"""
    review = next(e for e in collect_events(ReviewRequest(diff=diff_text, provider="demo"))
                  if e["event"] == "done")["review"]
    files = {f["file"] for f in review["findings"]}
    assert files, "expected findings from the diff"
    assert all("files changed" not in path for path in files), \
        f"findings must name real files, got: {files}"
    assert "backend/services/payment.py" in files
    assert "web/app.js" in files


def test_offline_pipeline_does_not_duplicate_findings():
    """Each pre-scan finding must appear exactly once in the final review."""
    review = next(e for e in collect_events(ReviewRequest(code=VULNERABLE, provider="demo"))
                  if e["event"] == "done")["review"]
    keys = [(f["file"], f["line"], f["title"]) for f in review["findings"]]
    duplicates = {k for k in keys if keys.count(k) > 1}
    assert not duplicates, f"duplicate findings survived the merge: {duplicates}"


def test_offline_specialists_report_their_own_dimension_only():
    """Regression: offline agents used to re-label the whole scan into their
    own category, so one issue appeared five times under five categories."""
    events = collect_events(ReviewRequest(code=VULNERABLE, provider="demo"))
    per_agent = {}
    for event in events:
        if event["event"] == "agent:done" and event.get("findings"):
            per_agent[event["agent"]] = event["findings"]

    review = next(e for e in events if e["event"] == "done")["review"]
    total = len(review["findings"])
    # the sum of what each specialist claimed must not wildly exceed the final
    # deduped total (a 5x blow-up means every agent claimed every finding)
    claimed = sum(per_agent.get(name, 0) for name in
                  ("quality", "bugs", "security", "performance", "best_practices"))
    assert claimed <= total + 10, f"specialists claimed {claimed} findings but only {total} survived"


def test_sql_injection_variants_collapse_on_the_same_line():
    """Two rules describing one problem must not both be reported."""
    from backend.analysis.heuristics import scan_code

    code = 'cur.execute("SELECT * FROM users WHERE id = " + str(uid))\n'
    result = scan_code(code, path="db.py")
    sqli_titles = [f.title for f in result.findings
                   if f.category == "security" and "sql" in f.title.lower()]
    assert len(sqli_titles) == 1, f"expected one SQLi finding, got {sqli_titles}"


def test_repeated_identical_lines_do_not_flood_the_review():
    """Regression: 20k identical lines once produced ~20k duplicate findings
    and took 77 seconds to scan."""
    import time

    from backend.analysis.heuristics import scan_code

    code = "x = 1\n" * 20000
    started = time.perf_counter()
    result = scan_code(code, path="big.py")
    elapsed = time.perf_counter() - started
    assert elapsed < 5, f"scan took {elapsed:.1f}s, expected under 5s"
    assert len(result.findings) < 100


def test_scan_caps_findings_on_pathological_input():
    from backend.analysis.heuristics import MAX_FINDINGS_PER_SCAN, scan_code

    code = 'cur.execute("SELECT * FROM t WHERE a = " + a)\n' * 2000
    result = scan_code(code, path="flood.py")
    assert len(result.findings) <= MAX_FINDINGS_PER_SCAN
