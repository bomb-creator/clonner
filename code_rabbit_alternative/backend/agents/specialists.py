"""The five specialist reviewers.

Each one owns exactly one dimension of the system prompt, which keeps prompts
short, focuses the model's attention, and lets a user disable any dimension.
"""
from __future__ import annotations

from typing import Optional

from .base import AgentContext, BaseAgent


class QualityAgent(BaseAgent):
    key = "quality"
    label = "Code quality"
    emoji = "🧹"
    category: Optional[str] = "quality"
    description = "Smells, anti-patterns, naming, organisation, refactoring."


class BugAgent(BaseAgent):
    key = "bugs"
    label = "Bug hunter"
    emoji = "🐛"
    category = "bug"
    description = "Logic errors, unhandled edge cases, null/undefined dereferences."


class SecurityAgent(BaseAgent):
    key = "security"
    label = "Security auditor"
    emoji = "🛡️"
    category = "security"
    description = "Injection, XSS, authz gaps, secrets, validation, crypto misuse."


class PerformanceAgent(BaseAgent):
    key = "performance"
    label = "Performance analyst"
    emoji = "⚡"
    category = "performance"
    description = "Complexity, N+1 I/O, blocking calls, memory and resource leaks."


class BestPracticesAgent(BaseAgent):
    key = "best_practices"
    label = "Best practices"
    emoji = "📐"
    category = "best_practices"
    description = "Language idioms, error handling, resource management, test coverage."


#: `quick` runs fewer passes; `deep` runs all of them plus a second bug pass.
SPECIALISTS = [
    QualityAgent,
    BugAgent,
    SecurityAgent,
    PerformanceAgent,
    BestPracticesAgent,
]

EFFORT_PLAN = {
    "quick": {"agents": ["security", "bugs"], "rounds": 1, "max_findings": 20},
    "standard": {
        "agents": ["quality", "bugs", "security", "performance", "best_practices"],
        "rounds": 1,
        "max_findings": 40,
    },
    "deep": {
        "agents": ["quality", "bugs", "security", "performance", "best_practices"],
        "rounds": 2,
        "max_findings": 80,
    },
}


def plan_for(effort: str, requested_categories) -> dict:
    plan = dict(EFFORT_PLAN.get(effort, EFFORT_PLAN["standard"]))
    allowed = set(requested_categories or plan["agents"])
    # map category names to agent keys ("bug" -> "bugs")
    aliases = {"bug": "bugs", "bugs": "bugs", "best_practices": "best_practices",
               "quality": "quality", "security": "security", "performance": "performance"}
    allowed_agents = {aliases.get(item, item) for item in allowed}
    plan["agents"] = [a for a in plan["agents"] if a in allowed_agents]
    return plan


def second_round_prompt(ctx: AgentContext, first_round_titles) -> str:
    """Deep mode: ask for what the first pass missed, without repeating itself."""
    if not first_round_titles:
        return ""
    listing = "\n".join(f"- {title}" for title in first_round_titles[:40])
    return (
        "## Second pass — do not repeat yourself\n\n"
        "A first pass over this exact code already reported:\n"
        f"{listing}\n\n"
        "Those are recorded. Report ONLY additional, distinct problems you can\n"
        "justify. Look specifically at interactions between components, failure\n"
        "paths under concurrency, inputs of unexpected shape or size, and\n"
        "assumptions the code makes about its environment. If you find nothing\n"
        "new, return an empty findings array.\n"
    )
