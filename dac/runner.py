"""Run every rule against its test logs and against the shared benign corpus."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dac.engine import Event
from dac.rules import (
    CASE_KINDS, CASES_DIR, RULES_DIR, TACTICS, Case, Rule, load_cases, load_rules, tactic_name,
)


@dataclass
class CaseResult:
    case: Case
    matched: bool
    error: Optional[str] = None

    @property
    def passed(self) -> bool:
        return self.error is None and self.matched == self.case.expected

    @property
    def failure(self) -> str:
        if self.error:
            return self.error
        return "expected the rule to fire, it did not" if self.case.expected else "expected no alert, the rule fired"


@dataclass
class RuleResult:
    rule: Rule
    cases: List[CaseResult]
    problems: List[str]

    @property
    def passed(self) -> bool:
        return not self.problems and all(c.passed for c in self.cases)

    def count(self, kind: str) -> int:
        return sum(1 for c in self.cases if c.case.kind == kind)

    def count_passed(self, kind: str) -> int:
        return sum(1 for c in self.cases if c.case.kind == kind and c.passed)


@dataclass
class Report:
    rules: List[RuleResult]
    fp_violations: List[Dict[str, str]] = field(default_factory=list)
    global_problems: List[str] = field(default_factory=list)
    benign_corpus: int = 0

    @property
    def passed(self) -> bool:
        return bool(self.rules) and not self.fp_violations and not self.global_problems and all(r.passed for r in self.rules)

    @property
    def case_results(self) -> List[CaseResult]:
        return [c for r in self.rules for c in r.cases]


def run_all(rules_dir: Path = RULES_DIR, cases_dir: Path = CASES_DIR) -> Report:
    rules = load_rules(rules_dir)
    cases_by_slug, global_problems = load_cases(cases_dir)

    known = {rule.slug for rule in rules}
    for slug in cases_by_slug:
        if slug not in known:
            global_problems.append(f"orphan test logs: tests/cases/{slug} has no rule named {slug}.yml")
    if not rules:
        global_problems.append("no rules found")

    results: List[RuleResult] = []
    for rule in rules:
        cases = cases_by_slug.get(rule.slug, [])
        problems = list(rule.problems)
        for kind in CASE_KINDS:
            if not any(c.kind == kind for c in cases):
                problems.append(f"needs at least one {kind} test log in tests/cases/{rule.slug}/{kind}/")
        case_results = []
        for case in cases:
            if rule.matcher is None:
                case_results.append(CaseResult(case, matched=False, error="rule did not compile"))
            else:
                case_results.append(CaseResult(case, matched=rule.matches(case.event)))
        results.append(RuleResult(rule, case_results, problems))

    # Every rule must stay quiet on every benign log in the repository, not only its own.
    benign = [c for cases in cases_by_slug.values() for c in cases if c.kind == "benign"]
    violations: List[Dict[str, str]] = []
    for rule in rules:
        if rule.matcher is None:
            continue
        for case in benign:
            if case.slug != rule.slug and rule.matches(case.event):
                violations.append({"rule": rule.slug, "log": case.label})
    return Report(results, violations, global_problems, len(benign))


def match_event(event: Event, rules_dir: Path = RULES_DIR) -> List[Rule]:
    """Which rules fire on this event?"""
    return [r for r in load_rules(rules_dir) if r.matcher is not None and r.matches(event)]


# ------------------------------------------------------------------------- serialising


def _commit() -> str:
    return (os.environ.get("GITHUB_SHA") or "local")[:7]


def report_to_dict(report: Report, generated_at: Optional[datetime] = None) -> Dict[str, Any]:
    generated_at = generated_at or datetime.now(timezone.utc)
    rules: List[Dict[str, Any]] = []
    for rr in report.rules:
        rule = rr.rule
        rules.append({
            "id": str(rule.data.get("id", "")),
            "slug": rule.slug,
            "file": rule.rel_path,
            "title": str(rule.data.get("title", rule.slug)),
            "status": str(rule.data.get("status", "")),
            "level": str(rule.data.get("level", "")),
            "description": " ".join(str(rule.data.get("description", "")).split()),
            "author": str(rule.data.get("author", "")),
            "date": str(rule.data.get("date", "")),
            "tactics": [{"id": t, "name": tactic_name(t)} for t in rule.tactics],
            "techniques": rule.techniques,
            "falsepositives": list(rule.data.get("falsepositives") or []),
            "references": list(rule.data.get("references") or []),
            "logsource": rule.data.get("logsource") or {},
            "detection": rule.data.get("detection") if rule.matcher is not None else None,
            "yaml": rule.text,
            "problems": rr.problems,
            "passed": rr.passed,
            "cases": [
                {
                    "kind": cr.case.kind,
                    "name": cr.case.name,
                    "file": cr.case.rel_path,
                    "expected": cr.case.expected,
                    "matched": cr.matched,
                    "passed": cr.passed,
                    "error": cr.error,
                    "event": cr.case.event,
                }
                for cr in rr.cases
            ],
        })
    technique_ids = {t["id"] for r in rules for t in r["techniques"]}
    tactic_ids = {t["id"] for r in rules for t in r["tactics"]}
    return {
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        "commit": _commit(),
        "passed": report.passed,
        "summary": {
            "rules": len(rules),
            "rules_passing": sum(1 for r in rules if r["passed"]),
            "logs": len(report.case_results),
            "malicious": sum(1 for c in report.case_results if c.case.kind == "malicious"),
            "benign": sum(1 for c in report.case_results if c.case.kind == "benign"),
            "techniques": len(technique_ids),
            "tactics_covered": len(tactic_ids),
            "benign_corpus": report.benign_corpus,
        },
        "tactics": [{"id": t, "name": tactic_name(t), "count": sum(1 for r in rules if any(x["id"] == t for x in r["tactics"]))} for t in TACTICS],
        "rules": rules,
        "fp_violations": report.fp_violations,
        "global_problems": report.global_problems,
    }


def parity_payload(report: Report) -> Dict[str, Any]:
    """Every rule's detection plus Python's verdict on every test log, for tests/parity.test.js."""
    cases = report.case_results
    compiled = [rr.rule for rr in report.rules if rr.rule.matcher is not None]
    return {
        "events": [{"name": c.case.label, "event": c.case.event} for c in cases],
        "rules": [
            {
                "slug": rule.slug,
                "detection": rule.data["detection"],
                "verdicts": [rule.matches(c.case.event) for c in cases],
            }
            for rule in compiled
        ],
    }
