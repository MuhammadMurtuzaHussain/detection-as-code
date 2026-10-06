"""The detection gate: every rule must fire on its malicious logs and stay quiet on its benign ones.

This is the file CI cares about. Each log becomes its own test, so a failure names the
exact rule and sample, for example:

    FAILED tests/test_rules.py::test_rule_against_its_logs[proc_creation_certutil_url_download/benign/hashfile-check]
"""

import pytest

from dac.runner import run_all

REPORT = run_all()
RULES = REPORT.rules
CASES = [(rr, cr) for rr in RULES for cr in rr.cases]


def test_repository_has_rules_and_no_structural_problems():
    assert RULES, "no rules found under rules/"
    assert not REPORT.global_problems, "\n".join(REPORT.global_problems)


@pytest.mark.parametrize("rr", RULES, ids=[r.rule.slug for r in RULES])
def test_rule_is_well_formed(rr):
    """Valid metadata, compilable detection, and at least one malicious and one benign log."""
    assert not rr.problems, "\n".join(rr.problems)


@pytest.mark.parametrize("rr, cr", CASES, ids=[cr.case.label for _, cr in CASES])
def test_rule_against_its_logs(rr, cr):
    """Malicious logs must fire the rule. Benign logs must not."""
    assert cr.passed, f"{cr.case.rel_path}: {cr.failure}"


def test_no_rule_fires_on_another_rules_benign_logs():
    """Shared false-positive corpus: all benign logs in the repo against all rules."""
    assert not REPORT.fp_violations, "\n".join(f"{v['rule']} fired on {v['log']}" for v in REPORT.fp_violations)
