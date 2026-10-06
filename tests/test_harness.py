"""Tests for the tests: prove the harness fails when it should.

A green build only means something if a broken rule would turn it red. Each test builds a
throwaway rule set in a temporary directory and checks that the runner reports the problem.
"""

import json
import textwrap

from dac.runner import run_all

RULE = textwrap.dedent(
    """\
    title: Test rule
    id: 11111111-2222-4333-8444-555555555555
    status: test
    description: A rule used to test the harness itself.
    author: tests
    date: 2026-10-06
    tags: [attack.execution, attack.t1059]
    logsource: {{category: process_creation, product: windows}}
    detection:
      selection:
        Image|endswith: '\\evil.exe'
      condition: {condition}
    falsepositives: [none]
    level: low
    """
)


def build(tmp_path, condition="selection", malicious=(r"C:\bad\evil.exe",), benign=(r"C:\ok\fine.exe",), rule_text=None):
    rules, cases = tmp_path / "rules", tmp_path / "cases"
    (rules).mkdir()
    (rules / "demo.yml").write_text(rule_text or RULE.format(condition=condition))
    for kind, images in (("malicious", malicious), ("benign", benign)):
        folder = cases / "demo" / kind
        folder.mkdir(parents=True)
        for i, image in enumerate(images):
            (folder / f"log{i}.json").write_text(json.dumps({"Image": image}))
    return run_all(rules, cases)


def test_healthy_rule_passes(tmp_path):
    assert build(tmp_path).passed


def test_rule_that_matches_everything_is_caught_by_benign_logs(tmp_path):
    report = build(tmp_path, condition="selection or not selection")
    assert not report.passed
    assert any(not c.passed and c.case.kind == "benign" for c in report.case_results)


def test_rule_that_matches_nothing_is_caught_by_malicious_logs(tmp_path):
    report = build(tmp_path, malicious=(r"C:\bad\other.exe",))
    assert not report.passed
    assert any(not c.passed and c.case.kind == "malicious" for c in report.case_results)


def test_rule_without_a_benign_log_fails(tmp_path):
    report = build(tmp_path, benign=())
    assert not report.passed
    assert any("benign test log" in p for p in report.rules[0].problems)


def test_rule_without_a_malicious_log_fails(tmp_path):
    report = build(tmp_path, malicious=())
    assert not report.passed
    assert any("malicious test log" in p for p in report.rules[0].problems)


def test_unsupported_sigma_feature_fails_loudly(tmp_path):
    text = RULE.format(condition="selection").replace("Image|endswith", "Image|base64offset|contains")
    report = build(tmp_path, rule_text=text)
    assert not report.passed
    assert any("not supported" in p for p in report.rules[0].problems)


def test_missing_metadata_is_reported(tmp_path):
    text = RULE.format(condition="selection").replace("level: low\n", "")
    report = build(tmp_path, rule_text=text)
    assert any("'level'" in p for p in report.rules[0].problems)


def test_orphan_test_logs_are_reported(tmp_path):
    report = build(tmp_path)
    orphan = tmp_path / "cases" / "ghost" / "malicious"
    orphan.mkdir(parents=True)
    (orphan / "x.json").write_text("{}")
    assert any("orphan" in p for p in run_all(tmp_path / "rules", tmp_path / "cases").global_problems)
    assert report.passed  # the first run, before the orphan existed


def test_invalid_json_log_is_reported(tmp_path):
    build(tmp_path)
    (tmp_path / "cases" / "demo" / "benign" / "broken.json").write_text("{not json")
    report = run_all(tmp_path / "rules", tmp_path / "cases")
    assert any("invalid JSON" in p for p in report.global_problems)


def test_cross_rule_false_positive_is_caught(tmp_path):
    build(tmp_path)
    other = RULE.format(condition="selection").replace("11111111-2222-4333-8444-555555555555", "99999999-2222-4333-8444-555555555555")
    other = other.replace("'\\evil.exe'", "'\\fine.exe'")
    (tmp_path / "rules" / "other.yml").write_text(other)
    for kind, image in (("malicious", r"C:\x\fine.exe"), ("benign", r"C:\x\clean.exe")):
        folder = tmp_path / "cases" / "other" / kind
        folder.mkdir(parents=True)
        (folder / "a.json").write_text(json.dumps({"Image": image}))
    report = run_all(tmp_path / "rules", tmp_path / "cases")
    # rule 'other' fires on demo's benign log C:\ok\fine.exe
    assert {"rule": "other", "log": "demo/benign/log0"} in report.fp_violations
    assert not report.passed


def test_duplicate_rule_ids_are_reported(tmp_path):
    build(tmp_path)
    (tmp_path / "rules" / "copy.yml").write_text((tmp_path / "rules" / "demo.yml").read_text())
    report = run_all(tmp_path / "rules", tmp_path / "cases")
    assert any("duplicate id" in p for rr in report.rules for p in rr.problems)


def test_tactic_names_use_attack_capitalisation():
    from dac.rules import tactic_name

    assert tactic_name("command_and_control") == "Command and Control"
    assert tactic_name("defense_evasion") == "Defense Evasion"
