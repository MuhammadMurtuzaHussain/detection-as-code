"""Command line interface: ``python -m dac check | build | match``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from dac.runner import Report, RuleResult, match_event, parity_payload, report_to_dict, run_all


def _summary_line(rr: RuleResult) -> str:
    return (
        f"{rr.count_passed('malicious')}/{rr.count('malicious')} malicious detected, "
        f"{rr.count_passed('benign')}/{rr.count('benign')} benign clean"
    )


def _failures(rr: RuleResult) -> List[str]:
    lines = list(rr.problems)
    lines += [f"{c.case.kind}/{c.case.name}: {c.failure}" for c in rr.cases if not c.passed]
    return lines


def format_console(report: Report) -> str:
    out = [f"Detection-as-code: {len(report.rules)} rules, {len(report.case_results)} test logs", ""]
    width = max([len(r.rule.slug) for r in report.rules] or [10])
    for rr in report.rules:
        level = str(rr.rule.data.get("level", "?"))
        status = "PASS" if rr.passed else "FAIL"
        out.append(f"{status}  {rr.rule.slug.ljust(width)}  {level.ljust(8)}  {_summary_line(rr)}")
        out += [f"      - {line}" for line in _failures(rr)]
    out.append("")
    out.append(
        f"Cross-rule false-positive check: {report.benign_corpus} benign logs against {len(report.rules)} rules, "
        f"{len(report.fp_violations)} violations"
    )
    out += [f"      - {v['rule']} fired on {v['log']}" for v in report.fp_violations]
    out += [f"Problem: {p}" for p in report.global_problems]
    out.append("Result: " + ("PASS" if report.passed else "FAIL"))
    return "\n".join(out)


def format_markdown(report: Report) -> str:
    out = [f"## Detection tests: {'PASS' if report.passed else 'FAIL'}", ""]
    out.append("| Rule | Level | Malicious detected | Benign clean | Result |")
    out.append("|---|---|---|---|---|")
    for rr in report.rules:
        out.append(
            f"| `{rr.rule.slug}` | {rr.rule.data.get('level', '?')} | "
            f"{rr.count_passed('malicious')}/{rr.count('malicious')} | "
            f"{rr.count_passed('benign')}/{rr.count('benign')} | {'pass' if rr.passed else '**fail**'} |"
        )
    out.append("")
    out.append(
        f"Cross-rule false-positive check: {report.benign_corpus} benign logs against "
        f"{len(report.rules)} rules, {len(report.fp_violations)} violations."
    )
    details = [f"- `{rr.rule.slug}`: {line}" for rr in report.rules for line in _failures(rr)]
    details += [f"- `{v['rule']}` fired on `{v['log']}`" for v in report.fp_violations]
    details += [f"- {p}" for p in report.global_problems]
    if details:
        out += ["", "### Problems", ""] + details
    return "\n".join(out)


def _cmd_check(args: argparse.Namespace) -> int:
    report = run_all()
    print(format_markdown(report) if args.markdown else format_console(report))
    return 0 if report.passed else 1


def _cmd_build(args: argparse.Namespace) -> int:
    from dac.site import build_site

    report = run_all()
    out = build_site(report_to_dict(report), Path(args.out))
    print(f"Wrote {out / 'index.html'} ({'all tests passing' if report.passed else 'FAILING tests are shown in the report'})")
    return 0


def _cmd_match(args: argparse.Namespace) -> int:
    try:
        event = json.loads(args.log.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read {args.log}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(event, dict):
        print("A log must be one JSON object.", file=sys.stderr)
        return 2
    hits = match_event(event)
    if not hits:
        print("No rule fired.")
        return 0
    for rule in hits:
        print(f"{rule.data.get('level', '?'):<8} {rule.slug}  ({rule.data.get('title')})")
    return 0


def _cmd_parity(_: argparse.Namespace) -> int:
    json.dump(parity_payload(run_all()), sys.stdout)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dac", description="Test Sigma detection rules against sample logs.")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="lint every rule and run it against its benign and malicious logs")
    check.add_argument("--markdown", action="store_true", help="print a Markdown summary (for $GITHUB_STEP_SUMMARY)")
    check.set_defaults(func=_cmd_check)

    build = sub.add_parser("build", help="write the HTML dashboard")
    build.add_argument("--out", default="site", help="output directory (default: site)")
    build.set_defaults(func=_cmd_build)

    match = sub.add_parser("match", help="show which rules fire on one log file")
    match.add_argument("log", type=Path)
    match.set_defaults(func=_cmd_match)

    parity = sub.add_parser("parity")  # internal: feeds tests/parity.test.js
    parity.set_defaults(func=_cmd_parity)

    args = parser.parse_args(argv)
    return args.func(args)
