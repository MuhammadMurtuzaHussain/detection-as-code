"""Load rules and test logs from disk and lint rule metadata."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from dac.engine import Event, Predicate, SigmaError, compile_detection

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
CASES_DIR = ROOT / "tests" / "cases"

CASE_KINDS = ("malicious", "benign")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
LEVELS = ("informational", "low", "medium", "high", "critical")
REQUIRED_FIELDS = (
    "title", "id", "status", "description", "author", "date",
    "logsource", "detection", "level", "tags", "falsepositives",
)
# ATT&CK Enterprise tactics in Sigma tag form, in kill-chain order.
TACTICS = (
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
)
_TECHNIQUE_TAG = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")
_DATE = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}$")


def tactic_name(tactic: str) -> str:
    """attack.command_and_control -> 'Command and Control' (ATT&CK's own capitalisation)."""
    return tactic.replace("_", " ").title().replace(" And ", " and ")


def technique_from_tag(tag: str) -> Optional[Dict[str, str]]:
    match = _TECHNIQUE_TAG.match(tag)
    if not match:
        return None
    base, sub = match.group(1), match.group(2)
    if sub:
        return {"id": f"T{base}.{sub}", "url": f"https://attack.mitre.org/techniques/T{base}/{sub}/"}
    return {"id": f"T{base}", "url": f"https://attack.mitre.org/techniques/T{base}/"}


def _relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


# ----------------------------------------------------------------------------- rules


@dataclass
class Rule:
    path: Path
    text: str
    data: Dict[str, Any]
    problems: List[str] = field(default_factory=list)
    matcher: Optional[Predicate] = None

    @property
    def slug(self) -> str:
        """File name without extension. Also the name of the test-log directory."""
        return self.path.stem

    @property
    def rel_path(self) -> str:
        return _relative(self.path)

    @property
    def tactics(self) -> List[str]:
        return [t[len("attack."):] for t in self.data.get("tags") or [] if t[len("attack."):] in TACTICS]

    @property
    def techniques(self) -> List[Dict[str, str]]:
        found = (technique_from_tag(t) for t in self.data.get("tags") or [] if isinstance(t, str))
        return [t for t in found if t]

    def matches(self, event: Event) -> bool:
        if self.matcher is None:
            raise RuntimeError(f"rule {self.slug} did not compile")
        return self.matcher(event)


def lint_metadata(data: Dict[str, Any]) -> List[str]:
    """Return a list of problems with a rule's metadata (not its detection logic)."""
    problems: List[str] = []
    for key in REQUIRED_FIELDS:
        if data.get(key) in (None, "", [], {}):
            problems.append(f"missing required field '{key}'")

    rule_id = data.get("id")
    if rule_id:
        try:
            uuid.UUID(str(rule_id))
        except ValueError:
            problems.append("'id' must be a UUID")
    if data.get("status") and data["status"] not in STATUSES:
        problems.append(f"'status' must be one of {', '.join(STATUSES)}")
    if data.get("level") and data["level"] not in LEVELS:
        problems.append(f"'level' must be one of {', '.join(LEVELS)}")

    when = data.get("date")
    if when and not (isinstance(when, (date, datetime)) or (isinstance(when, str) and _DATE.match(when))):
        problems.append("'date' must look like YYYY-MM-DD")

    tags = data.get("tags")
    if tags:
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            problems.append("'tags' must be a list of strings")
        else:
            attack = [t for t in tags if t.startswith("attack.")]
            if not any(t[len("attack."):] in TACTICS for t in attack):
                problems.append("tags need at least one ATT&CK tactic, for example attack.execution")
            if not any(_TECHNIQUE_TAG.match(t) for t in attack):
                problems.append("tags need at least one ATT&CK technique, for example attack.t1059.001")
            for tag in attack:
                if tag[len("attack."):] not in TACTICS and not _TECHNIQUE_TAG.match(tag):
                    problems.append(f"unrecognised ATT&CK tag '{tag}'")

    fps = data.get("falsepositives")
    if fps and (not isinstance(fps, list) or not all(isinstance(x, str) and x.strip() for x in fps)):
        problems.append("'falsepositives' must be a list of non-empty strings")

    logsource = data.get("logsource")
    if logsource and not (isinstance(logsource, dict) and any(k in logsource for k in ("product", "category", "service"))):
        problems.append("'logsource' needs at least one of product, category or service")
    return problems


def load_rules(rules_dir: Path = RULES_DIR) -> List[Rule]:
    """Parse every rule under ``rules_dir``. Problems are recorded on the rule, never raised."""
    rules: List[Rule] = []
    files = sorted(p for p in rules_dir.rglob("*") if p.suffix in (".yml", ".yaml") and not p.name.startswith("."))
    for path in files:
        text = path.read_text(encoding="utf-8")
        problems: List[str] = []
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            data = None
            problems.append(f"invalid YAML: {str(exc).splitlines()[0] if str(exc) else exc}")
        if not isinstance(data, dict):
            if not problems:
                problems.append("a rule must be a YAML mapping")
            data = {}
        rule = Rule(path=path, text=text, data=data, problems=problems)
        if path.suffix != ".yml":
            rule.problems.append("rule files must use the .yml extension")
        rule.problems.extend(lint_metadata(data))
        if "detection" in data:
            try:
                rule.matcher = compile_detection(data["detection"])
            except SigmaError as exc:
                rule.problems.append(f"detection: {exc}")
        rules.append(rule)

    seen_ids: Dict[str, Rule] = {}
    seen_slugs: Dict[str, Rule] = {}
    for rule in rules:
        rule_id = str(rule.data.get("id", "")).lower()
        if rule_id and rule_id in seen_ids:
            rule.problems.append(f"duplicate id (also used by {seen_ids[rule_id].rel_path})")
        elif rule_id:
            seen_ids[rule_id] = rule
        if rule.slug in seen_slugs:
            rule.problems.append(f"duplicate file name (also {seen_slugs[rule.slug].rel_path}); test logs are keyed by file name")
        else:
            seen_slugs[rule.slug] = rule
    return rules


# ----------------------------------------------------------------------------- cases


@dataclass
class Case:
    slug: str
    kind: str
    name: str
    path: Path
    event: Event

    @property
    def expected(self) -> bool:
        """Malicious logs must fire the rule; benign logs must not."""
        return self.kind == "malicious"

    @property
    def rel_path(self) -> str:
        return _relative(self.path)

    @property
    def label(self) -> str:
        return f"{self.slug}/{self.kind}/{self.name}"


def load_cases(cases_dir: Path = CASES_DIR) -> Tuple[Dict[str, List[Case]], List[str]]:
    """Read tests/cases/<rule-file-name>/<malicious|benign>/<name>.json, one event per file."""
    cases: Dict[str, List[Case]] = {}
    problems: List[str] = []
    if not cases_dir.is_dir():
        return cases, [f"test log directory not found: {_relative(cases_dir)}"]
    for rule_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir() and not p.name.startswith(".")):
        cases[rule_dir.name] = []
        for entry in sorted(rule_dir.iterdir()):
            if entry.name.startswith("."):
                continue
            if not (entry.is_dir() and entry.name in CASE_KINDS):
                problems.append(f"{_relative(entry)}: expected only 'malicious' and 'benign' directories")
                continue
            for path in sorted(entry.iterdir()):
                if path.name.startswith("."):
                    continue
                if path.suffix != ".json":
                    problems.append(f"{_relative(path)}: test logs must be .json files")
                    continue
                try:
                    event = json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    problems.append(f"{_relative(path)}: invalid JSON ({exc.msg}, line {exc.lineno})")
                    continue
                if not isinstance(event, dict):
                    problems.append(f"{_relative(path)}: a test log must be one JSON object")
                    continue
                cases[rule_dir.name].append(Case(rule_dir.name, entry.name, path.stem, path, event))
    return cases, problems
