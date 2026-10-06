"""A small, strict evaluator for a subset of the Sigma rule format.

Design principle: anything this engine does not understand raises
``UnsupportedFeature`` instead of being ignored. A silently ignored modifier
would make a rule match more (or less) than its author intended, and the tests
would then pass for the wrong reason.

Supported
  * selections as a mapping (fields ANDed) or a list of mappings (ORed)
  * value lists (ORed, or ANDed with the ``all`` modifier)
  * modifiers: contains, startswith, endswith, re (+ i, m, s), all
  * ``*`` and ``?`` wildcards in plain values, ``\\*`` and ``\\?`` to escape them
  * null values (field missing or null)
  * conditions: and, or, not, parentheses, ``1 of`` / ``all of`` with
    wildcards or ``them``
  * dotted field names for nested events (``process.name``)

Not supported (raises UnsupportedFeature): aggregations such as ``count()``,
``near``, ``timeframe``, keyword (free-text) selections and the remaining
Sigma value modifiers (base64, cidr, windash, lt/gt ...).

The browser dashboard ships a JavaScript port of this file (dac/web/engine.js).
tests/parity.test.js asserts that both engines return the same verdicts.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

Event = Dict[str, Any]
Predicate = Callable[[Event], bool]


class SigmaError(ValueError):
    """The rule is malformed."""


class UnsupportedFeature(SigmaError):
    """The rule uses Sigma syntax this engine deliberately does not implement."""


_MISSING = object()
_MATCH_MODIFIERS = ("contains", "startswith", "endswith", "re")
_REGEX_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


# --------------------------------------------------------------------------- fields


def _parse_field(key: str) -> Tuple[str, Optional[str], bool, int]:
    """Split ``Field|modifier|modifier`` into (field, match, require_all, regex_flags)."""
    field, *modifiers = key.split("|")
    if not field:
        raise SigmaError(f"'{key}': empty field name")
    match_modifier: Optional[str] = None
    require_all = False
    flags = 0
    for modifier in modifiers:
        if modifier in _MATCH_MODIFIERS:
            if match_modifier:
                raise SigmaError(f"'{key}': only one of contains/startswith/endswith/re is allowed")
            match_modifier = modifier
        elif modifier == "all":
            require_all = True
        elif modifier in _REGEX_FLAGS:
            if match_modifier != "re":
                raise SigmaError(f"'{key}': regex flag '{modifier}' is only valid after 're'")
            flags |= _REGEX_FLAGS[modifier]
        else:
            raise UnsupportedFeature(f"'{key}': modifier '{modifier}' is not supported")
    return field, match_modifier, require_all, flags


def _lookup(event: Event, field: str) -> Any:
    if field in event:
        return event[field]
    current: Any = event
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _glob_to_regex(pattern: str) -> str:
    """Turn a Sigma plain value into regex source: ``*`` and ``?`` are wildcards."""
    out: List[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            if nxt in "*?":  # \* and \? are literal characters
                out.append(re.escape(nxt))
                i += 2
                continue
            if nxt == "\\" and i + 2 < len(pattern) and pattern[i + 2] in "*?":
                out.append(re.escape("\\"))  # \\* is a literal backslash then a wildcard
                i += 2
                continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


def _string_test(value: str, modifier: Optional[str], flags: int) -> Callable[[str], bool]:
    if modifier == "re":
        try:
            pattern = re.compile(value, flags)
        except re.error as exc:
            raise SigmaError(f"invalid regular expression {value!r}: {exc}") from exc
        return lambda s: pattern.search(s) is not None
    body = _glob_to_regex(value)
    if modifier == "contains":
        source = body
    elif modifier == "startswith":
        source = r"\A(?:" + body + ")"
    elif modifier == "endswith":
        source = "(?:" + body + r")\Z"
    else:
        source = r"\A(?:" + body + r")\Z"
    compiled = re.compile(source, re.IGNORECASE | re.DOTALL)
    return lambda s: compiled.search(s) is not None


def _value_matcher(key: str, raw: Any, modifier: Optional[str], flags: int) -> Callable[[Any], bool]:
    """Return a function taking the event's value (or _MISSING) and giving a verdict."""
    if raw is None:
        if modifier:
            raise SigmaError(f"'{key}': null cannot be combined with '{modifier}'")
        return lambda found: found is _MISSING or found is None
    if isinstance(raw, (dict, list)):
        raise SigmaError(f"'{key}': nested values are not allowed here")
    test = _string_test(str(raw), modifier, flags)

    def matcher(found: Any) -> bool:
        if found is _MISSING or found is None:
            return False
        if isinstance(found, list):
            return any(test(str(item)) for item in found)
        return test(str(found))

    return matcher


def _compile_field(key: str, spec: Any) -> Predicate:
    field, modifier, require_all, flags = _parse_field(key)
    values = spec if isinstance(spec, list) else [spec]
    if not values:
        raise SigmaError(f"'{key}': empty value list")
    matchers = [_value_matcher(key, value, modifier, flags) for value in values]
    combine = all if require_all else any

    def predicate(event: Event) -> bool:
        found = _lookup(event, field)
        return combine(matcher(found) for matcher in matchers)

    return predicate


def _compile_selection(name: str, body: Any) -> Predicate:
    if isinstance(body, dict):
        if not body:
            raise SigmaError(f"selection '{name}' is empty and would match every event")
        predicates = [_compile_field(key, spec) for key, spec in body.items()]
        return lambda event: all(p(event) for p in predicates)
    if isinstance(body, list) and body and all(isinstance(item, dict) for item in body):
        alternatives = [_compile_selection(name, item) for item in body]
        return lambda event: any(p(event) for p in alternatives)
    raise UnsupportedFeature(f"selection '{name}': keyword (free-text) searches are not supported")


# ------------------------------------------------------------------------ conditions

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _any(predicates: List[Predicate]) -> Predicate:
    return lambda event: any(p(event) for p in predicates)


def _all(predicates: List[Predicate]) -> Predicate:
    return lambda event: all(p(event) for p in predicates)


def _not(predicate: Predicate) -> Predicate:
    return lambda event: not predicate(event)


class _ConditionParser:
    """Recursive descent: or < and < not < atom."""

    def __init__(self, text: str, selections: Dict[str, Predicate]) -> None:
        if "|" in text:
            raise UnsupportedFeature("aggregations (count, near, ...) are not supported")
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.selections = selections

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _peek_word(self) -> str:
        token = self._peek()
        return token.lower() if token is not None else ""

    def _take(self) -> Optional[str]:
        token = self._peek()
        self.pos += 1
        return token

    def parse(self) -> Predicate:
        if not self.tokens:
            raise SigmaError("condition is empty")
        node = self._or()
        if self._peek() is not None:
            raise SigmaError(f"unexpected '{self._peek()}' in condition")
        return node

    def _or(self) -> Predicate:
        parts = [self._and()]
        while self._peek_word() == "or":
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else _any(parts)

    def _and(self) -> Predicate:
        parts = [self._not()]
        while self._peek_word() == "and":
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else _all(parts)

    def _not(self) -> Predicate:
        if self._peek_word() == "not":
            self._take()
            return _not(self._not())
        return self._atom()

    def _atom(self) -> Predicate:
        token = self._take()
        if token is None:
            raise SigmaError("condition ended unexpectedly")
        if token == "(":
            node = self._or()
            if self._take() != ")":
                raise SigmaError("missing ')' in condition")
            return node
        if token.lower() in ("1", "all") and self._peek_word() == "of":
            self._take()
            target = self._take()
            if target is None:
                raise SigmaError(f"'{token} of' needs a selection name, pattern or 'them'")
            predicates = [self.selections[name] for name in self._resolve(target)]
            return _any(predicates) if token == "1" else _all(predicates)
        if token.lower() in ("and", "or") or token == ")":
            raise SigmaError(f"unexpected '{token}' in condition")
        if token not in self.selections:
            raise SigmaError(f"condition references unknown selection '{token}'")
        return self.selections[token]

    def _resolve(self, target: str) -> List[str]:
        if target.lower() == "them":
            names = list(self.selections)
        else:
            pattern = re.compile(_glob_to_regex(target), re.DOTALL)
            names = [name for name in self.selections if pattern.fullmatch(name)]
        if not names:
            raise SigmaError(f"'{target}' matches no selection")
        return names


# ---------------------------------------------------------------------------- public


def compile_detection(detection: Dict[str, Any]) -> Predicate:
    """Compile a Sigma ``detection`` block into a function ``event -> bool``."""
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaError("detection needs a 'condition'")
    if "timeframe" in detection:
        raise UnsupportedFeature("'timeframe' (aggregation) is not supported")
    selections = {
        name: _compile_selection(name, body)
        for name, body in detection.items()
        if name != "condition"
    }
    if not selections:
        raise SigmaError("detection has no selections")
    conditions = detection["condition"]
    if not isinstance(conditions, list):
        conditions = [conditions]
    if not all(isinstance(c, str) for c in conditions):
        raise SigmaError("condition must be a string or a list of strings")
    compiled = [_ConditionParser(c, selections).parse() for c in conditions]
    return compiled[0] if len(compiled) == 1 else _any(compiled)
