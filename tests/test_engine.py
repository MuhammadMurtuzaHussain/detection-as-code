"""Unit tests for the Sigma subset evaluator."""

import pytest

from dac.engine import SigmaError, UnsupportedFeature, compile_detection


def detect(body, condition="selection"):
    return compile_detection({"selection": body, "condition": condition})


# ---------------------------------------------------------------- value matching


def test_plain_value_is_an_exact_match_and_case_insensitive():
    rule = detect({"Image": "C:\\Windows\\cmd.exe"})
    assert rule({"Image": "c:\\windows\\CMD.EXE"})
    assert not rule({"Image": "C:\\Windows\\cmd.exe.bak"})


@pytest.mark.parametrize(
    "modifier, value, expected",
    [
        ("contains", "evil", True),
        ("contains", "good", False),
        ("startswith", "c:\\tools", True),
        ("startswith", "evil", False),
        ("endswith", ".exe", True),
        ("endswith", "tools", False),
    ],
)
def test_string_modifiers(modifier, value, expected):
    rule = detect({f"Image|{modifier}": value})
    assert rule({"Image": "C:\\Tools\\evil.exe"}) is expected


def test_value_list_is_or_by_default_and_and_with_all():
    event = {"CommandLine": "vssadmin delete shadows"}
    assert detect({"CommandLine|contains": ["delete", "nothing"]})(event)
    assert detect({"CommandLine|contains|all": ["delete", "shadows"]})(event)
    assert not detect({"CommandLine|contains|all": ["delete", "nothing"]})(event)


def test_wildcards_and_escaped_wildcards():
    # '\\*' (backslash, then a wildcard) is how Sigma writes "any directory under C:"
    assert detect({"Image": "C:\\\\*\\cmd.exe"})({"Image": "C:\\Windows\\System32\\cmd.exe"})
    # ...whereas '\*' is a literal asterisk, a common Sigma gotcha
    assert not detect({"Image": "C:\\*\\cmd.exe"})({"Image": "C:\\Windows\\System32\\cmd.exe"})
    assert detect({"Image": "C:\\*\\cmd.exe"})({"Image": "C:*\\cmd.exe"})
    assert detect({"Name": "a?c"})({"Name": "abc"})
    assert not detect({"Name": "a?c"})({"Name": "abbc"})
    literal_star = detect({"Name": "a\\*c"})
    assert literal_star({"Name": "a*c"})
    assert not literal_star({"Name": "abc"})
    assert detect({"Path": "\\\\*"})({"Path": "\\\\server"})  # \\* is a literal backslash then a wildcard


def test_regex_is_case_sensitive_unless_flagged():
    event = {"CommandLine": "PowerShell -ENC AAAA"}
    assert not detect({"CommandLine|re": "powershell"})(event)
    assert detect({"CommandLine|re|i": "powershell"})(event)
    assert detect({"CommandLine|re": "(?i)powershell"})(event)


def test_regex_search_is_not_anchored():
    assert detect({"CommandLine|re": r"\s-enc\s"})({"CommandLine": "powershell -enc AAA"})


def test_numbers_and_missing_fields():
    assert detect({"EventID": 1})({"EventID": 1})
    assert detect({"EventID": 1})({"EventID": "1"})
    assert not detect({"EventID": 1})({})
    assert not detect({"Image|contains": "x"})({})


def test_null_matches_missing_or_empty_field():
    rule = detect({"ParentImage": None})
    assert rule({"Image": "x"})
    assert rule({"ParentImage": None})
    assert not rule({"ParentImage": "cmd.exe"})


def test_nested_fields_by_dotted_path_and_list_values():
    assert detect({"process.name": "cmd.exe"})({"process": {"name": "CMD.exe"}})
    assert detect({"Tags|contains": "bad"})({"Tags": ["ok", "very-bad"]})


def test_selection_as_list_of_maps_is_or():
    rule = detect([{"Image|endswith": "\\a.exe"}, {"Image|endswith": "\\b.exe"}])
    assert rule({"Image": "C:\\b.exe"})
    assert not rule({"Image": "C:\\c.exe"})


# --------------------------------------------------------------------- conditions

SELECTIONS = {
    "sel_a": {"A": "1"},
    "sel_b": {"B": "1"},
    "filter": {"F": "1"},
}


def cond(text):
    return compile_detection({**SELECTIONS, "condition": text})


def test_boolean_logic_and_precedence():
    event = {"A": "1"}
    assert cond("sel_a or sel_b")(event)
    assert not cond("sel_a and sel_b")(event)
    assert cond("sel_a and not filter")(event)
    assert not cond("sel_a and not filter")({"A": "1", "F": "1"})
    assert cond("sel_b or sel_a and not filter")(event)  # and binds tighter than or
    assert not cond("(sel_b or sel_a) and filter")(event)


def test_quantifiers():
    assert cond("1 of sel_*")({"A": "1"})
    assert not cond("all of sel_*")({"A": "1"})
    assert cond("all of sel_*")({"A": "1", "B": "1"})
    assert cond("1 of them")({"F": "1"})
    assert not cond("all of them")({"A": "1", "B": "1"})
    assert cond("1 of sel_* and not filter")({"A": "1"})


def test_condition_list_is_or():
    rule = compile_detection({**SELECTIONS, "condition": ["sel_a", "sel_b"]})
    assert rule({"B": "1"})


# ------------------------------------------------------------------ failure modes


@pytest.mark.parametrize(
    "detection",
    [
        {"selection": {"A|base64": "x"}, "condition": "selection"},
        {"selection": {"A|windash|contains": "x"}, "condition": "selection"},
        {"selection": {"A": "x"}, "condition": "selection | count() > 5"},
        {"selection": {"A": "x"}, "condition": "selection", "timeframe": "5m"},
        {"keywords": ["mimikatz"], "condition": "keywords"},
    ],
    ids=["base64", "windash", "aggregation", "timeframe", "keywords"],
)
def test_unsupported_features_raise_instead_of_being_ignored(detection):
    with pytest.raises(UnsupportedFeature):
        compile_detection(detection)


@pytest.mark.parametrize(
    "detection",
    [
        {"selection": {"A": "x"}},  # no condition
        {"condition": "selection"},  # no selections
        {"selection": {"A": "x"}, "condition": "other"},  # unknown selection
        {"selection": {"A": "x"}, "condition": "selection and"},
        {"selection": {"A": "x"}, "condition": "(selection"},
        {"selection": {"A": "x"}, "condition": "1 of nothing_*"},
        {"selection": {}, "condition": "selection"},  # empty selection would match everything
        {"selection": {"A|contains|startswith": "x"}, "condition": "selection"},
        {"selection": {"A|i": "x"}, "condition": "selection"},
        {"selection": {"A|re": "("}, "condition": "selection"},
        {"selection": {"A|contains": None}, "condition": "selection"},
    ],
)
def test_malformed_rules_raise(detection):
    with pytest.raises(SigmaError):
        compile_detection(detection)
