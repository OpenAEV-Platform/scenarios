"""Hidden characters anywhere in a scenario: values, keys and the JSON texts it embeds.

Characters are written by code point, never raw, so that this file holds none of them."""

import json
from typing import Any

from scenario_tools.domain.catalogue.characters import hidden_character_findings
from scenario_tools.domain.shared.finding import REPORT_LIMIT, Severity

PATH = "scenarios/x/y/scenario.json"
RLO, ZWSP, LRI, RLM, NUL = chr(0x202E), chr(0x200B), chr(0x2066), chr(0x200F), chr(0)
TAG_A = chr(0xE0061)


def _fields(document: Any) -> list[tuple[str, str]]:
    findings = hidden_character_findings(document, PATH)
    assert {(f.code, f.severity, f.path) for f in findings} <= {("IO-017", Severity.BLOCKING, PATH)}
    return [(f.field, f.message) for f in findings]


def test_a_clean_scenario_has_no_finding() -> None:
    assert _fields({"scenario_injects": [{"inject_title": "Scan the host\n"}]}) == []


def test_a_value_is_reported_at_its_pointer_with_where_and_what_to_do() -> None:
    document = {"scenario_injects": [{"inject_title": f"rm -rf /tmp/x{RLO}#gnp.exe{RLO}"}]}

    [(field, message)] = _fields(document)

    assert field == "/scenario_injects/0/inject_title"
    assert "U+202E" in message
    assert "2 times, first at character 13" in message
    assert "export" in message  # what to do
    assert "rm -rf" not in message  # never the text


def test_a_key_is_reported_and_its_pointer_shows_the_character_escaped() -> None:
    [(field, message)] = _fields({"scenario_tags": [{f"na{ZWSP}me": "x"}]})

    assert field == "/scenario_tags/0/na\\u200bme"
    assert ZWSP not in field
    assert "in a key" in message


def test_pointers_escape_slash_and_tilde() -> None:
    [(field, _)] = _fields({"a/b~c": LRI})

    assert field == "/a~1b~0c"


def test_an_escaped_character_in_an_embedded_json_text_is_found_at_any_depth() -> None:
    # The platform decodes these texts: an escape would become the character itself.
    nested = "[" * 3000 + json.dumps(f"x{RLO}") + "]" * 3000
    double = json.dumps(json.dumps({"subject": f"{NUL}x"}))
    invalid = '{"subject": "' + json.dumps(RLM)[1:-1]
    document = {"inject_content": nested, "x": {"injector_contract_content": double}}
    document["y"] = {"inject_content": invalid}

    fields = _fields(document)

    assert sorted(field for field, _ in fields) == [
        "/inject_content",
        "/x/injector_contract_content",
        "/y/inject_content",
    ]
    assert all("as an escape" in message for _, message in fields)


def test_an_escaped_character_outside_the_basic_plane_is_found() -> None:
    document = {"inject_content": json.dumps({"a": f"x{TAG_A}"})}  # a surrogate pair escape

    [(_, message)] = _fields(document)

    assert "U+E0061" in message


def test_an_escape_is_found_in_any_value_since_any_may_be_json_text() -> None:
    nested = {"inject_content": {"k": json.dumps({"a": f"x{RLO}"})}}  # JSON text in a value

    [(field, message)] = _fields(nested)

    assert field == "/inject_content/k"
    assert "as an escape" in message


def test_a_misplaced_joiner_or_a_control_in_a_key_is_shown_escaped_in_the_pointer() -> None:
    fields = [field for field, _ in _fields({f"{chr(0x200D)}b": "x", f"c{RLO}": "y"})]

    assert all(field.isprintable() for field in fields)


def test_a_huge_key_gives_a_bounded_pointer() -> None:
    [(field, _)] = _fields({"k" * 1_000_000 + RLO: "x"})

    assert len(field) <= 400


def test_a_raw_character_in_an_embedded_text_is_reported_once() -> None:
    document = {"inject_content": json.dumps({"subject": f"{RLO}x"}, ensure_ascii=False)}

    assert len(_fields(document)) == 1


def test_findings_stay_bounded_with_a_summary_of_the_rest() -> None:
    document = {f"k{n}": f"x{RLO}" for n in range(1000)}

    fields = _fields(document)

    assert len(fields) == REPORT_LIMIT
    assert fields[-1] == ("", f"{1000 - REPORT_LIMIT + 1} more texts hold hidden characters")


def test_a_json_text_field_that_holds_no_text_is_walked_as_any_value() -> None:
    assert _fields({"inject_content": None, "injector_contract_content": {"a": f"x{RLO}"}}) == [
        ("/injector_contract_content/a", _fields({"a": f"x{RLO}"})[0][1])
    ]


def test_an_escape_of_an_ordinary_character_in_a_json_text_is_fine() -> None:
    accents = json.dumps({"subject": "caf" + chr(0xE9) + " " + chr(0x1F642)})  # ensure_ascii

    assert _fields({"inject_content": accents}) == []


def test_an_escape_of_an_escaped_backslash_is_followed_to_the_character() -> None:
    # Two decodings away: an escaped backslash, then the escape of the character.
    two_steps = "x \\u005cu202e y"

    [(_, message)] = _fields({"inject_content": two_steps})

    assert "U+202E" in message


def test_the_summary_of_a_single_text_left_is_in_the_singular() -> None:
    document = {f"k{n}": f"x{RLO}" for n in range(REPORT_LIMIT)}

    assert _fields(document)[-1] == ("", "1 more text holds hidden characters")


def test_an_escaped_joiner_is_placed_as_if_it_were_the_character() -> None:
    start = "\\u200dfoo"  # an escaped ZWJ at the start of the text
    after_ascii = "a\\u200d"
    keycap = "1\\ufe0f\\u20e3"  # a keycap, escaped

    assert [len(_fields({"v": text})) for text in (start, after_ascii, keycap)] == [1, 1, 0]
    assert "out of place as an escape" in _fields({"v": start})[0][1]


def test_a_character_both_raw_and_escaped_in_a_value_is_reported_once() -> None:
    assert len(_fields({"v": f"{RLO} \\u202e"})) == 1
