"""Hidden characters anywhere in a scenario: values, keys and the JSON texts it embeds.

Characters are written by code point, never raw, so that this file holds none of them."""

import json
import time
import tracemalloc
from typing import Any

import pytest

from scenario_tools.domain.catalogue.characters import hidden_character_findings, text_findings
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


def test_a_key_and_its_value_are_two_places() -> None:
    assert [where for where, _ in _fields({f"k{RLO}": RLO})] == ["/k\\u202e", "/k\\u202e"]


def test_two_keys_whose_pointers_would_collide_are_two_places() -> None:
    long = "k" * 400
    document = {long + "a": f"x{RLO}", long + "b": f"y{RLO}"}

    assert len(_fields(document)) == 2


def test_a_long_chain_of_escaped_backslashes_is_refused_in_linear_time() -> None:
    chain = "\\u005c" + "u005c" * 50_000 + "u202e"  # many decodings away from the character
    started = time.monotonic()

    [(_, message)] = _fields({"v": chain})

    assert message.startswith("escape sequence encoded more than 3 levels deep, 1 time, first at")
    assert time.monotonic() - started < 1


def test_escaped_backslashes_in_any_case_are_followed() -> None:
    assert len(_fields({"v": "\\u005Cu005cu202E"})) == 1


def test_a_character_both_raw_and_escaped_is_counted_in_full() -> None:
    [(_, message)] = _fields({"v": f"{RLO} \\u202e"})

    assert "2 times" in message


def _first(document: Any) -> list[str]:
    return [
        message.split("first at character ")[1].split(":")[0] for _, message in _fields(document)
    ]


def test_every_finding_gives_the_offset_of_the_first_occurrence_in_the_source() -> None:
    assert _first({f"ab{RLO}": "x"}) == ["2"]  # in a key
    assert _first({"v": "abc\\u202e"}) == ["3"]  # an escape: where it starts in the text
    assert _first({"v": "x\\u005cu202e"}) == ["1"]  # two decodings away
    assert _first({"v": f"{RLO} \\u202e"}) == ["0"]  # raw first
    assert _first({"v": "ok \\u200d"}) == ["3"]  # an escaped joiner out of place
    assert _first({"v": "\\u00e9 a\\u200d"}) == ["8"]  # after a shorter decoded escape
    assert _first({"v": f"\\u202e x{RLO}"}) == ["0"]  # escaped first, then raw
    assert _first({"v": "\\u202e ab \\u200b"}) == ["0", "10"]  # two escapes


@pytest.mark.parametrize(
    ("text", "first"),
    [("\\u00e9\\udc00\\ufe00", 12), ("\\u00e9\\udc00\\udc00\\ufe00", 18)],
    ids=["one", "two in a row, no pair"],
)
def test_a_lone_low_surrogate_stays_in_the_decoded_context(text: str, first: int) -> None:
    fields = _fields({"v": text})  # no letter before the selector, and the surrogate refused
    [message] = [message for _, message in fields if "U+FE00" in message]

    assert {field for field, _ in fields} == {"/v"}
    assert f"out of place as an escape, 1 time, first at character {first}:" in message
    assert any("(LONE SURROGATE) as an escape" in message for _, message in fields)


def test_a_raw_selector_out_of_place_only_once_decoded_is_found_where_it_stands() -> None:
    keycap = f"\\u0041{chr(0xFE0F)}{chr(0x20E3)}"  # a keycap in the text, an "A" once decoded

    [(field, message)] = _fields({"v": keycap})

    assert field == "/v"
    assert "U+FE0F" in message
    assert "out of place, 1 time, first at character 6:" in message


def test_decoding_escapes_takes_memory_in_proportion_to_the_text() -> None:
    for piece in ("\\u0061", "\\u200d", "abcdef"):  # a text with no escape is not copied
        text = piece * 200_000
        tracemalloc.start()
        try:
            hidden_character_findings({"v": text}, PATH)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert peak < 2 * len(text), piece


def test_walking_a_wide_list_holds_one_cursor_per_level_not_the_siblings() -> None:
    document = {"v": [None] * 200_000, "w": {str(key): None for key in range(50_000)}}
    tracemalloc.start()
    try:
        hidden_character_findings(document, PATH)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 100_000


@pytest.mark.parametrize(
    "text",
    [
        "\\u005c\\u0075202e",  # the u escaped
        "\\u005cu\\u0032\\u0030\\u0032\\u0065",  # the hex digits escaped
        "\\\\\\\\\\u0075202e",  # three decodings away
        "\\u202\\u0065",  # a lowercase hex digit escaped, the backslash raw
        "\\u202\\u0045",  # an uppercase one
        "\\\\\\\\u20\\\\u0032e",  # a pair of backslashes, which a reader makes one
    ],
    ids=["u", "hex digits", "three levels", "lower hex", "upper hex", "backslash pairs"],
)
def test_an_escape_written_with_escapes_is_decoded_as_a_reader_would(text: str) -> None:
    [(field, message)] = _fields({"v": text})

    assert field == "/v"
    assert "U+202E (RIGHT-TO-LEFT OVERRIDE) as an escape" in message


def test_an_escape_still_written_after_three_decodings_is_refused() -> None:
    deep = "\\u0041\\u0041 " + "\\" * 8 + "u202e"  # four decodings away, after two escapes

    [(_, message)] = _fields({"v": deep})

    assert message.startswith("escape sequence encoded more than 3 levels deep, 1 time, first at")
    assert "first at character 13:" in message


def test_a_lone_half_of_a_pair_is_found_where_a_reader_leaves_it() -> None:
    # A pair of backslashes, then a low half: alone once decoded, the high half written later.
    messages = [message for _, message in _fields({"v": "\\\\ud800\\udc41"})]

    assert any("U+DC41 (LONE SURROGATE) as an escape" in message for message in messages)


def test_a_soft_hyphen_is_placed_as_a_reader_decodes_its_neighbours() -> None:
    text = "\\\\u0065\\u00ad" + chr(0xE9)  # after a digit once decoded, a letter only later

    [(_, message)] = _fields({"v": text})

    assert "U+00AD (SOFT HYPHEN) out of place as an escape" in message


def test_literal_escapes_and_regex_or_path_escapes_in_a_json_text_are_allowed() -> None:
    document = {"a": "alert \\\\u0061lert(1)", "b": "\\\\bword\\\\b C:\\\\bin \\\\fx"}

    assert _fields(document) == []


def test_a_surrogate_pair_split_across_decodings_is_refused() -> None:
    messages = [message for _, message in _fields({"v": "\\udb40\\\\udc41"})]

    assert len(messages) == 2
    assert all("(LONE SURROGATE) as an escape" in message for message in messages)


def test_escapes_of_json_encoded_twice_and_of_plain_letters_are_allowed() -> None:
    assert _fields({"v": "caf\\\\u00e9", "w": "\\u0041\\u0062"}) == []


def test_a_key_is_taken_as_written_never_decoded() -> None:
    assert _fields({"\\u202e": 1}) == []


def test_the_count_covers_the_occurrence_given_first() -> None:
    # A raw non-joiner out of place only as written, then an escaped one out of place.
    text = f"\\u0645{chr(0x200C)}\\u0645 \\u200c"

    [(_, message)] = _fields({"v": text})

    assert "out of place, 1 time, first at character 6:" in message


def test_the_count_is_the_larger_of_the_two_views() -> None:
    # Two non-joiners out of place as written; once decoded, the first stands between letters.
    text = f"\\u0645{chr(0x200C)}\\u0645{chr(0x200C)}x"

    [(_, message)] = _fields({"v": text})

    assert "out of place, 2 times, first at character 6:" in message


def test_every_escape_still_written_after_three_decodings_is_counted() -> None:
    deep = "\\" * 8 + "u202e"

    [(_, message)] = _fields({"v": f"{deep} {deep}"})

    assert message.startswith(
        "escape sequence encoded more than 3 levels deep, 2 times, first at character 0:"
    )


def test_a_character_also_raw_is_not_said_to_be_an_escape() -> None:
    [(_, message)] = _fields({"v": f"\\u202e x{RLO}"})  # the escape first

    assert message.startswith("invisible or bidirectional control character U+202E")
    assert "OVERRIDE), 2 times, first at character 0:" in message


@pytest.mark.parametrize("after", ["", "\\u0041"], ids=["after the last escape", "between two"])
def test_a_raw_character_among_escapes_is_not_said_to_be_an_escape(after: str) -> None:
    # Out of place only once decoded: the escape before it writes a colon.
    [(_, message)] = _fields({"v": f"\\u003a{chr(0xAD)}{chr(0xE9)}{after}"})

    assert "U+00AD (SOFT HYPHEN) out of place, 1 time, first at character 6:" in message


@pytest.mark.parametrize("low", ["dc00", "dfff"])
def test_a_surrogate_pair_of_adjacent_escapes_is_one_character(low: str) -> None:
    assert _fields({"v": f"\\ud83d\\u{low}"}) == []


def test_findings_of_a_text_come_in_the_order_of_their_place_in_the_source() -> None:
    # The high half shows only in the second view, the low one in the first.
    text = "\\\\ud83d\\udfff x"

    assert _first({"v": text}) == ["0", "7"]


def test_an_escape_left_after_three_decodings_says_how_to_fix_it() -> None:
    [(_, message)] = _fields({"v": "\\" * 8 + "u202e"})

    assert message == (
        "escape sequence encoded more than 3 levels deep, 1 time, first at character 0: "
        "encode it fewer times, or remove it on the platform and export the scenario again"
    )


def test_an_escape_left_after_three_decodings_takes_its_place_in_the_order() -> None:
    text = "\\" * 8 + f"u0061 {chr(0x202E)}"

    assert _first({"v": text}) == ["0", "14"]


def test_a_text_with_more_characters_than_the_report_holds_keeps_those_that_fit() -> None:
    tags = "".join(chr(code) for code in range(0xE0020, 0xE0020 + 150))

    fields = _fields({"v": f"x{tags}", "w": f"y{RLO}"})

    assert [field for field, _ in fields] == ["/v"] * (REPORT_LIMIT - 1) + [""]
    assert fields[-1][1] == "2 more texts hold hidden characters"


def test_a_markdown_text_is_checked_as_written_never_decoded() -> None:
    text = f"# Title\n\nUse \\u202e with care.\n{RLO}x{ZWSP}\n{RLO}"

    findings = text_findings(text, "scenarios/x/y/README.md")

    assert [(f.code, f.severity, f.path, f.field) for f in findings] == [
        ("IO-017", Severity.BLOCKING, "scenarios/x/y/README.md", "")
    ] * 2
    assert [f.message for f in findings] == [
        "invisible or bidirectional control character U+202E (RIGHT-TO-LEFT OVERRIDE), "
        "2 times, first at character 31: remove it from the file",
        "invisible or bidirectional control character U+200B (ZERO WIDTH SPACE), 1 time, first "
        "at character 33: remove it from the file",
    ]
    assert text_findings("# Clean\n", "scenarios/x/y/README.md") == ()


def test_a_text_full_of_hidden_characters_gives_a_bounded_number_of_findings() -> None:
    text = "".join(chr(code) for code in range(0xE0000, 0xE0000 + 300))

    findings = text_findings(text, "scenarios/x/y/README.md")

    assert len(findings) == REPORT_LIMIT
    assert findings[-1].message == "201 more hidden characters in the file: remove them"
    assert findings[-1].severity is Severity.BLOCKING


def test_a_text_with_as_many_hidden_characters_as_the_report_holds_shows_them_all() -> None:
    text = "".join(chr(code) for code in range(0xE0000, 0xE0000 + REPORT_LIMIT))

    findings = text_findings(text, "scenarios/x/y/README.md")

    assert len(findings) == REPORT_LIMIT
    assert all("U+E00" in finding.message for finding in findings)


def test_characters_already_reported_as_written_are_not_reported_again() -> None:
    label = "U+202E (RIGHT-TO-LEFT OVERRIDE)"
    document = {"a": f"x{RLO}", "b": f"y{ZWSP}"}

    findings = hidden_character_findings(
        document, PATH, written=frozenset({label}), to_do="remove it from the file"
    )

    assert [(f.field, f.message.split(",")[0]) for f in findings] == [
        ("/b", "invisible or bidirectional control character U+200B (ZERO WIDTH SPACE)")
    ]
    assert findings[0].message.endswith(": remove it from the file")


def test_line_breaks_yaml_reads_but_a_reviewer_may_not_see_are_found_when_asked() -> None:
    text = f"a: 1 # note{chr(0x2028)}b: 2{chr(0x85)}c: 3{chr(0x2028)}d{chr(0x2029)}"

    assert text_findings(text, "scenarios/x/y/scenario.yaml") == ()
    findings = text_findings(text, "scenarios/x/y/scenario.yaml", breaks=True)

    assert [f.message for f in findings] == [
        "line break U+2028 (LINE SEPARATOR) other than \\n, which YAML reads while a reviewer "
        "may not see it, 2 times, first at character 11: remove it from the file",
        "line break U+0085 other than \\n, which YAML reads while a reviewer may not see it, "
        "1 time, first at character 16: remove it from the file",
        "line break U+2029 (PARAGRAPH SEPARATOR) other than \\n, which YAML reads while a "
        "reviewer may not see it, 1 time, first at character 23: remove it from the file",
    ]
