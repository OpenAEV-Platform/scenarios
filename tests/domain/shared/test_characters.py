"""Characters that hide text from a reviewer or reorder it: a closed list, shared by every check.

Characters are written by code point, never raw, so that this file holds none of them."""

import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.shared.characters import HIDDEN, hidden_in, hidden_occurrences

# The contract's list, restated independently of the implementation.
CONTRACT_RANGES = [
    (0x0000, 0x0008), (0x000B, 0x000C), (0x000E, 0x001F), (0x007F, 0x0084), (0x0086, 0x009F),
    (0x061C, 0x061C), (0x180E, 0x180E), (0x200B, 0x200B), (0x200E, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
]  # fmt: skip
ALLOWED = [chr(code) for code in (
    0x09, 0x0A, 0x0D, 0x85, 0x2028, 0x2029,  # tab and line breaks
    0xAD, 0xE9, 0x6F22, 0x1F642, 0x20, 0xA0, 0x034F, 0x115F, 0x2800,
)]  # fmt: skip
RLO, ZWSP, ZWJ, ZWNJ, VS16 = chr(0x202E), chr(0x200B), chr(0x200D), chr(0x200C), chr(0xFE0F)


def test_the_list_is_exactly_the_contract_s_one() -> None:
    contract = {chr(code) for first, last in CONTRACT_RANGES for code in range(first, last + 1)}

    assert contract == HIDDEN
    assert not HIDDEN & set(ALLOWED)


@pytest.mark.parametrize("code", [0x202E, 0x2065, 0xE0080, 0xE01F0, 0x000B, 0x0086, 0x3164])
def test_a_character_of_the_list_is_found_and_named_by_its_code_point(code: int) -> None:
    [found] = hidden_in(f"run {chr(code)}this")

    assert found.split()[0] == f"U+{code:04X}"


@pytest.mark.parametrize("character", ALLOWED, ids=lambda c: f"U+{ord(c):04X}")
def test_a_character_outside_the_list_is_allowed(character: str) -> None:
    assert hidden_in(f"a{character}b") == ()


def test_each_character_is_named_once_in_the_order_it_appears() -> None:
    assert hidden_in(f"{RLO} a {ZWSP} b {RLO}") == (
        "U+202E (RIGHT-TO-LEFT OVERRIDE)",
        "U+200B (ZERO WIDTH SPACE)",
    )


def test_occurrences_are_counted_with_the_offset_of_the_first() -> None:
    [rlo, zwsp] = hidden_occurrences(f"ab{RLO}c{ZWSP}{RLO}")

    assert (rlo.label, rlo.count, rlo.first) == ("U+202E (RIGHT-TO-LEFT OVERRIDE)", 2, 2)
    assert (zwsp.count, zwsp.first) == (1, 4)


def test_a_control_character_has_no_name_but_its_code_point() -> None:
    assert hidden_in(chr(0x1B)) == ("U+001B",)


# Joiners and variation selectors are allowed where scripts and emoji use them, never as a run
# or out of place, where they could carry hidden data.


@pytest.mark.parametrize(
    "text",
    [
        f"{chr(0x2764)}{VS16}",  # a heart shown as emoji
        f"{chr(0x2764)}{VS16}{ZWJ}{chr(0x1F525)}",  # heart on fire: VS16 then ZWJ
        f"{chr(0x1F468)}{ZWJ}{chr(0x1F469)}{ZWJ}{chr(0x1F467)}",  # a family
        f"1{VS16}{chr(0x20E3)}",  # keycap one
        f"{chr(0x0645)}{ZWNJ}{chr(0x06CC)}",  # Persian letters kept apart
        f"{chr(0x0915)}{chr(0x094D)}{ZWJ}{chr(0x0937)}",  # Devanagari conjunct
        f"iPhone{ZWNJ}{chr(0x0647)}{chr(0x0627)}",  # a Persian suffix after a foreign word
        f"{chr(0xA9)}{VS16}",  # the copyright sign shown as emoji
        f"{chr(0x8FBB)}{chr(0xFE00)}",  # a CJK ideograph with a standardized variant
        f"{chr(0x2139)}{VS16}",  # information source, a letter shown as emoji
        f"{chr(0x203C)}{VS16}",  # double exclamation mark shown as emoji
        f"{chr(0x3030)}{chr(0xFE0E)}",  # wavy dash shown as text
    ],
    ids=[
        "emoji",
        "emoji sequence",
        "family",
        "keycap",
        "persian",
        "devanagari",
        "suffix",
        "copyright",
        "cjk variant",
        "information source",
        "double exclamation",
        "wavy dash as text",
    ],
)
def test_joiners_and_selectors_where_text_uses_them_are_allowed(text: str) -> None:
    assert hidden_in(text) == ()


@pytest.mark.parametrize(
    ("text", "code"),
    [
        (f"{VS16}start", 0xFE0F),
        (f"a{VS16}", 0xFE0F),
        (f"a {ZWJ}b", 0x200D),
        (f"{chr(0x1F642)}{chr(0xFE00)}{chr(0xFE01)}", 0xFE01),
        (f"{chr(0x0645)}{ZWNJ}{ZWNJ}", 0x200C),
        (f"1{VS16}", 0xFE0F),
        (f"12{ZWNJ}x", 0x200C),
        (f"a{ZWNJ}{chr(0x0660)}", 0x200C),  # an Arabic-Indic digit is no suffix
        (f"{chr(0x0661)}{ZWJ}x", 0x200D),  # after an Arabic-Indic digit
        (f"{chr(0x060C)}{ZWNJ}x", 0x200C),  # after an Arabic comma
        (f"{chr(0xE9)}{VS16}{ZWJ}{chr(0x1F525)}", 0xFE0F),  # an emoji selector after a letter
        (f"{chr(0x00A1)}{VS16}", 0xFE0F),  # after a punctuation mark no emoji is drawn from
        (f"{chr(0x1F642)}{ZWJ}x", 0x200D),  # a joiner joins nothing ASCII
        (f"{chr(0x0645)}{ZWNJ}x", 0x200C),
        (f"{chr(0x1F642)}{ZWJ}", 0x200D),  # nor nothing at all
        (f"{chr(0x0645)}{ZWNJ}", 0x200C),
        (f"{chr(0x1F642)}{ZWJ}{chr(0x0661)}", 0x200D),  # nor a digit
        (f"{chr(0x0645)}{ZWNJ}{chr(0x1F642)}", 0x200C),  # a non-joiner keeps letters apart
    ],
    ids=[
        "at the start",
        "after ascii",
        "after a space",
        "a run",
        "two joiners",
        "no keycap",
        "zwnj between ascii",
        "zwnj before an arabic digit",
        "after a digit",
        "after punctuation",
        "emoji selector after a letter",
        "emoji selector after punctuation",
        "zwj before ascii",
        "zwnj before ascii",
        "zwj at the end",
        "zwnj at the end",
        "zwj before a digit",
        "zwnj before an emoji",
    ],
)
def test_joiners_and_selectors_out_of_place_are_found(text: str, code: int) -> None:
    [found] = hidden_in(text)

    assert found.startswith(f"U+{code:04X}")
    assert found.endswith("out of place")


@given(st.text(st.characters(codec="utf-8", exclude_characters=sorted(HIDDEN)), max_size=50))
def test_a_text_of_ordinary_characters_has_none(text: str) -> None:
    allowed_invisible = {ZWJ, ZWNJ, *map(chr, range(0xFE00, 0xFE10))}
    if not allowed_invisible & set(text):
        assert hidden_in(text) == ()


@given(st.text(), st.sampled_from(sorted(HIDDEN)), st.text())
def test_any_of_them_is_found_wherever_it_sits(before: str, character: str, after: str) -> None:
    assert f"U+{ord(character):04X}" in " ".join(hidden_in(before + character + after))


def test_many_keycap_candidates_are_checked_in_linear_time() -> None:
    started = time.monotonic()

    hidden_in(f"1{VS16}" * 200_000)

    assert time.monotonic() - started < 1
