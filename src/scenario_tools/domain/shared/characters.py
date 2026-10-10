"""Characters that hide text from a reviewer or change the order it is shown in.

A bidirectional control can make a command read differently from what runs ("Trojan Source"),
and a zero-width, tag or reserved invisible character can carry text no one sees. The list is
closed and shared by every check, so that the cleaning of a text and the refusal of a
contribution never drift apart. Tab and line breaks are allowed. The joiners and variation
selectors that scripts and emoji need (U+200C, U+200D, U+FE00 to U+FE0F) are allowed where
text uses them, after a letter, a mark or a symbol (the presentation selectors after an emoji
only), never at the start of a text, after ASCII or a space, nor as a run, where they could
carry hidden data.
"""

import unicodedata
from dataclasses import dataclass

_RANGES = (
    (0x0000, 0x0008), (0x000B, 0x000C), (0x000E, 0x001F), (0x007F, 0x0084), (0x0086, 0x009F),
    (0x061C, 0x061C), (0x180E, 0x180E), (0x200B, 0x200B), (0x200E, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)  # fmt: skip
HIDDEN = frozenset(chr(code) for first, last in _RANGES for code in range(first, last + 1))
JOINERS = frozenset((chr(0x200C), chr(0x200D), *map(chr, range(0xFE00, 0xFE10))))
_ZWNJ, _ZWJ, _VS16, _KEYCAP = chr(0x200C), chr(0x200D), chr(0xFE0F), chr(0x20E3)
_PRESENTATION = frozenset((chr(0xFE0E), _VS16))
# The emoji that are no symbol: a letter and punctuation marks Unicode draws as emoji too.
_EMOJI_NOT_SYMBOL = frozenset(map(chr, (0x203C, 0x2049, 0x2139, 0x3030, 0x303D)))
# Arabic letters: a Persian suffix may follow a foreign word after a ZWNJ.
_ARABIC = ((0x0600, 0x06FF), (0x0750, 0x077F), (0xFB50, 0xFDFF), (0xFE70, 0xFEFF))


@dataclass(frozen=True)
class Hidden:
    """One hidden character of a text: its label, how many times it appears, and where first."""

    label: str
    count: int
    first: int


def _label(character: str, misplaced: bool) -> str:
    code = f"U+{ord(character):04X}"
    name = unicodedata.name(character, "")
    label = f"{code} ({name})" if name else code
    return f"{label} out of place" if misplaced else label


def _misplaced(text: str, index: int) -> bool:
    """Whether the joiner or selector at ``index`` sits where no script or emoji puts one."""
    character = text[index]
    if index == 0:
        return True
    before = text[index - 1]
    if before in JOINERS:  # a run; only an emoji's VS16 may be followed by a ZWJ
        return not (before == _VS16 and character == _ZWJ)
    if before.isascii() or before.isspace():
        after = text[index + 1] if index + 1 < len(text) else ""
        keycap = character == _VS16 and before in "0123456789#*" and after == _KEYCAP
        suffix = character == _ZWNJ and before.isalpha() and _is_arabic(after)
        return not (keycap or suffix)
    category = unicodedata.category(before)[0]
    if character in _PRESENTATION:  # text or emoji presentation: only after an emoji
        return category != "S" and before not in _EMOJI_NOT_SYMBOL
    # Scripts and emoji put the others after a letter, a mark (a virama) or a symbol (an
    # emoji), never after a digit or a punctuation mark.
    return category not in "LMS"


def _is_arabic(character: str) -> bool:
    """Whether ``character`` is an Arabic letter, not a digit or a punctuation mark."""
    return character.isalpha() and any(first <= ord(character) <= last for first, last in _ARABIC)


def hidden_occurrences(text: str) -> tuple[Hidden, ...]:
    """The hidden characters of ``text``, each once, in the order they first appear, with their
    count and the offset of the first; never the text around them."""
    found: dict[str, list[int]] = {}
    for index, character in enumerate(text):
        if character in HIDDEN:
            label = _label(character, misplaced=False)
        elif character in JOINERS and _misplaced(text, index):
            label = _label(character, misplaced=True)
        else:
            continue
        found.setdefault(label, [0, index])[0] += 1
    return tuple(Hidden(label, count, first) for label, (count, first) in found.items())


def hidden_in(text: str) -> tuple[str, ...]:
    """The labels of the hidden characters of ``text``, in the order they first appear."""
    return tuple(hidden.label for hidden in hidden_occurrences(text))
