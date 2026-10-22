"""Text a contributor wrote, shown in a sheet that GitHub renders: plain text, never Markdown, HTML,
a link or an image. Every ASCII punctuation character is escaped, which CommonMark allows for each
of them; a word GitHub would link of itself, an address with a scheme, a `www.` name or an e-mail
address, is shown as code instead, since GitHub links them even escaped. A command is shown as
code, never run as Markdown: in a span or a block whose fence no text of it can close."""

import re
import string

from scenario_tools.domain.shared.characters import HIDDEN

_ESCAPED = re.compile(f"([{re.escape(string.punctuation)}])")
# Linear on any word: what GitHub would link (a scheme's "://", "www.", an e-mail address).
_LINKED = re.compile(r"(?i)://|www\.|[^\s@]@[^\s@]+\.\S")
_WORDS = re.compile(r"(\s+)")
_TICKS = re.compile(r"`+")
_LINES = re.compile(r"\r\n|\r|\n")


def _code(word: str) -> str:
    """``word`` as a code span, its fence longer than any run of backticks in it."""
    fence = "`" * (max((len(run) for run in _TICKS.findall(word)), default=0) + 1)
    # A space is added on both sides when the text starts or ends with a backtick, or starts and
    # ends with a space: CommonMark strips one on each side of such a span.
    edges = word.startswith("`") or word.endswith("`")
    spaced = word.startswith(" ") and word.endswith(" ") and bool(word.strip())
    padded = f" {word} " if edges or spaced else word
    return fence + padded + fence


def _visible(word: str, *, tabs: bool = False) -> str:
    """A character no reader sees, a control, a filler or a bidirectional mark that would reorder
    the text around it, as its code point: ``U+202E``; a tab stays one when ``tabs`` is set."""
    return "".join(
        char
        if (tabs and char == "\t") or (char.isprintable() and char not in HIDDEN)
        else f"U+{ord(char):04X}"
        for char in word
    )


def _word(word: str) -> str:
    """A word without spaces, every character visible: escaped, or as code if GitHub would link
    it; a ``|`` stays out of code, where a table would still read it as the end of a cell."""
    word = _visible(word)
    if not _LINKED.search(word):
        return _ESCAPED.sub(r"\\\1", word)
    return r"\|".join(_code(part) if part else "" for part in word.split("|"))


def inline(text: str) -> str:
    """``text`` on one line, each of its spaces, line breaks and tabs as a space, none leading or
    trailing, so that it never starts a code block; fit for a table cell."""
    return "".join(
        " " * len(word) if index % 2 else _word(word)
        for index, word in enumerate(_WORDS.split(text.strip()))
    )


def plain(text: str) -> str:
    """``text`` as it is written: each of its lines on a line of its own, a blank line between
    its paragraphs, its leading and trailing spaces dropped so that none starts a code block."""
    paragraphs: list[list[str]] = [[]]
    for line in _LINES.split(text):
        if line.strip():
            paragraphs[-1].append(inline(line.strip()))
        elif paragraphs[-1]:
            paragraphs.append([])
    return "\n\n".join("\\\n".join(lines) for lines in paragraphs if lines)


def code(text: str) -> str:
    """``text`` on one line as a code span, every character visible, its fence longer than any
    run of backticks in it."""
    return _code(_visible(" ".join(_LINES.split(text))))


def block(text: str) -> str:
    """``text`` as a block of code, line by line, every character visible but its tabs, which a
    command runs with, between fences longer than any run of backticks in it, so that no line of
    it closes the block."""
    lines = [_visible(line, tabs=True) for line in _LINES.split(text.rstrip("\r\n"))]
    fence = "`" * max([3, *(len(run) + 1 for run in _TICKS.findall(text))])
    return "\n".join([fence, *lines, fence])
