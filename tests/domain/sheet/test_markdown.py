"""Text a contributor wrote, shown in a sheet GitHub renders: plain text, never Markdown, HTML, a
link or an image; an address GitHub would link of itself is shown as code."""

import re
import time
from typing import Literal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from markdown_it import MarkdownIt

from scenario_tools.domain.sheet.markdown import inline, plain

PARSER = MarkdownIt("commonmark", {"html": True}).enable("table")
_LINKISH = re.compile(r"(?i)://|www\.|\S@\S+\.\S")


def _inline_tokens(markdown: str) -> list[tuple[str, str]]:
    """The kinds of the inline tokens of ``markdown``, and their text."""
    found = []
    for token in PARSER.parse(markdown):
        for child in token.children or []:
            found.append((child.type, child.content))
    return found


@pytest.mark.parametrize(
    ("text", "markdown"),
    [
        ("Active scanning", "Active scanning"),
        ("a*b_c [x](y) <b> `c` #1 & | ~", r"a\*b\_c \[x\]\(y\) \<b\> \`c\` \#1 \& \| \~"),
        ("two\nlines\tand a tab", "two lines and a tab"),
        ("see https://x.example/a.", "see `https://x.example/a.`"),
        ("www.example.com", "`www.example.com`"),
        ("mail a@corp.example now", "mail `a@corp.example` now"),
        ("0@0.@", "`0@0.@`"),  # found by the property below: an address's end is never trusted
        ("HTTP://X.EXAMPLE", "`HTTP://X.EXAMPLE`"),
        ("ftp://a`b", "``ftp://a`b``"),
        ("`https://x.example`", "`` `https://x.example` ``"),
        ("`https://x.example", "`` `https://x.example ``"),
        ("https://x.example`", "`` https://x.example` ``"),
        ("", ""),
        ("   leading and trailing  ", "leading and trailing"),
        ("a\u202eb\u200bc", "aU\\+202EbU\\+200Bc"),
        ("x\x00y", "xU\\+0000y"),
        ("a\u2800b\u3164c\u115fd\uffa0e", "aU\\+2800bU\\+3164cU\\+115FdU\\+FFA0e"),
    ],
)
def test_an_inline_text_is_escaped_and_an_address_is_code(text: str, markdown: str) -> None:
    assert inline(text) == markdown


def test_a_pipe_is_never_in_code_so_that_it_never_ends_a_table_cell() -> None:
    assert inline("a | https://x.example/a|b||c") == r"a \| `https://x.example/a`\|`b`\|\|`c`"


@pytest.mark.parametrize(
    ("text", "markdown"),
    [
        ("One line.", r"One line\."),
        ("First\nsecond", "First\\\nsecond"),
        ("Para one.\n\n\nPara two.", "Para one\\.\n\nPara two\\."),
        ("- item\n-  item two", "\\- item\\\n\\-  item two"),
        ("    indented\r\nCRLF\rCR", "indented\\\nCRLF\\\nCR"),
        (
            "# Title\n> quote\n1. one\n---\n***",
            "\\# Title\\\n\\> quote\\\n1\\. one\\\n\\-\\-\\-\\\n\\*\\*\\*",
        ),
        ("\n\n  \n", ""),
    ],
)
def test_a_text_keeps_its_lines_and_paragraphs_as_plain_text(text: str, markdown: str) -> None:
    """Each line as written, its line break kept, and a blank line between paragraphs."""
    assert plain(text) == markdown


_SURROGATES: tuple[Literal["Cs"]] = ("Cs",)  # never text on its own
_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=_SURROGATES)
    | st.sampled_from(list("<>[]()!*_`#|\\&@:/.w\n ")),
    max_size=80,
)


@settings(max_examples=400)
@given(_TEXT)
def test_no_text_becomes_markup_a_link_or_an_image(text: str) -> None:
    rendered = plain(text)
    blocks = {token.type for token in PARSER.parse(rendered)}

    assert blocks <= {"paragraph_open", "paragraph_close", "inline"}
    for kind, content in _inline_tokens(rendered):
        assert kind in {"text", "softbreak", "hardbreak", "code_inline"}, (kind, text)
        if kind == "text":
            assert not _LINKISH.search(content), (content, text)  # GitHub would link it
            assert all(char.isprintable() or char == " " for char in content), (content, text)


@settings(max_examples=300)
@given(_TEXT)
def test_a_cell_stays_one_cell_of_plain_text(text: str) -> None:
    table = f"| a | b |\n|---|---|\n| {inline(text)} | end |\n"
    tokens = PARSER.parse(table)

    cells = [token for token in tokens if token.type == "td_open"]
    assert len(cells) == 2
    for token in tokens:
        for child in token.children or []:
            assert child.type in {"text", "code_inline"}, (child.type, text)


@pytest.mark.parametrize("word", ["a" * 200_000, "a@" + "b" * 200_000, "x:" * 100_000])
def test_a_long_word_takes_linear_time(word: str) -> None:
    """A title of any length is read in linear time: a run never hangs on what a contributor
    wrote."""
    started = time.perf_counter()
    inline(word)
    assert time.perf_counter() - started < 1.0
