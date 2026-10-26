"""The changelog of an entry: one ## <version> — <date> section per version, newest first,
the first being the entry's version."""

import datetime
import itertools
import re
from collections.abc import Iterator

from scenario_tools.domain.shared.finding import Finding
from scenario_tools.domain.verification.entry_changes import VERSION_NUMBER, parsed_version
from scenario_tools.domain.verification.versioning import blocking

_HEADING = re.compile(  # a hyphen, an en dash or an em dash: they look alike
    rf"## {VERSION_NUMBER}\.{VERSION_NUMBER}\.{VERSION_NUMBER} "
    r"[-\u2013\u2014] ([0-9]{4})-([0-9]{2})-([0-9]{2})"
)
_LINES = re.compile(r"\r\n|\r|\n")  # Markdown's line endings, never the other breaks of Unicode
_FENCES = ("```", "~~~")


def _section(line: str) -> tuple[tuple[int, int, int], datetime.date] | None:
    match = _HEADING.fullmatch(line.rstrip(" \t"))
    if match is None:
        return None
    try:
        day = datetime.date(int(match[4]), int(match[5]), int(match[6]))
    except ValueError:
        return None
    return (int(match[1]), int(match[2]), int(match[3])), day


def _headings(text: str) -> Iterator[tuple[int, str]]:
    """The level-2 headings of a Markdown text, by line number, none in a fenced block. Read as
    a changelog writes them: an indented heading, a setext one or a fence closed by another
    kind of fence is read otherwise than Markdown renders it, and leaves a section unchecked."""
    fenced = False
    for number, line in enumerate(_LINES.split(text), 1):
        if line.startswith(_FENCES):
            fenced ^= True
        elif not fenced and line.startswith("## "):
            yield number, line


def changelog_findings(text: str | None, version: str, path: str) -> tuple[Finding, ...]:
    """What keeps ``CHANGELOG.md``, at ``path``, from holding one ``## <version> — <date>``
    section per version, newest first, the first being ``version``."""
    if text is None:
        return (
            blocking(
                "VER-004",
                path,
                "",
                "CHANGELOG.md is missing: add a `## <version> — <YYYY-MM-DD>` section for each "
                "version, newest first",
            ),
        )
    sections: list[tuple[int, tuple[int, int, int], datetime.date]] = []
    for number, line in _headings(text):
        section = _section(line)
        if section is None:
            return (
                blocking(
                    "VER-004",
                    path,
                    "",
                    f"line {number}: a level-2 heading opens a version's section, `## <version> — "
                    "<YYYY-MM-DD>` with a valid date; other headings take `###`",
                ),
            )
        sections.append((number, *section))
    if not sections:
        return (
            blocking(
                "VER-004",
                path,
                "",
                f"CHANGELOG.md has no section: add `## {version} — <YYYY-MM-DD>` for this version",
            ),
        )
    if sections[0][1] != parsed_version(version):
        return (
            blocking(
                "VER-004",
                path,
                "",
                f"the first section must be this version, {version}, newest first",
            ),
        )
    for (_, above, above_day), (number, below, below_day) in itertools.pairwise(sections):
        if below >= above:
            return (
                blocking(
                    "VER-004",
                    path,
                    "",
                    f"line {number}: each section's version is lower than the one above",
                ),
            )
        if below_day > above_day:
            return (
                blocking(
                    "VER-004",
                    path,
                    "",
                    f"line {number}: each section's date is no later than the one above",
                ),
            )
    return ()
