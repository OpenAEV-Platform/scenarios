"""How a report is written out: as text or as JSON, with what contributors wrote made unable to
break a line or pass for a CI workflow command, and with the messages, then the paths and fields,
withheld wherever the output would show a secret, whole or cut short."""

import dataclasses
import json
from collections.abc import Callable

from scenario_tools.domain.shared.finding import (
    COUNT_CODE,
    MESSAGE_LIMIT,
    Finding,
    Report,
    Severity,
    shorten,
)


def printable(text: str) -> str:
    """Escape every non-printable character (control, line break, undecodable byte) as Python
    writes it in a string literal, so contributor content can neither break a line nor be read
    as a CI workflow command."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def finding_line(finding: Finding) -> str:
    where = " ".join(part for part in (finding.path, finding.field) if part)
    location = f" {where}" if where else ""
    return printable(f"{finding.severity.name} {finding.code}{location}: {finding.message}")


def report_text(report: Report) -> str:
    lines = [finding_line(finding) for finding in report.findings]
    if report.ok:
        return "\n".join([*lines, f"{report.command}: ok"])
    blocking = sum(finding.severity is Severity.BLOCKING for finding in report.findings)
    plural = "" if blocking == 1 else "s"
    return "\n".join([*lines, f"{report.command}: {blocking} blocking finding{plural}"])


WITHHELD = "withheld: it would show a secret"


def cut_in(text: str, hidden: str) -> bool:
    """Whether ``text`` was cut short in the middle of ``hidden``: it then ends with the start
    of it, before the ellipsis, as it is or as JSON writes it."""
    for ellipsis in ("…", "\\u2026"):
        if text.endswith(ellipsis):
            shown = text[: -len(ellipsis)]
            # No start longer than the text can end it: the work stays bounded by the text.
            longest = min(len(hidden), len(shown))
            return any(shown.endswith(hidden[:length]) for length in range(1, longest + 1))
    return False


def cut_in_any_form(text: str, hidden: str) -> bool:
    """Whether ``text``, as the text or the JSON output writes it, was cut short in the middle
    of ``hidden``: an escape can write the start of the token."""
    forms = (printable(text), json.dumps(text)[1:-1])
    return any(cut_in(form, hidden) for form in forms)


def concealed(
    message: str, render: Callable[[str], str], hidden: str, limit: int = MESSAGE_LIMIT
) -> str:
    """``message`` as ``render`` writes it, or withheld when that would show ``hidden``, or the
    start of it where the message is cut short to ``limit``. The token's characters are never
    escaped, so the token shows as it is or not at all."""
    output = render(message)
    if hidden and (
        hidden in output
        or cut_in(output, hidden)
        or cut_in_any_form(shorten(message, limit), hidden)
    ):
        return render(WITHHELD)
    return output


def rendered(report: Report, output_format: str) -> str:
    return json.dumps(report.document()) if output_format == "json" else report_text(report)


def shows(output: str, report: Report, hidden: str) -> bool:
    """Whether ``hidden`` shows in the output, or its start in a message, a path or a field cut
    short. The token's characters are never escaped, so the token shows as it is or not at all."""
    return hidden in output or any(
        cut_in_any_form(text, hidden)
        for finding in report.findings
        for text in (finding.message, finding.path, finding.field)
    )


def withheld_output(report: Report, output_format: str, hidden: str) -> str:
    """The output, with the messages, then the paths and fields, of the findings withheld while
    it would show ``hidden``: what then remains is the tool's own text, never the platform's.
    The finding that counts those a report does not show is the tool's own text, and stays."""
    output = rendered(report, output_format)
    for paths_too in (False, True):
        if not hidden or not shows(output, report, hidden):
            break

        def withheld(f: Finding, paths_too: bool = paths_too) -> Finding:
            if f.code == COUNT_CODE:
                return f
            if paths_too:
                return dataclasses.replace(f, message=WITHHELD, path="", field="")
            return dataclasses.replace(f, message=WITHHELD)

        report = report.with_findings(withheld)
        output = rendered(report, output_format)
    return output
