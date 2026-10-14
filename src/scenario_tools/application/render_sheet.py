"""Render an entry's sheet, its README.md, and check the one it holds: the sheet is derived from
scenario.yaml and scenario.json, never edited by hand."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.policy.exceptions import PolicyException, exceptions_from_document
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.sheet.sheet import SHEET_LIMIT, render_sheet
from scenario_tools.ports.data import DataLoader
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError
from scenario_tools.ports.repository import EntrySource

SHEET = "README.md"
_UNREAD = (
    "the sheet cannot be rendered: scenario.yaml or scenario.json is missing or is not an object; "
    "validate says why"
)


def _stale(path: str, missing: bool) -> Finding:
    message = (
        "README.md is missing: write it with `scenario-tools render`, from scenario.yaml and "
        "scenario.json"
        if missing
        else "README.md is not the sheet scenario.yaml and scenario.json give: render it again "
        "with `scenario-tools render` rather than edit it"
    )
    return Finding("GEN-001", Severity.BLOCKING, path, "", message)


def _oversized(path: str) -> Finding:
    message = (
        "the sheet would be over the 1 MiB a README.md may hold: shorten the scenario's titles "
        "and texts"
    )
    return Finding("GEN-001", Severity.BLOCKING, path, "", message)


def sheet_findings(
    entry: str,
    names: frozenset[str],
    source: EntrySource,
    sheet: str,
    *,
    report_unreadable: bool = False,
) -> tuple[Finding, ...]:
    """``GEN-001`` when the entry's README.md is missing or is not ``sheet``, or when ``sheet`` is
    larger than a README.md may be; a README.md the readers refuse is reported when asked, which
    validate leaves to its check of the entry's texts."""
    path = f"{entry}/{SHEET}"
    if len(sheet.encode()) > SHEET_LIMIT:
        return (_oversized(path),)
    if SHEET not in names:
        return (_stale(path, missing=True),)
    try:
        held = source.read_text(path)
    except UnsafeInputError as error:
        refusal = Finding(error.code, Severity.BLOCKING, error.path, "", error.message)
        return (refusal,) if report_unreadable else ()
    return () if held == sheet else (_stale(path, missing=False),)


@dataclass(frozen=True)
class Sheet:
    """An entry's sheet, or the findings that keep it from being rendered, and the names of the
    files the entry holds."""

    text: str | None
    refusals: tuple[Finding, ...] = ()
    names: frozenset[str] = frozenset()


def sheet_of(entry: str, source: EntrySource, exceptions: Sequence[PolicyException]) -> Sheet:
    """The sheet of the entry at ``entry``, from its files as ``source`` reads them."""
    metadata_path = f"{entry}/scenario.yaml"
    try:
        names = source.names(entry)
        metadata: Any = source.read_yaml(metadata_path) if "scenario.yaml" in names else None
        stored: Any = (
            source.read_json(f"{entry}/scenario.json")[1] if "scenario.json" in names else None
        )
    except UnsafeInputError as error:
        return Sheet(None, (Finding(error.code, Severity.BLOCKING, error.path, "", error.message),))
    if not isinstance(metadata, Mapping) or not isinstance(stored, Mapping):
        return Sheet(None, (Finding("GEN-001", Severity.BLOCKING, metadata_path, "", _UNREAD),))
    text = render_sheet(metadata, stored, exceptions)
    if len(text.encode()) > SHEET_LIMIT:
        return Sheet(None, (_oversized(f"{entry}/{SHEET}"),), names)
    return Sheet(text, names=names)


def check_sheet(
    entry: str, source: EntrySource, exceptions: Sequence[PolicyException]
) -> tuple[Finding, ...]:
    """What ``render --check`` reports: why the sheet cannot be rendered, or ``GEN-001`` when the
    README.md the entry holds is not it."""
    sheet = sheet_of(entry, source, exceptions)
    if sheet.text is None:
        return sheet.refusals
    return sheet_findings(entry, sheet.names, source, sheet.text, report_unreadable=True)


def policy_exceptions(data: DataLoader) -> tuple[PolicyException, ...]:
    """The exceptions the maintainers grant, from the repository's data, which the sheet shows."""
    try:
        return exceptions_from_document(data.load("exceptions"))
    except (ValueError, UnsafeInputError) as error:  # the repository's data, not the entry's
        raise EnvironmentProblemError(f"policy data cannot be used: {error}") from error
