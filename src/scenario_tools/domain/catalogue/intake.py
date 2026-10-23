"""Intake: a platform export and a request become an entry of the catalogue, unless the
catalogue shows the request is wrong, and a plan that a pull request is opened from.

The entry's identity is its ``external_id``: a new entry takes an identifier, a place and a
scenario name no entry has; an update keeps the entry's place and scenario name, a rename being
declared with ``rewrite``. The plan is the same for the same inputs, with no timestamp."""

import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from scenario_tools.domain.shared.characters import visible
from scenario_tools.domain.shared.finding import REPORT_LIMIT, Finding, Severity

NEW, UPDATE = "new", "update"


@dataclass(frozen=True)
class CatalogueEntry:
    """An entry of the catalogue as intake compares it: its directory, its external ID and the
    scenario name its ``scenario.yaml`` declares; neither is known when it cannot be read."""

    path: str
    external_id: str
    name: str
    readable: bool = True


@dataclass(frozen=True)
class IntakeRequest:
    """A request already valid against ``intake-request.schema.json``."""

    mode: str
    external_id: str
    domain: str
    slug: str
    issue: int
    rewrite: bool = False
    threat: Mapping[str, Any] = field(default_factory=dict)
    sources: tuple[Any, ...] = ()
    generated_by: str | None = None
    # Catalogue facets for an export that has none, by the request's name of each.
    facets: Mapping[str, str] = field(default_factory=dict)
    # Hints about the payloads the export embeds, as the request gives them.
    claims: tuple[Mapping[str, Any], ...] = ()

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "IntakeRequest":
        return cls(
            mode=document["mode"],
            external_id=document["external_id"],
            domain=document["domain"],
            slug=document["slug"],
            issue=document["issue"],
            rewrite=document.get("rewrite", False),
            threat=document.get("threat", {}),
            sources=tuple(document.get("sources", ())),
            generated_by=document.get("generated_by"),
            facets={name: document[name] for name in FACETS if name in document},
            claims=tuple(document.get("payloads", ())),
        )

    @property
    def entry(self) -> str:
        """The entry's directory in the repository."""
        return f"scenarios/{self.domain}/{self.slug}"

    def metadata(self) -> dict[str, Any]:
        """The fields of ``scenario.yaml`` a request for a new entry gives."""
        given: dict[str, Any] = {"threat": dict(self.threat), "sources": list(self.sources)}
        if self.generated_by is not None:
            given["generated_by"] = self.generated_by
        return given


# The catalogue facets a request may give, each with the key of the export's information.
FACETS = {
    "severity": "scenario_severity",
    "category": "scenario_category",
    "main_focus": "scenario_main_focus",
}
_INFORMATION = "scenario_information"


def _held(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def completed_facets(
    export: object, given: Mapping[str, str], held: Mapping[str, object], path: str
) -> tuple[Any, tuple[Finding, ...]]:
    """``export``, a copy, with each catalogue facet its information lacks (absent, null or
    blank) taken from the request, ``given``, or else from the entry's stored scenario, ``held``,
    on an update, a facet the request gives changing the stored one; or nothing, and why, when
    a facet is given nowhere, or when the request gives another one than the export. The export
    holds what the platform imports: a facet written there reaches it and ``scenario.yaml``
    alike. An export without its information, or with a facet that is not text, is left to its
    own checks."""
    if not isinstance(export, Mapping):
        return export, ()
    information = export.get(_INFORMATION)
    if not isinstance(information, Mapping):
        return export, ()
    filled = dict(information)
    refused = []
    for name, key in FACETS.items():
        field = f"/{_INFORMATION}/{key}"
        value, asked = information.get(key), given.get(name)
        if value is not None and not isinstance(value, str):
            continue  # not a missing facet but a malformed one: its own check refuses it
        if _held(value):
            if asked is not None and asked != value:
                message = (
                    f"the request gives another {name} than the export: leave it out of the "
                    "request, or change it on the platform and export again"
                )
                refused.append(Finding("ITK-010", Severity.BLOCKING, path, field, message))
            continue
        fill = asked if asked is not None else held.get(key)
        if not _held(fill):
            message = (
                f"the export has no {name}: give it in the request ({name}), or set it on the "
                "platform and export again"
            )
            refused.append(Finding("ITK-010", Severity.BLOCKING, path, field, message))
            continue
        filled[key] = fill
    if refused:
        return None, tuple(refused)
    if filled == information:
        return export, ()
    return {**export, _INFORMATION: filled}, ()


def name_key(name: str) -> str:
    """What two scenario names that are the same name for a reader share: ``name`` in its
    compatibility form, without case, outer blanks or runs of blanks, without the hidden
    characters the checks find and without soft hyphens. Joiners where a script or emoji puts
    one stay, and letters of other scripts that look alike stay apart."""
    # What the hidden-character checks find, and a soft hyphen, which no reader sees; a joiner
    # where a script or emoji puts one stays, since it changes what is shown.
    shown = visible(unicodedata.normalize("NFKC", name)).replace(chr(0xAD), "")
    return " ".join(shown.casefold().split())


def same_name(first: str, second: str) -> bool:
    """Whether two scenario names are the same name for a reader (``name_key``)."""
    return name_key(first) == name_key(second)


def domain_refusals(
    request: IntakeRequest, domains: Iterable[str], request_path: str
) -> tuple[Finding, ...]:
    """An ``SCH-001`` finding when the request's domain is not one of the catalogue's."""
    domains = tuple(domains)
    if request.domain in domains:
        return ()
    message = f"{request.domain} is not one of {', '.join(domains)}"
    return (Finding("SCH-001", Severity.BLOCKING, request_path, "/domain", message),)


def intake_refusals(
    request: IntakeRequest,
    name: str,
    catalogue: Iterable[CatalogueEntry],
    *,
    request_path: str,
    export_path: str,
    place_taken: bool = False,
) -> tuple[Finding, ...]:
    """The ``ITK-*`` findings that refuse ``request``, given the export's scenario ``name``, the
    entries of the catalogue and whether anything is at the entry's place already; none when the
    request may proceed."""
    entries = tuple(catalogue)
    same = [entry for entry in entries if entry.external_id == request.external_id]

    def refused(code: str, path: str, pointer: str, message: str) -> tuple[Finding, ...]:
        return (Finding(code, Severity.BLOCKING, path, pointer, message),)

    unreadable = sorted(entry.path for entry in entries if not entry.readable)
    if unreadable:  # what it declares is not known, so neither is what is taken
        message = (
            f"the catalogue cannot be checked: {', '.join(unreadable)} cannot be read; "
            "fix it first, as validate says"
        )
        return refused("ITK-008", request_path, "", message)

    if request.mode == NEW:
        if same:
            where = ", ".join(sorted(entry.path for entry in same))
            return refused("ITK-001", request_path, "/external_id", f"an entry has it: {where}")
        if place_taken or any(entry.path == request.entry for entry in entries):
            return refused("ITK-002", request_path, "/slug", f"{request.entry} already exists")
        return _name_taken(name, entries, export_path)
    if not same:
        return refused("ITK-004", request_path, "/external_id", "no entry has it")
    if len(same) > 1:  # which entry the identifier names is not known
        where = ", ".join(sorted(entry.path for entry in same))
        message = f"several entries have it: {where}; give it to one only first"
        return refused("ITK-001", request_path, "/external_id", message)
    [entry] = same
    if entry.path != request.entry:
        message = f"the entry with this external_id is {entry.path}, not {request.entry}"
        in_domain = entry.path.rpartition("/")[0] == f"scenarios/{request.domain}"
        pointer = "/slug" if in_domain else "/domain"  # the field that differs
        return refused("ITK-005", request_path, pointer, message)
    if same_name(entry.name, name):
        return ()
    if not request.rewrite:
        message = (
            "the export's scenario name differs from the entry's: another scenario would take "
            "its identifier; declare rewrite: true if it is the same scenario renamed, then "
            "align scenario.yaml with the export by hand"
        )
        return refused("ITK-006", export_path, "", message)
    others = [other for other in entries if other.external_id != request.external_id]
    return _name_taken(name, others, export_path)


def _name_taken(
    name: str, entries: Iterable[CatalogueEntry], export_path: str
) -> tuple[Finding, ...]:
    """An ``ITK-003`` finding when one of ``entries`` has the scenario name ``name``."""
    if not name:  # normalisation refuses an export without a name, and says why
        return ()
    named = sorted(entry.path for entry in entries if entry.name and same_name(entry.name, name))
    if not named:
        return ()
    message = f"another entry has this scenario name: {', '.join(named)}"
    return (Finding("ITK-003", Severity.BLOCKING, export_path, "", message),)


# Every line terminator CommonMark or a browser may break a line at, and other controls.
_BREAKS = re.compile("[\\x00-\\x1f\\x7f-\\x9f" + chr(0x2028) + chr(0x2029) + "]+")


def _visible(text: str) -> str:
    """``text`` without what the checks find hidden in it, nor any invisible format character,
    bidirectional controls included."""
    return "".join(c for c in visible(text) if unicodedata.category(c) != "Cf")


def _span(text: str) -> str:
    """``text`` as inert Markdown: on one line, in a code span, with no invisible or
    bidirectional control, where no mention, link or HTML takes effect."""
    # Line breaks first, so that one the checks find hidden still parts the words around it.
    return "`" + _visible(_BREAKS.sub(" ", text)).replace("`", "'") + "`"


def _checklist(findings: Iterable[Finding]) -> list[Finding]:
    """Each finding once, in order: an informative one is dropped when it asks for nothing, or
    when a blocking one names the same file and field."""
    kept = [finding for finding in dict.fromkeys(findings) if not finding.asks_nothing]
    blocked = {(f.path, f.field) for f in kept if f.severity is Severity.BLOCKING}
    return [
        finding
        for finding in kept
        if finding.severity is Severity.BLOCKING or (finding.path, finding.field) not in blocked
    ]


# Characters the items of a body, what is left to do then its files, may take: GitHub takes
# 65,536 for a body, and the rest of it, the issue and the entry, takes far less than what is left.
BODY_ITEMS_LIMIT = 60_000


def intake_plan(
    request: IntakeRequest,
    *,
    base: str,
    changed: bool,
    files: Mapping[str, str],
    checklist: Iterable[Finding],
    changes: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """The plan of the pull request ``request`` leads to: from the commit ``base``, the files
    written (each path to its SHA-256), the title and a body that closes the request's issue and
    lists what is left to complete or review, then, for each new version of a payload, the
    fields that differ from its base, never a value. Nothing in it depends on the time it is
    made."""
    verb = "add" if request.mode == NEW else "update"
    findings = _checklist(checklist)
    lines = [f"Closes #{request.issue}", ""]
    if changed:
        lines.append(f"Entry {_span(request.entry)}, from a platform export.")
    else:
        lines.append("The export gives the stored scenario.json again: nothing to propose.")
    left: list[str] = []
    budget = BODY_ITEMS_LIMIT
    for finding in findings[:REPORT_LIMIT]:  # a body a pull request takes whole
        item = f"- [ ] {_span(finding.path)} {_span(finding.field)}: {_span(finding.message)}"
        budget -= len(item) + 1
        if budget < 0:
            break
        left.append(item)
    if left:
        lines += ["", "Left to complete or review:", *left]
    if len(findings) > len(left):
        more = len(findings) - len(left)
        lines.append(f"- and {more} more: run validate on the entry to see them all")
    changed_fields: list[str] = []
    for path, pointers in sorted((changes or {}).items()):  # what the checklist leaves
        item = f"- {_span(path)}: {', '.join(_span(pointer) for pointer in pointers)}"
        budget -= len(item) + 1
        if budget < 0:
            break
        changed_fields.append(item)
    if changed_fields:
        lines += ["", "Changed from the version each new version is based on:", *changed_fields]
    if changes and len(changes) > len(changed_fields):
        more = len(changes) - len(changed_fields)
        lines.append(f"- and {more} more: compare each new version's file with its base's")
    shown: list[str] = []
    for path in sorted(files):  # what the changes leave of the budget
        item = f"- {_span(path)} {_span(files[path])}"
        budget -= len(item) + 1
        if budget < 0:
            break
        shown.append(item)
    if files:
        lines += ["", "Files:", *shown]
    if len(files) > len(shown):
        lines.append(f"- and {len(files) - len(shown)} more: the plan's files list them all")
    return {  # in the order of its keys, as it is written
        "base": base,
        "blocking": sum(1 for finding in findings if finding.severity is Severity.BLOCKING),
        "body": "\n".join(lines) + "\n",
        "changed": changed,
        "entry": request.entry,
        "files": [{"path": path, "sha256": files[path]} for path in sorted(files)],
        "mode": request.mode,
        "title": f"feat(scenarios): {verb} {request.slug} (#{request.issue})",
    }
