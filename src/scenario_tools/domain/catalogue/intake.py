"""Intake: a platform export and a request become an entry of the catalogue, unless the
catalogue shows the request is wrong, and a plan that a pull request is opened from.

The entry's identity is its ``external_id``: a new entry takes an identifier, a place and a
scenario name no entry has; an update keeps the entry's place and scenario name, a rename being
declared with ``rewrite``. The plan is the same for the same inputs, with no timestamp."""

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from scenario_tools.domain.shared.characters import visible
from scenario_tools.domain.shared.finding import Finding, Severity

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
        )

    @property
    def entry(self) -> str:
        """The entry's directory in the repository."""
        return f"scenarios/{self.domain}/{self.slug}"

    def metadata(self) -> dict[str, Any]:
        """The fields of ``scenario.yaml`` the request gives, for a new entry."""
        if self.mode != NEW:
            return {}
        given: dict[str, Any] = {"threat": dict(self.threat), "sources": list(self.sources)}
        if self.generated_by is not None:
            given["generated_by"] = self.generated_by
        return given


def same_name(first: str, second: str) -> bool:
    """Whether two scenario names are the same name for a reader: compared in their
    compatibility form, without case, invisible format characters, outer blanks or runs of
    blanks. Letters of other scripts that look alike stay apart."""

    def key(name: str) -> str:
        return " ".join(_visible(unicodedata.normalize("NFKC", name)).casefold().split())

    return key(first) == key(second)


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
        return refused("ITK-005", request_path, "/slug", message)
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
    named = sorted(entry.path for entry in entries if same_name(entry.name, name))
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
    """One item per file and field, a blocking one first, and none with nothing to do."""
    items: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        if finding.message.endswith("nothing to do"):
            continue
        key = (finding.path, finding.field)
        kept = items.get(key)
        if kept is None or (
            finding.severity is Severity.BLOCKING and kept.severity is not Severity.BLOCKING
        ):
            items[key] = finding
    return list(items.values())


def intake_plan(
    request: IntakeRequest,
    *,
    base: str,
    changed: bool,
    files: Mapping[str, str],
    checklist: Iterable[Finding],
) -> dict[str, Any]:
    """The plan of the pull request ``request`` leads to: from the commit ``base``, the files
    written (each path to its SHA-256), the title and a body that closes the request's issue and
    lists what is left to complete or review. Nothing in it depends on the time it is made."""
    verb = "add" if request.mode == NEW else "update"
    findings = _checklist(checklist)
    lines = [f"Closes #{request.issue}", ""]
    if changed:
        lines.append(f"Entry {_span(request.entry)}, from a platform export.")
    else:
        lines.append("The export gives the stored scenario.json again: nothing to propose.")
    left = [
        f"- [ ] {_span(finding.path)} {_span(finding.field)}: {_span(finding.message)}"
        for finding in findings
    ]
    if left:
        lines += ["", "Left to complete or review:", *left]
    if files:
        lines += [
            "",
            "Files:",
            *(f"- {_span(path)} {_span(files[path])}" for path in sorted(files)),
        ]
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
