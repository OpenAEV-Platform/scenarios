"""Scenario metadata (``scenario.yaml``) and its cross-checks against the export.

The schema checks each document on its own; the cross-checks compare it with facts of the
normalised export: the name and facets must be the export's, the declared injectors must be
those the injects use, and the declared platforms must include every platform an inject runs on
through an executor. The facts of each inject come from the platform's definition of its
contract, never from the copy the export carries. Whether a scenario is tabletop is derived,
never declared.
"""

import hashlib
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from scenario_tools.domain.shared.finding import Finding, Severity


def _text(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise ValueError(f"scenario.yaml does not follow its schema: {key} must be a string")
    return value


def _texts(document: Mapping[str, object], key: str) -> frozenset[str]:
    value = document.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"scenario.yaml does not follow its schema: {key} must list strings")
    return frozenset(value)


@dataclass(frozen=True)
class Requirements:
    openaev: str
    edition: str
    injectors: frozenset[str]
    executors: frozenset[str]


@dataclass(frozen=True)
class ScenarioMetadata:
    """The fields of ``scenario.yaml`` a check uses; the others are added with their rules."""

    external_id: str
    version: str
    status: str
    name: str
    severity: str
    category: str
    main_focus: str
    type: str
    platforms: frozenset[str]
    requires: Requirements

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> "ScenarioMetadata":
        """Read a document already valid against ``scenario.schema.json``."""
        requires = document.get("requires")
        if not isinstance(requires, Mapping):
            raise ValueError("scenario.yaml does not follow its schema: requires must be a mapping")
        return cls(
            external_id=_text(document, "external_id"),
            version=_text(document, "version"),
            status=_text(document, "status"),
            name=_text(document, "name"),
            severity=_text(document, "severity"),
            category=_text(document, "category"),
            main_focus=_text(document, "main_focus"),
            type=_text(document, "type"),
            platforms=_texts(document, "platforms"),
            requires=Requirements(
                openaev=_text(requires, "openaev"),
                edition=_text(requires, "edition"),
                injectors=_texts(requires, "injectors"),
                executors=_texts(requires, "executors"),
            ),
        )


@dataclass(frozen=True)
class InjectFacts:
    """What the cross-checks need from one inject: its contract's injector type, whether it
    needs an executor, and the platforms the contract targets."""

    injector_type: str
    needs_executor: bool
    platforms: frozenset[str]


@dataclass(frozen=True)
class ExportFacts:
    """What the cross-checks need from the normalised export: its name and facets, and the facts
    of each inject, taken from the platform's definition of its contract."""

    name: str
    severity: str
    category: str
    main_focus: str
    injects: tuple[InjectFacts, ...]


def is_tabletop(facts: ExportFacts, communication: frozenset[str]) -> bool:
    """True when every inject uses a communication injector and none needs an executor. A
    scenario without any inject, with an injector outside the list, or with an inject that runs
    through an executor is technical. Both conditions are checked, so neither fact decides
    alone."""
    return bool(facts.injects) and all(
        inject.injector_type in communication and not inject.needs_executor
        for inject in facts.injects
    )


def _names(values: frozenset[str]) -> str:
    return ", ".join(sorted(values))


def _differences(missing: frozenset[str], extra: frozenset[str]) -> str:
    parts = [f"missing: {_names(missing)}"] if missing else []
    if extra:
        parts.append(f"not used: {_names(extra)}")
    return "; ".join(parts)


def cross_check(metadata: ScenarioMetadata, facts: ExportFacts, path: str) -> tuple[Finding, ...]:
    """The blocking findings of the metadata at ``path`` against the facts of its export."""
    findings = [
        Finding(
            "SCH-002",
            Severity.BLOCKING,
            path,
            f"/{field}",
            f"{field} is {value!r} but {expected!r} in the export",
        )
        for field, value, expected in (
            ("name", metadata.name, facts.name),
            ("severity", metadata.severity, facts.severity),
            ("category", metadata.category, facts.category),
            ("main_focus", metadata.main_focus, facts.main_focus),
        )
        if value != expected
    ]
    used = frozenset(inject.injector_type for inject in facts.injects)
    declared = metadata.requires.injectors
    if declared != used:
        findings.append(
            Finding(
                "SCH-003",
                Severity.BLOCKING,
                path,
                "/requires/injectors",
                "requires.injectors must list the injector types of the injects; "
                + _differences(used - declared, declared - used),
            )
        )
    required = frozenset(
        platform
        for inject in facts.injects
        if inject.needs_executor
        for platform in inject.platforms
    )
    if not required <= metadata.platforms:
        findings.append(
            Finding(
                "SCH-004",
                Severity.BLOCKING,
                path,
                "/platforms",
                "platforms must include every platform an inject runs on through an executor; "
                f"missing: {_names(required - metadata.platforms)}",
            )
        )
    return tuple(findings)


# The bounds of scenario.schema.json that a starting scenario.yaml must respect, so that the
# file stays small and every value it holds is one the schema accepts.
DESCRIPTION_LIMIT = 2000
DESCRIPTION_FLOOR = 1000  # a cut keeps at least this much of the text
TRUNCATION_MARK = chr(0x2026)
_SENTENCE = re.compile(r"[.!?](?=\s)")  # where a sentence ends: after its mark, before a blank
NAME_LIMIT = 120
FACET_LIMIT = 64
INJECTORS_LIMIT = 50
SEVERITIES = ("low", "medium", "high", "critical")
PLATFORMS = (
    "Linux", "Windows", "MacOS", "Android", "iOS", "Container", "Service", "Generic", "Internal",
    "Unknown",
)  # fmt: skip

_DEFAULTS = (
    ("/version", "default 1.0.0: give this entry's version, the next one for a new version"),
    ("/status", "default VERIFIED: review it before the pull request"),
)
_REQUIRES_DEFAULTS = (
    (
        "/requires/openaev",
        "default: the platform version the built-in contracts were recorded on; give the "
        "oldest version the scenario works on",
    ),
    ("/requires/edition", "default CE: give EE if the scenario needs the Enterprise Edition"),
)
_THREAT = (
    "give at least one of threat.cves (CVE-YYYY-NNNN), threat.intrusion_sets (names) or "
    "threat.ttps (MITRE ATT&CK IDs such as T1595)"
)
_SOURCES = "give at least one public source: {url: https://…, tlp: TLP:CLEAR}"
_FIX_ON_THE_PLATFORM = (
    "fix it on the platform, export the scenario again and write it in scenario.yaml too"
)
_WHEN_YOU_CAN = (
    "fix it on the platform when you can, export the scenario again and write it in "
    "scenario.yaml too"
)


# Line breaks other than "\n", and the blanks that may end a line: a tab or a space (Zs).
_BREAKS = ("\r", chr(0x85), chr(0x2028), chr(0x2029))
_TRAILING = "".join(
    map(chr, (0x09, 0x20, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x202F, 0x205F, 0x3000))
)


@dataclass(frozen=True)
class Cleaned:
    """A text cleaned for ``scenario.yaml``, and what cleaning it changed, by counts only."""

    text: str
    breaks: int  # line breaks made a plain "\n"
    trimmed: int  # lines whose ending blanks were removed
    hard_breaks: int  # of them, Markdown hard breaks lost: two spaces or more, then a line
    outer: bool  # blank lines before or after the text removed

    @property
    def changed(self) -> bool:
        """Whether cleaning changed anything."""
        return bool(self.breaks or self.trimmed or self.outer)


def clean(text: str) -> Cleaned:
    """``text`` with every line break a plain ``\n``, no tab or space ending a line, and no
    blank line before or after it, so that it is written as a block a person can edit; the
    first line's indentation is kept, as it may open a Markdown list or code block. Cleaning
    twice changes nothing."""
    breaks = text.count("\r\n")
    plain = text.replace("\r\n", "\n")
    for other in _BREAKS:
        breaks += plain.count(other)
        plain = plain.replace(other, "\n")
    lines = plain.split("\n")
    kept = [line.rstrip(_TRAILING) for line in lines]
    trimmed = sum(1 for line, short in zip(lines, kept, strict=True) if line != short)
    # A hard break shows only between two lines of text.
    hard_breaks = sum(
        1 for index in range(len(lines) - 1)
        if lines[index].endswith("  ") and kept[index] and kept[index + 1]
    )  # fmt: skip
    joined = "\n".join(kept)
    cleaned = joined.strip("\n")
    return Cleaned(cleaned, breaks, trimmed, hard_breaks, cleaned != joined)


def _cuts(text: str) -> Iterator[tuple[str, Iterator[int]]]:
    """The places a text may be cut at, by kind, from the one a reader notices least: before a
    paragraph break, after the end of a sentence, before a blank."""
    yield "paragraph", (match.start() for match in re.finditer("\n\n", text))
    yield "sentence", (match.end() for match in _SENTENCE.finditer(text))
    yield "word", (match.start() for match in re.finditer(r"\s", text))


def bound(text: str) -> tuple[str, str]:
    """``text`` within ``DESCRIPTION_LIMIT``, and where it was cut: whole when it fits, else cut
    at its last place of the first kind that keeps between ``DESCRIPTION_FLOOR`` and one less
    than the limit, never where the kept text announces a list with a colon, and marked with
    ``TRUNCATION_MARK``; empty, and cut nowhere, when no such place exists: never cut in the
    middle of a word."""
    if len(text) <= DESCRIPTION_LIMIT:
        return text, ""
    reach = text[: DESCRIPTION_LIMIT + 1]  # no cut lies beyond it, however long the text
    for kind, places in _cuts(reach):
        kept = [reach[:place].rstrip() for place in places if place < DESCRIPTION_LIMIT]
        kept = [part for part in kept if len(part) >= DESCRIPTION_FLOOR and not part.endswith(":")]
        if kept:
            return kept[-1] + TRUNCATION_MARK, kind
    return "", ""


def _times(count: int, one: str, several: str) -> str:
    return f"{count} {one if count == 1 else several}"


def _cleaned_reason(cleaned: Cleaned) -> tuple[str, bool]:
    """What cleaning the export's description changed, by counts, never its text, and whether
    that asks for nothing."""
    changes = []
    if cleaned.breaks:
        changes.append(f"{_times(cleaned.breaks, 'line break', 'line breaks')} unified")
    if cleaned.trimmed:
        changes.append(f"{_times(cleaned.trimmed, 'line end', 'line ends')} trimmed")
    if cleaned.outer:
        changes.append("the blank lines around the text removed")
    reason = f"the export's description was cleaned for scenario.yaml: {', '.join(changes)}"
    if cleaned.hard_breaks:
        lost = _times(cleaned.hard_breaks, "Markdown hard break", "Markdown hard breaks")
        verb = "is" if cleaned.hard_breaks == 1 else "are"
        return f"{reason}; {lost} (two spaces ending a line) {verb} lost: check its layout", False
    return f"{reason}; nothing to do", True


def _bounded(value: str, limit: int, field: str) -> tuple[str, tuple[str, str] | None]:
    """The export's text for ``field``, or nothing and why, when the schema would refuse it; a
    text that would need cleaning is kept as it is, since it must equal the export's, and why
    it should be fixed is given."""
    if not value.strip():
        return "", (f"/{field}", f"the export has no {field}: {_FIX_ON_THE_PLATFORM}")
    if len(value) > limit:
        why = f"the export's {field} has {len(value)} characters, more than {limit}"
        return "", (f"/{field}", f"{why}: {_FIX_ON_THE_PLATFORM}")
    cleaned = clean(value)
    if cleaned.changed or value != value.strip():  # a name has no indentation to keep
        what = (
            "blanks around it" if value != value.strip()
            else "line breaks other than \\n" if cleaned.breaks
            else "blanks ending a line"
        )  # fmt: skip
        kept = "kept as it is, since it must equal the export's"
        return value, (f"/{field}", f"the export's {field} has {what}: {kept}; {_WHEN_YOU_CAN}")
    return value, None


def starting_metadata(
    facts: ExportFacts,
    *,
    external_id: str,
    description: str,
    platform_version: str,
    unknown_injects: int,
    path: str,
) -> tuple[dict[str, object], tuple[Finding, ...]]:
    """The ``scenario.yaml`` of a first preparation, in the order of the data model, and an
    ``SCH-007`` finding for each default to review and each field left for a contributor to
    complete. It takes what the export and the recorded contracts establish, so that it passes
    the cross-checks, and only values the schema accepts, so that the file stays small enough to
    read back: a description over its bound once cleaned is cut where a reader can tell and
    marked, or left empty when it cannot be; another text over its bound or a value outside its
    list is left empty; each is reported, never copied whole."""
    todo: dict[str, str] = dict(_DEFAULTS)
    asking_nothing: set[str] = set()  # the fields whose finding is said, and asks for nothing
    name, why_name = _bounded(facts.name, NAME_LIMIT, "name")
    cleaned = clean(description)
    digest = hashlib.sha256(description.encode()).hexdigest()
    description = cleaned.text
    if len(description) > DESCRIPTION_LIMIT:
        too_long = (
            f"the export's description has {len(description)} characters"
            f"{' once cleaned' if cleaned.changed else ''}, more than {DESCRIPTION_LIMIT} "
            f"(SHA-256 {digest})"
        )
        description, kind = bound(description)
        why = (
            f"{too_long}: cut at a {kind} end and marked {TRUNCATION_MARK}; review the cut, close "
            "any code block or link left open, remove the mark; scenario.json keeps the whole "
            "text"
            if kind
            else f"{too_long}, and no paragraph, sentence or word end between {DESCRIPTION_FLOOR} "
            f"and {DESCRIPTION_LIMIT - 1} characters to cut at: write a shorter one; "
            "scenario.json keeps the whole text"
        )
        why_description: tuple[str, str] | None = ("/description", why)
    elif not description.strip():
        why_description = ("/description", "write a description: the export has none")
        description = ""
    elif cleaned.changed:
        said, asks_nothing = _cleaned_reason(cleaned)
        why_description = ("/description", said)
        if asks_nothing:  # said, and no item of a checklist
            asking_nothing.add("/description")
    else:
        why_description = None
    severity = facts.severity if facts.severity in SEVERITIES else ""
    why_severity = (
        None
        if severity
        else ("/severity", f"the export's severity is not one of {', '.join(SEVERITIES)}: "
              f"{_FIX_ON_THE_PLATFORM}")
    )  # fmt: skip
    category, why_category = _bounded(facts.category, FACET_LIMIT, "category")
    main_focus, why_main_focus = _bounded(facts.main_focus, FACET_LIMIT, "main_focus")
    executors = [inject for inject in facts.injects if inject.needs_executor]
    required = {platform for inject in executors for platform in inject.platforms}
    platforms = sorted(required & set(PLATFORMS))
    unknown_platforms = len(required - set(PLATFORMS))
    for reason in (why_name, why_description, why_severity, why_category, why_main_focus):
        if reason is not None:
            todo[reason[0]] = reason[1]
    reasons: dict[str, list[str]] = {}
    if unknown_platforms:
        plural = "s" if unknown_platforms > 1 else ""
        reasons.setdefault("/platforms", []).append(
            f"{unknown_platforms} platform{plural} of the injects that run through an executor "
            f"{'are' if plural else 'is'} not among {', '.join(PLATFORMS)}: left out"
        )
    todo["/threat"] = _THREAT
    todo["/sources"] = _SOURCES
    todo.update(_REQUIRES_DEFAULTS)
    injectors = sorted({inject.injector_type for inject in facts.injects})
    if len(injectors) > INJECTORS_LIMIT:
        todo["/requires/injectors"] = (
            f"the injects use {len(injectors)} injector types, more than {INJECTORS_LIMIT}: "
            "list those the scenario needs"
        )
        injectors = []
    if unknown_injects:
        # Their facts are unknown: they may need an executor, on any platform.
        several = unknown_injects > 1
        unknown = (
            f"{unknown_injects} inject{'s use' if several else ' uses'} a contract that is not "
            "a recorded built-in one"
        )
        they = "they" if several else "it"
        todo["/requires/injectors"] = "; ".join(
            filter(
                None, (todo.get("/requires/injectors"), f"complete requires.injectors: {unknown}")
            )
        )
        reasons.setdefault("/platforms", []).append(
            f"check them: {unknown}, so the platforms {they} run on are unknown"
        )
        reasons.setdefault("/requires/executors", []).append(
            f"check them: {unknown}, so whether {they} need an executor is unknown"
        )
    if executors:
        where = ", ".join(platforms) or "platforms left out above"
        reasons.setdefault("/requires/executors", []).insert(
            0, f"injects run through an executor on {where}: name the executors they need"
        )
    todo.update({field: "; ".join(why) for field, why in reasons.items()})
    metadata: dict[str, object] = {
        "schema_version": 1,
        "external_id": external_id,
        "version": "1.0.0",
        "status": "VERIFIED",
        "name": name,
        "description": description,
        "severity": severity,
        "category": category,
        "main_focus": main_focus,
        "type": "time-based",
        "platforms": platforms or ["Generic"],
        "threat": {},
        "sources": [],
        "requires": {
            "openaev": f">={platform_version}",
            "edition": "CE",
            "injectors": injectors,
            "executors": [],
        },
        "payloads": [],
    }
    findings = tuple(
        Finding(
            "SCH-007", Severity.INFO, path, field, message, asks_nothing=field in asking_nothing
        )
        for field, message in todo.items()
    )
    return metadata, findings
