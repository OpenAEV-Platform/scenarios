"""Scenario metadata (``scenario.yaml``) and its cross-checks against the export.

The schema checks each document on its own; the cross-checks compare it with facts of the
normalised export: the name and facets must be the export's, the declared injectors must be
those the injects use, and the declared platforms must include every platform an inject runs on
through an executor. The facts of each inject come from the platform's definition of its
contract, never from the copy the export carries. Whether a scenario is tabletop is derived,
never declared.
"""

from collections.abc import Mapping
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
NAME_LIMIT = 120
FACET_LIMIT = 64
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


def _bounded(value: str, limit: int, field: str) -> tuple[str, tuple[str, str] | None]:
    """The export's text for ``field``, or nothing and why, when the schema would refuse it."""
    if not value.strip():
        return "", (f"/{field}", f"the export has no {field}: {_FIX_ON_THE_PLATFORM}")
    if len(value) > limit:
        why = f"the export's {field} has {len(value)} characters, more than {limit}"
        return "", (f"/{field}", f"{why}: {_FIX_ON_THE_PLATFORM}")
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
    ``SCH-007`` finding for each default to review and each field left for a person or an agent
    to complete. It takes what the export and the recorded contracts
    establish, so that it passes the cross-checks, and only values the schema accepts: a text
    over its bound or a value outside its list is left empty and reported, never copied whole,
    so that the file stays small enough to read back."""
    todo: dict[str, str] = dict(_DEFAULTS)
    name, why_name = _bounded(facts.name, NAME_LIMIT, "name")
    if description.strip() and len(description) > DESCRIPTION_LIMIT:
        why_description: tuple[str, str] | None = (
            "/description",
            f"the export's description has {len(description)} characters, more than "
            f"{DESCRIPTION_LIMIT}: write a shorter one",
        )
        description = ""
    elif not description.strip():
        why_description = ("/description", "write a description: the export has none")
        description = ""
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
    if unknown_injects:
        # Their facts are unknown: they may need an executor, on any platform.
        several = unknown_injects > 1
        unknown = (
            f"{unknown_injects} inject{'s use' if several else ' uses'} a contract that is not "
            "a recorded built-in one"
        )
        they = "they" if several else "it"
        todo["/requires/injectors"] = f"complete requires.injectors: {unknown}"
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
            "injectors": sorted({inject.injector_type for inject in facts.injects}),
            "executors": [],
        },
        "payloads": [],
    }
    findings = tuple(
        Finding("SCH-007", Severity.INFO, path, *todo_item) for todo_item in todo.items()
    )
    return metadata, findings
