"""Scenario metadata (``scenario.yaml``) and its cross-checks against the export.

The schema checks each document on its own; the cross-checks compare it with facts taken from
the normalised export: the name and facets must be the export's, the declared injectors must be
those the injects use, and the declared platforms must include every platform an inject runs on
through an executor. Whether a scenario is tabletop is derived, never declared.
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
    """What the cross-checks need from the normalised export."""

    name: str
    severity: str
    category: str
    main_focus: str
    injects: tuple[InjectFacts, ...]


def is_tabletop(facts: ExportFacts, communication: frozenset[str]) -> bool:
    """True when every inject uses a communication injector; a scenario without any inject, or
    with an injector outside the list, is technical."""
    return bool(facts.injects) and all(
        inject.injector_type in communication for inject in facts.injects
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
