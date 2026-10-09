"""Facts of the injects for the cross-checks, from the platform's definition of each contract.

The copy of a contract the export carries is the contributor's, so it is never read for the
facts. A built-in contract has the same identifier on every instance: its facts are recorded,
as data, for the targeted platform version. A contract created from a payload runs the payload
through an implant, so it needs an executor, on the payload's platforms, of which it must name at
least one. The facts of any other contract cannot be established, which is a blocking finding.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from scenario_tools.domain.catalogue.metadata import ExportFacts, InjectFacts
from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.shared.finding import Finding, Severity

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_IMPLANT = "openaev_implant"
_INFORMATION, _INJECTS = "scenario_information", "scenario_injects"
_CONTRACT, _PAYLOAD = "inject_injector_contract", "injector_contract_payload"
_FACETS = ("scenario_name", "scenario_severity", "scenario_category", "scenario_main_focus")


@dataclass(frozen=True)
class BuiltinContracts:
    """The built-in contracts the catalogue uses, as recorded on a given platform version."""

    platform_version: str
    contracts: Mapping[str, InjectFacts]

    @classmethod
    def from_document(cls, document: object) -> "BuiltinContracts":
        """Read the builtin-contracts data document."""

        def fail(what: str) -> ValueError:
            return ValueError(f"builtin-contracts: {what}")

        def text(item: Mapping[str, Any], key: str) -> str:
            value = item.get(key)
            if not isinstance(value, str) or not value:
                raise fail(f"{key} must be non-empty text")
            return value

        if not isinstance(document, Mapping):
            raise fail("the document must be a mapping")
        version = text(document, "platform_version")
        items = document.get("contracts")
        if not isinstance(items, list):
            raise fail("contracts must be a list")
        contracts: dict[str, InjectFacts] = {}
        for item in items:
            if not isinstance(item, Mapping):
                raise fail("each contract must be a mapping")
            identifier = item.get("id")
            if not isinstance(identifier, str) or not _UUID.fullmatch(identifier):
                raise fail(f"{identifier!r} is not a lowercase canonical UUID")
            if identifier in contracts:
                raise fail(f"{identifier} is recorded twice")
            text(item, "name")
            needs_executor = item.get("needs_executor")
            if not isinstance(needs_executor, bool):
                raise fail(f"{identifier}: needs_executor must be a boolean")
            platforms = item.get("platforms")
            if not isinstance(platforms, list) or not all(
                isinstance(platform, str) and platform for platform in platforms
            ):
                raise fail(f"{identifier}: platforms must be a list of names")
            contracts[identifier] = InjectFacts(
                text(item, "injector_type"), needs_executor, frozenset(platforms)
            )
        return cls(version, MappingProxyType(contracts))

    @property
    def identifiers(self) -> tuple[str, ...]:
        """The identifiers of the recorded contracts, in the order of the data."""
        return tuple(self.contracts)

    def facts(self, identifier: str) -> InjectFacts | None:
        """The recorded facts of the contract, or ``None`` when it is not recorded."""
        return self.contracts.get(identifier)


def _refuse(what: str) -> ExportStructureError:
    error = ExportStructureError(f"not an OpenAEV scenario export: {what}")
    error.what = what
    return error


def _mapping(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _refuse(f"{where} must be an object")
    return value


def _text(item: Mapping[str, Any], key: str, where: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise _refuse(f"{where}.{key} must be text")
    return value


def _payload_facts(payload: object) -> InjectFacts:
    platforms = _mapping(payload, _PAYLOAD).get("payload_platforms")
    # A payload on no platform would need an executor without requiring any platform.
    if (
        not isinstance(platforms, list)
        or not platforms
        or not all(isinstance(item, str) and item for item in platforms)
    ):
        raise _refuse(f"{_PAYLOAD}.payload_platforms must name at least one platform")
    return InjectFacts(_IMPLANT, True, frozenset(platforms))


def _inject_facts(inject: object, builtin: BuiltinContracts) -> InjectFacts | None:
    value = _mapping(inject, _INJECTS).get(_CONTRACT)
    if value is None:
        return None
    contract = _mapping(value, _CONTRACT)
    payload = contract.get(_PAYLOAD)
    if payload not in (None, {}):  # an empty object counts as no payload, as in normalisation
        return _payload_facts(payload)
    return builtin.facts(_text(contract, "injector_contract_id", _CONTRACT))


def export_facts(
    document: object, builtin: BuiltinContracts, path: str
) -> tuple[ExportFacts, tuple[Finding, ...]]:
    """The facts of a stored scenario, and an ``SCH-005`` finding for each inject whose facts
    cannot be established; such an inject is left out of the facts."""
    export = _mapping(document, "the export")
    information = _mapping(export.get(_INFORMATION), _INFORMATION)
    name, severity, category, main_focus = (
        _text(information, facet, _INFORMATION) for facet in _FACETS
    )
    injects = export.get(_INJECTS)
    if not isinstance(injects, list):
        raise _refuse(f"{_INJECTS} must be a list")
    known: list[InjectFacts] = []
    findings: list[Finding] = []
    for index, inject in enumerate(injects):
        facts = _inject_facts(inject, builtin)
        if facts is None:
            findings.append(
                Finding(
                    "SCH-005",
                    Severity.BLOCKING,
                    path,
                    f"/{_INJECTS}/{index}",
                    "the inject's contract is neither a recorded built-in contract nor created "
                    "from a payload: its injector type, executor need and platforms cannot be "
                    "established",
                )
            )
        else:
            known.append(facts)
    return ExportFacts(name, severity, category, main_focus, tuple(known)), tuple(findings)
