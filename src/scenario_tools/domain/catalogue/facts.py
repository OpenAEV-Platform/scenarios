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
from scenario_tools.domain.catalogue.structure import (
    CONTRACT,
    INFORMATION,
    INJECTS,
    PAYLOAD,
    not_an_export,
    require_object,
    require_text,
)
from scenario_tools.domain.shared.canonical import ContentHash
from scenario_tools.domain.shared.finding import Finding, Severity

_SHA256 = re.compile(r"[0-9a-f]{64}")
INJECTOR_TYPE_LIMIT = 64  # characters, as the schema says for requires.injectors
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_IMPLANT = "openaev_implant"
_FACETS = ("scenario_name", "scenario_severity", "scenario_category", "scenario_main_focus")


@dataclass(frozen=True)
class BuiltinContracts:
    """The built-in contracts the catalogue uses, as recorded on a given platform version."""

    platform_version: str
    contracts: Mapping[str, InjectFacts]
    # The SHA-256 of the canonical form of each contract's normalised copy, as the platform
    # exports it: an instance that lacks the contract builds it from the copy.
    copies: Mapping[str, str]

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
        if not _VERSION.fullmatch(version):  # it starts the requires.openaev of new entries
            raise fail("platform_version must be a version such as 3.261005.0")
        items = document.get("contracts")
        if not isinstance(items, list):
            raise fail("contracts must be a list")
        contracts: dict[str, InjectFacts] = {}
        copies: dict[str, str] = {}
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
            digest = item.get("copy_sha256")
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise fail(f"{identifier}: copy_sha256 must be a SHA-256 hex digest")
            injector_type = text(item, "injector_type")
            if len(injector_type) > INJECTOR_TYPE_LIMIT:  # it goes into requires.injectors
                raise fail(f"injector_type must be at most {INJECTOR_TYPE_LIMIT} characters")
            contracts[identifier] = InjectFacts(injector_type, needs_executor, frozenset(platforms))
            copies[identifier] = digest
        return cls(version, MappingProxyType(contracts), MappingProxyType(copies))

    @property
    def identifiers(self) -> tuple[str, ...]:
        """The identifiers of the recorded contracts, in the order of the data."""
        return tuple(self.contracts)

    def facts(self, identifier: str) -> InjectFacts | None:
        """The recorded facts of the contract, or ``None`` when it is not recorded."""
        return self.contracts.get(identifier)


def _payload_facts(payload: object) -> InjectFacts:
    platforms = require_object(payload, PAYLOAD).get("payload_platforms")
    # A payload on no platform would need an executor without requiring any platform.
    if (
        not isinstance(platforms, list)
        or not platforms
        or not all(isinstance(item, str) and item for item in platforms)
    ):
        raise not_an_export(f"{PAYLOAD}.payload_platforms must name at least one platform")
    return InjectFacts(_IMPLANT, True, frozenset(platforms))


def _inject_facts(inject: object, builtin: BuiltinContracts) -> InjectFacts | None:
    value = require_object(inject, INJECTS).get(CONTRACT)
    if value is None:
        return None
    contract = require_object(value, CONTRACT)
    payload = contract.get(PAYLOAD)
    if payload not in (None, {}):  # an empty object counts as no payload, as in normalisation
        return _payload_facts(payload)
    return builtin.facts(require_text(contract, "injector_contract_id", CONTRACT))


def export_facts(
    document: object, builtin: BuiltinContracts, path: str
) -> tuple[ExportFacts, tuple[Finding, ...]]:
    """The facts of a stored scenario, and an ``SCH-005`` finding for each inject whose facts
    cannot be established; such an inject is left out of the facts."""
    export = require_object(document, "the export")
    information = require_object(export.get(INFORMATION), INFORMATION)
    name, severity, category, main_focus = (
        require_text(information, facet, INFORMATION) for facet in _FACETS
    )
    injects = export.get(INJECTS)
    if not isinstance(injects, list):
        raise not_an_export(f"{INJECTS} must be a list")
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
                    f"/{INJECTS}/{index}",
                    "the inject's contract is neither a recorded built-in contract nor created "
                    "from a payload: its injector type, executor need and platforms cannot be "
                    "established",
                )
            )
        else:
            known.append(facts)
    return ExportFacts(name, severity, category, main_focus, tuple(known)), tuple(findings)


def copy_findings(document: object, builtin: BuiltinContracts, path: str) -> tuple[Finding, ...]:
    """An ``SCH-006`` finding for each inject whose recorded built-in contract carries a copy
    other than the recorded one: an instance that lacks the contract would build it from the
    copy, its domains and attack patterns included."""
    injects = require_object(document, "the export").get(INJECTS)
    if not isinstance(injects, list):
        raise not_an_export(f"{INJECTS} must be a list")
    findings = []
    for index, inject in enumerate(injects):
        contract = require_object(inject, INJECTS).get(CONTRACT)
        if contract is None:
            continue
        contract_copy = require_object(contract, CONTRACT)
        recorded = builtin.copies.get(str(contract_copy.get("injector_contract_id")))
        if recorded is not None and ContentHash.of_json(contract_copy).hex != recorded:
            findings.append(
                Finding(
                    "SCH-006",
                    Severity.BLOCKING,
                    path,
                    f"/{INJECTS}/{index}",
                    "the copy of this built-in contract is not the recorded one: an instance "
                    "that lacks the contract would build it from this copy; normalise a fresh "
                    "export, or update its recorded digest if the platform changed the contract",
                )
            )
    return tuple(findings)
