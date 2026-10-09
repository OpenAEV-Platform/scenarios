"""Facts of the starter-pack scenarios, from the recorded built-in contracts and their payloads."""

import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.catalogue.facts import BuiltinContracts, export_facts
from scenario_tools.domain.catalogue.metadata import InjectFacts, is_tabletop

ROOT = Path(__file__).parents[2]
NORMALISED = ROOT / "tests" / "golden" / "normalised"
DATA = YamlDataLoader(ROOT / "policy" / "data")
BUILTIN = BuiltinContracts.from_document(DATA.load("builtin-contracts"))
COMMUNICATION = frozenset(DATA.load("tabletop-injectors")["injectors"])


REFERENCES = {
    "easm-scenario": ({"openaev_nmap", "openaev_nuclei"}, set(), False),
    "salt-typhoon-cve-ttps-validation": ({"openaev_implant", "openaev_nuclei"}, {"Windows"}, False),
    "tabletop-exercise-akira-ransomware-crisis": ({"openaev_email"}, set(), True),
}


def _builtin_contracts(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The contract copies of the injects that use a built-in contract."""
    return [
        contract
        for inject in document["scenario_injects"]
        if (contract := inject.get("inject_injector_contract"))
        and not contract.get("injector_contract_payload")
    ]


def _load(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((NORMALISED / f"{name}.json").read_bytes())
    return document


def test_every_reference_is_listed() -> None:
    assert set(REFERENCES) == {path.stem for path in NORMALISED.glob("*.json")}


@pytest.mark.parametrize("name", sorted(REFERENCES))
def test_every_inject_of_a_reference_has_facts(name: str) -> None:
    injector_types, executor_platforms, tabletop = REFERENCES[name]
    document = _load(name)

    facts, findings = export_facts(document, BUILTIN, f"{name}.json")

    assert findings == ()
    assert len(facts.injects) == len(document["scenario_injects"])
    assert {inject.injector_type for inject in facts.injects} == injector_types
    assert {
        platform
        for inject in facts.injects
        if inject.needs_executor
        for platform in inject.platforms
    } == executor_platforms
    assert is_tabletop(facts, COMMUNICATION) is tabletop


@pytest.mark.parametrize("name", sorted(REFERENCES))
def test_recorded_facts_agree_with_the_platform_s_copies_in_the_references(name: str) -> None:
    # The references come from the platform itself, not from a contributor: a recording mistake
    # in the data shows here.
    for contract in _builtin_contracts(_load(name)):
        assert BUILTIN.facts(contract["injector_contract_id"]) == InjectFacts(
            contract["injector_contract_injector_type"],
            contract["injector_contract_needs_executor"],
            frozenset(contract["injector_contract_platforms"]),
        ), contract["injector_contract_id"]


def test_every_built_in_contract_of_the_references_is_recorded_in_order() -> None:
    used = {
        contract["injector_contract_id"]
        for name in REFERENCES
        for contract in _builtin_contracts(_load(name))
    }

    assert used <= set(BUILTIN.identifiers)
    assert list(BUILTIN.identifiers) == sorted(BUILTIN.identifiers)
