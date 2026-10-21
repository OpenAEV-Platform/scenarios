"""Normalisation of the starter-pack exports: no trace of the instance, the same bytes every run."""

import copy
import json
import random
import re
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader, read_export
from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.domain.catalogue.normalisation import NormalisationRules
from scenario_tools.domain.shared.workflow import ExportKeys

ROOT = Path(__file__).parents[2]
EXPORTS = ROOT / "tests" / "golden" / "exports"
NORMALISED = ROOT / "tests" / "golden" / "normalised"
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
# Fields that hold an identifier of the instance the export comes from.
_INSTANCE_KEYS = re.compile(
    r"(scenario|inject|team|variable|tag|document|channel|article|challenge|organization"
    r"|payload|attack_pattern|phase|domain)_id"
    r"|injector_contract_(injectors|domains)"
    r"|(injector_contract_)?payload_author(_organization|_user|_team)?"
)
_COLLECTIONS = (
    "scenario_injects", "scenario_teams", "scenario_variables", "scenario_tags",
    "scenario_documents", "scenario_channels", "scenario_articles", "scenario_challenges",
    "scenario_organizations",
)  # fmt: skip
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _rules() -> NormalisationRules:
    data = YamlDataLoader(ROOT / "policy" / "data")
    return NormalisationRules.from_document(
        data.load("volatile-fields"), ExportKeys.from_document(data.load("export-keys"))
    )


def _normalise(document: Any, previous: Any = None) -> bytes:
    data = YamlDataLoader(ROOT / "policy" / "data")
    return prepare_entry(document, ENTRY_ID, data, path="export", previous=previous).scenario_json


def _prepare(export: Path) -> bytes:
    return _normalise(read_export(export))


def _shuffle(value: Any, keys: frozenset[str], shuffler: random.Random) -> None:
    """Every list whose order carries no meaning shuffled, at any depth."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key in keys and isinstance(child, list):
                shuffler.shuffle(child)
            _shuffle(child, keys, shuffler)
    elif isinstance(value, list):
        for child in value:
            _shuffle(child, keys, shuffler)


def _instance_identifiers(value: Any) -> set[str]:
    """Identifiers of the source instance: in identifier fields, in identifier lists, and as
    object keys."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if _UUID.fullmatch(key):
                found.add(key)
            if _INSTANCE_KEYS.fullmatch(key):
                items = child if isinstance(child, list) else [child]
                found |= {item for item in items if isinstance(item, str)}
            found |= _instance_identifiers(child)
    elif isinstance(value, list):
        for child in value:
            found |= _instance_identifiers(child)
    return found


@pytest.mark.parametrize("export", sorted(EXPORTS.glob("*.zip")), ids=lambda path: path.stem)
def test_a_starter_pack_export_normalises_to_its_reviewed_form(export: Path) -> None:
    assert _prepare(export) == (NORMALISED / f"{export.stem}.json").read_bytes()


@pytest.mark.parametrize("export", sorted(EXPORTS.glob("*.zip")), ids=lambda path: path.stem)
def test_no_identifier_of_the_source_instance_is_left(export: Path) -> None:
    identifiers = _instance_identifiers(read_export(export))
    text = _prepare(export).decode()

    assert identifiers
    assert sorted(identifier for identifier in identifiers if identifier in text) == []


@pytest.mark.parametrize("seed", range(5))
@pytest.mark.parametrize("export", sorted(EXPORTS.glob("*.zip")), ids=lambda path: path.stem)
def test_the_order_of_the_export_does_not_change_the_bytes(export: Path, seed: int) -> None:
    shuffled = copy.deepcopy(read_export(export))
    _shuffle(shuffled, _rules().sorted_lists | set(_COLLECTIONS), random.Random(seed))  # noqa: S311 (test shuffling)

    assert _normalise(shuffled) == _prepare(export)


@pytest.mark.parametrize("export", sorted(EXPORTS.glob("*.zip")), ids=lambda path: path.stem)
def test_a_stored_form_normalised_with_itself_gives_the_same_bytes(export: Path) -> None:
    stored = json.loads(_prepare(export))

    assert _normalise(copy.deepcopy(stored), previous=stored) == _prepare(export)


_AUTHORS = (
    ("injector_contract_payload_author_user", "injector_contract_payload_author_team"),
    ("payload_author_user", "payload_author_team", "payload_author_organization"),
)


def test_payload_authors_are_removed() -> None:
    export = copy.deepcopy(read_export(EXPORTS / "salt-typhoon-cve-ttps-validation.zip"))
    for inject in export["scenario_injects"]:
        contract = inject["inject_injector_contract"]
        if contract.get("injector_contract_payload"):
            for number, key in enumerate(_AUTHORS[0]):
                contract[key] = f"30000000-0000-4000-8000-{number:012x}"
            for number, key in enumerate(_AUTHORS[1]):
                contract["injector_contract_payload"][key] = (
                    f"40000000-0000-4000-8000-{number:012x}"
                )
            contract["injector_contract_payload"]["payload_collector_type"] = "internal-collector"

    text = _normalise(export).decode()

    assert [key for keys in _AUTHORS for key in keys if f'"{key}"' in text] == []
    assert '"payload_collector_type"' not in text


def test_the_reviewed_forms_are_stored_forms() -> None:
    for path in sorted(NORMALISED.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        assert text.endswith("}\n")
        assert (
            json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            == text
        )


def _volatile_keys(value: Any, rules: NormalisationRules) -> set[str]:
    """Volatile fields left anywhere, inside the JSON text of contract copies too."""
    if isinstance(value, dict):
        found = {
            key for key in value if key in rules.removed or key.endswith(rules.removed_suffixes)
        }
        for key, child in value.items():
            if key == "injector_contract_content" and isinstance(child, str):
                child = json.loads(child)
            found |= _volatile_keys(child, rules)
        return found
    if isinstance(value, list):
        return {key for child in value for key in _volatile_keys(child, rules)}
    return set()


@pytest.mark.parametrize("export", sorted(EXPORTS.glob("*.zip")), ids=lambda path: path.stem)
def test_no_volatile_field_is_left_even_inside_contract_copies(export: Path) -> None:
    rules = _rules()

    assert _volatile_keys(read_export(export), rules)
    assert _volatile_keys(json.loads(_prepare(export)), rules) == set()


# Lists that are sets: the platform serialises several of them in varying orders.
_SETS = (
    "injector_contract_tags", "domains", "expectation_expected_security_platform_types",
    "contract_attack_patterns_external_ids", "contract_vulnerability_external_ids",
    "injector_contract_vulnerabilities", "injector_contract_providing", "payload_expectations",
    "payload_platforms", "payload_detection_remediations", "payload_output_parsers", "platforms",
    "labels", "mandatoryGroups", "availableExpectations", "predefinedExpectations",
)  # fmt: skip
# Lists whose order carries meaning: a form, a choice, or what the author ordered.
_ORDERED = (
    "fields", "children", "choices", "conditions", "variables", "target_selector",
    "expectations", "payload_arguments", "payload_prerequisites", "outputs",
)  # fmt: skip


@pytest.mark.parametrize("key", _SETS)
def test_these_lists_are_sets(key: str) -> None:
    assert key in _rules().sorted_lists


@pytest.mark.parametrize("key", _ORDERED)
def test_these_lists_keep_their_order(key: str) -> None:
    assert key not in _rules().sorted_lists


def test_an_export_from_an_instance_that_linked_techniques_gives_the_reviewed_form() -> None:
    # The same platform version, once its MITRE collector ran, links techniques to the built-in
    # contracts: their copies in a later export carry them, and the stored file must not change.
    export = read_export(EXPORTS / "easm-scenario.zip")
    for inject in export["scenario_injects"]:
        inject["inject_injector_contract"]["injector_contract_attack_patterns"] = [
            {
                "attack_pattern_id": "a443a0ba-2bf3-5328-8d32-578372eb6a16",
                "attack_pattern_external_id": "T1595.002",
                "attack_pattern_name": "Vulnerability Scanning",
                "attack_pattern_kill_chain_phases": [],
            }
        ]

    assert _normalise(export) == (NORMALISED / "easm-scenario.json").read_bytes()
