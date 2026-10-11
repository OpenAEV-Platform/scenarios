"""The starting scenario.yaml of the reference scenarios: valid but for what only a person or an
agent can give, and consistent with its export."""

import json
from pathlib import Path

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.safe_readers import YAML_LIMIT, yaml_bytes
from scenario_tools.application.prepare_entry import start_metadata
from scenario_tools.domain.catalogue.facts import (
    INJECTOR_TYPE_LIMIT,
    BuiltinContracts,
    export_facts,
)
from scenario_tools.domain.catalogue.metadata import (
    DESCRIPTION_LIMIT,
    FACET_LIMIT,
    INJECTORS_LIMIT,
    NAME_LIMIT,
    PLATFORMS,
    SEVERITIES,
    TRUNCATION_MARK,
    ScenarioMetadata,
    cross_check,
)

ROOT = Path(__file__).parents[2]
NORMALISED = ROOT / "tests" / "golden" / "normalised"
DATA = YamlDataLoader(ROOT / "policy" / "data")
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
PATH = "scenarios/x/y/scenario.yaml"
THREAT_AND_SOURCES = {
    "threat": {"ttps": ["T1595"]},
    "sources": [{"url": "https://example.com/", "tlp": "TLP:CLEAR"}],
}


@pytest.mark.parametrize("reference", sorted(NORMALISED.glob("*.json")), ids=lambda p: p.stem)
def test_a_starting_metadata_is_valid_once_threat_and_sources_are_given(reference: Path) -> None:
    document = json.loads(reference.read_bytes())

    metadata, findings = start_metadata(document, ENTRY_ID, DATA, path=PATH, source="export.zip")

    validator = JsonSchemaValidator(ROOT / "schemas")
    long = len(document["scenario_information"]["scenario_description"]) > DESCRIPTION_LIMIT
    to_complete = {"/threat", "/sources"}
    # Every value written is one the schema accepts; an empty one is left to complete, and a
    # description over its bound is cut, marked, and left to review.
    assert {v.pointer for v in validator.validate("scenario", metadata)} == to_complete
    assert to_complete | ({"/description"} if long else set()) <= {f.field for f in findings}
    assert str(metadata["description"]).endswith(TRUNCATION_MARK) is long
    assert len(yaml_bytes(metadata)) < YAML_LIMIT
    complete = {**metadata, **THREAT_AND_SOURCES, "description": "A scenario."}
    assert validator.validate("scenario", complete) == ()
    facts, _ = export_facts(
        document, BuiltinContracts.from_document(DATA.load("builtin-contracts")), PATH
    )
    assert cross_check(ScenarioMetadata.from_document(complete), facts, PATH) == ()


def test_the_reference_scenarios_start_with_their_injectors_and_platforms() -> None:
    def start(name: str) -> dict[str, object]:
        document = json.loads((NORMALISED / f"{name}.json").read_bytes())
        return start_metadata(document, ENTRY_ID, DATA, path=PATH, source="export.zip")[0]

    easm = start("easm-scenario")
    akira = start("tabletop-exercise-akira-ransomware-crisis")

    assert easm["platforms"] == ["Generic"]  # Nmap and Nuclei run from the platform
    assert easm["requires"] == {
        "openaev": ">=3.261005.0",
        "edition": "CE",
        "injectors": ["openaev_nmap", "openaev_nuclei"],
        "executors": [],
    }
    assert akira["requires"]["injectors"] == ["openaev_email"]  # type: ignore[index]


def test_an_export_without_description_starts_with_one_to_write() -> None:
    document = json.loads((NORMALISED / "easm-scenario.json").read_bytes())
    document["scenario_information"]["scenario_description"] = None

    metadata, findings = start_metadata(document, ENTRY_ID, DATA, path=PATH, source="export.zip")

    assert metadata["description"] == ""
    assert "/description" in {finding.field for finding in findings}


def test_the_bounds_of_the_starting_metadata_are_those_of_the_schema() -> None:
    properties = json.loads((ROOT / "schemas" / "scenario.schema.json").read_text())["properties"]

    assert properties["description"]["maxLength"] == DESCRIPTION_LIMIT
    assert properties["name"]["maxLength"] == NAME_LIMIT
    assert properties["category"]["maxLength"] == FACET_LIMIT
    assert properties["main_focus"]["maxLength"] == FACET_LIMIT
    assert tuple(properties["severity"]["enum"]) == SEVERITIES
    assert tuple(properties["platforms"]["items"]["enum"]) == PLATFORMS
    injectors = properties["requires"]["properties"]["injectors"]
    assert (injectors["maxItems"], injectors["items"]["maxLength"]) == (
        INJECTORS_LIMIT,
        INJECTOR_TYPE_LIMIT,
    )
