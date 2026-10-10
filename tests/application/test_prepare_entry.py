"""Preparing an entry: an export normalised with the rules kept as data."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

import scenario_tools.application.prepare_entry as prepare_entry_module
from scenario_tools.application.prepare_entry import prepare_entry, start_metadata
from scenario_tools.domain.catalogue.identifiers import scenario_namespace, stable_id
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

ROOT = Path(__file__).parents[2]
EXTERNAL_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
INJECT = "00000000-0000-4000-8000-000000000002"
BUILT_IN = "2790bd39-37d4-4e39-be7e-53f3ca783f86"  # a contract that ships with the platform
EXPORT: dict[str, Any] = {
    "scenario_information": {"scenario_id": "00000000-0000-4000-8000-000000000001"},
    "scenario_injects": [
        {
            "inject_id": INJECT,
            "inject_title": "Note",
            "inject_depends_on": [],
            "inject_injector_contract": {"injector_contract_id": BUILT_IN, "listened": True},
        }
    ],
}


class FakeData:
    def load(self, name: str) -> Any:
        assert name == "volatile-fields"
        return {
            "removed": ["listened"],
            "removed_suffixes": [],
            "sorted": [],
            "emptied_in_builtin_contracts": [],
        }


def test_an_export_becomes_the_stored_form_of_its_normalised_document() -> None:
    prepared = prepare_entry(EXPORT, EXTERNAL_ID, FakeData(), path="export.zip")
    document = json.loads(prepared.scenario_json)

    assert prepared.scenario_json.endswith(b"}\n")
    assert INJECT not in prepared.scenario_json.decode()
    assert "listened" not in json.dumps(document)
    assert prepared.removed_injects == ()


def test_injects_removed_since_the_previous_version_are_given() -> None:
    previous = json.loads(prepare_entry(EXPORT, EXTERNAL_ID, FakeData(), path="e").scenario_json)
    smaller = copy.deepcopy(EXPORT)
    smaller["scenario_injects"] = []

    prepared = prepare_entry(smaller, EXTERNAL_ID, FakeData(), path="e", previous=previous)

    assert prepared.removed_injects == (previous["scenario_injects"][0]["inject_id"],)


@pytest.mark.parametrize(
    ("export", "code"),
    [({"scenario_information": []}, "IO-014"), ("not an export", "IO-014")],
)
def test_a_refusal_names_its_code_and_the_export(export: Any, code: str) -> None:
    with pytest.raises(UnsafeInputError) as error:
        prepare_entry(export, EXTERNAL_ID, FakeData(), path="exports/a.zip")
    assert (error.value.code, error.value.path) == (code, "exports/a.zip")


def test_an_invalid_mapping_is_refused_with_its_code() -> None:
    with pytest.raises(UnsafeInputError) as error:
        prepare_entry(EXPORT, EXTERNAL_ID, FakeData(), path="e", mapping={"unknown": "x"})
    assert error.value.code == "VER-011"


def test_a_refusal_of_the_previous_version_names_its_file() -> None:
    with pytest.raises(UnsafeInputError) as error:
        prepare_entry(
            EXPORT, EXTERNAL_ID, FakeData(), path="e", previous=[], previous_path="p/scenario.json"
        )
    assert (error.value.code, error.value.path) == ("IO-014", "p/scenario.json")


def test_a_refused_mapping_names_its_file() -> None:
    with pytest.raises(UnsafeInputError) as error:
        prepare_entry(
            EXPORT, EXTERNAL_ID, FakeData(), path="e", mapping={"unknown": "x"}, mapping_path="m"
        )
    assert (error.value.code, error.value.path) == ("VER-011", "m")


def test_an_ambiguous_match_is_reported_on_the_export() -> None:
    twin = {"inject_title": "Note", "inject_injector_contract": {"injector_contract_id": BUILT_IN}}
    entry = stable_id(scenario_namespace(EXTERNAL_ID), "scenario", EXTERNAL_ID)
    previous = {
        "scenario_information": {"scenario_id": entry},
        "scenario_injects": [
            dict(twin, inject_id="00000000-0000-4000-8000-0000000000a1"),
            dict(twin, inject_id="00000000-0000-4000-8000-0000000000a2"),
        ],
    }

    with pytest.raises(UnsafeInputError) as error:
        prepare_entry(
            EXPORT, EXTERNAL_ID, FakeData(), path="e", previous=previous, mapping={},
            mapping_path="m",
        )  # fmt: skip
    assert (error.value.code, error.value.path) == ("VER-010", "e")


def test_a_normalised_form_above_the_limit_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    size = len(prepare_entry(EXPORT, EXTERNAL_ID, FakeData(), path="e").scenario_json)
    monkeypatch.setattr(prepare_entry_module, "MAX_STORED_SIZE", size - 1)

    with pytest.raises(UnsafeInputError) as error:
        prepare_entry(EXPORT, EXTERNAL_ID, FakeData(), path="exports/a.zip")
    assert (error.value.code, error.value.path) == ("IO-001", "exports/a.zip")


def test_a_normalised_form_at_the_limit_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    size = len(prepare_entry(EXPORT, EXTERNAL_ID, FakeData(), path="e").scenario_json)
    monkeypatch.setattr(prepare_entry_module, "MAX_STORED_SIZE", size)

    assert len(prepare_entry(EXPORT, EXTERNAL_ID, FakeData(), path="e").scenario_json) == size


def test_the_limit_of_a_normalised_form_is_that_of_a_json_input() -> None:
    assert prepare_entry_module.MAX_STORED_SIZE == 20 * 1024 * 1024


def test_malformed_policy_data_is_an_environment_problem() -> None:
    class BrokenData:
        def load(self, name: str) -> Any:
            return {
                "removed": 5,
                "removed_suffixes": [],
                "sorted": [],
                "emptied_in_builtin_contracts": [],
            }

    with pytest.raises(EnvironmentProblemError, match="volatile-fields"):
        prepare_entry(EXPORT, EXTERNAL_ID, BrokenData(), path="e")


def test_unreadable_policy_data_is_an_environment_problem() -> None:
    class UnreadableData:
        def load(self, name: str) -> Any:
            raise UnsafeInputError("IO-003", "not valid YAML", "policy/data/volatile-fields.yaml")

    with pytest.raises(EnvironmentProblemError, match="volatile-fields"):
        prepare_entry(EXPORT, EXTERNAL_ID, UnreadableData(), path="e")


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("builtin-contracts: contracts must be a list"),
        UnsafeInputError("IO-002", "x", "f"),
    ],
    ids=["malformed", "unreadable"],
)
def test_builtin_contracts_that_cannot_be_used_are_an_environment_problem(
    failure: Exception,
) -> None:
    class BrokenData:
        def load(self, name: str) -> Any:
            assert name == "builtin-contracts"
            if isinstance(failure, UnsafeInputError):
                raise failure
            return {"platform_version": "3.261005.0"}  # no contracts

    document = json.loads(prepare_entry(EXPORT, EXTERNAL_ID, FakeData(), path="e").scenario_json)

    with pytest.raises(EnvironmentProblemError, match="policy data"):
        start_metadata(document, EXTERNAL_ID, BrokenData(), path="scenario.yaml", source="e")


class RepositoryData:
    """The repository's own policy data, for the starting metadata."""

    def load(self, name: str) -> Any:
        from scenario_tools.adapters.data_files import YamlDataLoader

        return YamlDataLoader(ROOT / "policy" / "data").load(name)


def test_a_first_preparation_also_gives_the_starting_metadata() -> None:
    export = json.loads(
        (ROOT / "tests" / "golden" / "normalised" / "easm-scenario.json").read_bytes()
    )

    prepared = prepare_entry(export, EXTERNAL_ID, RepositoryData(), path="e.zip", start_at="m.yaml")

    assert prepared.metadata is not None
    assert prepared.metadata["name"] == "EASM Scenario"
    assert {f.path for f in prepared.to_complete} == {"m.yaml"}
    later = prepare_entry(export, EXTERNAL_ID, RepositoryData(), path="e.zip")
    assert (later.metadata, later.to_complete) == (None, ())


def test_an_export_whose_facts_cannot_be_read_is_refused_before_anything_is_written() -> None:
    export = json.loads(
        (ROOT / "tests" / "golden" / "normalised" / "easm-scenario.json").read_bytes()
    )
    export["scenario_information"]["scenario_main_focus"] = None

    with pytest.raises(UnsafeInputError) as error:
        prepare_entry(export, EXTERNAL_ID, RepositoryData(), path="e.zip", start_at="m.yaml")
    assert (error.value.code, error.value.path) == ("IO-014", "e.zip")
