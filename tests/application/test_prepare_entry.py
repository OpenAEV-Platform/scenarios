"""Preparing an entry: an export normalised with the rules kept as data."""

import copy
import json
from typing import Any

import pytest

from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.ports.errors import UnsafeInputError

EXTERNAL_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
INJECT = "00000000-0000-4000-8000-000000000002"
EXPORT: dict[str, Any] = {
    "scenario_information": {"scenario_id": "00000000-0000-4000-8000-000000000001"},
    "scenario_injects": [
        {
            "inject_id": INJECT,
            "inject_title": "Note",
            "inject_depends_on": [],
            "inject_injector_contract": {"injector_contract_id": "c", "listened": True},
        }
    ],
}


class FakeData:
    def load(self, name: str) -> Any:
        assert name == "volatile-fields"
        return {"removed": ["listened"], "removed_suffixes": [], "sorted": []}


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
