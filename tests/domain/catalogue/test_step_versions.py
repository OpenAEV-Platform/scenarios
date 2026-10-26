"""The steps of a new version of a scenario in chaining, matched with those of the previous one:
a step keeps its identifier when the matcher can tell it is the same step."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.catalogue.export_reading import ExportStructureError
from scenario_tools.domain.catalogue.identifiers import (
    AmbiguousInjectError,
    InjectSignature,
    InvalidInjectMappingError,
    match_injects,
    scenario_namespace,
    stable_id,
)
from scenario_tools.domain.catalogue.normalisation import normalise
from scenario_tools.domain.shared.workflow import MAX_STEPS, TOO_MANY_STEPS
from tests.domain.catalogue.test_normalisation import RULES

ROOT = Path(__file__).resolve().parents[3]
EXPORT: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "two-steps.json").read_text(encoding="utf-8")
)
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
FIRST, SECOND = "00000000-0000-4000-8000-000000000016", "00000000-0000-4000-8000-000000000018"
STEP_1, STEP_2 = "Step 1 - list processes", "Step 2 - list processes again"


def _normalised(
    export: dict[str, Any], previous: Any = None, mapping: dict[str, str] | None = None
) -> Any:
    return normalise(copy.deepcopy(export), ENTRY_ID, RULES, previous=previous, mapping=mapping)


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = document["scenario_workflow"]["workflow_steps"]
    return steps


def _ids(document: dict[str, Any]) -> dict[str, str]:
    """The stored identifier of each step, by title."""
    return {step["step_data"]["inject_title"]: step["step_id"] for step in _steps(document)}


def _retitled(export: dict[str, Any], step_id: str, title: str) -> dict[str, Any]:
    edited = copy.deepcopy(export)
    step = next(step for step in _steps(edited) if step["step_id"] == step_id)
    data = json.loads(step["step_data"])
    data["inject_title"] = title
    step["step_data"] = json.dumps(data)
    return edited


PREVIOUS = _normalised(EXPORT).document


def test_an_unchanged_export_keeps_every_identifier() -> None:
    assert _normalised(EXPORT, PREVIOUS).document == PREVIOUS


def test_a_step_after_a_retitled_one_keeps_its_identifier() -> None:
    document = _normalised(_retitled(EXPORT, FIRST, "Step 1 - renamed"), PREVIOUS).document
    ids, before = _ids(document), _ids(PREVIOUS)
    assert ids[STEP_2] == before[STEP_2]
    assert ids["Step 1 - renamed"] != before[STEP_1]
    second = next(step for step in _steps(document) if step["step_id"] == ids[STEP_2])
    assert second["step_conditions"][0]["condition_value"] == ids["Step 1 - renamed"]


def test_a_retitled_step_keeps_its_identifier_when_mapped() -> None:
    export = _retitled(EXPORT, FIRST, "Step 1 - renamed")
    mapping = {FIRST: _ids(PREVIOUS)[STEP_1]}
    assert _ids(_normalised(export, PREVIOUS, mapping).document) == {
        "Step 1 - renamed": _ids(PREVIOUS)[STEP_1],
        STEP_2: _ids(PREVIOUS)[STEP_2],
    }


def test_a_retitled_step_is_reported_as_removed_from_the_previous_version() -> None:
    normalised = _normalised(_retitled(EXPORT, FIRST, "Step 1 - renamed"), PREVIOUS)
    assert normalised.removed_steps == (_ids(PREVIOUS)[STEP_1],)
    assert normalised.removed_injects == ()


def test_a_mapping_to_a_step_of_no_previous_version_is_refused() -> None:
    with pytest.raises(InvalidInjectMappingError, match="not in the previous version"):
        _normalised(EXPORT, PREVIOUS, {FIRST: "00000000-0000-4000-8000-0000000000aa"})


def _four_steps() -> dict[str, Any]:
    """Two steps of one title, each waiting for its own step."""
    export = copy.deepcopy(EXPORT)
    first, second = _steps(export)
    steps = []
    for number, (source, waits_for) in enumerate(
        [("a1", None), ("a2", None), ("b1", "a1"), ("b2", "a2")], start=1
    ):
        step = copy.deepcopy(second if waits_for else first)
        identifier = f"00000000-0000-4000-8000-0000000001{number:02x}"
        data = json.loads(step["step_data"])
        data["inject_title"] = "Wait" if waits_for else f"Start {source}"
        step["step_data"] = json.dumps(data)
        step["step_id"] = identifier
        if waits_for:
            condition = step["step_conditions"][0]
            condition["condition_id"] = f"00000000-0000-4000-8000-0000000002{number:02x}"
            condition["condition_value"] = f"00000000-0000-4000-8000-0000000001{number - 2:02x}"
        steps.append(step)
    _steps(export)[:] = steps
    return export


def test_steps_that_cannot_be_told_apart_are_refused_by_their_export_identifier() -> None:
    export = _four_steps()
    previous = _normalised(export).document
    edited = _retitled(
        _retitled(export, "00000000-0000-4000-8000-000000000101", "Start a1 - renamed"),
        "00000000-0000-4000-8000-000000000102",
        "Start a2 - renamed",
    )
    with pytest.raises(AmbiguousInjectError) as error:
        _normalised(edited, previous)
    assert error.value.source_id in {
        "00000000-0000-4000-8000-000000000103",
        "00000000-0000-4000-8000-000000000104",
    }
    assert str(error.value).startswith(f"step {error.value.source_id!r}")


def test_a_previous_version_with_a_step_identifier_that_is_not_one_is_refused() -> None:
    previous = copy.deepcopy(PREVIOUS)
    _steps(previous)[0]["step_id"] = "not-an-identifier"
    with pytest.raises(ExportStructureError) as error:
        _normalised(EXPORT, previous)
    assert error.value.origin == "previous"


def test_the_matcher_names_the_object_it_matches() -> None:
    namespace = scenario_namespace(ENTRY_ID)
    new = [InjectSignature("d1", "p", "t", ())]
    matching = match_injects(namespace, new, [], object_type="step")
    assert matching.ids == {"d1": stable_id(namespace, "step", "d1")}
    with pytest.raises(InvalidInjectMappingError, match="unknown source step 'x'"):
        match_injects(namespace, new, [], {"x": "y"}, object_type="step")


def test_a_new_step_never_takes_the_identifier_an_edited_step_kept() -> None:
    edited = _retitled(EXPORT, FIRST, "Edited first")
    kept = _ids(PREVIOUS)[STEP_1]
    second = _normalised(edited, PREVIOUS, {FIRST: kept}).document
    assert _ids(second)["Edited first"] == kept
    again = copy.deepcopy(edited)
    original = copy.deepcopy(next(step for step in _steps(EXPORT) if step["step_id"] == FIRST))
    original["step_id"] = "00000000-0000-4000-8000-0000000000ab"
    _steps(again).append(original)
    third = _normalised(again, second).document
    ids = _ids(third)
    assert ids["Edited first"] == kept
    assert ids[STEP_1] not in {kept, *_ids(second).values()}
    assert _normalised(copy.deepcopy(third), third).document == third


def test_a_previous_version_with_a_step_given_twice_is_refused() -> None:
    previous = copy.deepcopy(PREVIOUS)
    _steps(previous).append(copy.deepcopy(_steps(previous)[0]))
    with pytest.raises(ExportStructureError) as error:
        _normalised(EXPORT, previous)
    assert error.value.origin == "previous"


def test_every_step_is_removed_when_the_export_has_no_workflow() -> None:
    export = copy.deepcopy(EXPORT)
    export["scenario_workflow"] = None
    assert _normalised(export, PREVIOUS).removed_steps == tuple(sorted(_ids(PREVIOUS).values()))


def test_the_steps_of_a_previous_version_of_another_entry_are_not_read() -> None:
    previous = copy.deepcopy(PREVIOUS)
    previous["scenario_information"]["scenario_id"] = "00000000-0000-4000-8000-0000000000ac"
    _steps(previous)[0]["step_id"] = "not-an-identifier"
    with pytest.raises(ExportStructureError) as error:
        _normalised(EXPORT, previous)
    assert (error.value.origin, error.value.what) == (
        "previous",
        "its scenario identifier is not this entry's",
    )


@pytest.mark.parametrize(
    ("value", "what"),
    [
        ("00000000-0000-4000-8000-0000000000ad", "which is no step of it"),
        (None, "waits for itself"),
    ],
    ids=["dangling", "loop"],
)
def test_a_previous_version_whose_steps_cannot_be_read_as_a_graph_is_refused(
    value: object, what: str
) -> None:
    previous = copy.deepcopy(PREVIOUS)
    waiting = next(step for step in _steps(previous) if step["step_conditions"])
    waiting["step_conditions"][0]["condition_value"] = value or waiting["step_id"]
    with pytest.raises(ExportStructureError) as error:
        _normalised(EXPORT, previous)
    assert error.value.origin == "previous"
    assert what in error.value.what


@pytest.mark.parametrize(
    ("change", "what"),
    [
        (lambda document: document.update(scenario_workflow=["not", "an", "object"]), "object"),
        (lambda document: _steps(document)[0].update(step_data="text"), "step_data"),
    ],
    ids=["workflow", "step-data"],
)
def test_a_previous_version_of_another_shape_is_refused(change: Any, what: str) -> None:
    previous = copy.deepcopy(PREVIOUS)
    change(previous)
    with pytest.raises(ExportStructureError) as error:
        _normalised(EXPORT, previous)
    assert error.value.origin == "previous"
    assert what in error.value.what


def test_a_step_retitled_back_without_a_mapping_never_takes_an_identifier_of_the_previous() -> None:
    kept = _ids(PREVIOUS)[STEP_1]
    second = _normalised(_retitled(EXPORT, FIRST, "Renamed"), PREVIOUS, {FIRST: kept})
    assert _ids(second.document)["Renamed"] == kept
    third = _normalised(EXPORT, second.document)
    assert _ids(third.document)[STEP_1] != kept
    assert third.removed_steps == (kept,)


@pytest.mark.parametrize("identifier", [[], {}])
def test_a_step_identifier_of_another_shape_is_refused_not_a_crash(identifier: object) -> None:
    export = copy.deepcopy(EXPORT)
    _steps(export)[:] = [next(step for step in _steps(export) if not step["step_conditions"])]
    _steps(export)[0]["step_id"] = identifier
    with pytest.raises(ExportStructureError):
        _normalised(export, PREVIOUS, {FIRST: _ids(PREVIOUS)[STEP_1]})


def test_a_previous_version_with_too_many_steps_is_refused() -> None:
    previous = copy.deepcopy(PREVIOUS)
    first = _steps(previous)[0]
    _steps(previous)[:] = [
        {**copy.deepcopy(first), "step_id": f"00000000-0000-4000-8000-{index:012x}"}
        for index in range(1, MAX_STEPS + 2)
    ]
    with pytest.raises(ExportStructureError) as error:
        _normalised(EXPORT, previous)
    assert (error.value.origin, error.value.what) == ("previous", TOO_MANY_STEPS)
