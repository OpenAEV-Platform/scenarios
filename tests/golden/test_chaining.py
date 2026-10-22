"""A hand-built export of a scenario in chaining, read with the repository's closed lists."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.domain.shared.workflow import (
    KEY_UNKNOWN,
    ExportKeys,
    Refusal,
    export_refusals,
)
from scenario_tools.domain.sheet.sheet import render_sheet

ROOT = Path(__file__).resolve().parents[2]
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
EXPORT = json.loads((ROOT / "tests" / "golden" / "chaining" / "two-steps.json").read_text())
KEYS = ExportKeys.from_document(YamlDataLoader(ROOT / "policy" / "data").load("export-keys"))
WORKFLOW = "/scenario_workflow"
NORMALISED = ROOT / "tests" / "golden" / "chaining" / "two-steps.normalised.json"
DATA = YamlDataLoader(ROOT / "policy" / "data")


def test_the_export_holds_two_steps_one_after_the_other() -> None:
    steps = EXPORT["scenario_workflow"]["workflow_steps"]
    assert len(steps) == 2
    assert EXPORT["scenario_injects"] == []
    (dependency,) = steps[1]["step_conditions"]
    assert (dependency["condition_type"], dependency["condition_value"]) == (
        "DEPEND_ON",
        steps[0]["step_id"],
    )


def test_every_key_it_holds_is_in_the_closed_lists() -> None:
    assert list(export_refusals(EXPORT, KEYS)) == []


@pytest.mark.parametrize(
    ("place", "pointer"),
    [
        (lambda e: e["scenario_workflow"], f"{WORKFLOW}/added"),
        (
            lambda e: e["scenario_workflow"]["workflow_steps"][0],
            f"{WORKFLOW}/workflow_steps/0/added",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_steps"][1]["step_conditions"][0],
            f"{WORKFLOW}/workflow_steps/1/step_conditions/0/added",
        ),
    ],
)
def test_a_key_added_at_each_level_is_refused(place: Any, pointer: str) -> None:
    export = copy.deepcopy(EXPORT)
    place(export)["added"] = True
    assert next(export_refusals(export, KEYS)) == Refusal(KEY_UNKNOWN, pointer)


def _prepare(export: Any, previous: Any = None) -> bytes:
    prepared = prepare_entry(export, ENTRY_ID, DATA, path="two-steps.json", previous=previous)
    return prepared.scenario_json


def test_it_normalises_to_its_reviewed_form() -> None:
    assert _prepare(copy.deepcopy(EXPORT)) == NORMALISED.read_bytes()


def test_its_stored_form_normalised_with_itself_gives_the_same_bytes() -> None:
    stored = json.loads(NORMALISED.read_bytes())
    assert _prepare(copy.deepcopy(stored), previous=stored) == NORMALISED.read_bytes()


def test_no_identifier_of_its_steps_is_left() -> None:
    text = NORMALISED.read_text(encoding="utf-8")
    sources = [step["step_id"] for step in EXPORT["scenario_workflow"]["workflow_steps"]]
    sources += [
        condition["condition_id"]
        for step in EXPORT["scenario_workflow"]["workflow_steps"]
        for condition in step["step_conditions"]
    ]
    assert [source for source in sources if source in text] == []


SHEET = ROOT / "tests" / "golden" / "chaining" / "two-steps.README.md"
SHEET_METADATA: dict[str, Any] = {
    "name": "Two steps",
    "description": "Lists the processes of an endpoint, then lists them again once it is done.",
    "version": "1.0.0",
    "status": "VERIFIED",
    "type": "chained",
    "platforms": ["Linux", "MacOS"],
    "requires": {
        "openaev": ">=3.261005.0",
        "edition": "EE",
        "injectors": ["openaev_implant"],
        "executors": ["openaev"],
    },
}


def test_its_sheet_is_the_reviewed_one_and_renders_the_same_twice() -> None:
    stored = json.loads(NORMALISED.read_bytes())
    first = render_sheet(SHEET_METADATA, stored, ())
    assert first == render_sheet(SHEET_METADATA, copy.deepcopy(stored), ())
    assert first == SHEET.read_text(encoding="utf-8")
