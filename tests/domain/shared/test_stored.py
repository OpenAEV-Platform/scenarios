"""The walk over the injects of a stored scenario: each inject with its JSON pointer and origin."""

import json

import pytest

from scenario_tools.domain.shared.stored import (
    INJECTS,
    STEPS,
    WORKFLOW,
    Origin,
    StoredInject,
    inject_pointer,
    injects,
    step_pointer,
    steps_decoded,
)


def test_each_inject_comes_with_its_pointer_in_order() -> None:
    first, second = {"inject_id": "a"}, {"inject_id": "b"}
    assert list(injects({INJECTS: [first, second]})) == [
        StoredInject("/scenario_injects/0", first, Origin.INJECT),
        StoredInject("/scenario_injects/1", second, Origin.INJECT),
    ]


def test_an_item_that_is_not_an_object_is_skipped_and_the_next_keeps_its_index() -> None:
    item = {"inject_id": "b"}
    assert [found.pointer for found in injects({INJECTS: ["text", None, item]})] == [
        "/scenario_injects/2"
    ]


@pytest.mark.parametrize(
    "stored",
    [None, [], "text", {}, {INJECTS: None}, {INJECTS: "text"}, {INJECTS: {"0": {}}}],
)
def test_a_document_or_part_of_another_shape_yields_nothing(stored: object) -> None:
    assert list(injects(stored)) == []


def test_the_part_and_its_pointers_are_named_as_the_platform_names_them() -> None:
    assert INJECTS == "scenario_injects"
    assert inject_pointer(3) == "/scenario_injects/3"


def test_the_inject_of_each_step_follows_the_injects() -> None:
    inject, first, second = {"inject_id": "a"}, {"inject_title": "s1"}, {"inject_title": "s2"}
    stored = {
        INJECTS: [inject],
        WORKFLOW: {STEPS: [{"step_data": first}, {"step_data": second}]},
    }
    assert list(injects(stored)) == [
        StoredInject("/scenario_injects/0", inject, Origin.INJECT),
        StoredInject("/scenario_workflow/workflow_steps/0/step_data", first, Origin.STEP),
        StoredInject("/scenario_workflow/workflow_steps/1/step_data", second, Origin.STEP),
    ]
    assert step_pointer(4) == "/scenario_workflow/workflow_steps/4/step_data"


@pytest.mark.parametrize(
    "workflow",
    [None, {}, "text", {STEPS: "text"}, {STEPS: ["text", {}, {"step_data": "{}"}]}],
)
def test_a_workflow_or_step_of_another_shape_yields_no_step(workflow: object) -> None:
    assert list(injects({INJECTS: [], WORKFLOW: workflow})) == []


def _decode(text: str) -> object:
    return json.loads(text)


def test_each_step_given_as_json_text_is_decoded_and_the_rest_kept() -> None:
    document = {
        "scenario_injects": [{"inject_title": "kept"}],
        "scenario_workflow": {
            "workflow_id": "w",
            "workflow_steps": [
                {"step_id": "a", "step_data": '{"inject_title": "decoded"}'},
                {"step_id": "b", "step_data": {"inject_title": "object"}},
                "x",
            ],
        },
    }
    before = json.dumps(document)

    decoded, unreadable = steps_decoded(document, _decode)

    assert decoded == {
        "scenario_injects": [{"inject_title": "kept"}],
        "scenario_workflow": {
            "workflow_id": "w",
            "workflow_steps": [
                {"step_id": "a", "step_data": {"inject_title": "decoded"}},
                {"step_id": "b", "step_data": {"inject_title": "object"}},
                "x",
            ],
        },
    }
    assert unreadable == ()
    assert json.dumps(document) == before  # the document itself is left as it is


def test_a_step_whose_text_the_decoder_refuses_is_named_and_left_as_it_is() -> None:
    document = {"scenario_workflow": {"workflow_steps": [{"step_data": "{"}, {"step_data": "1"}]}}

    decoded, unreadable = steps_decoded(document, _decode)

    assert unreadable == ("/scenario_workflow/workflow_steps/0/step_data",)
    assert decoded == {
        "scenario_workflow": {"workflow_steps": [{"step_data": "{"}, {"step_data": 1}]}
    }


@pytest.mark.parametrize(
    "document",
    ["x", {}, {"scenario_workflow": "x"}, {"scenario_workflow": {"workflow_steps": "x"}}],
    ids=["no object", "no workflow", "a workflow of another shape", "steps of another shape"],
)
def test_a_document_without_steps_is_returned_as_it_is(document: object) -> None:
    assert steps_decoded(document, _decode) == (document, ())
