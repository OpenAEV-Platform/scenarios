"""The walk over the injects of a stored scenario: each inject with its JSON pointer and origin."""

import pytest

from scenario_tools.domain.shared.stored import (
    INJECTS,
    Origin,
    StoredInject,
    inject_pointer,
    injects,
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
