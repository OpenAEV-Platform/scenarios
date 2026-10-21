"""The shape of a stored scenario as the checks read it: the injects, refused when misshapen."""

import pytest

from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.catalogue.structure import (
    CONTRACT,
    PAYLOAD,
    checked_injects,
    contracts_with_payloads,
)
from scenario_tools.domain.shared.stored import INJECTS, Origin, StoredInject


def test_checked_injects_are_the_walk_when_the_part_is_well_shaped() -> None:
    first, second = {"inject_id": "a"}, {"inject_id": "b"}
    assert list(checked_injects({INJECTS: [first, second]})) == [
        StoredInject("/scenario_injects/0", first, Origin.INJECT),
        StoredInject("/scenario_injects/1", second, Origin.INJECT),
    ]


@pytest.mark.parametrize("export", [{}, {INJECTS: None}, {INJECTS: "text"}, {INJECTS: {}}])
def test_a_part_that_is_not_a_list_is_refused(export: dict[str, object]) -> None:
    with pytest.raises(ExportStructureError) as raised:
        list(checked_injects(export))
    assert str(raised.value) == "not an OpenAEV scenario export: scenario_injects must be a list"
    assert raised.value.what == "scenario_injects must be a list"


def test_an_item_that_is_not_an_object_is_refused_after_the_items_before_it() -> None:
    found = checked_injects({INJECTS: [{"inject_id": "a"}, "text"]})
    assert next(found).pointer == "/scenario_injects/0"
    with pytest.raises(ExportStructureError, match=r"scenario_injects must be an object$"):
        next(found)


def test_contracts_with_payloads_are_the_injects_whose_contract_embeds_one() -> None:
    contract = {PAYLOAD: {"payload_name": "Process Discovery - ps"}}
    with_payload = {CONTRACT: contract}
    stored = {
        INJECTS: [
            {CONTRACT: {PAYLOAD: None}},
            {CONTRACT: {PAYLOAD: {}}},
            {CONTRACT: "text"},
            "text",
            with_payload,
        ]
    }
    assert list(contracts_with_payloads(stored)) == [
        ("/scenario_injects/4", with_payload, contract)
    ]


def test_a_payload_of_another_shape_is_still_yielded_for_its_check_to_refuse() -> None:
    contract = {PAYLOAD: "text"}
    inject = {CONTRACT: contract}
    assert list(contracts_with_payloads({INJECTS: [inject]})) == [
        ("/scenario_injects/0", inject, contract)
    ]
