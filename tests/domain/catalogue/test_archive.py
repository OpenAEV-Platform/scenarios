"""What keeps a stored scenario out of an import archive: a payload outside an inject's contract,
which no reference can name; the payloads of the injects are checked against their references."""

import copy
from typing import Any

import pytest

from scenario_tools.domain.catalogue.archive import (
    STORED_PARTS,
    archive_findings,
    belongs_to,
    payloads_outside_contracts,
)
from scenario_tools.domain.catalogue.identifiers import scenario_namespace, stable_id
from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.shared.finding import Severity

PATH = "scenarios/ransomware/akira/scenario.json"
BUILT_IN = {"injector_contract_id": "2790bd39-37d4-4e39-be7e-53f3ca783f86"}
PAYLOAD = {"payload_id": "00000000-0000-4000-8000-000000000008", "payload_name": "Dump"}
DOCUMENT: dict[str, Any] = {
    "scenario_information": {"scenario_name": "Akira"},
    "scenario_injects": [
        {"inject_injector_contract": {**BUILT_IN, "injector_contract_payload": None}},
        {"inject_injector_contract": None},
    ],
}


def test_a_scenario_without_payload_or_recurrence_can_be_archived() -> None:
    assert archive_findings(DOCUMENT, PATH) == ()


def test_an_empty_payload_object_is_no_payload() -> None:
    document = copy.deepcopy(DOCUMENT)
    document["scenario_injects"][0]["inject_injector_contract"]["injector_contract_payload"] = {}

    assert archive_findings(document, PATH) == ()


def test_the_payloads_of_the_injects_are_left_to_their_references() -> None:
    document = copy.deepcopy(DOCUMENT)
    values: tuple[object, ...] = (PAYLOAD, "x", [])
    for value in values:
        document["scenario_injects"].append(
            {"inject_injector_contract": {"injector_contract_payload": value}}
        )

    assert archive_findings(document, PATH) == ()


def test_a_recurrence_is_left_to_the_policy() -> None:
    document = copy.deepcopy(DOCUMENT)
    document["scenario_information"]["scenario_recurrence"] = "0 0 8 * * MON"

    assert archive_findings(document, PATH) == ()


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(scenario_information=[]),
        lambda d: d.pop("scenario_information"),
        lambda d: d.update(scenario_injects={}),
        lambda d: d["scenario_injects"].append("x"),
        lambda d: d["scenario_injects"][0].update(inject_injector_contract="x"),
    ],
    ids=["information", "no information", "injects", "inject", "contract"],
)
def test_a_document_not_shaped_like_a_stored_scenario_is_refused(change: Any) -> None:
    document = copy.deepcopy(DOCUMENT)
    change(document)

    with pytest.raises(ExportStructureError):
        archive_findings(document, PATH)


@pytest.mark.parametrize(
    ("part", "value"),
    [
        ("exercise_information", {}),
        ("exercise_injects", []),
        ("anything", None),
        ("scenario_lessons_categories", [{"lesson": "x"}]),
        ("scenario_objectives", ["x"]),
    ],
)
def test_a_part_a_normalised_scenario_never_has_is_refused(part: str, value: Any) -> None:
    # The importer reads other parts too, such as an exercise set or lessons. The checks would not
    # see them, so the archive fails closed; the workflow is a part of its own, checked as such.
    document = copy.deepcopy(DOCUMENT)
    document[part] = value

    with pytest.raises(ExportStructureError) as error:
        archive_findings(document, PATH)
    assert error.value.what == f"{part} is not a part of a stored scenario"


@pytest.mark.parametrize(
    "part",
    [
        "scenario_workflow",
        "scenario_objectives",
        "scenario_lessons_categories",
        "scenario_lessons_questions",
    ],
)
@pytest.mark.parametrize("empty", [[], {}, None])
def test_a_part_normalisation_leaves_empty_is_accepted_empty(part: str, empty: Any) -> None:
    document = copy.deepcopy(DOCUMENT)
    document[part] = empty

    assert archive_findings(document, PATH) == ()


@pytest.mark.parametrize("value", [0, False, "", " "], ids=["zero", "false", "empty text", "text"])
def test_a_part_left_empty_must_be_an_empty_collection_or_null(value: Any) -> None:
    # Scalars survive normalisation unchanged: only the empty forms it leaves are accepted.
    document = copy.deepcopy(DOCUMENT)
    document["scenario_workflow"] = value

    with pytest.raises(ExportStructureError):
        archive_findings(document, PATH)


def test_every_part_of_a_normalised_scenario_is_accepted() -> None:
    document = copy.deepcopy(DOCUMENT)
    for part in STORED_PARTS:
        document.setdefault(part, [])

    assert archive_findings(document, PATH) == ()


def test_a_payload_outside_an_inject_s_contract_is_refused() -> None:
    document = copy.deepcopy(DOCUMENT)
    document["scenario_articles"] = [
        {"article/name": {"nested~": {"injector_contract_payload": PAYLOAD}}}
    ]
    document["scenario_injects"][0]["inject_content"] = {"injector_contract_payload": PAYLOAD}

    findings = archive_findings(document, PATH)

    assert [(f.code, f.severity, f.path, f.field) for f in findings] == [
        ("PAY-004", Severity.BLOCKING, PATH, "/scenario_injects/0/inject_content"),
        ("PAY-004", Severity.BLOCKING, PATH, "/scenario_articles/0/article~1name/nested~0"),
    ]
    assert findings[0].message == (
        "the document embeds a payload outside an inject's or a step's contract: no reference "
        "can name it, and the archive cannot carry it"
    )


@pytest.mark.parametrize("value", [[], "x", ["x"]], ids=["empty list", "text", "list"])
def test_a_payload_outside_a_contract_that_is_not_an_object_is_refused_too(value: Any) -> None:
    document = copy.deepcopy(DOCUMENT)
    document["scenario_channels"] = [{"injector_contract_payload": value}]

    assert [finding.code for finding in archive_findings(document, PATH)] == ["PAY-004"]


def test_a_stored_scenario_belongs_to_the_entry_its_identifier_derives_from() -> None:
    external_id = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
    document = copy.deepcopy(DOCUMENT)
    document["scenario_information"]["scenario_id"] = stable_id(
        scenario_namespace(external_id), "scenario", external_id
    )

    assert belongs_to(document, external_id)
    assert not belongs_to(document, "00000000-0000-4000-8000-000000000001")
    assert not belongs_to({"scenario_information": []}, external_id)
    assert not belongs_to([], external_id)


def test_a_document_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ExportStructureError):
        archive_findings([], PATH)


@pytest.mark.parametrize(
    ("document", "fields"),
    [
        (None, []),
        ([], []),
        ({"scenario_injects": "x", "other": {"injector_contract_payload": PAYLOAD}}, ["/other"]),
        (
            {
                "scenario_injects": [
                    {"inject_injector_contract": {"injector_contract_payload": PAYLOAD}}
                ]
            },
            [],
        ),
        (  # an item that is not an object keeps the index of the next one
            {
                "scenario_injects": [
                    "x",
                    {"inject_injector_contract": {"injector_contract_payload": PAYLOAD}},
                ]
            },
            [],
        ),
    ],
)
def test_a_payload_outside_a_contract_is_found_in_any_document(
    document: object, fields: list[str]
) -> None:
    assert [f.field for f in payloads_outside_contracts(document, PATH)] == fields
