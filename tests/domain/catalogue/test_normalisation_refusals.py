"""What normalisation says, word for word, when it refuses the identifiers of an export: each
refusal names the collection and the key at fault."""

import copy
from collections.abc import Callable
from typing import Any

import pytest

from scenario_tools.domain.catalogue.normalisation import ExportStructureError, normalise
from tests.domain.catalogue.test_normalisation import (
    AUTHOR,
    EXPORT,
    EXTERNAL_ID,
    NAMED,
    ORGANISATION,
    RULES,
    TEAM,
    USER,
)


def _refusal(change: Callable[[dict[str, Any]], None]) -> str:
    export = copy.deepcopy(EXPORT)
    change(export)
    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"
    return str(error.value.what)


def _implant(export: dict[str, Any]) -> dict[str, Any]:
    contract: dict[str, Any] = export["scenario_injects"][1]["inject_injector_contract"]
    return contract


def _mail(export: dict[str, Any]) -> dict[str, Any]:
    contract: dict[str, Any] = export["scenario_injects"][0]["inject_injector_contract"]
    return contract


def test_a_scenario_id_that_is_no_text_is_named() -> None:
    def change(export: dict[str, Any]) -> None:
        export["scenario_information"]["scenario_id"] = 7

    assert _refusal(change) == "scenario_information.scenario_id must be text"


@pytest.mark.parametrize(("collection", "id_key", "name_key", "object_type"), NAMED)
def test_an_object_s_identifier_and_name_are_named_with_their_collection(
    collection: str, id_key: str, name_key: str, object_type: str
) -> None:
    def no_text_id(export: dict[str, Any]) -> None:
        export[collection] = [{id_key: 7, name_key: "Alpha"}]

    def empty_name(export: dict[str, Any]) -> None:
        export[collection] = [{id_key: USER, name_key: ""}]

    def twice(export: dict[str, Any]) -> None:
        export[collection] = [
            {id_key: USER, name_key: "Alpha"},
            {id_key: AUTHOR, name_key: "Alpha"},
        ]

    assert _refusal(no_text_id) == f"{collection}.{id_key} must be text"
    assert _refusal(empty_name) == f"{collection}.{name_key} must not be empty"
    assert _refusal(twice) == f"two objects of {collection} are named 'Alpha'"


def _articles(*articles: dict[str, Any]) -> Callable[[dict[str, Any]], None]:
    def change(export: dict[str, Any]) -> None:
        export["scenario_channels"] = [{"channel_id": AUTHOR, "channel_name": "Press"}]
        export["scenario_articles"] = list(articles)

    return change


@pytest.mark.parametrize(
    ("articles", "message"),
    [
        (
            [{"article_id": 7, "article_name": "Release", "article_channel": AUTHOR}],
            "scenario_articles.article_id must be text",
        ),
        (
            [{"article_id": USER, "article_name": "", "article_channel": AUTHOR}],
            "scenario_articles.article_name must not be empty",
        ),
        (
            [{"article_id": USER, "article_name": "Release", "article_channel": [AUTHOR]}],
            "scenario_articles.article_channel must be text",
        ),
        (
            [{"article_id": USER, "article_name": "Release", "article_channel": TEAM}],
            "article 'Release' has no channel of the scenario",
        ),
        (
            [
                {"article_id": USER, "article_name": "Release", "article_channel": AUTHOR},
                {"article_id": TEAM, "article_name": "Release", "article_channel": AUTHOR},
            ],
            "two articles of channel 'Press' are named 'Release'",
        ),
    ],
    ids=["id not text", "empty name", "channel not text", "unknown channel", "twice"],
)
def test_an_article_s_refusal_is_named(articles: list[dict[str, Any]], message: str) -> None:
    assert _refusal(_articles(*articles)) == message


@pytest.mark.parametrize(
    ("custom", "message"),
    [
        ("yes", "injector_contract_custom must be true or false"),
        (True, "custom contracts without a payload are not supported yet"),
    ],
)
def test_a_custom_contract_without_a_payload_is_refused_by_name(
    custom: object, message: str
) -> None:
    def change(export: dict[str, Any]) -> None:
        _mail(export)["injector_contract_custom"] = custom

    assert _refusal(change) == message


def test_a_built_in_contract_s_identifier_that_is_no_text_is_named() -> None:
    def change(export: dict[str, Any]) -> None:
        _mail(export)["injector_contract_id"] = 7

    assert _refusal(change) == "inject_injector_contract.injector_contract_id must be text"


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("payload_id", 7, "injector_contract_payload.payload_id must be text"),
        ("payload_name", "", "injector_contract_payload.payload_name must not be empty"),
    ],
)
def test_a_payload_s_identifier_and_name_are_named(key: str, value: object, message: str) -> None:
    def change(export: dict[str, Any]) -> None:
        _implant(export)["injector_contract_payload"][key] = value

    assert _refusal(change) == message


def test_a_payload_contract_s_identifier_that_is_no_text_is_named() -> None:
    def change(export: dict[str, Any]) -> None:
        _implant(export)["injector_contract_id"] = 7

    assert _refusal(change) == "inject_injector_contract.injector_contract_id must be text"


def test_two_versions_of_one_payload_are_refused_by_name() -> None:
    def change(export: dict[str, Any]) -> None:
        twin = copy.deepcopy(export["scenario_injects"][1])
        twin["inject_id"] = USER
        twin["inject_title"] = "Dump again"
        twin["inject_injector_contract"]["injector_contract_id"] = AUTHOR
        payload = twin["inject_injector_contract"]["injector_contract_payload"]
        payload["payload_id"] = ORGANISATION
        payload["payload_name"] = "Dump (1.1.0)"
        export["scenario_injects"].append(twin)

    assert _refusal(change) == (
        "two versions of the payload 'Dump' are embedded: a scenario embeds one version of a "
        "payload"
    )


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        (
            {"attack_pattern_id": 7, "attack_pattern_external_id": "T1003"},
            "attack_pattern_id must be text",
        ),
        (
            {"attack_pattern_id": USER, "attack_pattern_external_id": ""},
            "attack_pattern_id needs a non-empty attack_pattern_external_id",
        ),
    ],
)
def test_a_catalogue_object_without_its_shared_key_is_refused_by_name(
    pattern: dict[str, Any], message: str
) -> None:
    def change(export: dict[str, Any]) -> None:
        _implant(export)["injector_contract_attack_patterns"] = [pattern]

    assert _refusal(change) == message
