"""Normalisation of an exported scenario: stable identifiers, no volatile or internal data."""

import copy
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.catalogue.identifiers import (
    NS_OPENAEV_SCENARIOS,
    AmbiguousInjectError,
    scenario_namespace,
    stable_id,
)
from scenario_tools.domain.catalogue.normalisation import (
    PLACEHOLDER_SENDER,
    ExportStructureError,
    NormalisationRules,
    normalise,
)

EXTERNAL_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
NS = scenario_namespace(EXTERNAL_ID)

SCENARIO = "00000000-0000-4000-8000-000000000001"
USER = "00000000-0000-4000-8000-000000000002"
TEAM = "00000000-0000-4000-8000-000000000003"
VARIABLE = "00000000-0000-4000-8000-000000000004"
TAG = "00000000-0000-4000-8000-000000000005"
MAIL = "00000000-0000-4000-8000-000000000006"
IMPLANT = "00000000-0000-4000-8000-000000000007"
PAYLOAD_CONTRACT = "00000000-0000-4000-8000-000000000008"
PAYLOAD = "00000000-0000-4000-8000-000000000009"
AUTHOR = "00000000-0000-4000-8000-00000000000a"
ORGANISATION = "00000000-0000-4000-8000-00000000000b"
ATTACK_PATTERN = "00000000-0000-4000-8000-00000000000c"
PHASE = "00000000-0000-4000-8000-00000000000d"
BUILT_IN = "2790bd39-37d4-4e39-be7e-53f3ca783f86"  # a contract that ships with the platform
DOMAIN_A, DOMAIN_B = "2a6577e3-20b3-4101-bc85-e80307696a2b", "1b6577e3-20b3-4101-bc85-e80307696a2b"
INSTANCE_IDS = (
    SCENARIO, USER, TEAM, VARIABLE, TAG, MAIL, IMPLANT, PAYLOAD_CONTRACT, PAYLOAD, AUTHOR,
    ORGANISATION, ATTACK_PATTERN, PHASE,
)  # fmt: skip

RULES = NormalisationRules(
    removed=frozenset(
        {
            "listened",
            "injector_contract_injectors",
            "injector_contract_payload_author",
            "injector_contract_payload_author_organization",
        }
    ),
    removed_suffixes=("_created_at", "_updated_at"),
    sorted_lists=frozenset({"injector_contract_domains", "inject_teams", "inject_tags"}),
)

EXPORT: dict[str, Any] = {
    "export_version": 1,
    "scenario_information": {
        "scenario_id": SCENARIO,
        "scenario_name": "Akira",
        "scenario_mail_from": "animation@internal.example.com",
        "scenario_created_at": "2026-10-07T13:16:22Z",
    },
    "scenario_users": [{"user_id": USER, "user_email": "someone@internal.example.com"}],
    "scenario_teams": [{"team_id": TEAM, "team_name": "Blue", "team_users": [USER]}],
    "scenario_variables": [{"variable_id": VARIABLE, "variable_key": "k", "variable_value": "v"}],
    "scenario_tags": [{"tag_id": TAG, "tag_name": "crisis"}],
    "scenario_injects": [
        {
            "inject_id": MAIL,
            "inject_title": "Ransom note",
            "inject_depends_on": [],
            "inject_teams": [TEAM],
            "inject_tags": [TAG],
            "inject_content": json.dumps({"teams": [TEAM], "body": "hello"}),
            "inject_injector_contract": {
                "injector_contract_id": BUILT_IN,
                "injector_contract_domains": [DOMAIN_A, DOMAIN_B],
                "injector_contract_injectors": ["49229430-b5b5-431f-ba5b-f36f599b0233"],
                "injector_contract_created_at": "2026-10-07T13:16:22Z",
                "listened": True,
                "injector_contract_payload": None,
            },
        },
        {
            "inject_id": IMPLANT,
            "inject_title": "Dump credentials",
            "inject_depends_on": [
                {
                    "dependency_relationship": {
                        "inject_parent_id": MAIL,
                        "inject_children_id": IMPLANT,
                    },
                    "dependency_created_at": "2026-10-07T13:16:22Z",
                }
            ],
            "inject_teams": [],
            "inject_tags": [],
            "inject_content": None,
            "inject_injector_contract": {
                "injector_contract_id": PAYLOAD_CONTRACT,
                "injector_contract_content": json.dumps({"contract_id": PAYLOAD_CONTRACT}),
                "injector_contract_domains": [],
                "injector_contract_payload_author": AUTHOR,
                "injector_contract_payload_author_organization": ORGANISATION,
                "injector_contract_attack_patterns": [
                    {
                        "attack_pattern_id": ATTACK_PATTERN,
                        "attack_pattern_external_id": "T1003",
                        "attack_pattern_kill_chain_phases": [
                            {"phase_id": PHASE, "phase_external_id": "TA0006"}
                        ],
                    }
                ],
                "injector_contract_payload": {
                    "payload_id": PAYLOAD,
                    "payload_name": "Dump",
                    "payload_updated_at": "2026-10-07T13:16:22Z",
                },
            },
        },
    ],
}


def _injects(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {inject["inject_title"]: inject for inject in document["scenario_injects"]}


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in _keys(child)}
    return set()


# Identifiers


def test_no_instance_identifier_is_left_anywhere() -> None:
    text = json.dumps(normalise(EXPORT, EXTERNAL_ID, RULES).document)

    assert [identifier for identifier in INSTANCE_IDS if identifier in text] == []


def test_scenario_objects_take_identifiers_derived_from_the_entry() -> None:
    document = normalise(EXPORT, EXTERNAL_ID, RULES).document
    implant = _injects(document)["Dump credentials"]["inject_injector_contract"]

    assert document["scenario_information"]["scenario_id"] == stable_id(NS, "scenario", SCENARIO)
    assert document["scenario_teams"][0]["team_id"] == stable_id(NS, "team", TEAM)
    assert document["scenario_variables"][0]["variable_id"] == stable_id(NS, "variable", VARIABLE)
    assert document["scenario_tags"][0]["tag_id"] == stable_id(NS, "tag", TAG)
    assert implant["injector_contract_id"] == stable_id(NS, "contract", PAYLOAD_CONTRACT)
    assert implant["injector_contract_payload"]["payload_id"] == stable_id(NS, "payload", PAYLOAD)


def test_built_in_contracts_and_domains_keep_their_identifiers() -> None:
    mail = _injects(normalise(EXPORT, EXTERNAL_ID, RULES).document)["Ransom note"]

    assert mail["inject_injector_contract"]["injector_contract_id"] == BUILT_IN
    assert set(mail["inject_injector_contract"]["injector_contract_domains"]) == {
        DOMAIN_A,
        DOMAIN_B,
    }


def test_attack_patterns_and_phases_derive_from_their_external_identifiers() -> None:
    implant = _injects(normalise(EXPORT, EXTERNAL_ID, RULES).document)["Dump credentials"]
    pattern = implant["inject_injector_contract"]["injector_contract_attack_patterns"][0]

    assert pattern["attack_pattern_id"] == stable_id(
        NS_OPENAEV_SCENARIOS, "attack-pattern", "T1003"
    )
    assert pattern["attack_pattern_kill_chain_phases"][0]["phase_id"] == stable_id(
        NS_OPENAEV_SCENARIOS, "kill-chain-phase", "TA0006"
    )


def test_every_reference_follows_the_rewritten_identifier() -> None:
    document = normalise(EXPORT, EXTERNAL_ID, RULES).document
    injects = _injects(document)
    mail, implant = injects["Ransom note"], injects["Dump credentials"]
    team = document["scenario_teams"][0]["team_id"]
    relationship = implant["inject_depends_on"][0]["dependency_relationship"]

    assert relationship == {
        "inject_parent_id": mail["inject_id"],
        "inject_children_id": implant["inject_id"],
    }
    assert mail["inject_teams"] == [team]
    assert json.loads(mail["inject_content"])["teams"] == [team]
    contract = implant["inject_injector_contract"]
    assert json.loads(contract["injector_contract_content"]) == {
        "contract_id": contract["injector_contract_id"]
    }


def test_a_new_version_keeps_the_identifiers_of_the_previous_one() -> None:
    first = normalise(EXPORT, EXTERNAL_ID, RULES).document

    second = normalise(EXPORT, EXTERNAL_ID, RULES, previous=first)

    assert second.document == first
    assert second.removed_injects == ()


def test_an_inject_from_another_instance_is_matched_by_contract_and_title() -> None:
    first = normalise(EXPORT, EXTERNAL_ID, RULES).document
    elsewhere = copy.deepcopy(EXPORT)
    elsewhere["scenario_injects"][0]["inject_id"] = "00000000-0000-4000-8000-0000000000ff"

    second = normalise(elsewhere, EXTERNAL_ID, RULES, previous=first).document

    assert (
        _injects(second)["Ransom note"]["inject_id"] == _injects(first)["Ransom note"]["inject_id"]
    )


def test_an_ambiguous_match_is_refused_until_mapped() -> None:
    first = normalise(EXPORT, EXTERNAL_ID, RULES).document
    twins = copy.deepcopy(EXPORT)
    for number, inject in enumerate(twins["scenario_injects"][:1] * 2):
        clone = copy.deepcopy(inject)
        clone["inject_id"] = f"00000000-0000-4000-8000-0000000000e{number}"
        twins["scenario_injects"].append(clone)
    del twins["scenario_injects"][0]

    with pytest.raises(AmbiguousInjectError):
        normalise(twins, EXTERNAL_ID, RULES, previous=first)
    mapped = normalise(
        twins,
        EXTERNAL_ID,
        RULES,
        previous=first,
        mapping={
            "00000000-0000-4000-8000-0000000000e0": _injects(first)["Ransom note"]["inject_id"]
        },
    )
    ransom_notes = [
        inject["inject_id"]
        for inject in mapped.document["scenario_injects"]
        if inject["inject_title"] == "Ransom note"
    ]
    assert _injects(first)["Ransom note"]["inject_id"] in ransom_notes
    assert stable_id(NS, "inject", "00000000-0000-4000-8000-0000000000e1") in ransom_notes


# Volatile and internal data


def test_volatile_fields_are_removed_wherever_they_are() -> None:
    keys = _keys(normalise(EXPORT, EXTERNAL_ID, RULES).document)

    assert {key for key in keys if key.endswith(("_created_at", "_updated_at"))} == set()
    assert keys & RULES.removed == set()


def test_internal_data_is_neutralised() -> None:
    document = normalise(EXPORT, EXTERNAL_ID, RULES).document

    assert document["scenario_information"]["scenario_mail_from"] == PLACEHOLDER_SENDER
    assert document["scenario_users"] == []
    assert document["scenario_teams"][0]["team_users"] == []
    assert "variable_value" not in document["scenario_variables"][0]
    assert "internal.example.com" not in json.dumps(document)


def test_the_export_is_never_modified() -> None:
    before = copy.deepcopy(EXPORT)

    normalise(EXPORT, EXTERNAL_ID, RULES)

    assert before == EXPORT


# Order


def test_set_like_lists_and_collections_are_sorted() -> None:
    document = normalise(EXPORT, EXTERNAL_ID, RULES).document
    mail = _injects(document)["Ransom note"]
    inject_ids = [inject["inject_id"] for inject in document["scenario_injects"]]

    assert mail["inject_injector_contract"]["injector_contract_domains"] == sorted(
        [DOMAIN_A, DOMAIN_B]
    )
    assert inject_ids == sorted(inject_ids)


@given(st.randoms(use_true_random=False))
def test_the_result_does_not_depend_on_the_order_of_the_export(random: Any) -> None:
    shuffled = copy.deepcopy(EXPORT)
    random.shuffle(shuffled["scenario_injects"])
    random.shuffle(
        shuffled["scenario_injects"][0]["inject_injector_contract"]["injector_contract_domains"]
    )
    random.shuffle(shuffled["scenario_teams"])

    assert normalise(shuffled, EXTERNAL_ID, RULES) == normalise(EXPORT, EXTERNAL_ID, RULES)


# Hostile input


@pytest.mark.parametrize(
    "export",
    [
        [],
        {},
        {"scenario_information": []},
        {"scenario_information": {"scenario_id": 1}},
        {"scenario_information": {"scenario_id": SCENARIO}, "scenario_injects": {}},
        {"scenario_information": {"scenario_id": SCENARIO}, "scenario_injects": ["x"]},
        {"scenario_information": {"scenario_id": SCENARIO}, "scenario_injects": [{"inject_id": 1}]},
        {"scenario_information": {"scenario_id": SCENARIO}, "scenario_teams": [{"team_id": None}]},
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_teams": [{"team_id": SCENARIO}],
        },
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_injects": [{"inject_injector_contract": "x"}],
        },
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_injects": [{"inject_injector_contract": {"injector_contract_payload": "x"}}],
        },
    ],
    ids=[
        "not an object",
        "no information",
        "information not an object",
        "scenario id not text",
        "injects not a list",
        "inject not an object",
        "inject id not text",
        "team id not text",
        "one identifier for two objects",
        "contract not an object",
        "payload not an object",
    ],
)
def test_an_export_without_the_expected_structure_is_refused(export: Any) -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


# Rules read as data


def test_rules_are_read_from_their_data_document() -> None:
    document = {
        "removed": ["listened"],
        "removed_suffixes": ["_created_at"],
        "sorted": ["inject_tags"],
    }

    assert NormalisationRules.from_document(document) == NormalisationRules(
        removed=frozenset({"listened"}),
        removed_suffixes=("_created_at",),
        sorted_lists=frozenset({"inject_tags"}),
    )


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"removed": [], "removed_suffixes": []},
        {"removed": "x", "removed_suffixes": [], "sorted": []},
    ],
    ids=["not an object", "missing list", "not a list"],
)
def test_rules_that_are_not_lists_of_names_are_refused(document: Any) -> None:
    with pytest.raises(ValueError, match="volatile-fields"):
        NormalisationRules.from_document(document)


def test_an_inject_running_the_same_payload_is_matched_by_payload_and_title() -> None:
    first = normalise(EXPORT, EXTERNAL_ID, RULES).document
    copied = copy.deepcopy(EXPORT)
    copied["scenario_injects"][1]["inject_id"] = "00000000-0000-4000-8000-0000000000fe"

    second = normalise(copied, EXTERNAL_ID, RULES, previous=first).document

    assert (
        _injects(second)["Dump credentials"]["inject_id"]
        == _injects(first)["Dump credentials"]["inject_id"]
    )


def test_twins_are_told_apart_by_their_parents_on_another_instance() -> None:
    def inject(identifier: str, title: str, parent: str | None) -> dict[str, Any]:
        relation = {"inject_parent_id": parent, "inject_children_id": identifier}
        relations = [] if parent is None else [{"dependency_relationship": relation}]
        return {
            "inject_id": identifier,
            "inject_title": title,
            "inject_depends_on": relations,
            "inject_injector_contract": {"injector_contract_id": BUILT_IN},
        }

    def export(prefix: str) -> dict[str, Any]:
        ids = [f"00000000-0000-4000-8000-0000000{prefix}{n:03d}" for n in range(4)]
        return {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_injects": [
                inject(ids[0], "Parent one", None),
                inject(ids[1], "Parent two", None),
                inject(ids[2], "Child", ids[0]),
                inject(ids[3], "Child", ids[1]),
            ],
        }

    def child_of(document: dict[str, Any], parent_title: str) -> str:
        parent = next(
            item["inject_id"]
            for item in document["scenario_injects"]
            if item["inject_title"] == parent_title
        )
        return str(
            next(
                item["inject_id"]
                for item in document["scenario_injects"]
                if item["inject_depends_on"]
                and item["inject_depends_on"][0]["dependency_relationship"]["inject_parent_id"]
                == parent
            )
        )

    first = normalise(export("10"), EXTERNAL_ID, RULES).document
    second = normalise(export("20"), EXTERNAL_ID, RULES, previous=first).document

    for parent_title in ("Parent one", "Parent two"):
        assert child_of(second, parent_title) == child_of(first, parent_title)


def test_identifiers_used_as_object_keys_are_rewritten_too() -> None:
    keyed = copy.deepcopy(EXPORT)
    keyed["scenario_information"]["by_team"] = {TEAM: "Blue"}

    document = normalise(keyed, EXTERNAL_ID, RULES).document

    assert document["scenario_information"]["by_team"] == {stable_id(NS, "team", TEAM): "Blue"}


@pytest.mark.parametrize("where", ["export", "previous"])
def test_repeated_inject_identifiers_are_refused(where: str) -> None:
    repeated = copy.deepcopy(EXPORT)
    repeated["scenario_injects"].append(copy.deepcopy(repeated["scenario_injects"][0]))
    if where == "export":
        export, previous = repeated, None
    else:
        previous = normalise(EXPORT, EXTERNAL_ID, RULES).document
        previous["scenario_injects"].append(copy.deepcopy(previous["scenario_injects"][0]))
        export = EXPORT

    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES, previous=previous)
    assert error.value.code == "IO-014"
