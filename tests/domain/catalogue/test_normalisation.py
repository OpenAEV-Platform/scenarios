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
    ORGANISATION, ATTACK_PATTERN, PHASE, DOMAIN_A, DOMAIN_B,
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
                "convertedContent": {
                    "domains": [
                        {"domain_id": DOMAIN_A, "domain_name": "E-mail Infiltration"},
                        {"domain_id": None, "domain_name": "Tabletop"},
                    ]
                },
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


def test_scenario_objects_take_identifiers_from_their_natural_key() -> None:
    document = normalise(EXPORT, EXTERNAL_ID, RULES).document
    implant = _injects(document)["Dump credentials"]["inject_injector_contract"]

    assert document["scenario_information"]["scenario_id"] == stable_id(NS, "scenario", EXTERNAL_ID)
    assert document["scenario_teams"][0]["team_id"] == stable_id(NS, "team", "Blue")
    assert document["scenario_variables"][0]["variable_id"] == stable_id(NS, "variable", "k")
    assert document["scenario_tags"][0]["tag_id"] == stable_id(NS, "tag", "crisis")
    assert implant["injector_contract_id"] == stable_id(NS, "contract", "Dump")
    assert implant["injector_contract_payload"]["payload_id"] == stable_id(NS, "payload", "Dump")


NAMED = [
    ("scenario_teams", "team_id", "team_name", "team"),
    ("scenario_variables", "variable_id", "variable_key", "variable"),
    ("scenario_tags", "tag_id", "tag_name", "tag"),
    ("scenario_documents", "document_id", "document_target", "document"),
    ("scenario_channels", "channel_id", "channel_name", "channel"),
    ("scenario_challenges", "challenge_id", "challenge_name", "challenge"),
    ("scenario_organizations", "organization_id", "organization_name", "organization"),
]


@pytest.mark.parametrize(("collection", "id_key", "name_key", "object_type"), NAMED)
def test_every_named_collection_takes_identifiers_from_its_key(
    collection: str, id_key: str, name_key: str, object_type: str
) -> None:
    export = copy.deepcopy(EXPORT)
    export[collection] = [{id_key: USER, name_key: "Alpha"}]

    document = normalise(export, EXTERNAL_ID, RULES).document

    assert document[collection][0][id_key] == stable_id(NS, object_type, "Alpha")


@pytest.mark.parametrize(("collection", "id_key", "name_key", "object_type"), NAMED)
def test_two_objects_with_the_same_key_are_refused(
    collection: str, id_key: str, name_key: str, object_type: str
) -> None:
    export = copy.deepcopy(EXPORT)
    export[collection] = [{id_key: USER, name_key: "Alpha"}, {id_key: AUTHOR, name_key: "Alpha"}]

    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


def test_two_payloads_with_the_same_name_are_refused() -> None:
    export = copy.deepcopy(EXPORT)
    twin = copy.deepcopy(export["scenario_injects"][1])
    twin["inject_id"] = USER
    twin["inject_title"] = "Dump again"
    twin["inject_injector_contract"]["injector_contract_id"] = AUTHOR
    twin["inject_injector_contract"]["injector_contract_payload"]["payload_id"] = ORGANISATION
    export["scenario_injects"].append(twin)

    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


def test_a_re_export_from_another_instance_gives_the_same_document() -> None:
    first = normalise(EXPORT, EXTERNAL_ID, RULES).document
    text = json.dumps(EXPORT)
    for number, identifier in enumerate(INSTANCE_IDS):
        text = text.replace(identifier, f"10000000-0000-4000-8000-{number:012x}")

    again = normalise(json.loads(text), EXTERNAL_ID, RULES, previous=first)

    assert again.document == first
    assert again.removed_injects == ()


def test_a_stored_document_normalised_with_itself_is_unchanged() -> None:
    stored = normalise(EXPORT, EXTERNAL_ID, RULES).document

    again = normalise(copy.deepcopy(stored), EXTERNAL_ID, RULES, previous=stored)

    assert again.document == stored
    assert again.removed_injects == ()


def test_an_identifier_in_capitals_inside_text_is_rewritten() -> None:
    export = copy.deepcopy(EXPORT)
    export["scenario_information"]["scenario_description"] = f"see {ATTACK_PATTERN.upper()}"

    document = normalise(export, EXTERNAL_ID, RULES).document

    pattern = stable_id(NS_OPENAEV_SCENARIOS, "attack-pattern", "T1003")
    assert document["scenario_information"]["scenario_description"] == f"see {pattern}"


def test_a_chained_scenario_is_refused() -> None:
    export = copy.deepcopy(EXPORT)
    export["scenario_workflow"] = {"workflow_steps": [{"step_id": USER}]}

    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


def _many_injects(count: int) -> dict[str, Any]:
    export = copy.deepcopy(EXPORT)
    export["scenario_injects"] = [
        {"inject_id": f"20000000-0000-4000-8000-{number:012x}", "inject_title": f"Step {number}"}
        for number in range(count)
    ]
    return export


def test_an_export_of_a_thousand_injects_is_accepted() -> None:
    assert (
        len(normalise(_many_injects(1000), EXTERNAL_ID, RULES).document["scenario_injects"]) == 1000
    )


def test_an_export_of_more_than_a_thousand_injects_is_refused() -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise(_many_injects(1001), EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


def _domain(name: str) -> str:
    return stable_id(NS_OPENAEV_SCENARIOS, "domain", name)


def test_built_in_contracts_keep_their_identifiers() -> None:
    mail = _injects(normalise(EXPORT, EXTERNAL_ID, RULES).document)["Ransom note"]

    assert mail["inject_injector_contract"]["injector_contract_id"] == BUILT_IN


def test_domains_take_identifiers_from_their_names() -> None:
    mail = _injects(normalise(EXPORT, EXTERNAL_ID, RULES).document)["Ransom note"]
    contract = mail["inject_injector_contract"]

    assert contract["injector_contract_domains"] == sorted(
        [_domain("E-mail Infiltration"), _domain("Tabletop")]
    )
    assert contract["convertedContent"]["domains"] == [
        {"domain_id": _domain("E-mail Infiltration"), "domain_name": "E-mail Infiltration"},
        {"domain_id": None, "domain_name": "Tabletop"},
    ]


def _with_domains(contract_fields: dict[str, Any]) -> dict[str, Any]:
    export = copy.deepcopy(EXPORT)
    contract = export["scenario_injects"][0]["inject_injector_contract"]
    del contract["convertedContent"]
    contract.update(contract_fields)
    return export


def test_without_converted_content_domains_are_named_by_the_contract_text() -> None:
    text = json.dumps({"domains": [{"domain_name": "Network"}, {"domain_name": "Cloud"}]})
    export = _with_domains({"injector_contract_content": text})

    mail = _injects(normalise(export, EXTERNAL_ID, RULES).document)["Ransom note"]

    assert mail["inject_injector_contract"]["injector_contract_domains"] == sorted(
        [_domain("Network"), _domain("Cloud")]
    )


@pytest.mark.parametrize(
    "contract_fields",
    [
        {"convertedContent": {"domains": [{"domain_name": "Network"}]}},
        {"injector_contract_content": json.dumps({"domains": [{"domain_name": "Network"}]})},
        {},
        {"convertedContent": {"domains": [{"domain_name": 1}, {"domain_name": "x"}]}},
        {"convertedContent": {"domains": "x"}},
        {"convertedContent": "x"},
        {
            "injector_contract_domains": [1, 2],
            "convertedContent": {"domains": [{"domain_name": "a"}, {"domain_name": "b"}]},
        },
        {
            "convertedContent": {
                "domains": [{"domain_name": "a"}, {"domain_name": "b"}, {"domain_name": "c"}]
            }
        },
        {
            "injector_contract_domains": ["x", "y"],
            "convertedContent": {"domains": [{"domain_name": "a"}, {"domain_name": "b"}]},
        },
    ],
    ids=[
        "copy too short",
        "text too short",
        "no copy",
        "name not text",
        "not a list",
        "not an object",
        "identifiers not text",
        "copy too long",
        "identifiers not UUIDs",
    ],
)
def test_a_domain_list_that_does_not_match_its_copy_is_refused(
    contract_fields: dict[str, Any],
) -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise(_with_domains(contract_fields), EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


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


def _with_content(content: object) -> dict[str, Any]:
    export = copy.deepcopy(EXPORT)
    export["scenario_injects"][1]["inject_injector_contract"]["injector_contract_content"] = content
    return export


def _content(document: dict[str, Any]) -> str:
    contract = _injects(document)["Dump credentials"]["inject_injector_contract"]
    text: str = contract["injector_contract_content"]
    return text


def test_volatile_fields_are_removed_inside_the_contract_copy_text() -> None:
    domain = {"domain_id": DOMAIN_A, "listened": True, "domain_created_at": "2026-03-23T10:28:12Z"}
    content = json.dumps(
        {"contract_id": PAYLOAD_CONTRACT, "label": {"en": "Dump é"}, "domains": [domain]},
        separators=(",", ":"),
        ensure_ascii=False,
    )

    document = normalise(_with_content(content), EXTERNAL_ID, RULES).document

    contract = stable_id(NS, "contract", "Dump")
    assert _content(document) == (
        f'{{"contract_id":"{contract}","label":{{"en":"Dump é"}},'
        f'"domains":[{{"domain_id":"{_domain("E-mail Infiltration")}"}}]}}'
    )


def test_a_contract_copy_text_without_volatile_fields_is_kept_as_it_is() -> None:
    content = f'{{"contract_id": "{PAYLOAD_CONTRACT}", "fields": [1, 2.50]}}'

    document = normalise(_with_content(content), EXTERNAL_ID, RULES).document

    contract = stable_id(NS, "contract", "Dump")
    assert _content(document) == f'{{"contract_id": "{contract}", "fields": [1, 2.50]}}'


def test_a_contract_copy_text_as_deep_as_allowed_is_accepted() -> None:
    content = "[" * 64 + "]" * 64

    document = normalise(_with_content(content), EXTERNAL_ID, RULES).document

    assert _content(document) == content


def test_a_contract_copy_without_text_keeps_none() -> None:
    document = normalise(_with_content(None), EXTERNAL_ID, RULES).document

    contract = _injects(document)["Dump credentials"]["inject_injector_contract"]
    assert contract["injector_contract_content"] is None


@pytest.mark.parametrize(
    "content",
    [
        "{",
        '{"a": NaN}',
        '{"a": 1e400}',
        '{"a": 1, "a": 2}',
        '{"a": 1} x',
        {"a": 1},
        "[" * 65 + "]" * 65,
        '{"a":' * 65 + "1" + "}" * 65,
        "[" * 100_000 + "]" * 100_000,
        '{"listened": true, "a": "\\ud800"}',
        '{"a": ' + "9" * 5000 + "}",
    ],
    ids=[
        "not JSON",
        "not a number",
        "out of range",
        "repeated key",
        "trailing text",
        "not text",
        "too deep",
        "too deep in objects",
        "deeper than the parser",
        "unpaired surrogate",
        "too many digits",
    ],
)
def test_a_contract_copy_text_that_is_not_json_is_refused(content: object) -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise(_with_content(content), EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


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
        [_domain("E-mail Infiltration"), _domain("Tabletop")]
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
            "scenario_teams": [{"team_id": SCENARIO, "team_name": "Blue"}],
        },
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_injects": [{"inject_injector_contract": "x"}],
        },
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_injects": [{"inject_injector_contract": {"injector_contract_payload": "x"}}],
        },
        {"scenario_information": {"scenario_id": BUILT_IN.upper()}},
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_teams": [{"team_id": "source-id"}],
        },
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_teams": [{"team_id": f"team-{TEAM}"}],
        },
        {
            "scenario_information": {
                "scenario_id": SCENARIO,
                "pattern": {"attack_pattern_id": "T1003", "attack_pattern_external_id": "T1003"},
            }
        },
        {
            "scenario_information": {
                "scenario_id": SCENARIO,
                "pattern": {"attack_pattern_id": ATTACK_PATTERN, "attack_pattern_external_id": ""},
            }
        },
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_injects": [{"inject_id": MAIL, "inject_title": "t", "inject_depends_on": 1}],
        },
        {"scenario_information": {"scenario_id": SCENARIO}, "scenario_teams": [{"team_id": TEAM}]},
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_teams": [{"team_id": TEAM, "team_name": ""}],
        },
        {"scenario_information": {"scenario_id": SCENARIO}, "scenario_objectives": [{"x": 1}]},
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_lessons_categories": [{"x": 1}],
        },
        {
            "scenario_information": {"scenario_id": SCENARIO},
            "scenario_lessons_questions": [{"x": 1}],
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
        "scenario id in capitals",
        "team id not a UUID",
        "team id holding a UUID",
        "attack pattern id not a UUID",
        "empty external identifier",
        "dependencies not a list",
        "team without a name",
        "team with an empty name",
        "objectives",
        "lessons categories",
        "lessons questions",
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
        {"removed": [], "removed_suffixes": [""], "sorted": []},
    ],
    ids=["not an object", "missing list", "not a list", "empty name"],
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

    assert document["scenario_information"]["by_team"] == {stable_id(NS, "team", "Blue"): "Blue"}


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


@pytest.mark.parametrize("previous", [[], [{"scenario_injects": []}], "text", 1])
def test_a_previous_version_that_is_not_an_object_is_refused(previous: Any) -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise(EXPORT, EXTERNAL_ID, RULES, previous=previous)
    assert error.value.code == "IO-014"


@pytest.mark.parametrize(
    "copy_inside",
    [
        {"injector_contract_content": "{}"},
        {"in_object": {"injector_contract_content": "{}"}},
        {"in_list": [{"injector_contract_content": "{}"}]},
    ],
    ids=["at the top", "in an object", "in a list"],
)
def test_a_contract_copy_inside_another_is_refused(copy_inside: dict[str, Any]) -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise(_with_content(json.dumps(copy_inside)), EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


def test_a_previous_inject_identifier_that_is_not_a_uuid_is_refused() -> None:
    previous = normalise(EXPORT, EXTERNAL_ID, RULES).document
    previous["scenario_injects"][0]["inject_id"] = "not-a-uuid"

    with pytest.raises(ExportStructureError) as error:
        normalise(EXPORT, EXTERNAL_ID, RULES, previous=previous, mapping={MAIL: "not-a-uuid"})
    assert error.value.code == "IO-014"


@pytest.mark.parametrize(
    "previous",
    [
        [],
        {"scenario_injects": [{"inject_id": MAIL}]},
        {"scenario_injects": [{"inject_id": MAIL, "inject_title": "t"}] * 2},
        {"scenario_injects": [{"inject_id": "x", "inject_title": "t"}]},
    ],
    ids=["not an object", "inject without title", "repeated inject", "not a UUID"],
)
def test_a_refusal_of_the_previous_version_says_so(previous: Any) -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise(EXPORT, EXTERNAL_ID, RULES, previous=previous)
    assert error.value.origin == "previous"


def test_a_refusal_of_the_export_says_so() -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise({"scenario_information": []}, EXTERNAL_ID, RULES)
    assert error.value.origin == "export"


def test_an_empty_payload_is_no_payload() -> None:
    export = copy.deepcopy(EXPORT)
    export["scenario_injects"][0]["inject_injector_contract"]["injector_contract_payload"] = {}

    mail = _injects(normalise(export, EXTERNAL_ID, RULES).document)["Ransom note"]

    assert mail["inject_injector_contract"]["injector_contract_id"] == BUILT_IN


def _channel_and_articles(*articles: tuple[str, str]) -> dict[str, Any]:
    export = copy.deepcopy(EXPORT)
    export["scenario_channels"] = [
        {"channel_id": USER, "channel_name": "Press"},
        {"channel_id": AUTHOR, "channel_name": "Radio"},
    ]
    channels = {"Press": USER, "Radio": AUTHOR}
    export["scenario_articles"] = [
        {"article_id": f"50000000-0000-4000-8000-{number:012x}", "article_name": name,
         "article_channel": channels[channel]}
        for number, (channel, name) in enumerate(articles)
    ]  # fmt: skip
    return export


def test_articles_take_identifiers_from_their_channel_and_name() -> None:
    export = _channel_and_articles(("Press", "Release"), ("Radio", "Release"))

    articles = normalise(export, EXTERNAL_ID, RULES).document["scenario_articles"]

    identifiers = [article["article_id"] for article in articles]
    assert identifiers == sorted(identifiers)
    assert sorted(identifiers) == sorted(
        [
            stable_id(NS, "article", json.dumps(["Press", "Release"])),
            stable_id(NS, "article", json.dumps(["Radio", "Release"])),
        ]
    )
    assert {article["article_channel"] for article in articles} == {
        stable_id(NS, "channel", "Press"),
        stable_id(NS, "channel", "Radio"),
    }


def test_two_articles_with_the_same_name_in_one_channel_are_refused() -> None:
    with pytest.raises(ExportStructureError) as error:
        normalise(
            _channel_and_articles(("Press", "Release"), ("Press", "Release")), EXTERNAL_ID, RULES
        )
    assert error.value.code == "IO-014"


@pytest.mark.parametrize(
    "article",
    [
        {"article_id": USER, "article_name": "Release", "article_channel": TEAM},
        {"article_id": USER, "article_name": "Release"},
        {"article_id": USER, "article_name": "", "article_channel": AUTHOR},
        {"article_id": USER, "article_name": "Release", "article_channel": [AUTHOR]},
    ],
    ids=["unknown channel", "no channel", "empty name", "channel not text"],
)
def test_an_article_without_a_known_channel_or_name_is_refused(article: dict[str, Any]) -> None:
    export = copy.deepcopy(EXPORT)
    export["scenario_channels"] = [{"channel_id": AUTHOR, "channel_name": "Press"}]
    export["scenario_articles"] = [article]

    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


def test_a_previous_version_of_another_entry_is_refused() -> None:
    other = normalise(EXPORT, "6b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42", RULES).document

    with pytest.raises(ExportStructureError) as error:
        normalise(EXPORT, EXTERNAL_ID, RULES, previous=other)
    assert (error.value.code, error.value.origin) == ("IO-014", "previous")
    assert str(error.value).startswith("not a previous version of this entry")


@pytest.mark.parametrize(
    ("content", "domains"),
    [
        ('{"a": "\\ud800"}', []),
        ('{"\\udc00": 1}', []),
        ('{"domains": [{"domain_name": "\\ud800"}]}', [DOMAIN_A]),
    ],
    ids=["in a value", "in a key", "in a domain name"],
)
def test_a_contract_copy_text_with_an_unpaired_surrogate_is_refused(
    content: str, domains: list[str]
) -> None:
    export = _with_content(content)
    export["scenario_injects"][1]["inject_injector_contract"]["injector_contract_domains"] = domains

    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


def test_converted_content_comes_before_the_contract_text_for_domains() -> None:
    text = json.dumps({"domains": [{"domain_name": "Network"}]})
    export = _with_domains(
        {
            "injector_contract_content": text,
            "convertedContent": {"domains": [{"domain_name": "Cloud"}]},
        }
    )
    export["scenario_injects"][0]["inject_injector_contract"]["injector_contract_domains"] = [
        DOMAIN_A
    ]

    mail = _injects(normalise(export, EXTERNAL_ID, RULES).document)["Ransom note"]

    assert mail["inject_injector_contract"]["injector_contract_domains"] == [_domain("Cloud")]


def test_domain_identifiers_inside_the_contract_text_are_rewritten() -> None:
    text = json.dumps(
        {
            "domains": [
                {"domain_id": DOMAIN_A, "domain_name": "Network"},
                {"domain_id": DOMAIN_B, "domain_name": "Cloud"},
            ]
        }
    )
    export = _with_domains({"injector_contract_content": text})

    mail = _injects(normalise(export, EXTERNAL_ID, RULES).document)["Ransom note"]

    decoded = json.loads(mail["inject_injector_contract"]["injector_contract_content"])
    assert [domain["domain_id"] for domain in decoded["domains"]] == [
        _domain("Network"),
        _domain("Cloud"),
    ]


def test_an_external_id_that_is_not_canonical_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="canonical"):
        normalise(EXPORT, EXTERNAL_ID.upper(), RULES)


def test_a_custom_contract_without_a_payload_is_refused() -> None:
    export = copy.deepcopy(EXPORT)
    export["scenario_injects"][0]["inject_injector_contract"]["injector_contract_custom"] = True

    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES)
    assert error.value.code == "IO-014"


def test_a_custom_contract_with_a_payload_is_accepted() -> None:
    export = copy.deepcopy(EXPORT)
    export["scenario_injects"][1]["inject_injector_contract"]["injector_contract_custom"] = True

    implant = _injects(normalise(export, EXTERNAL_ID, RULES).document)["Dump credentials"]

    assert implant["inject_injector_contract"]["injector_contract_id"] == stable_id(
        NS, "contract", "Dump"
    )
