"""The canonical form of a payload and its hash: what the repository, the release builder and the
platform must compute the same way (shared test vectors: ``conformance/payload-hash.json``)."""

from typing import Any

import pytest

from scenario_tools.domain.shared.canonical import ContentHash, jcs
from scenario_tools.domain.verification.payload_hash import (
    EmbeddedPayload,
    UnhashablePayloadError,
    canonical_payload,
    embedded_payloads,
    payload_hash,
)

FILE = "f4e16ee63844ece8ff5f335e71482784049fd1af4ff0e6d771321bed24a65b6a"
DOCUMENT = "10955664-c5d6-4cc9-8a50-deeb2d967969"
UNEXPECTED = "a value of an unexpected type"
UNKNOWN = "a field the canonical form of a payload does not know"
FOREIGN = "a field of another payload type"
TWICE = "a set holds the same item twice"
NO_BYTES = "the bytes of this attached file are not in the entry, so its hash cannot be computed"
REMEDIATION = (
    "a detection remediation names its security platform by an identifier, which the canonical "
    "form cannot use"
)
FREE_FORM = "a free-form object the canonical form does not cover yet"
TECHNIQUE = "each technique of the contract needs one external ID"


def _files(document: str) -> str | None:
    return FILE if document == DOCUMENT else None


def command(**fields: Any) -> dict[str, Any]:
    return {"payload_type": "Command", "payload_name": "Discovery", **fields}


def canonical(payload: object, attack_patterns: tuple[object, ...] = ()) -> dict[str, Any]:
    return canonical_payload(payload, attack_patterns, _files)


def refused(payload: object, attack_patterns: tuple[object, ...] = ()) -> UnhashablePayloadError:
    with pytest.raises(UnhashablePayloadError) as error:
        canonical_payload(payload, attack_patterns, _files)
    return error.value


def test_a_command_payload_keeps_its_fields_under_their_exported_names() -> None:
    payload = command(
        payload_description="Lists the users",
        payload_platforms=["Windows"],
        payload_execution_arch="ALL_ARCHITECTURES",
        payload_elevation_required=True,
        payload_expectations=["PREVENTION"],
        payload_cleanup_executor="psh",
        payload_cleanup_command="Remove-Item x",
        command_executor="psh",
        command_content="Get-LocalUser",
    )

    assert canonical(payload) == payload


def test_the_hash_is_the_sha256_of_the_jcs_of_the_canonical_form() -> None:
    assert payload_hash(command(command_content="whoami"), (), _files) == ContentHash.of_bytes(
        b'{"command_content":"whoami","payload_name":"Discovery","payload_type":"Command"}'
    )


@pytest.mark.parametrize(
    "key",
    [
        "payload_id",
        "payload_external_id",
        "payload_source",
        "payload_status",
        "payload_collector_type",
        "payload_author_user",
        "payload_author_team",
        "payload_author_organization",
        "payload_tags",
        "listened",
        "payload_created_at",
        "payload_updated_at",
    ],
)
def test_instance_fields_are_left_out(key: str) -> None:
    assert canonical(command(**{key: "a value"})) == command()


@pytest.mark.parametrize("key", ["x_id", "command_tags", "argument_created_at"])
def test_a_field_is_left_out_by_name_never_by_its_ending(key: str) -> None:
    error = refused(command(**{key: "curl evil"}))

    assert str(error) == f"/{key}: {UNKNOWN}"


@pytest.mark.parametrize("empty", [None, "", [], {}])
def test_an_empty_field_is_left_out(empty: object) -> None:
    assert canonical(command(payload_description=empty, payload_platforms=empty)) == command()


def test_false_and_zero_are_kept() -> None:
    payload = {
        "payload_type": "NetworkTraffic",
        "payload_elevation_required": False,
        "network_traffic_port_src": 0,
    }

    assert canonical(payload) == payload


@pytest.mark.parametrize(
    ("given", "kept"),
    [
        (["Windows", "Linux"], ["Linux", "Windows"]),
        # UTF-16 code units, as JCS orders keys: a character outside the basic plane sorts before
        # U+E000 to U+FFFF, and after every other character of the basic plane.
        (["\uffff", "\U0001f600"], ["\U0001f600", "\uffff"]),
        (["\ue000", "\U00010000"], ["\U00010000", "\ue000"]),
        (["\uffff", "\U00010000"], ["\U00010000", "\uffff"]),
        (["\U00010000", "\ud7ff"], ["\ud7ff", "\U00010000"]),
        (["\U0010ffff", "\U00010000"], ["\U00010000", "\U0010ffff"]),
        (["\uffff", "\ue000"], ["\ue000", "\uffff"]),
        (["ab", "a"], ["a", "ab"]),
    ],
)
def test_a_set_of_texts_is_sorted(given: list[str], kept: list[str]) -> None:
    assert canonical(command(payload_platforms=given))["payload_platforms"] == kept


def test_the_techniques_of_the_contract_enter_sorted_by_their_external_id() -> None:
    assert canonical(command(), ("T1082", "T1059.001")) == command(
        payload_attack_patterns=["T1059.001", "T1082"]
    )


@pytest.mark.parametrize("techniques", [("T1082", None), ("T1082", 1), ("T1082", "")])
def test_a_technique_without_one_external_id_is_refused_on_the_contract(
    techniques: tuple[object, ...],
) -> None:
    error = refused(command(), techniques)

    assert (str(error), error.on_contract, error.code) == (
        f"/injector_contract_attack_patterns: {TECHNIQUE}",
        True,
        "PAY-005",
    )


def test_a_technique_held_twice_is_refused_on_the_contract() -> None:
    error = refused(command(), ("T1082", "T1082"))

    assert (str(error), error.on_contract) == (f"/injector_contract_attack_patterns: {TWICE}", True)


def test_expected_security_platforms_are_sets_by_expectation() -> None:
    payload = command(
        payload_expected_security_platforms={
            "PREVENTION": ["XDR", "EDR"],
            "DETECTION": [],
            "MANUAL": None,
        }
    )

    assert canonical(payload) == command(
        payload_expected_security_platforms={"PREVENTION": ["EDR", "XDR"]}
    )


def test_arguments_and_prerequisites_keep_their_order_and_lose_their_empty_fields() -> None:
    payload = command(
        payload_arguments=[
            {
                "type": "text",
                "key": "b",
                "default_value": "2",
                "description": None,
                "separator": "",
            },
            {"type": "text", "key": "a", "default_value": "1", "description": "First"},
        ],
        payload_prerequisites=[
            {"executor": "psh", "get_command": "get b", "check_command": None, "description": ""},
            {"executor": "cmd", "get_command": "get a", "check_command": "check a"},
            {"get_command": [], "description": None},
        ],
    )

    assert canonical(payload) == command(
        payload_arguments=[
            {"type": "text", "key": "b", "default_value": "2"},
            {"type": "text", "key": "a", "default_value": "1", "description": "First"},
        ],
        payload_prerequisites=[
            {"executor": "psh", "get_command": "get b"},
            {"executor": "cmd", "get_command": "get a", "check_command": "check a"},
        ],
    )


def test_a_document_argument_enters_by_the_hash_of_its_file() -> None:
    payload = command(
        payload_arguments=[
            {"type": "document", "key": "tool", "default_value": DOCUMENT},
            {"type": "text", "key": "path", "default_value": DOCUMENT},
            {"type": "document", "key": "none"},
        ]
    )

    assert canonical(payload)["payload_arguments"] == [
        {"type": "document", "key": "tool", "default_value": FILE},
        {"type": "text", "key": "path", "default_value": DOCUMENT},
        {"type": "document", "key": "none"},
    ]


def test_output_parsers_lose_their_instance_fields_and_are_sorted_at_every_level() -> None:
    parsers = [
        {
            "output_parser_id": "1",
            "listened": True,
            "output_parser_created_at": "2026-10-13T00:00:00Z",
            "output_parser_updated_at": "2026-10-13T00:00:00Z",
            "output_parser_mode": "STDERR",
            "output_parser_type": "REGEX",
            "output_parser_contract_output_elements": [],
        },
        {
            "output_parser_mode": "STDOUT",
            "output_parser_type": "REGEX",
            "output_parser_contract_output_elements": [
                {
                    "contract_output_element_id": "2",
                    "listened": True,
                    "contract_output_element_tags": ["t"],
                    "contract_output_element_created_at": "2026-10-13T00:00:00Z",
                    "contract_output_element_updated_at": "2026-10-13T00:00:00Z",
                    "contract_output_element_key": "beta",
                    "contract_output_element_is_finding": False,
                    "contract_output_element_regex_groups": [
                        {
                            "regex_group_id": "3",
                            "listened": True,
                            "regex_group_created_at": "2026-10-13T00:00:00Z",
                            "regex_group_updated_at": "2026-10-13T00:00:00Z",
                            "regex_group_field": "port",
                            "regex_group_index_values": "$2",
                        },
                        {"regex_group_field": "host", "regex_group_index_values": "$1"},
                    ],
                },
                {
                    "contract_output_element_key": "alpha",
                    "contract_output_element_name": "Alpha",
                    "contract_output_element_rule": "(\\w+)",
                    "contract_output_element_type": "text",
                    "contract_output_element_is_finding": True,
                },
            ],
        },
    ]

    # Each set is sorted by the canonical text of its items, given here in reverse.
    assert canonical(command(payload_output_parsers=parsers))["payload_output_parsers"] == [
        {
            "output_parser_contract_output_elements": [
                {
                    "contract_output_element_is_finding": False,
                    "contract_output_element_key": "beta",
                    "contract_output_element_regex_groups": [
                        {"regex_group_field": "host", "regex_group_index_values": "$1"},
                        {"regex_group_field": "port", "regex_group_index_values": "$2"},
                    ],
                },
                {
                    "contract_output_element_is_finding": True,
                    "contract_output_element_key": "alpha",
                    "contract_output_element_name": "Alpha",
                    "contract_output_element_rule": "(\\w+)",
                    "contract_output_element_type": "text",
                },
            ],
            "output_parser_mode": "STDOUT",
            "output_parser_type": "REGEX",
        },
        {"output_parser_mode": "STDERR", "output_parser_type": "REGEX"},
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"payload_type": "Executable", "executable_file": DOCUMENT},
        {"payload_type": "FileDrop", "file_drop_file": DOCUMENT},
    ],
)
def test_an_attached_file_enters_by_the_hash_of_its_bytes(payload: dict[str, Any]) -> None:
    (field,) = (key for key in payload if key != "payload_type")

    assert canonical(payload) == {**payload, field: FILE}


@pytest.mark.parametrize(
    "payload",
    [
        {"payload_type": "DnsResolution", "dns_resolution_hostname": "host.example.com"},
        {
            "payload_type": "NetworkTraffic",
            "network_traffic_ip_src": "192.0.2.1",
            "network_traffic_ip_dst": "192.0.2.2",
            "network_traffic_port_src": 4444,
            "network_traffic_port_dst": 9_007_199_254_740_991,
            "network_traffic_protocol": "TCP",
        },
        {
            "payload_type": "AiAttack",
            "ai_attack_engine": "native",
            "ai_attack_category": "jailbreak",
            "ai_attack_content": "Say hello",
            "ai_attack_converters": ["leetspeak", "base64"],
        },
    ],
)
def test_every_other_type_keeps_its_own_fields(payload: dict[str, Any]) -> None:
    assert canonical(payload) == payload


def test_an_empty_field_of_another_type_or_free_form_object_is_left_out() -> None:
    payload = command(
        dns_resolution_hostname=None,
        executable_file="",
        ai_attack_converters=[],
        payload_detection_remediations=[],
    )

    assert canonical(payload) == command()
    assert canonical({"payload_type": "AiAttack", "ai_attack_multi_turn": {}}) == {
        "payload_type": "AiAttack"
    }


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("not a payload", f"(payload): {UNEXPECTED}"),
        ({"payload_type": "Teleport"}, "/payload_type: an unknown payload type"),
        ({"payload_name": "No type"}, "/payload_type: an unknown payload type"),
        ({"payload_type": ["Command"]}, "/payload_type: an unknown payload type"),
        (command(payload_new_field="x"), f"/payload_new_field: {UNKNOWN}"),
        (command(**{"a/b~c": 0}), f"/a~1b~0c: {UNKNOWN}"),
        (
            command(dns_resolution_hostname="host.example.com"),
            f"/dns_resolution_hostname: {FOREIGN}",
        ),
        (
            command(payload_detection_remediations=[{"x": 1}]),
            f"/payload_detection_remediations: {REMEDIATION}",
        ),
        (
            {"payload_type": "AiAttack", "ai_attack_multi_turn": {"turns": 2}},
            f"/ai_attack_multi_turn: {FREE_FORM}",
        ),
        (
            {"payload_type": "AiAttack", "ai_attack_success_detector": {"k": 1}},
            f"/ai_attack_success_detector: {FREE_FORM}",
        ),
        (
            {"payload_type": "Executable", "executable_file": "another"},
            f"/executable_file: {NO_BYTES}",
        ),
        ({"payload_type": "FileDrop", "file_drop_file": 1}, f"/file_drop_file: {UNEXPECTED}"),
        (
            command(
                payload_arguments=[{"key": "a"}, {"type": "document", "default_value": "another"}]
            ),
            f"/payload_arguments/1/default_value: {NO_BYTES}",
        ),
        (command(payload_name=1), f"/payload_name: {UNEXPECTED}"),
        (command(payload_name="\ud800"), f"/payload_name: {UNEXPECTED}"),
        (command(payload_elevation_required="true"), f"/payload_elevation_required: {UNEXPECTED}"),
        (
            {"payload_type": "NetworkTraffic", "network_traffic_port_dst": "443"},
            f"/network_traffic_port_dst: {UNEXPECTED}",
        ),
        (
            {"payload_type": "NetworkTraffic", "network_traffic_port_dst": True},
            f"/network_traffic_port_dst: {UNEXPECTED}",
        ),
        (
            {"payload_type": "NetworkTraffic", "network_traffic_port_dst": 2**53},
            f"/network_traffic_port_dst: {UNEXPECTED}",
        ),
        (
            {"payload_type": "NetworkTraffic", "network_traffic_port_dst": -(2**53)},
            f"/network_traffic_port_dst: {UNEXPECTED}",
        ),
        (command(payload_platforms="Windows"), f"/payload_platforms: {UNEXPECTED}"),
        (command(payload_platforms=["Windows", 1]), f"/payload_platforms/1: {UNEXPECTED}"),
        (command(payload_platforms=["Windows", ""]), f"/payload_platforms/1: {UNEXPECTED}"),
        (
            command(payload_platforms=["Windows", "Linux", "Windows"]),
            f"/payload_platforms: {TWICE}",
        ),
        (
            {"payload_type": "AiAttack", "ai_attack_converters": ["a", None]},
            f"/ai_attack_converters/1: {UNEXPECTED}",
        ),
        ({"payload_type": "AiAttack", "ai_attack_converters": ["a", "a"]}, None),
        (
            command(payload_expected_security_platforms=["EDR"]),
            f"/payload_expected_security_platforms: {UNEXPECTED}",
        ),
        (
            command(payload_expected_security_platforms={"a/b": "EDR"}),
            f"/payload_expected_security_platforms/a~1b: {UNEXPECTED}",
        ),
        (
            command(payload_expected_security_platforms={"P": ["EDR", 1]}),
            f"/payload_expected_security_platforms/P/1: {UNEXPECTED}",
        ),
        (command(payload_arguments="x"), f"/payload_arguments: {UNEXPECTED}"),
        (command(payload_arguments=["x"]), f"/payload_arguments/0: {UNEXPECTED}"),
        (command(payload_arguments=[{"key": 1}]), f"/payload_arguments/0/key: {UNEXPECTED}"),
        (
            command(payload_arguments=[{"argument_id": "1"}]),
            f"/payload_arguments/0/argument_id: {UNKNOWN}",
        ),
        (
            command(payload_prerequisites=[{"get_command": [1]}]),
            f"/payload_prerequisites/0/get_command: {UNEXPECTED}",
        ),
        (command(payload_output_parsers="x"), f"/payload_output_parsers: {UNEXPECTED}"),
        (
            command(
                payload_output_parsers=[{"output_parser_mode": "A"}, {"output_parser_mode": "A"}]
            ),
            f"/payload_output_parsers: {TWICE}",
        ),
        (
            command(
                payload_output_parsers=[
                    {
                        "output_parser_contract_output_elements": [
                            {"contract_output_element_is_finding": "yes"}
                        ]
                    }
                ]
            ),
            "/payload_output_parsers/0/output_parser_contract_output_elements/0"
            f"/contract_output_element_is_finding: {UNEXPECTED}",
        ),
        (
            command(
                payload_output_parsers=[
                    {
                        "output_parser_contract_output_elements": [
                            {"contract_output_element_regex_groups": [{"regex_group_tags": "x"}]}
                        ]
                    }
                ]
            ),
            "/payload_output_parsers/0/output_parser_contract_output_elements/0"
            f"/contract_output_element_regex_groups/0/regex_group_tags: {UNKNOWN}",
        ),
    ],
)
def test_what_cannot_be_hashed_without_guessing_is_refused(
    payload: object, message: str | None
) -> None:
    if message is None:  # an ordered list may repeat an item
        assert canonical(payload)["ai_attack_converters"] == ["a", "a"]
        return
    error = refused(payload)

    assert (str(error), error.code, error.on_contract) == (message, "PAY-005", False)
    assert error.field == message.split(": ", 1)[0].replace("(payload)", "")


def test_the_refusal_names_the_field_never_its_value() -> None:
    error = refused(command(payload_new_field="secret-value"))

    assert "secret-value" not in str(error)
    assert error.reason == UNKNOWN


def test_the_file_hash_is_asked_only_for_a_file() -> None:
    asked: list[str] = []

    def files(document: str) -> str | None:
        asked.append(document)
        return FILE

    canonical_payload(
        command(payload_arguments=[{"type": "text", "default_value": "x"}]), (), files
    )

    assert asked == []


def test_a_file_hash_that_is_not_a_sha256_is_a_fault_of_the_caller() -> None:
    with pytest.raises(ValueError, match="not a SHA-256 hex digest"):
        canonical_payload(
            {"payload_type": "FileDrop", "file_drop_file": DOCUMENT}, (), lambda _: "ABC"
        )


def test_the_canonical_text_of_a_rich_payload() -> None:
    payload = command(
        command_content="café",
        payload_arguments=[{"type": "document", "key": "tool", "default_value": DOCUMENT}],
        payload_output_parsers=[{"output_parser_mode": "STDOUT", "output_parser_type": "REGEX"}],
        payload_expected_security_platforms={"PREVENTION": ["EDR"]},
    )

    assert jcs(canonical(payload, ("T1082",))) == (
        b'{"command_content":"caf\xc3\xa9","payload_arguments":[{"default_value":"'
        + FILE.encode()
        + b'","key":"tool","type":"document"}],"payload_attack_patterns":["T1082"],'
        b'"payload_expected_security_platforms":{"PREVENTION":["EDR"]},'
        b'"payload_name":"Discovery","payload_output_parsers":[{"output_parser_mode":"STDOUT",'
        b'"output_parser_type":"REGEX"}],"payload_type":"Command"}'
    )


def _stored(*injects: object) -> dict[str, Any]:
    return {"scenario_injects": list(injects)}


def test_embedded_payloads_come_with_the_techniques_of_their_contract() -> None:
    payload = command(command_content="whoami")
    stored = _stored(
        {"inject_injector_contract": {"injector_contract_payload": None}},
        {
            "inject_injector_contract": {
                "injector_contract_payload": payload,
                "injector_contract_attack_patterns": [
                    {"attack_pattern_external_id": "T1082", "attack_pattern_name": "System"},
                    {"attack_pattern_name": "No external ID"},
                    "not an object",
                ],
            }
        },
    )

    assert list(embedded_payloads(stored)) == [
        EmbeddedPayload(
            "/scenario_injects/1/inject_injector_contract", payload, ("T1082", None, None)
        )
    ]


@pytest.mark.parametrize(
    ("held", "techniques"),
    [(None, ()), ([], ()), ("x", (None,)), ({"a": 1}, (None,)), ("", (None,)), ({}, (None,))],
)
def test_techniques_the_contract_does_not_list_are_refused_later(
    held: object, techniques: tuple[object, ...]
) -> None:
    stored = _stored(
        {
            "inject_injector_contract": {
                "injector_contract_payload": "not a payload",
                "injector_contract_attack_patterns": held,
            }
        }
    )

    (embedded,) = embedded_payloads(stored)
    assert (embedded.payload, embedded.attack_patterns) == ("not a payload", techniques)


def test_a_refusal_is_located_in_the_payload_or_in_its_contract() -> None:
    embedded = EmbeddedPayload("/scenario_injects/3/inject_injector_contract", command(), (None,))

    assert (
        embedded.pointer == "/scenario_injects/3/inject_injector_contract/injector_contract_payload"
    )
    assert embedded.locate(refused(command(payload_name=1))) == (
        "/scenario_injects/3/inject_injector_contract/injector_contract_payload/payload_name"
    )
    assert embedded.locate(refused(command(), (None,))) == (
        "/scenario_injects/3/inject_injector_contract/injector_contract_attack_patterns"
    )
    assert embedded.locate(refused("x")) == (
        "/scenario_injects/3/inject_injector_contract/injector_contract_payload"
    )


def test_a_field_whose_content_is_all_left_out_is_left_out_too() -> None:
    payload = command(
        payload_expected_security_platforms={"DETECTION": [], "PREVENTION": None},
        payload_arguments=[{"description": None, "separator": ""}],
        payload_output_parsers=[{"output_parser_id": "1", "listened": True}],
    )

    assert canonical(payload) == command()


def test_an_empty_or_instance_field_ahead_of_others_does_not_stop_the_reading() -> None:
    payload = {
        "payload_id": "1",
        "payload_description": None,
        "payload_type": "Command",
        "payload_expected_security_platforms": {"DETECTION": [], "PREVENTION": ["EDR"]},
        "payload_arguments": [{"description": None, "key": "a"}],
        "payload_output_parsers": [
            {
                "output_parser_id": "1",
                "output_parser_mode": "STDOUT",
                "output_parser_contract_output_elements": [
                    {
                        "contract_output_element_tags": [],
                        "contract_output_element_key": "k",
                        "contract_output_element_regex_groups": [
                            {"regex_group_id": "2", "regex_group_field": "f"}
                        ],
                    }
                ],
            }
        ],
    }

    assert canonical(payload) == {
        "payload_type": "Command",
        "payload_expected_security_platforms": {"PREVENTION": ["EDR"]},
        "payload_arguments": [{"key": "a"}],
        "payload_output_parsers": [
            {
                "output_parser_mode": "STDOUT",
                "output_parser_contract_output_elements": [
                    {
                        "contract_output_element_key": "k",
                        "contract_output_element_regex_groups": [{"regex_group_field": "f"}],
                    }
                ],
            }
        ],
    }


@pytest.mark.parametrize("character", [chr(0xD800), chr(0xDBFF), chr(0xDC00), chr(0xDFFF)])
def test_a_text_holding_a_lone_surrogate_is_refused(character: str) -> None:
    assert str(refused(command(command_content=f"a{character}b"))) == (
        f"/command_content: {UNEXPECTED}"
    )


@pytest.mark.parametrize("character", ["퟿", "", "\U0001f600"])
def test_a_text_holding_any_other_character_is_kept(character: str) -> None:
    assert canonical(command(command_content=character))["command_content"] == character


def test_the_techniques_are_ordered_as_any_other_set_of_texts() -> None:
    assert canonical(command(), ("￿", "\U0001f600"))["payload_attack_patterns"] == [
        "\U0001f600",
        "￿",
    ]


def test_the_hash_of_a_payload_with_an_attached_file() -> None:
    assert payload_hash({"payload_type": "FileDrop", "file_drop_file": DOCUMENT}, (), _files) == (
        ContentHash.of_bytes(
            b'{"file_drop_file":"' + FILE.encode() + b'","payload_type":"FileDrop"}'
        )
    )


@pytest.mark.parametrize("techniques", [(chr(0xD800),), "T1082"])
def test_a_technique_that_is_no_text_or_a_bare_text_is_refused(techniques: object) -> None:
    error = refused(command(), techniques)  # type: ignore[arg-type]

    assert (str(error), error.on_contract) == (
        f"/injector_contract_attack_patterns: {TECHNIQUE}",
        True,
    )


def test_a_key_of_the_expected_security_platforms_is_a_text_too() -> None:
    error = refused(command(payload_expected_security_platforms={chr(0xD800): ["EDR"]}))

    assert (error.field, error.reason) == (
        f"/payload_expected_security_platforms/{chr(0xD800)}",
        UNEXPECTED,
    )
