"""The payload references of an entry: each payload a scenario embeds carries, in its
``payload_external_id``, the ID its content has, the one derived from its hash or the one the
registry agrees for it, and one reference of ``scenario.yaml`` gives that ID with the hash."""

import copy
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.catalogue.identifiers import NS_OPENAEV_SCENARIOS, stable_id
from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.payload_hash import (
    UnhashablePayloadError,
    embedded_payloads,
    payload_hash,
)
from scenario_tools.domain.verification.payload_references import (
    AgreedId,
    AgreedIds,
    HeldVersions,
    PayloadReference,
    assign,
    declared_references,
    derived_id,
    reference_findings,
    unhashable_findings,
)

JSON = "scenarios/techniques/x/scenario.json"
YAML = "scenarios/techniques/x/scenario.yaml"
CONTRACT = "/scenario_injects/{}/inject_injector_contract"
PAYLOAD = CONTRACT + "/injector_contract_payload"
FIELD = PAYLOAD + "/payload_external_id"
RUN = "run `scenario-tools payloads --assign`"
NONE = AgreedIds({})
ID_RULE = (
    "an id is lower-case letters, digits and ':._-', starting with a letter or a digit, at most "
    "128 characters"
)
DERIVED_FORM = "an id is never a UUID v5, the form of the IDs derived from contents"
WRONG_ID = (
    "this ID is not the one its content has (the ID derived from its hash, or the one "
    "policy/data/payload-ids.yaml agrees for it): a changed payload takes a new ID; " + RUN
)


def _no_files(document: str) -> str | None:
    return None


def payload(name: str, content: str = "whoami", **fields: Any) -> dict[str, Any]:
    return {"payload_type": "Command", "payload_name": name, "command_content": content, **fields}


def stored(*payloads: object, techniques: object = None) -> dict[str, Any]:
    contract: dict[str, Any] = {}
    if techniques is not None:
        contract["injector_contract_attack_patterns"] = techniques
    return {
        "scenario_injects": [
            {"inject_injector_contract": {**contract, "injector_contract_payload": item}}
            for item in payloads
        ]
    }


def digest(item: dict[str, Any], techniques: tuple[object, ...] = ()) -> str:
    return payload_hash(item, techniques, _no_files).hex


def named(item: dict[str, Any], identifier: str = "") -> dict[str, Any]:
    """``item`` carrying ``identifier``, by default the ID derived from its hash."""
    return {**item, "payload_external_id": identifier or derived_id(digest(item))}


def reference(
    item: dict[str, Any], identifier: str = "", version: str = "1.0.0"
) -> PayloadReference:
    return PayloadReference(identifier or derived_id(digest(item)), version, digest(item))


EMPTY = HeldVersions.of([])


def held(
    scenario: object,
    agreed: AgreedIds = NONE,
    references: tuple[PayloadReference, ...] = (),
    files: Callable[[str], str | None] = _no_files,
) -> HeldVersions:
    """A catalogue holding each payload ``scenario`` embeds as its version 1.0.0, and the
    versions ``references`` name, so that a test of another rule reads the catalogue as
    agreeing."""
    versions = []
    for embedded in embedded_payloads(scenario):
        try:
            hashed = payload_hash(embedded.payload, embedded.attack_patterns, files).hex
        except UnhashablePayloadError:
            continue
        versions.append(PayloadReference(agreed.id_for(hashed), "1.0.0", hashed))
    return HeldVersions.of([*versions, *references])


def findings(
    scenario: object,
    references: tuple[PayloadReference, ...],
    agreed: AgreedIds = NONE,
    catalogue: HeldVersions | None = None,
) -> list[tuple[str, str, str, str]]:
    return [
        (f.code, f.path, f.field, f.message)
        for f in reference_findings(
            scenario,
            references,
            agreed=agreed,
            catalogue=held(scenario, agreed, references) if catalogue is None else catalogue,
            scenario=JSON,
            metadata=YAML,
            files=_no_files,
        )
    ]


# IDs


def test_a_payload_s_id_is_derived_from_its_hash_alone() -> None:
    hex_digest = "a" * 64

    assert derived_id(hex_digest) == stable_id(NS_OPENAEV_SCENARIOS, "payload-content", hex_digest)
    assert derived_id(hex_digest) != derived_id("b" * 64)


def test_the_registry_agrees_an_id_for_one_content_and_derives_the_others() -> None:
    agreed = AgreedIds({"a" * 64: AgreedId("agreed", "A")})

    assert (agreed.id_for("a" * 64), agreed.id_for("b" * 64)) == ("agreed", derived_id("b" * 64))


def test_the_registry_is_read_from_its_document() -> None:
    document = {
        "payloads": [
            {"id": "13973155-b166-4bbf-a34a-6b74c0d92957", "name": "A", "sha256": "a" * 64},
            {"id": "agreed:1.x_y-z", "name": "B", "sha256": "b" * 64},
        ]
    }

    assert AgreedIds.from_document(document) == AgreedIds(
        {
            "a" * 64: AgreedId("13973155-b166-4bbf-a34a-6b74c0d92957", "A"),
            "b" * 64: AgreedId("agreed:1.x_y-z", "B"),
        }
    )
    assert AgreedIds.from_document({"payloads": []}) == NONE


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "the document must be a mapping holding payloads"),
        ({"payloads": "x"}, "the document must be a mapping holding payloads"),
        ({"payloads": [], "b": 1, "a": 2}, "unknown keys a, b"),
        ({"payloads": ["x"]}, "each payload is an id, a name and a sha256"),
        ({"payloads": [{"id": "a", "name": "A"}]}, "each payload is an id, a name and a sha256"),
        (
            {"payloads": [{"id": "a", "name": "A", "sha256": "a" * 64, "x": 1}]},
            "each payload is an id, a name and a sha256",
        ),
        (
            {"payloads": [{"id": "-a", "name": "A", "sha256": "a" * 64}]},
            ID_RULE,
        ),
        ({"payloads": [{"id": "Agreed", "name": "A", "sha256": "a" * 64}]}, ID_RULE),
        (
            {"payloads": [{"id": derived_id("b" * 64), "name": "A", "sha256": "a" * 64}]},
            DERIVED_FORM,
        ),
        (
            {"payloads": [{"id": "a" * 129, "name": "A", "sha256": "a" * 64}]},
            ID_RULE,
        ),
        (
            {"payloads": [{"id": 1, "name": "A", "sha256": "a" * 64}]},
            ID_RULE,
        ),
        ({"payloads": [{"id": "a", "name": "", "sha256": "a" * 64}]}, "a name is a text"),
        ({"payloads": [{"id": "a", "name": 1, "sha256": "a" * 64}]}, "a name is a text"),
        (
            {"payloads": [{"id": "a", "name": "A", "sha256": "A" * 64}]},
            "a sha256 is 64 hexadecimal digits in lower case",
        ),
        (
            {"payloads": [{"id": "a", "name": "A", "sha256": "a" * 63}]},
            "a sha256 is 64 hexadecimal digits in lower case",
        ),
        (
            {"payloads": [{"id": "a", "name": "A", "sha256": 1}]},
            "a sha256 is 64 hexadecimal digits in lower case",
        ),
        (
            {
                "payloads": [
                    {"id": "a", "name": "A", "sha256": "a" * 64},
                    {"id": "a", "name": "B", "sha256": "b" * 64},
                ]
            },
            "each id once",
        ),
        (
            {
                "payloads": [
                    {"id": "a", "name": "A", "sha256": "a" * 64},
                    {"id": "b", "name": "B", "sha256": "a" * 64},
                ]
            },
            "each sha256 once: one content has one ID",
        ),
    ],
)
def test_a_malformed_registry_is_refused(document: object, message: str) -> None:
    with pytest.raises(ValueError, match=f"^payload-ids: {message}$"):
        AgreedIds.from_document(document)


def test_references_are_read_from_the_metadata() -> None:
    metadata = {
        "payloads": [
            {"id": "a", "version": "1.0.0", "sha256": "1" * 64},
            {"id": "b", "version": "1.2.0", "sha256": "2" * 64},
        ]
    }

    assert declared_references(metadata) == (
        PayloadReference("a", "1.0.0", "1" * 64),
        PayloadReference("b", "1.2.0", "2" * 64),
    )


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        [],
        {},
        {"payloads": "x"},
        {"payloads": ["x", {"id": "a"}, {"id": 1, "version": "1.0.0", "sha256": "1"}]},
    ],
)
def test_a_reference_not_shaped_as_one_names_nothing(metadata: object) -> None:
    assert declared_references(metadata) == ()


# The check


def test_payloads_carrying_the_id_their_content_has_pass() -> None:
    first, second = named(payload("a")), named(payload("b", "id"), "agreed")
    agreed = AgreedIds({digest(second): AgreedId("agreed", "b")})

    assert (
        findings(
            stored(first, second, copy.deepcopy(first)),
            (reference(first), reference(second, "agreed")),
            agreed,
        )
        == []
    )


def test_a_payload_carrying_no_id_or_one_no_reference_gives_is_refused() -> None:
    unnamed, unknown = payload("a"), named(payload("b", "id"))

    assert findings(stored(unnamed, unknown), ()) == [
        (
            "PAY-001",
            JSON,
            FIELD.format(index),
            f"no reference of scenario.yaml names this payload: {RUN}",
        )
        for index in (0, 1)
    ]


@pytest.mark.parametrize("carried", [1, None, ["x"]])
def test_an_id_that_is_no_text_names_nothing(carried: object) -> None:
    item = payload("a", payload_external_id=carried)

    assert [code for code, *_ in findings(stored(item), ())] == ["PAY-001"]


def test_a_changed_payload_still_carrying_its_old_id_is_refused() -> None:
    before = payload("a")
    after = named(payload("a", "id; curl example"), derived_id(digest(before)))

    assert findings(stored(after), (reference(before),)) == [
        ("PAY-003", JSON, FIELD.format(0), WRONG_ID)
    ]


def test_an_agreed_id_on_another_content_is_refused() -> None:
    agreed_content, other = payload("a"), named(payload("a", "id"), "agreed")
    agreed = AgreedIds({digest(agreed_content): AgreedId("agreed", "a")})

    assert findings(stored(other), (reference(other, "agreed"),), agreed) == [
        ("PAY-003", JSON, FIELD.format(0), WRONG_ID)
    ]


def test_a_derived_id_for_content_the_registry_agrees_another_id_is_refused() -> None:
    item = named(payload("a"))

    assert [
        code
        for code, *_ in findings(
            stored(item), (reference(item),), AgreedIds({digest(item): AgreedId("agreed", "a")})
        )
    ] == ["PAY-003"]


def test_a_reference_whose_hash_is_not_its_payload_s_is_refused_once() -> None:
    item = named(payload("a"))
    stale = PayloadReference(item["payload_external_id"], "1.0.0", "0" * 64)

    assert findings(stored(item, copy.deepcopy(item)), (stale,)) == [
        (
            "PAY-002",
            YAML,
            "/payloads/0/sha256",
            f"this hash is not the hash of the payload the reference names: {RUN}",
        )
    ]


def test_a_reference_whose_version_is_not_the_file_s_is_refused() -> None:
    item = named(payload("a"))

    assert findings(
        stored(item), (reference(item, version="1.1.0"),), catalogue=held(stored(item))
    ) == [
        (
            "PAY-008",
            YAML,
            "/payloads/0/version",
            f"the version file with this ID is another version: {RUN}",
        )
    ]


def test_two_references_giving_one_id_are_refused_and_the_first_counts() -> None:
    item = named(payload("a"))
    stale = PayloadReference(item["payload_external_id"], "1.0.0", "0" * 64)

    assert findings(stored(item), (reference(item), stale), catalogue=held(stored(item))) == [
        (
            "PAY-002",
            YAML,
            "/payloads/1/id",
            "two references give this ID: each payload has one reference",
        )
    ]


def test_a_reference_naming_no_embedded_payload_is_refused() -> None:
    item = named(payload("a"))

    assert findings(stored(item), (reference(item), reference(payload("b")))) == [
        (
            "PAY-006",
            YAML,
            "/payloads/1",
            f"this reference names no payload the scenario embeds: {RUN}, which drops it",
        )
    ]


def test_the_reference_of_a_payload_refused_otherwise_is_not_said_to_name_nothing() -> None:
    hashable = named(payload("a"))
    unhashable = {**hashable, "payload_new_field": "x"}
    wrong = named(payload("b", "id"), derived_id(digest(payload("a"))) + "x")

    found = findings(
        stored(unhashable, wrong),
        (reference(hashable), reference(payload("b"), wrong["payload_external_id"])),
    )

    assert [code for code, *_ in found] == ["PAY-005", "PAY-003"]


def test_a_payload_that_cannot_be_hashed_is_refused_where_it_fails() -> None:
    scenario = stored(payload("a", payload_new_field="x"), "not a payload")
    scenario["scenario_injects"].append(
        {
            "inject_injector_contract": {
                "injector_contract_payload": payload("b"),
                "injector_contract_attack_patterns": "x",
            }
        }
    )

    assert findings(scenario, ()) == [
        (
            "PAY-005",
            JSON,
            PAYLOAD.format(0) + "/payload_new_field",
            "this payload cannot be hashed without guessing: a field the canonical form of a "
            "payload does not know",
        ),
        (
            "PAY-005",
            JSON,
            PAYLOAD.format(1),
            "this payload cannot be hashed without guessing: a value of an unexpected type",
        ),
        (
            "PAY-005",
            JSON,
            CONTRACT.format(2) + "/injector_contract_attack_patterns",
            "this payload cannot be hashed without guessing: each technique of the contract "
            "needs one external ID",
        ),
    ]


def test_every_finding_blocks() -> None:
    found = reference_findings(
        stored(payload("a")),
        (reference(payload("b")),),
        agreed=NONE,
        catalogue=EMPTY,
        scenario=JSON,
        metadata=YAML,
        files=_no_files,
    )

    assert {f.severity for f in found} == {Severity.BLOCKING}
    assert [f.code for f in found] == ["PAY-008", "PAY-008", "PAY-001", "PAY-006"]


def test_the_techniques_of_the_contract_enter_the_hash() -> None:
    item = payload("a")
    techniques = [{"attack_pattern_external_id": "T1082"}]
    identifier = derived_id(digest(item, ("T1082",)))
    with_techniques = stored({**item, "payload_external_id": identifier}, techniques=techniques)

    assert (
        findings(
            with_techniques, (PayloadReference(identifier, "1.0.0", digest(item, ("T1082",))),)
        )
        == []
    )
    assert [code for code, *_ in findings(with_techniques, (reference(item, identifier),))] == [
        "PAY-002"
    ]


# Assignment


def test_assign_gives_each_payload_the_id_its_content_has() -> None:
    first, second, third = payload("a"), payload("b", "id"), payload("c", "ls")
    first["payload_external_id"] = "anything"  # replaced: the ID follows the content
    agreed = AgreedIds({digest(third): AgreedId("agreed", "c")})

    scenario = stored(first, second, copy.deepcopy(first), third)
    result = assign(
        scenario,
        agreed=agreed,
        catalogue=held(scenario, agreed),
        files=_no_files,
        scenario=JSON,
    )

    assert result.refusals == ()
    assert result.stored is not None
    assert [
        inject["inject_injector_contract"]["injector_contract_payload"]["payload_external_id"]
        for inject in result.stored["scenario_injects"]
    ] == [
        derived_id(digest(payload("a"))),
        derived_id(digest(second)),
        derived_id(digest(payload("a"))),
        "agreed",
    ]
    assert first["payload_external_id"] == "anything"  # the given scenario is left as it is


def test_assign_writes_one_reference_per_content_sorted_by_id() -> None:
    first, second = payload("a"), payload("b", "id")
    agreed = AgreedIds(
        {digest(first): AgreedId("b-agreed", "a"), digest(second): AgreedId("a-agreed", "b")}
    )

    scenario = stored(first, second, copy.deepcopy(first))
    result = assign(
        scenario, agreed=agreed, catalogue=held(scenario, agreed), files=_no_files, scenario=JSON
    )

    assert result.references == (
        PayloadReference("a-agreed", "1.0.0", digest(second)),
        PayloadReference("b-agreed", "1.0.0", digest(first)),
    )


def test_an_assigned_scenario_passes_the_check() -> None:
    first, second = payload("a"), payload("b", "id")
    scenario = stored(
        first, second, copy.deepcopy(first), techniques=[{"attack_pattern_external_id": "T1"}]
    )
    agreed = AgreedIds({digest(second, ("T1",)): AgreedId("agreed", "b")})

    result = assign(
        scenario, agreed=agreed, catalogue=held(scenario, agreed), files=_no_files, scenario=JSON
    )

    assert findings(result.stored, result.references, agreed) == []


def test_assign_writes_nothing_when_a_payload_cannot_be_hashed() -> None:
    result = assign(
        stored(payload("a"), "x"),
        agreed=NONE,
        catalogue=held(stored(payload("a"))),
        files=_no_files,
        scenario=JSON,
    )

    assert (result.stored, result.references) == (None, ())
    assert [(f.code, f.field) for f in result.refusals] == [("PAY-005", PAYLOAD.format(1))]


def test_assign_of_a_scenario_without_payloads_gives_no_reference() -> None:
    result = assign(
        {"scenario_injects": []},
        agreed=NONE,
        catalogue=held({"scenario_injects": []}, NONE),
        files=_no_files,
        scenario=JSON,
    )

    assert (result.stored, result.references, result.refusals) == ({"scenario_injects": []}, (), ())


def test_an_attached_file_enters_by_the_hash_its_resolver_gives() -> None:
    def files(document: str) -> str | None:
        return "f" * 64 if document == "doc" else None

    item = {"payload_type": "FileDrop", "payload_name": "drop", "file_drop_file": "doc"}
    digest_with_file = payload_hash(item, (), files).hex

    result = assign(
        stored(item),
        agreed=NONE,
        catalogue=held(stored(item), files=files),
        files=files,
        scenario=JSON,
    )

    assert result.references == (
        PayloadReference(derived_id(digest_with_file), "1.0.0", digest_with_file),
    )
    assert (
        reference_findings(
            result.stored,
            result.references,
            agreed=NONE,
            catalogue=held(stored(item), files=files),
            scenario=JSON,
            metadata=YAML,
            files=files,
        )
        == ()
    )


def test_a_reference_repeating_an_id_does_not_stop_the_reading_of_the_others() -> None:
    first, second = named(payload("a")), named(payload("b", "id"))

    assert [
        code
        for code, *_ in findings(
            stored(first, second), (reference(first), reference(first), reference(second))
        )
    ] == ["PAY-002"]


@pytest.mark.parametrize(
    "refused",
    [payload("x", "x"), named(payload("x", "x"), "wrong"), named(payload("x", "x"))],
    ids=["no id", "an id that is not its content's", "an id no reference gives"],
)
def test_a_refused_payload_does_not_stop_the_reading_of_the_next(refused: dict[str, Any]) -> None:
    good = named(payload("a"))

    assert [field for _, _, field, _ in findings(stored(refused, good), (reference(good),))] == [
        FIELD.format(0)
    ]


def test_a_payload_whose_reference_exists_is_refused_once_for_its_id() -> None:
    item = payload("a")
    wrong = named(payload("a"), "wrong")

    assert [code for code, *_ in findings(stored(item), (reference(item),))] == ["PAY-001"]
    assert [code for code, *_ in findings(stored(wrong), (reference(item),))] == ["PAY-003"]


NAME = PAYLOAD + "/payload_name"
OTHER_NAME = (
    "policy/data/payload-ids.yaml agrees this content's ID under another name: correct the name "
    "there, to the payload's"
)
SAME_NAME = (
    "another payload of the scenario has this name, with another content: give each payload its "
    "own name"
)


def test_the_registry_must_name_the_payload_it_agrees() -> None:
    item = payload("a")
    agreed = AgreedIds({digest(item): AgreedId("agreed", "another")})
    carrying = named(item, "agreed")

    assert findings(stored(carrying), (reference(item, "agreed"),), agreed) == [
        ("PAY-003", JSON, NAME.format(0), OTHER_NAME)
    ]
    result = assign(
        stored(item),
        agreed=agreed,
        catalogue=held(stored(item), agreed),
        files=_no_files,
        scenario=JSON,
    )
    assert (result.stored, [(f.code, f.field, f.message) for f in result.refusals]) == (
        None,
        [("PAY-003", NAME.format(0), OTHER_NAME)],
    )


def test_two_payloads_sharing_a_name_with_other_contents_are_refused() -> None:
    first, second = named(payload("a")), named(payload("a", "id"))
    scenario = stored(first, second, copy.deepcopy(first))

    assert findings(scenario, (reference(first), reference(second))) == [
        ("PAY-007", JSON, NAME.format(1), SAME_NAME)
    ]
    scenario = stored(payload("a"), payload("a", "id"))
    result = assign(scenario, agreed=NONE, catalogue=held(scenario), files=_no_files, scenario=JSON)
    assert [(f.code, f.field) for f in result.refusals] == [("PAY-007", NAME.format(1))]


@given(
    st.lists(
        st.tuples(st.text("abc", min_size=1, max_size=3), st.text("xyz", max_size=3)),
        max_size=6,
        unique_by=lambda pair: pair[0],
    )
)
def test_a_scenario_naming_versions_of_its_catalogue_gives_no_finding(
    named_contents: list[tuple[str, str]],
) -> None:
    scenario = stored(*(payload(name, content) for name, content in named_contents))
    catalogue = held(scenario)

    result = assign(scenario, agreed=NONE, catalogue=catalogue, files=_no_files, scenario=JSON)

    assert result.refusals == ()
    assert result.stored is not None
    assert findings(result.stored, result.references, catalogue=catalogue) == []


def test_a_reference_whose_file_has_another_hash_is_refused() -> None:
    item = named(payload("a"))
    other = HeldVersions.of([PayloadReference(item["payload_external_id"], "1.0.0", "f" * 64)])

    assert [
        (code, field)
        for code, _, field, _ in findings(stored(item), (reference(item),), catalogue=other)
    ] == [
        ("PAY-008", "/payloads/0/sha256"),
        (
            "PAY-008",
            "/scenario_injects/0/inject_injector_contract/injector_contract_payload/payload_external_id",
        ),
    ]


@pytest.mark.parametrize(
    ("held_as", "field", "message"),
    [
        (None, "id", "no version file of payloads/ has this ID"),
        (("1.0.0", "f" * 64), "sha256", "the version file with this ID has another hash"),
    ],
    ids=["no file", "another hash"],
)
def test_a_reference_the_catalogue_does_not_hold_says_why_at_its_field(
    held_as: tuple[str, str] | None, field: str, message: str
) -> None:
    item = named(payload("a"))
    versions = [] if held_as is None else [PayloadReference(item["payload_external_id"], *held_as)]

    found = findings(stored(item), (reference(item),), catalogue=HeldVersions.of(versions))

    assert found[0] == ("PAY-008", YAML, f"/payloads/0/{field}", f"{message}: {RUN}")


def test_the_payloads_that_cannot_be_hashed_are_refused_and_no_other() -> None:
    scenario = stored(payload("a"), payload("b", payload_new_field=1))

    found = unhashable_findings(scenario, _no_files, JSON)

    assert [(f.code, f.severity, f.path, f.field) for f in found] == [
        ("PAY-005", Severity.BLOCKING, JSON, PAYLOAD.format(1) + "/payload_new_field")
    ]
    assert unhashable_findings(stored(payload("a")), _no_files, JSON) == ()


def test_a_payload_whose_attached_file_the_entry_holds_can_be_hashed() -> None:
    attached = {"payload_type": "Executable", "payload_name": "a", "executable_file": "doc"}
    scenario = stored(attached)

    assert unhashable_findings(scenario, lambda document: "0" * 64, JSON) == ()
    assert [f.code for f in unhashable_findings(scenario, _no_files, JSON)] == ["PAY-005"]
