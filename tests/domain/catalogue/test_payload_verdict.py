"""The verdict intake gives each payload an export embeds: already in the catalogue, by its hash,
or a new payload, written as the first version of a folder of its own."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.catalogue.payload_verdict import (
    BASE_NAME_TAKEN,
    CLAIM_NAMES_NOTHING,
    GIVEN_TWICE,
    NO_SLUG,
    NOT_HIGHER,
    NOT_KEPT,
    OUT_OF_SCHEMA,
    OVER_SIZE,
    SUFFIXED,
    TAKEN_IN_EXPORT,
    TOO_MANY_NEW,
    TWO_CONTENTS,
    Claim,
    claimed_verdicts,
    export_renamed,
    named_at,
    names_held,
    proposed_slug,
    renamed,
    verdicts,
    version_document,
)
from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.payload_catalogue import Catalogue
from scenario_tools.domain.verification.payload_references import AgreedIds, derived_id
from scenario_tools.domain.verification.payload_version import PayloadVersion

ROOT = Path(__file__).resolve().parents[3]
TREE = ROOT / "tests" / "golden" / "payloads"
STORED: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "two-steps.normalised.json").read_text("utf-8")
)
NONE = AgreedIds({})
ANY = lambda _: True  # noqa: E731  # every document within the schema


def _catalogue(*slugs: str) -> Catalogue:
    versions = [
        PayloadVersion(
            slug, path.stem, f"payloads/{slug}/{path.name}", json.loads(path.read_text())
        )
        for slug in slugs
        for path in sorted((TREE / slug).glob("*.json"))
    ]
    return Catalogue.of(versions)


def _payloads(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        step["step_data"]["inject_injector_contract"]["injector_contract_payload"]
        for step in document["scenario_workflow"]["workflow_steps"]
    ]


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("Process Discovery - ps", "process-discovery-ps"),
        ("System Owner/User Discovery - whoami", "system-owner-user-discovery-whoami"),
        ("Café  (beta)!", "cafe-beta"),
        ("x" * 80, "x" * 64),
        ("a" + "-" * 70 + "b", "a-b"),
    ],
)
def test_a_slug_is_proposed_from_the_base_name(name: str, slug: str) -> None:
    assert proposed_slug(name) == slug


def test_a_payload_the_catalogue_holds_is_already_there() -> None:
    catalogue = _catalogue("process-discovery-ps")
    held = catalogue.by_slug["process-discovery-ps"][0]
    stored = json.loads(json.dumps(STORED))
    for payload in _payloads(stored):  # the payload of the catalogue, as embedded
        payload.clear()
        payload.update(
            {k: v for k, v in held.document.items() if k not in ("payload_attack_patterns",)}
        )
    found, given = verdicts(stored, catalogue, NONE, accepted=ANY)
    assert [(f.code, f.message) for f in found] == [
        ("PAY-010", "already there: process-discovery-ps 1.0.0")
    ] * 2
    assert given == {}


def test_a_payload_the_catalogue_does_not_hold_is_a_new_payload_written_once() -> None:
    found, given = verdicts(
        STORED, _catalogue("system-owner-user-discovery-whoami"), NONE, accepted=ANY
    )
    assert [(f.code, f.message) for f in found] == [
        ("PAY-010", "new payload: process-discovery-ps 1.0.0")
    ] * 2
    (version,) = given.values()
    assert (version.slug, version.version, version.path) == (
        "process-discovery-ps",
        "1.0.0",
        "payloads/process-discovery-ps/1.0.0.json",
    )
    assert version.identifier == derived_id(version.digest())
    assert "payload_id" not in version.document
    assert "payload_source" not in version.document
    assert version.techniques == ("T1057",)


def test_a_new_payload_has_the_hash_of_its_embedded_copy() -> None:
    from scenario_tools.domain.verification.payload_hash import embedded_payloads, payload_hash

    _, given = verdicts(STORED, _catalogue(), NONE, accepted=ANY)
    embedded = next(embedded_payloads(STORED))
    (version,) = given.values()
    assert (
        version.digest()
        == payload_hash(embedded.payload, embedded.attack_patterns, lambda _: None).hex
    )


def test_a_new_payload_whose_base_name_the_catalogue_holds_is_refused() -> None:
    catalogue = _catalogue("process-discovery-ps")
    found, given = verdicts(STORED, catalogue, NONE, accepted=ANY)  # same name, another content
    assert {(f.code, f.message, f.severity.value) for f in found} == {
        ("PAY-009", BASE_NAME_TAKEN.format(payload="process-discovery-ps"), "blocking")
    }
    assert given == {}


def test_a_new_payload_takes_the_id_the_registry_agrees_for_it() -> None:
    _, given = verdicts(STORED, _catalogue(), NONE, accepted=ANY)
    (version,) = given.values()
    agreed = AgreedIds.from_document(
        {"payloads": [{"id": "agreed-ps", "name": version.name, "sha256": version.digest()}]}
    )
    _, again = verdicts(STORED, _catalogue(), agreed, accepted=ANY)
    assert [v.identifier for v in again.values()] == ["agreed-ps"]


def test_the_verdict_is_reported_at_each_embedded_payload() -> None:
    found, _ = verdicts(STORED, _catalogue(), NONE, accepted=ANY)
    steps = "/scenario_workflow/workflow_steps"
    contract = "step_data/inject_injector_contract/injector_contract_payload"
    assert [f.field for f in found] == [f"{steps}/0/{contract}", f"{steps}/1/{contract}"]


@pytest.mark.parametrize("second", ["Process Discovery: ps!", "process discovery - PS"])
def test_a_new_payload_taking_the_slug_or_base_name_of_another_new_one_is_refused(
    second: str,
) -> None:
    stored = json.loads(json.dumps(STORED))
    later = _payloads(stored)[1]
    later.update({"payload_name": second, "command_content": "ps -ef"})
    found, given = verdicts(stored, _catalogue(), NONE, accepted=ANY)
    assert [(f.code, f.message) for f in found] == [
        ("PAY-010", "new payload: process-discovery-ps 1.0.0"),
        ("PAY-009", TAKEN_IN_EXPORT.format(payload="process-discovery-ps")),
    ]
    assert [v.name for v in given.values()] == ["Process Discovery - ps"]


def _renamed(*names: object) -> dict[str, Any]:
    """The scenario in chaining, its two steps' payloads named ``names``, each its own content."""
    stored: dict[str, Any] = copy.deepcopy(STORED)
    for index, (payload, name) in enumerate(zip(_payloads(stored), names, strict=True)):
        payload["command_content"] = f"echo {index}"
        if name is None:
            del payload["payload_name"]
        else:
            payload["payload_name"] = name
    return stored


@pytest.mark.parametrize("names", [("日本語", "!!!"), (None, None), ("日本語", "ps")])
def test_a_new_payload_whose_name_gives_no_slug_is_refused(names: tuple[object, ...]) -> None:
    found, given = verdicts(_renamed(*names), _catalogue(), NONE, accepted=ANY)
    refused = [f.message for f in found if f.code == "PAY-009"]
    assert refused == [NO_SLUG] * sum(1 for name in names if name != "ps")
    assert all(version.slug for version in given.values())


def test_a_new_payload_whose_name_carries_a_version_is_refused() -> None:
    found, given = verdicts(_renamed("ps (2.0.0)", "other"), _catalogue(), NONE, accepted=ANY)
    assert [(f.code, f.message) for f in found] == [
        ("PAY-009", SUFFIXED),
        ("PAY-010", "new payload: other 1.0.0"),
    ]
    assert [version.slug for version in given.values()] == ["other"]


def test_a_new_payload_the_payload_schema_refuses_is_not_written() -> None:
    seen: list[object] = []

    def refuse(document: object) -> bool:
        seen.append(document)
        return False

    found, given = verdicts(STORED, _catalogue(), NONE, accepted=refuse)
    assert {(f.code, f.message) for f in found} == {("PAY-009", OUT_OF_SCHEMA)}
    assert given == {}
    assert seen
    assert all(isinstance(document, dict) for document in seen)
    assert {document["payload_name"] for document in seen} == {"Process Discovery - ps"}  # type: ignore[index]


def test_a_new_payload_whose_file_the_catalogue_checks_refuse_is_not_written() -> None:
    _, given = verdicts(STORED, _catalogue(), NONE, accepted=ANY)
    (version,) = given.values()
    elsewhere = AgreedIds.from_document(  # the registry agrees its content under another name
        {"payloads": [{"id": "agreed-ps", "name": "Another name", "sha256": version.digest()}]}
    )
    found, again = verdicts(STORED, _catalogue(), elsewhere, accepted=ANY)
    assert {(f.code, f.message) for f in found} == {("PAY-009", NOT_KEPT)}
    assert again == {}


def test_the_sets_of_a_new_payload_are_sorted_whatever_their_items() -> None:
    payload = {
        "payload_type": "Command",
        "payload_name": "x",
        "payload_expected_security_platforms": {"PREVENTION": ["b", "a"], "DETECTION": "text"},
        "payload_domains": [{"domain_name": "z"}, "text", {"domain_name": "a"}],
    }
    document = version_document(payload, ["T2", "T1"], "id")
    assert document["payload_expected_security_platforms"] == {
        "PREVENTION": ["a", "b"],
        "DETECTION": "text",
    }
    assert document["payload_domains"] == ["text", {"domain_name": "a"}, {"domain_name": "z"}]
    assert document["payload_attack_patterns"] == ["T1", "T2"]


def test_a_new_payload_the_schema_refuses_is_refused_before_its_file_is_checked() -> None:
    stored = copy.deepcopy(STORED)
    for payload in _payloads(stored):
        payload["payload_domains"] = ["text"]  # out of the schema; read as objects by the checks

    found, given = verdicts(stored, _catalogue(), NONE, accepted=lambda _: False)

    assert {(f.code, f.message) for f in found} == {("PAY-009", OUT_OF_SCHEMA)}
    assert given == {}


def test_a_new_payload_whose_file_would_be_over_its_size_bound_is_refused() -> None:
    stored = copy.deepcopy(STORED)
    for payload in _payloads(stored):
        payload["payload_description"] = "\U0001f600" * 65_536  # four bytes each in UTF-8

    found, given = verdicts(stored, _catalogue(), NONE, accepted=ANY)

    assert {(f.code, f.message) for f in found} == {("PAY-009", OVER_SIZE)}
    assert given == {}


def _injects_running(count: int) -> dict[str, Any]:
    return {
        "scenario_injects": [
            {
                "inject_injector_contract": {
                    "injector_contract_payload": {
                        "payload_type": "Command",
                        "payload_name": f"Payload {index}",
                        "payload_description": "Prints a number.",
                        "payload_platforms": ["Linux"],
                        "command_executor": "sh",
                        "command_content": f"echo {index}",
                    }
                }
            }
            for index in range(count)
        ]
    }


def test_an_export_of_more_new_payloads_than_one_intake_writes_is_refused() -> None:
    found, given = verdicts(_injects_running(101), _catalogue(), NONE, accepted=ANY)
    _, written = verdicts(_injects_running(100), _catalogue(), NONE, accepted=ANY)

    assert [(f.code, f.path, f.field, f.message) for f in found] == [
        ("PAY-009", "scenario.json", "", TOO_MANY_NEW)
    ]
    assert given == {}
    assert len(written) == 100


def test_a_new_payload_takes_the_domains_its_contract_declares() -> None:
    """An export holds a payload's domains on its contract, in the contract's own copy: the
    version file carries them as the payload's, by name and colour, sorted."""
    stored = copy.deepcopy(STORED)
    for step in stored["scenario_workflow"]["workflow_steps"]:
        contract = step["step_data"]["inject_injector_contract"]
        copy_of = json.loads(contract["injector_contract_content"])
        copy_of["domains"] = [
            {"domain_color": "#FF0000", "domain_id": "x", "domain_name": "Network"},
            {"domain_color": "#389CFF", "domain_id": "y", "domain_name": "Endpoint"},
        ]
        contract["injector_contract_content"] = json.dumps(copy_of)
        contract["convertedContent"] = copy_of

    _, given = verdicts(stored, _catalogue(), NONE, accepted=ANY)

    (version,) = given.values()
    assert version.document["payload_domains"] == [
        {"domain_color": "#389CFF", "domain_name": "Endpoint"},
        {"domain_color": "#FF0000", "domain_name": "Network"},
    ]


@pytest.mark.parametrize(
    "content", ["not json", json.dumps({"domains": "Endpoint"}), json.dumps({"domains": [5]})]
)
def test_a_contract_whose_copy_names_no_domain_gives_the_payload_none(content: str) -> None:
    stored = copy.deepcopy(STORED)
    for step in stored["scenario_workflow"]["workflow_steps"]:
        contract = step["step_data"]["inject_injector_contract"]
        contract["injector_contract_content"] = content
        contract.pop("convertedContent")

    _, given = verdicts(stored, _catalogue(), NONE, accepted=ANY)

    assert all("payload_domains" not in version.document for version in given.values())


# Claims (a payload declared as based on one of the catalogue)

PS = "process-discovery-ps"
STEP_PAYLOAD = (
    "/scenario_workflow/workflow_steps/{}/step_data/inject_injector_contract/"
    "injector_contract_payload"
)


def _claimed(stored: dict[str, Any], *claims: Claim) -> Any:
    return claimed_verdicts(stored, _catalogue(PS), NONE, accepted=ANY, claims=claims)


def _codes_of(result: Any) -> list[tuple[str, str]]:
    return [(f.code, f.message) for f in result.findings]


def test_a_payload_based_on_a_catalogue_payload_is_its_next_minor_version() -> None:
    result = _claimed(STORED, Claim("Process Discovery - ps", PS))

    assert _codes_of(result) == [("PAY-010", f"new version: {PS} 1.2.0 (based on {PS} 1.1.0)")] * 2
    (version,) = result.versions.values()
    assert (version.slug, version.version, version.path) == (
        PS,
        "1.2.0",
        f"payloads/{PS}/1.2.0.json",
    )
    assert version.name == "Process Discovery - ps (1.2.0)"
    assert result.renames == {
        STEP_PAYLOAD.format(0): "Process Discovery - ps (1.2.0)",
        STEP_PAYLOAD.format(1): "Process Discovery - ps (1.2.0)",
    }
    assert result.changes[f"payloads/{PS}/1.2.0.json"]  # by pointer, never a value
    assert all(p.startswith("/") for p in result.changes[f"payloads/{PS}/1.2.0.json"])


def test_a_requested_version_higher_than_the_highest_is_taken() -> None:
    result = _claimed(STORED, Claim("Process Discovery - ps", PS, version="2.0.0"))

    assert [v.version for v in result.versions.values()] == ["2.0.0"]


@pytest.mark.parametrize("version", ["1.1.0", "1.0.5", "0.9.0"])
def test_a_requested_version_not_higher_than_the_highest_is_refused(version: str) -> None:
    result = _claimed(STORED, Claim("Process Discovery - ps", PS, version=version))

    assert result.versions == {}
    assert [
        (f.code, f.path, f.field, f.message) for f in result.findings if f.code == "ITK-009"
    ] == [
        (
            "ITK-009",
            "request.yaml",
            "/payloads/0/version",
            f"the version asked for is not higher than {PS} 1.1.0, the highest the catalogue holds",
        )
    ]


def test_a_stale_base_is_said_and_the_new_version_still_follows_the_highest() -> None:
    result = _claimed(STORED, Claim("Process Discovery - ps", PS, based_version="1.0.0"))

    assert (
        "PAY-011",
        f"based on {PS} 1.0.0, whereas the latest version is {PS} 1.1.0",
    ) in _codes_of(result)
    assert ("PAY-010", f"new version: {PS} 1.2.0 (based on {PS} 1.0.0)") in _codes_of(result)


@pytest.mark.parametrize(
    ("claim", "field", "message"),
    [
        (
            Claim("Process Discovery - ps", "no-such-payload"),
            "/payloads/0/based_on/payload",
            "based_on names no payload of the catalogue",
        ),
        (
            Claim("Process Discovery - ps", PS, based_version="9.9.9"),
            "/payloads/0/based_on/version",
            f"based_on names a version {PS} does not have",
        ),
        (
            Claim("No such payload", PS),
            "/payloads/0/name",
            "this claim names no payload the export embeds",
        ),
    ],
    ids=["no payload", "no version", "no embedded payload"],
)
def test_a_claim_that_cannot_hold_is_refused(claim: Claim, field: str, message: str) -> None:
    result = _claimed(STORED, claim)

    assert ("ITK-009", "request.yaml", field, message) in [
        (f.code, f.path, f.field, f.message) for f in result.findings
    ]
    assert result.versions == {}


def test_a_payload_claimed_twice_is_refused() -> None:
    claim = Claim("Process Discovery - ps", PS)

    result = _claimed(STORED, claim, claim)

    assert [(f.code, f.field, f.message) for f in result.findings if f.code == "ITK-009"] == [
        ("ITK-009", "/payloads/1/name", "this payload is claimed twice: claim each payload once")
    ]


def _as_version(version: str, name: str) -> dict[str, Any]:
    """The scenario in chaining whose steps embed the catalogue's version ``version`` of ps,
    unchanged but for its name, ``name``."""
    held = json.loads((TREE / PS / f"{version}.json").read_text())
    payload = {
        k: v
        for k, v in held.items()
        if k not in ("payload_external_id", "payload_attack_patterns", "payload_domains")
    }
    stored = copy.deepcopy(STORED)
    for step in stored["scenario_workflow"]["workflow_steps"]:
        step["step_data"]["inject_injector_contract"]["injector_contract_payload"] = {
            **payload,
            "payload_name": name,
        }
    return stored


def test_a_claimed_copy_of_a_catalogue_version_is_that_version_and_takes_its_name() -> None:
    """Idempotent: an author who duplicated 1.1.0 keeps the duplicate's name; under the name of
    1.1.0 it has its hash, so it is that version, and no file is written."""
    result = _claimed(
        _as_version("1.1.0", "Process Discovery - ps"), Claim("Process Discovery - ps", PS)
    )

    assert _codes_of(result) == [("PAY-010", f"already there: {PS} 1.1.0")] * 2
    assert result.versions == {}
    assert set(result.renames.values()) == {"Process Discovery - ps (1.1.0)"}


def test_a_claim_on_a_payload_already_there_is_ignored_and_said() -> None:
    result = _claimed(
        _as_version("1.1.0", "Process Discovery - ps (1.1.0)"),
        Claim("Process Discovery - ps (1.1.0)", PS),
    )

    assert (
        "PAY-011",
        "this payload is already in the catalogue: the claim is ignored",
    ) in _codes_of(result)
    assert result.renames == {}


def test_a_payload_carrying_a_catalogue_id_with_another_content_is_said_changed() -> None:
    stored = copy.deepcopy(STORED)
    held = json.loads((TREE / PS / "1.0.0.json").read_text())
    for payload in _payloads(stored):
        payload["payload_external_id"] = held["payload_external_id"]

    result = _claimed(stored, Claim("Process Discovery - ps", PS))

    assert (
        "PAY-011",
        f"this payload carries the ID of {PS} 1.0.0 but another content: it is treated as changed",
    ) in _codes_of(result)


def test_without_a_claim_a_taken_base_name_points_to_based_on() -> None:
    result = _claimed(STORED)

    assert {f.message for f in result.findings} == {BASE_NAME_TAKEN.format(payload=PS)}
    assert "based_on" in BASE_NAME_TAKEN


def test_a_renamed_copy_changes_only_the_names_at_the_pointers_given() -> None:
    stored = {
        "a": [{"payload_name": "x", "k": 1}, {"payload_name": "y"}],
        "b": {"payload_name": "z"},
    }
    before = copy.deepcopy(stored)

    assert renamed(stored, {"/a/0": "x (1.1.0)", "/b": "z (2.0.0)"}) == {
        "a": [{"payload_name": "x (1.1.0)", "k": 1}, {"payload_name": "y"}],
        "b": {"payload_name": "z (2.0.0)"},
    }
    assert stored == before
    assert renamed(stored, {}) == before


def test_a_claim_on_a_payload_that_cannot_be_hashed_names_it_and_leaves_it_to_its_checks() -> None:
    stored = copy.deepcopy(STORED)
    for payload in _payloads(stored):
        payload["payload_elevation_required"] = "yes"  # the reference checks say why

    result = _claimed(stored, Claim("Process Discovery - ps", PS))

    assert result.findings == ()
    assert (result.versions, result.renames) == ({}, {})


def test_a_new_version_the_catalogue_would_refuse_is_refused_and_not_given() -> None:
    result = claimed_verdicts(
        STORED,
        _catalogue(PS),
        NONE,
        accepted=lambda _: False,
        claims=(Claim("Process Discovery - ps", PS),),
    )

    assert {f.code for f in result.findings} == {"PAY-009"}
    assert (result.versions, result.renames, result.changes) == ({}, {}, {})


def _held_by(payload: object) -> dict[str, Any]:
    """An inject or a step's data holding ``payload`` as its contract's."""
    return {"inject_injector_contract": {"injector_contract_payload": payload}}


def test_an_export_renamed_gives_each_copy_its_name_in_injects_and_step_data() -> None:
    export = {
        "scenario_injects": [
            _held_by({"payload_name": "A", "payload_description": "kept"}),
            _held_by({"payload_name": "B"}),
        ],
        "scenario_workflow": {
            "workflow_steps": [{"step_data": json.dumps(_held_by({"payload_name": "A"}))}]
        },
    }
    before = copy.deepcopy(export)

    renamed_export: Any = export_renamed(export, {"A": "A (1.1.0)"})

    assert renamed_export["scenario_injects"] == [
        _held_by({"payload_name": "A (1.1.0)", "payload_description": "kept"}),
        _held_by({"payload_name": "B"}),
    ]
    (data,) = renamed_export["scenario_workflow"]["workflow_steps"]
    assert json.loads(data["step_data"]) == _held_by(
        {"payload_name": "A (1.1.0)", "payload_description": "A"}
    )
    assert export == before


@pytest.mark.parametrize("description", [None, "", "  "])
def test_a_renamed_copy_without_a_description_is_described_by_its_first_name(
    description: object,
) -> None:
    export = {
        "scenario_injects": [_held_by({"payload_name": "A", "payload_description": description})]
    }

    assert export_renamed(export, {"A": "A (2.0.0)"}) == {
        "scenario_injects": [_held_by({"payload_name": "A (2.0.0)", "payload_description": "A"})]
    }


def test_an_inject_s_content_is_never_read_nor_rewritten() -> None:
    content = {"payload_name": "A", "step_data": '{"a":1,"a":2}', "x": '{ "spaced": 1 }'}
    inject = {**_held_by({"payload_name": "A"}), "inject_content": content}
    step_inject = {**_held_by({"payload_name": "A"}), "inject_content": content}
    export = {
        "scenario_injects": [inject, {"inject_content": content}, "not an inject"],
        "scenario_workflow": {
            "workflow_steps": [
                {"step_data": json.dumps(step_inject)},
                {"step_data": step_inject},  # as a stored scenario holds it
                {"step_id": "no data"},
            ]
        },
    }

    renamed_export: Any = export_renamed(export, {"A": "B"})

    first, second, third = renamed_export["scenario_injects"]
    assert first["inject_content"] == content
    assert first["inject_injector_contract"]["injector_contract_payload"]["payload_name"] == "B"
    assert (second, third) == ({"inject_content": content}, "not an inject")
    text, stored, bare = renamed_export["scenario_workflow"]["workflow_steps"]
    assert json.loads(text["step_data"])["inject_content"] == content
    assert stored["step_data"]["inject_content"] == content
    assert (
        stored["step_data"]["inject_injector_contract"]["injector_contract_payload"]["payload_name"]
        == "B"
    )
    assert bare == {"step_id": "no data"}


@pytest.mark.parametrize(
    "export",
    [
        {"scenario_workflow": {"workflow_steps": [{"step_data": "{not json"}]}},
        {"scenario_workflow": "not a workflow"},
        {"scenario_injects": [_held_by("not a payload")]},
        {"scenario_injects": [_held_by({"payload_name": "C"})]},
        "not an export",
    ],
    ids=["step data not json", "no workflow", "payload no object", "another name", "no export"],
)
def test_what_names_no_claimed_copy_is_left_as_it_is(export: object) -> None:
    assert export_renamed(export, {"A": "B"}) == export


def test_the_name_at_a_pointer_is_the_payload_s() -> None:
    stored = {"a": [{"payload_name": "x"}, {"b": {"payload_name": "y"}}]}

    assert (named_at(stored, "/a/0"), named_at(stored, "/a/1/b")) == ("x", "y")


def test_a_payload_that_is_no_object_is_left_to_the_reference_checks() -> None:
    stored = copy.deepcopy(STORED)
    for step in stored["scenario_workflow"]["workflow_steps"]:
        step["step_data"]["inject_injector_contract"]["injector_contract_payload"] = "text"

    result = _claimed(stored, Claim("Process Discovery - ps", PS))

    assert [f.message for f in result.findings] == [CLAIM_NAMES_NOTHING]


def _two_copies(first: str, second: str) -> dict[str, Any]:
    """The stored scenario with its two steps' payloads made two copies of ps, named apart."""
    stored = copy.deepcopy(STORED)
    for step, (name, command) in zip(
        stored["scenario_workflow"]["workflow_steps"],
        ((first, "ps -e"), (second, "ps -ef")),
        strict=True,
    ):
        payload = step["step_data"]["inject_injector_contract"]["injector_contract_payload"]
        payload.update(payload_name=name, command_content=command)
    return stored


def test_versions_asked_for_are_taken_whatever_order_the_copies_come_in() -> None:
    claims = (Claim("B", PS, version="1.3.0"), Claim("A", PS, version="1.2.0"))

    result = _claimed(_two_copies("B", "A"), *claims)  # the higher one met first

    assert sorted(v.version for v in result.versions.values()) == ["1.2.0", "1.3.0"]
    assert all(f.code == "PAY-010" for f in result.findings)


def test_a_version_asked_for_twice_in_one_export_is_refused() -> None:
    claims = (Claim("A", PS, version="1.2.0"), Claim("B", PS, version="1.2.0"))

    result = _claimed(_two_copies("A", "B"), *claims)

    assert ("ITK-009", GIVEN_TWICE) in _codes_of(result)


def test_a_claim_naming_two_contents_is_refused() -> None:
    result = _claimed(_two_copies("A", "A"), Claim("A", PS))

    assert ("ITK-009", TWO_CONTENTS) in _codes_of(result)


def test_a_version_given_automatically_follows_the_highest_asked_for_before_it() -> None:
    stored = _two_copies("A", "B")
    steps = stored["scenario_workflow"]["workflow_steps"]
    steps.append(copy.deepcopy(steps[0]))
    third = steps[2]["step_data"]["inject_injector_contract"]["injector_contract_payload"]
    third.update(payload_name="C", command_content="ps -eo pid")
    claims = (Claim("A", PS, version="1.3.0"), Claim("B", PS, version="1.2.0"), Claim("C", PS))

    result = _claimed(stored, *claims)

    assert sorted(v.version for v in result.versions.values()) == ["1.2.0", "1.3.0", "1.4.0"]


def test_a_claim_s_findings_point_at_its_place_in_the_request() -> None:
    claims = (Claim("A", PS, version="1.0.0", position=3), Claim("nothing", position=5))

    result = _claimed(_two_copies("A", "B"), *claims)

    assert {f.field for f in result.findings if f.code == "ITK-009"} == {
        "/payloads/3/version",
        "/payloads/5/name",
    }


def test_the_base_a_claimed_copy_follows_is_given_even_when_its_claim_is_refused() -> None:
    result = _claimed(_two_copies("A", "B"), Claim("A", PS, version="1.0.0"))

    assert ("ITK-009", NOT_HIGHER.format(payload=PS, version="1.1.0")) in _codes_of(result)
    assert result.bases == {STEP_PAYLOAD.format(0): "Process Discovery - ps"}


@pytest.mark.parametrize("unchanged_first", [True, False])
def test_a_claim_naming_a_catalogue_version_and_another_content_is_refused(
    unchanged_first: bool,
) -> None:
    held = _catalogue(PS).by_slug[PS][0]
    stored = copy.deepcopy(STORED)
    payloads = _payloads(stored)
    unchanged, edited = (
        (payloads[0], payloads[1]) if unchanged_first else (payloads[1], payloads[0])
    )
    unchanged.clear()
    unchanged.update({k: v for k, v in held.document.items() if k != "payload_attack_patterns"})
    edited.update(payload_name=held.name, command_content="ps -ef")

    result = _claimed(stored, Claim(held.name, PS))

    assert ("ITK-009", TWO_CONTENTS) in _codes_of(result)


def test_the_names_held_are_those_of_payloads_the_catalogue_holds_as_they_are() -> None:
    catalogue = _catalogue(PS)
    held = catalogue.by_slug[PS][0]
    stored = copy.deepcopy(STORED)
    first, second = _payloads(stored)
    first.clear()
    first.update({k: v for k, v in held.document.items() if k != "payload_attack_patterns"})
    second["payload_elevation_required"] = "yes"  # cannot be hashed

    assert names_held(stored, catalogue) == {held.name}
    assert names_held({"scenario_injects": [{"inject_injector_contract": {}}]}, catalogue) == set()


def test_no_name_is_held_for_a_payload_that_is_no_object_or_another_content() -> None:
    stored = copy.deepcopy(STORED)
    first, _ = _payloads(stored)
    stored["scenario_workflow"]["workflow_steps"][0]["step_data"]["inject_injector_contract"][
        "injector_contract_payload"
    ] = "text"
    first["command_content"] = "ps -e"  # no longer referenced: the step holds text now

    assert names_held(stored, _catalogue(PS)) == set()


def _first_payload_of(document: dict[str, Any], payload: object) -> dict[str, Any]:
    first = document["scenario_injects"][0]["inject_injector_contract"]
    first["injector_contract_payload"] = payload
    return document


def test_more_new_payloads_than_one_intake_writes_give_the_refusal_alone() -> None:
    result = claimed_verdicts(_injects_running(101), _catalogue(), NONE, accepted=ANY)

    assert [(f.code, f.severity) for f in result.findings] == [("PAY-009", Severity.BLOCKING)]
    assert (result.versions, result.renames, result.changes, result.bases) == ({}, {}, {}, {})


@pytest.mark.parametrize(
    "payload",
    [
        "not an object",
        {"payload_type": "Command", "payload_name": "Payload 0", "payload_platforms": "Linux"},
    ],
    ids=["not an object", "cannot be hashed"],
)
def test_a_payload_left_to_the_reference_checks_leaves_the_next_one_judged(payload: object) -> None:
    stored = _first_payload_of(_injects_running(2), payload)

    result = claimed_verdicts(stored, _catalogue(), NONE, accepted=ANY)

    assert [v.name for v in result.versions.values()] == ["Payload 1"]


@pytest.mark.parametrize("name", [["a", "list"], {"an": "object"}, 3])
def test_a_payload_whose_name_is_no_text_is_named_by_no_claim(name: object) -> None:
    payload = _injects_running(1)["scenario_injects"][0]["inject_injector_contract"]
    stored = _first_payload_of(
        _injects_running(1), {**payload["injector_contract_payload"], "payload_name": name}
    )

    result = claimed_verdicts(
        stored, _catalogue(), NONE, accepted=ANY, claims=(Claim("Payload 0", PS),)
    )

    assert ("ITK-009", CLAIM_NAMES_NOTHING) in [(f.code, f.message) for f in result.findings]


def test_more_new_payloads_than_one_intake_writes_keep_the_bases_claimed() -> None:
    result = claimed_verdicts(
        _injects_running(101),
        _catalogue(PS),
        NONE,
        accepted=ANY,
        claims=(Claim("Payload 0", PS),),
    )

    assert [f.code for f in result.findings] == ["PAY-009"]
    assert (result.versions, result.renames, result.changes) == ({}, {}, {})
    assert list(result.bases.values()) == ["Process Discovery - ps"]


def test_a_claim_without_a_base_leaves_a_new_payload_new() -> None:
    result = claimed_verdicts(
        _injects_running(1), _catalogue(), NONE, accepted=ANY, claims=(Claim("Payload 0"),)
    )

    assert [v.name for v in result.versions.values()] == ["Payload 0"]
    assert (result.renames, result.bases) == ({}, {})
    assert "ITK-009" not in [f.code for f in result.findings]


def test_a_claim_without_a_base_on_a_payload_already_there_is_not_ignored() -> None:
    name = "Process Discovery - ps (1.1.0)"
    result = _claimed(_as_version("1.1.0", name), Claim(name))

    assert _codes_of(result) == [("PAY-010", f"already there: {PS} 1.1.0")] * 2
    assert (result.versions, result.renames, result.bases) == ({}, {}, {})
