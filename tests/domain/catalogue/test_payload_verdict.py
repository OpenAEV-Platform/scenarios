"""The verdict intake gives each payload an export embeds: already in the catalogue, by its hash,
or a new payload, written as the first version of a folder of its own."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.catalogue.payload_verdict import (
    BASE_NAME_TAKEN,
    NO_SLUG,
    NOT_KEPT,
    OUT_OF_SCHEMA,
    OVER_SIZE,
    SUFFIXED,
    TAKEN_IN_EXPORT,
    TOO_MANY_NEW,
    proposed_slug,
    verdicts,
    version_document,
)
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
