"""Facts of the injects for the cross-checks, from the platform's definition of each contract."""

import copy
import re
from typing import Any

import pytest

from scenario_tools.domain.catalogue.export_reading import ExportStructureError
from scenario_tools.domain.catalogue.facts import BuiltinContracts, copy_findings, export_facts
from scenario_tools.domain.catalogue.metadata import ExportFacts, InjectFacts
from scenario_tools.domain.shared.canonical import ContentHash
from scenario_tools.domain.shared.finding import Finding, Severity

PATH = "scenarios/ransomware/akira/scenario.json"
MAIL = "2790bd39-37d4-4e39-be7e-53f3ca783f86"
SCAN = "93d27459-68d0-43b1-ad65-eacc3cfa5cf7"
PAYLOAD_CONTRACT = "00000000-0000-4000-8000-000000000008"
UNKNOWN = "00000000-0000-4000-8000-0000000000ff"


def _inject(contract: dict[str, Any] | None) -> dict[str, Any]:
    return {"inject_id": UNKNOWN, "inject_title": "t", "inject_injector_contract": contract}


DOCUMENT: dict[str, Any] = {
    "scenario_information": {
        "scenario_name": "Akira",
        "scenario_severity": "high",
        "scenario_category": "global-crisis",
        "scenario_main_focus": "incident-response",
    },
    "scenario_injects": [
        _inject(
            {
                "injector_contract_id": MAIL,
                # the copy claims otherwise: it is never read
                "injector_contract_injector_type": "openaev_manual",
                "injector_contract_needs_executor": True,
                "injector_contract_platforms": ["Windows"],
                "injector_contract_payload": None,
            }
        ),
        _inject(
            {
                "injector_contract_id": PAYLOAD_CONTRACT,
                "injector_contract_needs_executor": False,
                "injector_contract_payload": {
                    "payload_id": PAYLOAD_CONTRACT,
                    "payload_name": "Dump",
                    "payload_platforms": ["Windows", "Linux"],
                },
            }
        ),
    ],
}


MAIL_COPY = DOCUMENT["scenario_injects"][0]["inject_injector_contract"]
DATA: dict[str, Any] = {
    "platform_version": "3.261005.0",
    "contracts": [
        {
            "id": MAIL,
            "name": "Send multi-recipients mail",
            "injector_type": "openaev_email",
            "needs_executor": False,
            "platforms": ["Service"],
            "copy_sha256": ContentHash.of_json(MAIL_COPY).hex,
        },
        {
            "id": SCAN,
            "name": "Nmap - TCP Connect Scan",
            "injector_type": "openaev_nmap",
            "needs_executor": False,
            "platforms": [],
            "copy_sha256": "0" * 64,
        },
    ],
}
BUILTIN = BuiltinContracts.from_document(DATA)


def test_facts_come_from_the_recorded_contract_and_the_embedded_payload() -> None:
    facts, findings = export_facts(DOCUMENT, BUILTIN, PATH)

    assert findings == ()
    assert facts == ExportFacts(
        name="Akira",
        severity="high",
        category="global-crisis",
        main_focus="incident-response",
        injects=(
            InjectFacts("openaev_email", False, frozenset({"Service"})),
            InjectFacts("openaev_implant", True, frozenset({"Windows", "Linux"})),
        ),
        holds_workflow=False,
    )


@pytest.mark.parametrize(
    "contract",
    [
        {"injector_contract_id": UNKNOWN, "injector_contract_payload": None},
        {"injector_contract_id": UNKNOWN},
        None,
    ],
    ids=["unknown contract", "no payload field", "no contract"],
)
def test_an_inject_whose_facts_cannot_be_established_is_a_blocking_finding(
    contract: dict[str, Any] | None,
) -> None:
    document = copy.deepcopy(DOCUMENT)
    document["scenario_injects"].append(_inject(contract))

    facts, findings = export_facts(document, BUILTIN, PATH)

    assert len(facts.injects) == 2
    assert [(f.code, f.severity, f.path, f.field) for f in findings] == [
        ("SCH-005", Severity.BLOCKING, PATH, "/scenario_injects/2")
    ]
    assert "neither a recorded built-in contract nor created from a payload" in findings[0].message


def test_a_contract_that_embeds_a_payload_is_read_as_one_whatever_its_identifier() -> None:
    # The stricter reading: an implant needs an executor, so the endpoint checks still apply.
    document = copy.deepcopy(DOCUMENT)
    document["scenario_injects"][1]["inject_injector_contract"]["injector_contract_id"] = MAIL

    facts, _ = export_facts(document, BUILTIN, PATH)

    assert facts.injects[1] == InjectFacts("openaev_implant", True, frozenset({"Windows", "Linux"}))


def test_an_empty_payload_object_counts_as_no_payload() -> None:
    document = copy.deepcopy(DOCUMENT)
    document["scenario_injects"][0]["inject_injector_contract"]["injector_contract_payload"] = {}
    document["scenario_injects"].append(
        _inject({"injector_contract_id": UNKNOWN, "injector_contract_payload": {}})
    )

    facts, findings = export_facts(document, BUILTIN, PATH)

    assert facts.injects[0] == InjectFacts("openaev_email", False, frozenset({"Service"}))
    assert [finding.field for finding in findings] == ["/scenario_injects/2"]


def test_each_unknown_inject_is_reported() -> None:
    document = copy.deepcopy(DOCUMENT)
    document["scenario_injects"] = [_inject(None), *document["scenario_injects"], _inject(None)]

    _, findings = export_facts(document, BUILTIN, PATH)

    assert [finding.field for finding in findings] == ["/scenario_injects/0", "/scenario_injects/3"]
    assert all(isinstance(finding, Finding) for finding in findings)


def _contract(d: dict[str, Any], index: int) -> dict[str, Any]:
    contract: dict[str, Any] = d["scenario_injects"][index]["inject_injector_contract"]
    return contract


def _payload(d: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = _contract(d, 1)["injector_contract_payload"]
    return payload


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(
            lambda d: d.clear(), "scenario_information must be an object", id="no information"
        ),
        pytest.param(
            lambda d: d.update(scenario_information=[]),
            "scenario_information must be an object",
            id="information not an object",
        ),
        pytest.param(
            lambda d: d["scenario_information"].update(scenario_severity=3),
            "scenario_information.scenario_severity must be text",
            id="facet not text",
        ),
        pytest.param(
            lambda d: d["scenario_information"].pop("scenario_name"),
            "scenario_information.scenario_name must be text",
            id="no name",
        ),
        pytest.param(
            lambda d: d.update(scenario_injects={}),
            "scenario_injects must be a list",
            id="injects not a list",
        ),
        pytest.param(
            lambda d: d["scenario_injects"].append("x"),
            "scenario_injects must be an object",
            id="inject not an object",
        ),
        pytest.param(
            lambda d: d["scenario_injects"][0].update(inject_injector_contract="x"),
            "inject_injector_contract must be an object",
            id="contract not an object",
        ),
        pytest.param(
            lambda d: _contract(d, 0).update(injector_contract_id=3),
            "inject_injector_contract.injector_contract_id must be text",
            id="contract id not text",
        ),
        pytest.param(
            lambda d: _contract(d, 0).pop("injector_contract_id"),
            "inject_injector_contract.injector_contract_id must be text",
            id="no contract id",
        ),
        pytest.param(
            lambda d: _contract(d, 1).update(injector_contract_payload="x"),
            "injector_contract_payload must be an object",
            id="payload not an object",
        ),
        pytest.param(
            lambda d: _contract(d, 1).update(injector_contract_payload=[]),
            "injector_contract_payload must be an object",
            id="payload an empty list",
        ),
        pytest.param(
            lambda d: _payload(d).update(payload_platforms="Windows"),
            "injector_contract_payload.payload_platforms must name at least one platform",
            id="payload platforms not a list",
        ),
        pytest.param(
            lambda d: _payload(d).update(payload_platforms=[1]),
            "injector_contract_payload.payload_platforms must name at least one platform",
            id="payload platform not text",
        ),
        pytest.param(
            lambda d: _payload(d).update(payload_platforms=[]),
            "injector_contract_payload.payload_platforms must name at least one platform",
            id="payload names no platform",
        ),
        pytest.param(
            lambda d: _payload(d).update(payload_platforms=["Windows", ""]),
            "injector_contract_payload.payload_platforms must name at least one platform",
            id="empty payload platform",
        ),
    ],
)
def test_a_document_not_shaped_like_a_stored_scenario_is_refused(change: Any, reason: str) -> None:
    document = copy.deepcopy(DOCUMENT)
    change(document)

    with pytest.raises(ExportStructureError) as error:
        export_facts(document, BUILTIN, PATH)
    assert error.value.code == "IO-014"
    assert str(error.value) == f"not an OpenAEV scenario export: {reason}"
    assert error.value.what == reason


def test_a_document_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ExportStructureError, match="the export must be an object"):
        export_facts([], BUILTIN, PATH)


# Recorded contracts, read as data


def test_recorded_contracts_are_read_by_identifier() -> None:
    assert BUILTIN.facts(SCAN) == InjectFacts("openaev_nmap", False, frozenset())
    assert BUILTIN.facts(UNKNOWN) is None
    assert BUILTIN.platform_version == "3.261005.0"
    assert BUILTIN.identifiers == (MAIL, SCAN)


def test_recorded_contracts_keep_the_order_of_the_data() -> None:
    document = copy.deepcopy(DATA)
    document["contracts"].reverse()

    assert BuiltinContracts.from_document(document).identifiers == (SCAN, MAIL)


def test_recorded_contracts_cannot_be_changed_once_read() -> None:
    with pytest.raises(TypeError):
        BUILTIN.contracts[UNKNOWN] = InjectFacts("openaev_manual", False, frozenset())  # type: ignore[index]


def _first(d: dict[str, Any]) -> dict[str, Any]:
    contract: dict[str, Any] = d["contracts"][0]
    return contract


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(lambda d: d.clear(), "platform_version must be non-empty text", id="empty"),
        pytest.param(
            lambda d: d["contracts"][0].update(injector_type="t" * 65),
            "injector_type must be at most 64 characters",
            id="injector type too long",
        ),
        pytest.param(
            lambda d: d.update(platform_version="3.26-rc"),
            "platform_version must be a version such as 3.261005.0",
            id="not a version",
        ),
        pytest.param(
            lambda d: d.update(platform_version=3),
            "platform_version must be non-empty text",
            id="version not text",
        ),
        pytest.param(
            lambda d: d.update(platform_version=""),
            "platform_version must be non-empty text",
            id="empty version",
        ),
        pytest.param(
            lambda d: d.update(contracts={}), "contracts must be a list", id="contracts not a list"
        ),
        pytest.param(
            lambda d: d["contracts"].append("x"),
            "each contract must be a mapping",
            id="contract not an object",
        ),
        pytest.param(
            lambda d: _first(d).update(id=3),
            "3 is not a lowercase canonical UUID",
            id="id not text",
        ),
        pytest.param(
            lambda d: _first(d).update(id=MAIL.upper()),
            "is not a lowercase canonical UUID",
            id="id in capitals",
        ),
        pytest.param(
            lambda d: _first(d).update(id="2790BD39" + MAIL[8:]),
            "is not a lowercase canonical UUID",
            id="first group in capitals",
        ),
        pytest.param(
            lambda d: _first(d).update(id=MAIL + "0"),
            "is not a lowercase canonical UUID",
            id="id followed by text",
        ),
        pytest.param(
            lambda d: _first(d).update(id=SCAN), f"{SCAN} is recorded twice", id="id twice"
        ),
        pytest.param(
            lambda d: _first(d).update(name=""), "name must be non-empty text", id="empty name"
        ),
        pytest.param(
            lambda d: _first(d).update(injector_type=""),
            "injector_type must be non-empty text",
            id="empty injector type",
        ),
        pytest.param(
            lambda d: _first(d).update(needs_executor="no"),
            f"{MAIL}: needs_executor must be a boolean",
            id="executor need not a boolean",
        ),
        pytest.param(
            lambda d: _first(d).update(platforms="Service"),
            f"{MAIL}: platforms must be a list of names",
            id="platforms not a list",
        ),
        pytest.param(
            lambda d: _first(d).pop("copy_sha256"),
            f"{MAIL}: copy_sha256 must be a SHA-256 hex digest",
            id="no copy digest",
        ),
        pytest.param(
            lambda d: _first(d).update(copy_sha256="A" * 64),
            f"{MAIL}: copy_sha256 must be a SHA-256 hex digest",
            id="copy digest in capitals",
        ),
        pytest.param(
            lambda d: _first(d).update(platforms=[""]),
            f"{MAIL}: platforms must be a list of names",
            id="empty platform",
        ),
    ],
)
def test_malformed_recorded_contracts_are_refused(change: Any, reason: str) -> None:
    document = copy.deepcopy(DATA)
    change(document)

    with pytest.raises(ValueError, match=f"^builtin-contracts: .*{re.escape(reason)}"):
        BuiltinContracts.from_document(document)


def test_recorded_contracts_that_are_not_a_mapping_are_refused() -> None:
    with pytest.raises(ValueError, match="builtin-contracts: the document must be a mapping"):
        BuiltinContracts.from_document([DATA])


# The copy a recorded built-in contract carries


def test_a_copy_that_is_the_recorded_one_passes() -> None:
    assert copy_findings(DOCUMENT, BUILTIN, PATH) == ()


def test_a_copy_that_differs_from_the_recorded_one_is_refused() -> None:
    # An instance that lacks the contract would build it from this copy.
    document = copy.deepcopy(DOCUMENT)
    document["scenario_injects"][0]["inject_injector_contract"]["injector_contract_platforms"] = [
        "Linux"
    ]

    findings = copy_findings(document, BUILTIN, PATH)

    assert [(f.code, f.severity, f.path, f.field) for f in findings] == [
        ("SCH-006", Severity.BLOCKING, PATH, "/scenario_injects/0")
    ]
    message = findings[0].message
    assert "normalise a fresh export" in message  # a hand edit, or a platform that changed it
    assert "update its recorded digest" in message


def test_only_recorded_built_in_copies_are_compared() -> None:
    # Unknown contracts are SCH-005's; payload contracts are the payload's.
    document = copy.deepcopy(DOCUMENT)
    document["scenario_injects"].append(_inject({"injector_contract_id": UNKNOWN, "x": 1}))
    document["scenario_injects"].append(_inject(None))

    assert copy_findings(document, BUILTIN, PATH) == ()


def test_copies_are_compared_per_inject() -> None:
    document = copy.deepcopy(DOCUMENT)
    document["scenario_injects"].append(_inject({"injector_contract_id": SCAN}))

    assert [f.field for f in copy_findings(document, BUILTIN, PATH)] == ["/scenario_injects/2"]


def test_copies_of_a_document_not_shaped_like_a_stored_scenario_are_refused() -> None:
    with pytest.raises(ExportStructureError):
        copy_findings({"scenario_injects": {}}, BUILTIN, PATH)
