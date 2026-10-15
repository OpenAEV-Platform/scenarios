"""A release's own output, verified before it is published: the manifest, each archive by its
hash and size, and each payload the archives embed by the canonical hash the manifest lists."""

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.release_output import (
    archive_findings,
    item_findings,
    manifest_findings,
    payload_content_findings,
)

VECTORS = json.loads(
    (Path(__file__).parents[3] / "conformance" / "payload-hash.json").read_text(encoding="utf-8")
)["vectors"]
VECTOR = VECTORS[1]
PAYLOAD_ID = "starter-pack-command"
PAYLOAD = dict(VECTOR["payload"], payload_external_id=PAYLOAD_ID)  # its ID is outside its hash
NAME = "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d-1.0.0.zip"
DATA = b"the archive's bytes"


def _item(**payloads: str) -> dict[str, Any]:
    return {
        "archive": {"name": NAME, "sha256": hashlib.sha256(DATA).hexdigest(), "size": len(DATA)},
        "payloads": [
            {"id": id_, "version": "1.0.0", "sha256": sha} for id_, sha in payloads.items()
        ],
    }


def _stored(*payloads: object, attack_patterns: list[str] = VECTOR["attack_patterns"]) -> Any:
    contract = {
        "injector_contract_attack_patterns": [
            {"attack_pattern_external_id": external} for external in attack_patterns
        ]
    }
    return {
        "scenario_injects": [
            {"inject_injector_contract": dict(contract, injector_contract_payload=payload)}
            for payload in payloads
        ]
    }


def _no_files(document: str) -> str | None:
    return None


def _codes(findings: tuple[Any, ...]) -> list[tuple[str, str, str, str]]:
    return [(f.code, f.path, f.field, f.message) for f in findings]


def test_an_archive_as_the_manifest_lists_it_is_accepted() -> None:
    assert archive_findings(_item(), DATA) == ()


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (None, "the archive the manifest lists is missing"),
        (DATA + b"!", f"{len(DATA) + 1} bytes, where the manifest lists {len(DATA)}"),
        (b"X" * len(DATA), "its SHA-256 is not the one the manifest lists"),
    ],
)
def test_an_archive_missing_or_other_than_listed_is_refused(
    data: bytes | None, message: str
) -> None:
    (finding,) = archive_findings(_item(), data)

    assert (finding.code, finding.severity, finding.path, finding.field, finding.message) == (
        "VRF-006",
        Severity.BLOCKING,
        NAME,
        "",
        message,
    )


def test_each_payload_embedded_with_the_hash_the_manifest_lists_is_accepted() -> None:
    item = _item(**{PAYLOAD_ID: VECTOR["sha256"]})
    stored = _stored(PAYLOAD, PAYLOAD)  # embedded twice, listed once

    assert payload_content_findings(item, stored, _no_files) == ()


def test_a_payload_whose_content_is_not_the_one_listed_is_refused() -> None:
    changed = copy.deepcopy(PAYLOAD)
    changed["command_content"] = "Write-Output changed"

    findings = payload_content_findings(
        _item(**{PAYLOAD_ID: VECTOR["sha256"]}), _stored(changed), _no_files
    )

    assert _codes(findings) == [
        (
            "VRF-008",
            NAME,
            "/scenario_injects/0/inject_injector_contract/injector_contract_payload",
            f"the payload {PAYLOAD_ID} has another content than the hash the manifest lists",
        )
    ]


def test_a_payload_embedded_but_not_listed_and_one_listed_but_not_embedded_are_refused() -> None:
    other = dict(PAYLOAD, payload_external_id="other-payload")

    findings = payload_content_findings(
        _item(**{"listed-only": "0" * 64}), _stored(other), _no_files
    )

    assert _codes(findings) == [
        (
            "VRF-008",
            NAME,
            "/scenario_injects/0/inject_injector_contract/injector_contract_payload",
            "the archive embeds the payload other-payload, which the manifest does not list",
        ),
        (
            "VRF-008",
            NAME,
            "",
            "the manifest lists the payload listed-only, which the archive does not embed",
        ),
    ]


@pytest.mark.parametrize("payload_id", [None, 1, ""])
def test_a_payload_without_its_id_is_refused(payload_id: object) -> None:
    unnamed = dict(PAYLOAD, payload_external_id=payload_id)

    (finding,) = payload_content_findings(_item(), _stored(unnamed), _no_files)

    assert (finding.code, finding.message) == (
        "VRF-008",
        "the archive embeds a payload without its ID, which the manifest cannot list",
    )


def test_a_payload_that_is_not_an_object_is_refused_as_one_without_its_id() -> None:
    (finding,) = payload_content_findings(_item(), _stored("a payload"), _no_files)

    assert (finding.code, finding.message) == (
        "VRF-008",
        "the archive embeds a payload without its ID, which the manifest cannot list",
    )


def test_an_attached_file_enters_the_hash_by_the_bytes_the_archive_holds() -> None:
    executable = next(v for v in VECTORS if v["payload"].get("payload_type") == "Executable")
    payload = dict(executable["payload"], payload_external_id=PAYLOAD_ID)
    stored = _stored(payload, attack_patterns=executable["attack_patterns"])

    findings = payload_content_findings(
        _item(**{PAYLOAD_ID: executable["sha256"]}), stored, executable["files"].get
    )

    assert findings == ()


@pytest.mark.parametrize(
    "refused",
    [
        dict(PAYLOAD, payload_external_id=None),
        dict(PAYLOAD, payload_external_id="other-payload"),
        dict(PAYLOAD, payload_platforms="Windows"),
    ],
    ids=["without its ID", "not listed", "not hashable"],
)
def test_a_payload_refused_leaves_the_next_one_verified(refused: dict[str, Any]) -> None:
    changed = dict(PAYLOAD, command_content="Write-Output changed")

    findings = payload_content_findings(
        _item(**{PAYLOAD_ID: VECTOR["sha256"]}), _stored(refused, changed), _no_files
    )

    assert len(findings) == 2
    assert _codes(findings)[1] == (
        "VRF-008",
        NAME,
        "/scenario_injects/1/inject_injector_contract/injector_contract_payload",
        f"the payload {PAYLOAD_ID} has another content than the hash the manifest lists",
    )


def test_a_payload_that_cannot_be_hashed_is_refused() -> None:
    broken = dict(PAYLOAD, payload_platforms="Windows")

    (finding,) = payload_content_findings(
        _item(**{PAYLOAD_ID: VECTOR["sha256"]}), _stored(broken), _no_files
    )

    assert finding.code == "VRF-008"
    assert finding.message.startswith(f"the payload {PAYLOAD_ID} cannot be hashed: ")


def test_a_manifest_that_meets_its_schema_is_accepted_and_an_approved_one_names_its_approver() -> (
    None
):
    assert manifest_findings((), {}, approved=False) == ()
    assert manifest_findings((), {"release_approver": "alice"}, approved=True) == ()


def test_a_manifest_out_of_its_schema_or_approved_without_its_approver_is_refused_with_why() -> (
    None
):
    violations = (("/items/0/version", "'1.0' is not a version"), ("", "'items' is required"))

    findings = manifest_findings(violations, {}, approved=True)

    assert _codes(findings) == [
        ("VRF-009", "manifest.json", "/items/0/version",
         "does not meet the manifest's schema: '1.0' is not a version"),
        ("VRF-009", "manifest.json", "",
         "does not meet the manifest's schema: 'items' is required"),
        ("VRF-009", "manifest.json", "/release_approver",
         "an approved manifest names its release approver"),
    ]  # fmt: skip


ONE_ID, TWO_ID = "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d", "1a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"


def _listed(external_id: str, version: str, name: str | None = None) -> dict[str, Any]:
    return {
        "external_id": external_id,
        "version": version,
        "archive": {"name": name or f"{external_id}-{version}.zip"},
    }


def test_items_each_of_one_scenario_named_by_it_are_accepted() -> None:
    assert item_findings([_listed(ONE_ID, "1.0.0"), _listed(TWO_ID, "2.1.0")]) == ()


def test_an_item_whose_archive_is_named_after_another_scenario_or_version_is_refused() -> None:
    wrong = f"{TWO_ID}-1.0.0.zip"

    assert _codes(item_findings([_listed(ONE_ID, "1.0.0", wrong)])) == [
        ("VRF-009", "manifest.json", "/items/0/archive/name",
         f"the archive of {ONE_ID} 1.0.0 is named {wrong}"),
    ]  # fmt: skip


def test_a_scenario_or_an_archive_listed_twice_is_refused() -> None:
    items = [_listed(ONE_ID, "1.0.0"), _listed(ONE_ID, "1.0.0"), _listed(ONE_ID, "2.0.0")]

    assert _codes(item_findings(items)) == [
        ("VRF-009", "manifest.json", "/items/1", f"the scenario {ONE_ID} is listed twice"),
        ("VRF-009", "manifest.json", "/items/2", f"the scenario {ONE_ID} is listed twice"),
    ]


def test_a_payload_listed_twice_in_an_item_is_refused() -> None:
    item = _item(**{PAYLOAD_ID: VECTOR["sha256"]})
    item["payloads"].append({"id": PAYLOAD_ID, "version": "1.0.0", "sha256": "0" * 64})

    findings = payload_content_findings(item, _stored(PAYLOAD), _no_files)

    assert _codes(findings) == [
        ("VRF-008", NAME, "", f"the manifest lists the payload {PAYLOAD_ID} twice")
    ]


def test_the_id_of_a_payload_is_outside_its_hash() -> None:
    """What the domain tests above rely on: the vector, as exported, gives the same hash."""
    from scenario_tools.domain.verification.payload_hash import payload_hash

    assert payload_hash(PAYLOAD, VECTOR["attack_patterns"], _no_files).hex == VECTOR["sha256"]
