"""The payload references of an entry, as the commands check and give them."""

from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.catalogue_files import CatalogueDirectory
from scenario_tools.application.assign_payloads import (
    assigned_entry,
    catalogue_of,
    no_attached_files,
    payload_findings,
)
from scenario_tools.domain.verification.payload_hash import payload_hash
from scenario_tools.domain.verification.payload_references import (
    AgreedId,
    AgreedIds,
    HeldVersions,
    PayloadReference,
    derived_id,
)
from scenario_tools.ports.errors import EnvironmentProblemError
from tests.support.catalogue import held

ENTRY = "scenarios/techniques/x"
PAYLOAD = {"payload_type": "Command", "payload_name": "a", "command_content": "whoami"}
HASH = payload_hash(PAYLOAD, (), no_attached_files).hex
NONE = AgreedIds({})


def stored(payload: object) -> dict[str, Any]:
    return {
        "scenario_injects": [{"inject_injector_contract": {"injector_contract_payload": payload}}]
    }


def test_no_attached_file_is_read_yet() -> None:
    assert no_attached_files("any") is None


def test_the_findings_name_the_entry_s_two_files() -> None:
    declared = {"payloads": [{"id": "x", "version": "1.0.0", "sha256": "0" * 64}]}

    findings = payload_findings(declared, stored(PAYLOAD), ENTRY, NONE, held(stored(PAYLOAD)))

    assert [(f.code, f.path) for f in findings] == [
        ("PAY-008", f"{ENTRY}/scenario.yaml"),
        ("PAY-001", f"{ENTRY}/scenario.json"),
        ("PAY-006", f"{ENTRY}/scenario.yaml"),
    ]


def test_an_attached_file_is_refused_until_its_bytes_are_read() -> None:
    findings = payload_findings(
        {"payloads": []},
        stored({"payload_type": "FileDrop", "file_drop_file": "doc"}),
        ENTRY,
        NONE,
        held(stored({"payload_type": "FileDrop", "file_drop_file": "doc"})),
    )

    assert [(f.code, f.field) for f in findings] == [
        (
            "PAY-005",
            "/scenario_injects/0/inject_injector_contract/injector_contract_payload/file_drop_file",
        )
    ]


def test_an_assigned_entry_keeps_its_metadata_in_place_and_replaces_its_references() -> None:
    declared = {"name": "X", "payloads": [], "targets": []}

    result = assigned_entry(declared, stored(PAYLOAD), ENTRY, NONE, held(stored(PAYLOAD)))

    assert result.refusals == ()
    assert result.metadata is not None
    assert result.stored is not None
    assert list(result.metadata) == ["name", "payloads", "targets"]
    assert result.metadata["payloads"] == [
        {"id": derived_id(HASH), "version": "1.0.0", "sha256": HASH}
    ]
    assert payload_findings(result.metadata, result.stored, ENTRY, NONE, held(result.stored)) == ()
    assert declared["payloads"] == []  # the given metadata is left as it is


def test_an_agreed_id_is_given_for_its_content() -> None:
    result = assigned_entry(
        {"payloads": []},
        stored(PAYLOAD),
        ENTRY,
        AgreedIds({HASH: AgreedId("agreed", "a")}),
        # The catalogue holds that content under the agreed ID, as validate-payloads requires.
        HeldVersions.of([PayloadReference("agreed", "1.0.0", HASH)]),
    )

    assert result.metadata is not None
    assert result.metadata["payloads"][0]["id"] == "agreed"


def test_nothing_is_assigned_when_a_payload_cannot_be_hashed() -> None:
    result = assigned_entry({"payloads": []}, stored("x"), ENTRY, NONE, held(stored("x")))

    assert (result.metadata, result.stored) == (None, None)
    assert [(f.code, f.path) for f in result.refusals] == [("PAY-005", f"{ENTRY}/scenario.json")]


@pytest.mark.parametrize(
    ("declared", "scenario", "expected"),
    [
        (
            ["a"],
            {},
            (
                "SCH-001",
                f"{ENTRY}/scenario.yaml",
                "scenario.yaml must be an object holding the entry's metadata",
            ),
        ),
        (
            {},
            [],
            (
                "IO-014",
                f"{ENTRY}/scenario.json",
                "not an OpenAEV scenario export: the document must be an object",
            ),
        ),
    ],
)
def test_a_file_that_is_no_object_is_refused(
    declared: object, scenario: object, expected: tuple[str, str, str]
) -> None:
    result = assigned_entry(declared, scenario, ENTRY, NONE, held(scenario))

    assert (result.metadata, result.stored) == (None, None)
    assert [(f.code, f.path, f.message) for f in result.refusals] == [expected]


@pytest.mark.parametrize(
    "content",
    [b'{"payload_name": "a", "payload_name": "b"}', b"{not json", b"\xff\xfe"],
    ids=["a key twice", "no JSON", "no UTF-8"],
)
def test_a_catalogue_file_that_cannot_be_read_is_the_repository_s_fault(
    tmp_path: Path, content: bytes
) -> None:
    folder = tmp_path / "payloads" / "a"
    folder.mkdir(parents=True)
    (folder / "1.0.0.json").write_bytes(content)

    with pytest.raises(EnvironmentProblemError, match="run `scenario-tools validate-payloads`"):
        catalogue_of(CatalogueDirectory(tmp_path, ("payloads",)))


@pytest.mark.parametrize("stray", ["README.md", "a/notes.txt", "a/1.0.0.json"])
def test_a_catalogue_its_layout_refuses_is_the_repository_s_fault(
    tmp_path: Path, stray: str
) -> None:
    (tmp_path / "payloads" / "a").mkdir(parents=True)
    if stray == "a/1.0.0.json":  # over the size bound: left out of the layout
        (tmp_path / "payloads" / stray).write_bytes(b" " * 262_145 + b"{}")
    else:
        (tmp_path / "payloads" / "a" / "1.0.0.json").write_text("{}")
        (tmp_path / "payloads" / stray).write_text("Not a version.\n")

    with pytest.raises(EnvironmentProblemError, match="run `scenario-tools validate-payloads`"):
        catalogue_of(CatalogueDirectory(tmp_path, ("payloads",)))
