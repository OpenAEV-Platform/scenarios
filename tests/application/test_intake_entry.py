"""Intake of an export into the catalogue: refused before anything is written when the request,
the catalogue or the metadata it completes says so; otherwise what to write, and what is left.

Characters are written by code point, never raw, so that this file holds none of them."""

import copy
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader, read_export
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.application.intake_entry import (
    IntakeResult,
    intake_entry,
    intake_files,
    plan_document,
)
from scenario_tools.domain.catalogue.intake import CatalogueEntry
from scenario_tools.domain.shared.finding import Finding

ROOT = Path(__file__).parents[2]
EASM = read_export(ROOT / "tests" / "golden" / "exports" / "easm-scenario.zip")
DATA = YamlDataLoader(ROOT / "policy" / "data")
SCHEMA = JsonSchemaValidator(ROOT / "schemas")
DOMAINS = ("vulnerabilities", "intrusion-sets", "ransomware", "techniques")
ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
ENTRY = "scenarios/techniques/easm"
REQUEST = "request.yaml"
EXPORT = "export.zip"
NEW: dict[str, Any] = {
    "mode": "new",
    "external_id": ID,
    "domain": "techniques",
    "slug": "easm",
    "threat": {"ttps": ["T1595"]},
    "sources": [{"url": "https://attack.mitre.org/techniques/T1595/", "tlp": "TLP:CLEAR"}],
    "generated_by": "run 42",
    "issue": 12,
}
UPDATE = {"mode": "update", "external_id": ID, "domain": "techniques", "slug": "easm", "issue": 13}


class FakeSource:
    def __init__(
        self,
        entries: tuple[CatalogueEntry, ...] = (),
        stored: tuple[bytes, object] | None = None,
        taken: frozenset[str] = frozenset(),
    ) -> None:
        self._entries = entries
        self.stored = stored
        self.taken = taken

    def entries(self) -> tuple[CatalogueEntry, ...]:
        return self._entries

    def exists(self, path: str) -> bool:
        return path in self.taken

    def read_json(self, path: str) -> tuple[bytes, object]:
        assert path == f"{ENTRY}/scenario.json"
        assert self.stored is not None
        return self.stored

    def names(self, entry: str) -> frozenset[str]:
        raise AssertionError("intake never asks")

    def read_yaml(self, path: str) -> object:
        raise AssertionError("intake never asks")

    def read_text(self, path: str) -> str:
        raise AssertionError("intake never asks")

    def external_ids(self) -> Mapping[str, tuple[str, ...]]:
        raise AssertionError("intake never asks")


def _intake(
    request: Mapping[str, Any], source: FakeSource | None = None, export: Any = EASM
) -> IntakeResult:
    return intake_entry(
        export,
        dict(request),
        request_path=REQUEST,
        export_path=EXPORT,
        source=source or FakeSource(),
        data=DATA,
        schema=SCHEMA,
        domains=DOMAINS,
    )


def _codes(findings: tuple[Finding, ...]) -> list[tuple[str, str, str]]:
    return [(finding.code, finding.path, finding.field) for finding in findings]


def test_a_new_entry_is_its_export_and_a_starting_metadata_the_request_completes() -> None:
    result = _intake(NEW)

    assert result.refusals == ()
    assert result.changed
    assert result.scenario_json is not None
    assert result.metadata is not None
    assert result.metadata["threat"] == NEW["threat"]
    assert result.metadata["sources"] == NEW["sources"]
    assert result.metadata["generated_by"] == "run 42"
    assert SCHEMA.validate("scenario", result.metadata) == ()
    left = {finding.field for finding in result.to_complete}
    assert not left & {"/threat", "/sources"}  # given by the request
    assert {finding.path for finding in result.to_complete} == {f"{ENTRY}/scenario.yaml"}


@pytest.mark.parametrize(
    ("change", "pointer"),
    [({"mode": "replace"}, "/mode"), ({"slug": "Bad_Slug"}, "/slug")],
    ids=["mode", "slug"],
)
def test_a_request_outside_its_schema_is_refused(change: dict[str, Any], pointer: str) -> None:
    result = _intake({**NEW, **change})

    assert ("SCH-001", REQUEST, pointer) in _codes(result.refusals)
    assert result.scenario_json is None


def test_a_request_for_an_unknown_domain_is_refused() -> None:
    result = _intake({**NEW, "domain": "malware"})

    assert _codes(result.refusals) == [("SCH-001", REQUEST, "/domain")]
    assert "vulnerabilities" in result.refusals[0].message


def test_the_catalogue_refuses_what_it_already_holds() -> None:
    taken = FakeSource((CatalogueEntry("scenarios/ransomware/other", ID, "Other"),))

    assert _codes(_intake(NEW, taken).refusals) == [("ITK-001", REQUEST, "/external_id")]
    occupied = FakeSource(taken=frozenset({ENTRY}))
    assert _codes(_intake(NEW, occupied).refusals) == [("ITK-002", REQUEST, "/slug")]


def test_metadata_the_request_makes_invalid_is_refused_with_its_violations() -> None:
    insecure = [{"url": "http://example.org", "tlp": "TLP:CLEAR"}]

    result = _intake({**NEW, "sources": insecure})

    codes = _codes(result.refusals)
    assert codes[0] == ("ITK-007", REQUEST, "")
    assert ("SCH-001", f"{ENTRY}/scenario.yaml", "/sources/0/url") in codes
    assert result.scenario_json is None


def test_an_export_holding_a_hidden_character_is_refused() -> None:
    hostile = copy.deepcopy(EASM)
    hostile["scenario_information"]["scenario_subtitle"] = f"x{chr(0x202E)}"

    result = _intake(NEW, export=hostile)

    assert [finding.code for finding in result.refusals] == ["IO-017"]
    assert result.scenario_json is None


def _stored() -> FakeSource:
    first = _intake(NEW)
    assert first.scenario_json is not None
    name = EASM["scenario_information"]["scenario_name"]
    return FakeSource(
        (CatalogueEntry(ENTRY, ID, name),), (first.scenario_json, json.loads(first.scenario_json))
    )


def test_an_update_with_the_same_export_changes_nothing() -> None:
    result = _intake(UPDATE, _stored())

    assert result.refusals == ()
    assert not result.changed
    assert result.metadata is None  # scenario.yaml is never rewritten
    assert result.to_complete == ()  # no new version to give


def test_an_update_with_a_changed_export_rewrites_scenario_json_only() -> None:
    changed = copy.deepcopy(EASM)
    changed["scenario_information"]["scenario_subtitle"] = "A new subtitle"

    result = _intake(UPDATE, _stored(), export=changed)

    assert result.refusals == ()
    assert result.changed
    assert result.metadata is None
    assert result.scenario_json is not None
    assert b"A new subtitle" in result.scenario_json
    assert [(f.code, f.path, f.field) for f in result.to_complete] == [
        ("SCH-007", f"{ENTRY}/scenario.yaml", "/version")
    ]
    assert "CHANGELOG.md" in result.to_complete[0].message


def test_an_update_of_an_unknown_entry_is_refused() -> None:
    assert _codes(_intake(UPDATE).refusals) == [("ITK-004", REQUEST, "/external_id")]


def test_an_update_whose_export_holds_a_hidden_character_is_refused() -> None:
    hostile = copy.deepcopy(EASM)
    hostile["scenario_information"]["scenario_subtitle"] = f"x{chr(0x202E)}"

    result = _intake(UPDATE, _stored(), export=hostile)

    assert [finding.code for finding in result.refusals] == ["IO-017"]
    assert result.scenario_json is None


def _render(metadata: dict[str, Any]) -> bytes:
    return b"yaml"


def test_a_new_entry_writes_its_metadata_then_its_scenario() -> None:
    result = _intake(NEW)

    files = intake_files(result, _render)

    assert list(files) == ["scenario.yaml", "scenario.json"]
    assert files["scenario.yaml"] == b"yaml"
    assert files["scenario.json"] == result.scenario_json


def test_an_update_writes_its_scenario_only_and_nothing_when_unchanged() -> None:
    changed = copy.deepcopy(EASM)
    changed["scenario_information"]["scenario_subtitle"] = "A new subtitle"

    assert list(intake_files(_intake(UPDATE, _stored(), export=changed), _render)) == [
        "scenario.json"
    ]
    assert intake_files(_intake(UPDATE, _stored()), _render) == {}
    assert intake_files(_intake({**NEW, "mode": "replace"}), _render) == {}  # refused


def test_the_plan_gives_each_file_written_its_digest() -> None:
    result = _intake(NEW)
    files = {"scenario.yaml": b"a", "scenario.json": b"b"}

    plan = plan_document(result, files, "f" * 40, ())

    assert plan["files"] == [
        {"path": f"{ENTRY}/scenario.json", "sha256": hashlib.sha256(b"b").hexdigest()},
        {"path": f"{ENTRY}/scenario.yaml", "sha256": hashlib.sha256(b"a").hexdigest()},
    ]
    assert plan["base"] == "f" * 40
    assert plan["title"] == "feat(scenarios): add easm (#12)"


def test_a_renamed_scenario_leaves_its_metadata_to_align() -> None:
    renamed = copy.deepcopy(EASM)
    renamed["scenario_information"]["scenario_name"] = "EASM, renamed"

    result = _intake({**UPDATE, "rewrite": True}, _stored(), export=renamed)

    assert result.refusals == ()
    assert ("SCH-007", f"{ENTRY}/scenario.yaml", "/name") in _codes(result.to_complete)


def test_injects_the_update_no_longer_has_are_reported() -> None:
    smaller = copy.deepcopy(EASM)
    removed = smaller["scenario_injects"].pop()

    result = _intake(UPDATE, _stored(), export=smaller)

    assert ("VER-012", f"{ENTRY}/scenario.json", "") in _codes(result.to_complete)
    assert removed["inject_title"] not in " ".join(f.message for f in result.to_complete)


def test_a_refused_request_has_no_plan() -> None:
    with pytest.raises(ValueError, match="no plan"):
        plan_document(_intake({**NEW, "mode": "replace"}), {}, "f" * 40, ())
