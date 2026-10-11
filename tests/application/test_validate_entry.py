"""Validating an entry: each of its files checked as the data model says, every refusal a
finding of the entry, so that one broken file never hides the others' findings.

Characters are written by code point, never raw, so that this file holds none of them."""

import copy
from collections.abc import Mapping
from typing import Any

import pytest

from scenario_tools.application.validate_entry import validate_entry
from scenario_tools.domain.catalogue.facts import BuiltinContracts
from scenario_tools.domain.catalogue.intake import CatalogueEntry
from scenario_tools.domain.catalogue.metadata import InjectFacts
from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.errors import UnsafeInputError
from scenario_tools.ports.schema import SchemaViolation

ENTRY = "scenarios/ransomware/akira"
YAML, JSON = f"{ENTRY}/scenario.yaml", f"{ENTRY}/scenario.json"
README, CHANGELOG = f"{ENTRY}/README.md", f"{ENTRY}/CHANGELOG.md"
ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
RLO = chr(0x202E)
BUILTIN = BuiltinContracts("3.261005.0", {}, {})
DOMAINS = ("vulnerabilities", "intrusion-sets", "ransomware", "techniques")
STORED = b"{stored}"
METADATA: dict[str, Any] = {
    "schema_version": 1,
    "external_id": ID,
    "version": "1.0.0",
    "status": "VERIFIED",
    "name": "Akira",
    "description": "A crisis exercise.",
    "severity": "high",
    "category": "Ransomware",
    "main_focus": "Crisis",
    "type": "time-based",
    "platforms": ["Generic"],
    "threat": {"ttps": ["T1486"]},
    "sources": [{"url": "https://example.org", "tlp": "TLP:CLEAR"}],
    "requires": {"openaev": ">=3.261005.0", "edition": "CE", "injectors": [], "executors": []},
    "payloads": [],
}
SCENARIO: dict[str, Any] = {
    "scenario_information": {
        "scenario_name": "Akira",
        "scenario_severity": "high",
        "scenario_category": "Ransomware",
        "scenario_main_focus": "Crisis",
    },
    "scenario_injects": [],
}


class FakeSource:
    def __init__(
        self,
        files: Mapping[str, object],
        others: Mapping[str, tuple[str, ...]] | None = None,
        raw: Mapping[str, str] | None = None,
    ) -> None:
        self.files = dict(files)
        self.others = others or {ID: (ENTRY,)}
        self.raw = dict(raw or {})

    def names(self, entry: str) -> frozenset[str]:
        return frozenset(path.rsplit("/", 1)[1] for path in self.files if path.startswith(entry))

    def _read(self, path: str) -> object:
        value = self.files[path]
        if isinstance(value, UnsafeInputError):
            raise value
        return value

    def read_yaml(self, path: str) -> object:
        return self._read(path)

    def read_json(self, path: str) -> tuple[bytes, object]:
        return STORED, self._read(path)

    def read_text(self, path: str) -> str:
        if path in self.raw:
            return self.raw[path]
        if path == YAML:
            return ""  # what the document's own check sees is enough for these tests
        value = self._read(path)
        assert isinstance(value, str)
        return value

    def external_ids(self) -> Mapping[str, tuple[str, ...]]:
        return self.others

    def exists(self, path: str) -> bool:
        raise AssertionError("validate never asks")

    def entries(self) -> tuple[CatalogueEntry, ...]:
        raise AssertionError("validate never asks")


class FakeSchema:
    def __init__(self, *violations: SchemaViolation) -> None:
        self.violations = violations
        self.seen: list[tuple[str, object]] = []

    def validate(self, schema: str, document: object) -> tuple[SchemaViolation, ...]:
        self.seen.append((schema, document))
        return self.violations


def _same(document: object, external_id: str, path: str) -> bytes:
    return STORED


def _validate(
    files: Mapping[str, object] | None = None,
    *,
    schema: FakeSchema | None = None,
    others: Mapping[str, tuple[str, ...]] | None = None,
    renormalised: Any = _same,
) -> tuple[Finding, ...]:
    source = FakeSource(files if files is not None else {YAML: METADATA, JSON: SCENARIO}, others)
    return validate_entry(
        ENTRY,
        source,
        schema=schema or FakeSchema(),
        builtin=BUILTIN,
        renormalised=renormalised,
        domains=DOMAINS,
    )


def _codes(findings: tuple[Finding, ...]) -> list[tuple[str, str, str]]:
    return [(finding.code, finding.path, finding.field) for finding in findings]


def _changed(**changes: Any) -> dict[str, Any]:
    metadata = copy.deepcopy(METADATA)
    metadata.update(changes)
    return metadata


def test_a_sound_entry_has_no_finding_and_its_metadata_meets_its_schema() -> None:
    schema = FakeSchema()

    assert _validate(schema=schema) == ()
    assert schema.seen == [("scenario", METADATA)]


def test_a_missing_file_is_reported_and_the_other_still_checked() -> None:
    findings = _validate({JSON: {"scenario_information": {}, "scenario_injects": [RLO]}})

    assert ("SCH-008", YAML, "") in _codes(findings)
    assert ("IO-017", JSON, "/scenario_injects/0") in _codes(findings)


def test_a_file_the_readers_refuse_is_a_finding_of_the_entry() -> None:
    refused = UnsafeInputError("IO-002", "not valid YAML", YAML)

    findings = _validate({YAML: refused, JSON: SCENARIO})

    assert findings == (Finding("IO-002", Severity.BLOCKING, YAML, "", "not valid YAML"),)


def test_schema_violations_are_reported_and_stop_the_checks_that_need_the_schema() -> None:
    schema = FakeSchema(SchemaViolation("/severity", "'High' is not one of the values"))
    metadata = _changed(severity="High", description=f"Cut{chr(0x2026)}")

    findings = _validate({YAML: metadata, JSON: SCENARIO}, schema=schema)

    assert findings == (
        Finding("SCH-001", Severity.BLOCKING, YAML, "/severity", "'High' is not one of the values"),
    )


def test_a_stored_scenario_not_shaped_like_an_export_is_refused_and_not_renormalised() -> None:
    renormalised: list[object] = []

    def record(document: object, external_id: str, path: str) -> bytes:
        renormalised.append(document)
        return STORED

    findings = _validate({YAML: METADATA, JSON: {"scenario_information": []}}, renormalised=record)

    [finding] = findings
    assert (finding.code, finding.severity, finding.path) == ("IO-014", Severity.BLOCKING, JSON)
    assert renormalised == []


@pytest.mark.parametrize(
    "error",
    [
        UnsafeInputError("IO-014", "scenario_injects must be a list", JSON),
        ExportStructureError("scenario_injects must be a list"),
    ],
    ids=["refused input", "not an export"],
)
def test_a_renormalisation_the_stored_scenario_breaks_keeps_its_other_findings(
    error: Exception,
) -> None:
    def broken(document: object, external_id: str, path: str) -> bytes:
        raise error

    findings = _validate(
        {YAML: METADATA, JSON: dict(SCENARIO, scenario_tags=[f"x{RLO}"])}, renormalised=broken
    )

    assert _codes(findings) == [("IO-017", JSON, "/scenario_tags/0"), ("IO-014", JSON, "")]


def test_the_metadata_is_cross_checked_against_the_stored_scenario() -> None:
    findings = _validate({YAML: _changed(name="Other"), JSON: SCENARIO})

    assert _codes(findings) == [("SCH-002", YAML, "/name")]


def test_a_stored_scenario_normalisation_would_change_is_refused() -> None:
    findings = _validate(renormalised=lambda document, external_id, path: b"{other}")

    assert _codes(findings) == [("GEN-002", JSON, "")]


def test_the_renormalisation_gets_the_entry_s_external_id_and_path() -> None:
    calls: list[tuple[object, str, str]] = []

    def record(document: object, external_id: str, path: str) -> bytes:
        calls.append((document, external_id, path))
        return STORED

    _validate(renormalised=record)

    assert calls == [(SCENARIO, ID, JSON)]


def test_an_external_id_another_entry_declares_is_refused() -> None:
    others = {ID: (ENTRY, "scenarios/techniques/other")}

    findings = _validate(others=others)

    assert findings == (
        Finding(
            "SCH-010",
            Severity.BLOCKING,
            YAML,
            "/external_id",
            "another entry has this external_id: scenarios/techniques/other",
        ),
    )


def test_a_cut_description_is_refused() -> None:
    findings = _validate({YAML: _changed(description=f"Cut{chr(0x2026)}"), JSON: SCENARIO})

    assert _codes(findings) == [("SCH-009", YAML, "/description")]


def test_an_old_minimum_version_is_information_only() -> None:
    requires = dict(METADATA["requires"], openaev=">=3.260923")

    findings = _validate({YAML: _changed(requires=requires), JSON: SCENARIO})

    assert [(f.code, f.severity) for f in findings] == [("SCH-011", Severity.INFO)]


def test_hidden_characters_in_the_metadata_are_refused() -> None:
    # Written as escapes, which the reader decodes: only the document shows them.
    findings = _validate({YAML: _changed(generated_by=f"x{RLO}"), JSON: SCENARIO})

    assert _codes(findings) == [("IO-017", YAML, "/generated_by")]
    assert findings[0].message.endswith(": remove it from the file")


def test_hidden_characters_in_the_stored_scenario_are_refused() -> None:
    findings = _validate({YAML: METADATA, JSON: dict(SCENARIO, scenario_tags=[f"x{RLO}"])})

    assert _codes(findings) == [("IO-017", JSON, "/scenario_tags/0")]


@pytest.mark.parametrize("name", [README, CHANGELOG])
def test_the_markdown_files_are_checked_as_written_when_present(name: str) -> None:
    files: dict[str, object] = {YAML: METADATA, JSON: SCENARIO, name: f"# Notes\n{RLO}\\u200b\n"}

    findings = _validate(files)

    assert _codes(findings) == [("IO-017", name, "")]


def test_a_markdown_file_the_readers_refuse_is_a_finding_too() -> None:
    files: dict[str, object] = {
        YAML: METADATA,
        JSON: SCENARIO,
        README: UnsafeInputError("IO-013", "not a regular file", README),
    }

    assert _codes(_validate(files)) == [("IO-013", README, "")]


class LinkedEntry(FakeSource):
    def names(self, entry: str) -> frozenset[str]:
        raise UnsafeInputError("IO-013", "a symbolic link", entry)


def test_an_entry_the_readers_cannot_list_is_a_finding_of_the_entry() -> None:
    findings = validate_entry(
        ENTRY,
        LinkedEntry({}),
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
    )

    assert findings == (Finding("IO-013", Severity.BLOCKING, ENTRY, "", "a symbolic link"),)


def test_a_stored_scenario_the_readers_refuse_is_a_finding_too() -> None:
    files: dict[str, object] = {
        YAML: METADATA,
        JSON: UnsafeInputError("IO-001", "larger than 20971520 bytes", JSON),
    }

    assert _codes(_validate(files)) == [("IO-001", JSON, "")]


def test_a_built_in_contract_copy_other_than_the_recorded_one_is_refused() -> None:
    contract = "11111111-2222-4333-8444-555555555555"
    builtin = BuiltinContracts(
        "3.261005.0",
        {contract: InjectFacts("openaev_email", False, frozenset())},
        {contract: "0" * 64},
    )
    inject = {"inject_injector_contract": {"injector_contract_id": contract}}
    requires = dict(METADATA["requires"], injectors=["openaev_email"])

    findings = validate_entry(
        ENTRY,
        FakeSource(
            {YAML: _changed(requires=requires), JSON: dict(SCENARIO, scenario_injects=[inject])}
        ),
        schema=FakeSchema(),
        builtin=builtin,
        renormalised=_same,
        domains=DOMAINS,
    )

    assert _codes(findings) == [("SCH-006", JSON, "/scenario_injects/0")]


def test_metadata_that_is_no_mapping_is_left_to_its_schema() -> None:
    findings = _validate({YAML: ["not", "a", "mapping"], JSON: SCENARIO})

    assert findings == ()  # the schema refuses it; nothing reads its fields


def test_the_metadata_is_checked_as_written_too_comments_included() -> None:
    source = FakeSource({YAML: METADATA, JSON: SCENARIO}, raw={YAML: f"# a note {RLO}\n"})

    findings = validate_entry(
        ENTRY, source, schema=FakeSchema(), builtin=BUILTIN, renormalised=_same, domains=DOMAINS
    )

    assert _codes(findings) == [("IO-017", YAML, "")]


def test_a_hidden_character_written_in_the_metadata_is_reported_once() -> None:
    raw = {YAML: f"generated_by: x{RLO}\n"}
    source = FakeSource({YAML: _changed(generated_by=f"x{RLO}"), JSON: SCENARIO}, raw=raw)

    findings = validate_entry(
        ENTRY, source, schema=FakeSchema(), builtin=BUILTIN, renormalised=_same, domains=DOMAINS
    )

    assert _codes(findings) == [("IO-017", YAML, "")]
    assert findings[0].message.endswith(": remove it from the file")


def test_a_line_break_yaml_reads_but_a_reviewer_may_not_see_is_refused() -> None:
    raw = {YAML: f"# note{chr(0x2028)}name: Akira\n"}
    source = FakeSource({YAML: METADATA, JSON: SCENARIO}, raw=raw)

    findings = validate_entry(
        ENTRY, source, schema=FakeSchema(), builtin=BUILTIN, renormalised=_same, domains=DOMAINS
    )

    assert _codes(findings) == [("IO-017", YAML, "")]


def test_a_renormalisation_refused_still_lets_the_metadata_be_cross_checked() -> None:
    def broken(document: object, external_id: str, path: str) -> bytes:
        raise UnsafeInputError("IO-014", "a chained scenario is not supported", JSON)

    findings = _validate({YAML: _changed(name="Other"), JSON: SCENARIO}, renormalised=broken)

    assert _codes(findings) == [("IO-014", JSON, ""), ("SCH-002", YAML, "/name")]
