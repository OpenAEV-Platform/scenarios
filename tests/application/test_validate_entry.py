"""Validating an entry: each of its files checked as the data model says, every refusal a
finding of the entry, so that one broken file never hides the others' findings.

Characters are written by code point, never raw, so that this file holds none of them."""

import copy
import dataclasses
from collections.abc import Mapping
from typing import Any

import pytest

from scenario_tools.application.assign_payloads import no_attached_files
from scenario_tools.application.validate_entry import validate_entry
from scenario_tools.domain.catalogue.export_reading import ExportStructureError
from scenario_tools.domain.catalogue.facts import BuiltinContracts
from scenario_tools.domain.catalogue.intake import CatalogueEntry, name_key
from scenario_tools.domain.catalogue.metadata import InjectFacts
from scenario_tools.domain.policy.exceptions import PolicyException
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.sheet.sheet import render_sheet
from scenario_tools.domain.verification.payload_hash import payload_hash
from scenario_tools.domain.verification.payload_references import AgreedIds, derived_id
from scenario_tools.ports.errors import UnsafeInputError
from scenario_tools.ports.schema import SchemaViolation
from tests.domain.policy.cases import DATA
from tests.support.catalogue import held

ENTRY = "scenarios/ransomware/akira"
YAML, JSON = f"{ENTRY}/scenario.yaml", f"{ENTRY}/scenario.json"
README, CHANGELOG = f"{ENTRY}/README.md", f"{ENTRY}/CHANGELOG.md"
ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
RLO = chr(0x202E)
BUILTIN = BuiltinContracts("3.261005.0", {}, {})
DOMAINS = ("vulnerabilities", "intrusion-sets", "ransomware", "techniques")
STORED = b"{stored}"
LOG = "## 1.0.0 — 2026-10-12\n"
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
        catalogue: tuple[CatalogueEntry, ...] | None = None,
    ) -> None:
        # The sheet the entry gives by default, as render writes it; a file given as None is
        # absent.
        given = {README: _sheet(files), **files} if files.get(YAML) is not None else dict(files)
        self.files = {name: value for name, value in given.items() if value is not None}
        self.others = others or {ID: (ENTRY,)}
        self.raw = dict(raw or {})
        self.catalogue = catalogue or (CatalogueEntry(ENTRY, ID, str(METADATA["name"])),)

    def names(self, entry: str) -> frozenset[str]:
        return frozenset(
            path.rsplit("/", 1)[1] for path in self.files if path.startswith(f"{entry}/")
        )

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
        raise AssertionError("validate reads the names' index, never every entry")

    def scenario_names(self) -> Mapping[str, tuple[str, ...]]:
        index: dict[str, tuple[str, ...]] = {}
        for entry in self.catalogue:
            if entry.name:
                index[name_key(entry.name)] = (*index.get(name_key(entry.name), ()), entry.path)
        return index


class FakeSchema:
    def __init__(self, *violations: SchemaViolation) -> None:
        self.violations = violations
        self.seen: list[tuple[str, object]] = []

    def validate(self, schema: str, document: object) -> tuple[SchemaViolation, ...]:
        self.seen.append((schema, document))
        return self.violations


def _same(document: object, external_id: str, path: str) -> bytes:
    return STORED


def _sheet(files: Mapping[str, object]) -> str | None:
    """The sheet of the entry ``files`` hold, when their metadata and stored scenario are
    objects: the README.md render writes."""
    metadata, stored = files.get(YAML), files.get(JSON)
    if not isinstance(metadata, Mapping) or not isinstance(stored, Mapping):
        return None
    return render_sheet(metadata, stored, DATA.exceptions)


def _validate(
    files: Mapping[str, object] | None = None,
    *,
    schema: FakeSchema | None = None,
    others: Mapping[str, tuple[str, ...]] | None = None,
    renormalised: Any = _same,
    catalogue: tuple[CatalogueEntry, ...] | None = None,
) -> tuple[Finding, ...]:
    given = files if files is not None else {YAML: METADATA, JSON: SCENARIO}
    files = {CHANGELOG: LOG, **given}  # a changelog by default, absent when given as None
    source = FakeSource(files, others, catalogue=catalogue)
    return validate_entry(
        ENTRY,
        source,
        schema=schema or FakeSchema(),
        builtin=BUILTIN,
        renormalised=renormalised,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(given.get(JSON)),
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


@pytest.mark.parametrize(
    "error",
    [
        UnsafeInputError("IO-014", "a refusal", JSON, "/scenario_workflow/workflow_steps"),
        ExportStructureError("a refusal", pointer="/scenario_workflow/workflow_steps"),
    ],
    ids=["refused input", "not an export"],
)
def test_a_refusal_points_at_the_node_at_fault(error: Exception) -> None:
    def broken(document: object, external_id: str, path: str) -> bytes:
        raise error

    findings = _validate({YAML: METADATA, JSON: SCENARIO}, renormalised=broken)

    assert _codes(findings) == [("IO-014", JSON, "/scenario_workflow/workflow_steps")]


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


def test_a_scenario_name_another_entry_has_is_refused_and_its_own_is_not_compared() -> None:
    name = str(METADATA["name"])
    catalogue = (
        CatalogueEntry(ENTRY, ID, name),  # its own: never another's
        CatalogueEntry("scenarios/techniques/other", "another-id", f"  {name.upper()} "),
    )

    findings = _validate(catalogue=catalogue)

    assert findings == (
        Finding(
            "SCH-012",
            Severity.BLOCKING,
            YAML,
            "/name",
            "another entry has this scenario name: scenarios/techniques/other",
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
    text = f"## 1.0.0 — 2026-10-12\n# Notes\n{RLO}\\u200b\n"  # a valid changelog besides
    files: dict[str, object] = {YAML: METADATA, JSON: SCENARIO, name: text}

    findings = _validate(files)

    stale = [("GEN-001", README, "")] if name == README else []  # nor is it the sheet
    assert _codes(findings) == [*stale, ("IO-017", name, "")]


def test_a_missing_sheet_is_a_finding() -> None:
    (finding,) = _validate({YAML: METADATA, JSON: SCENARIO, README: None})

    assert (finding.code, finding.severity, finding.path, finding.field, finding.message) == (
        "GEN-001",
        Severity.BLOCKING,
        README,
        "",
        "README.md is missing: write it with `scenario-tools render`, from scenario.yaml and "
        "scenario.json",
    )


def test_a_sheet_that_is_not_the_one_the_entry_gives_is_a_finding() -> None:
    sheet = _sheet({YAML: METADATA, JSON: SCENARIO})
    assert sheet is not None

    (finding,) = _validate({YAML: METADATA, JSON: SCENARIO, README: sheet + "edited\n"})

    assert (finding.code, finding.severity, finding.path, finding.message) == (
        "GEN-001",
        Severity.BLOCKING,
        README,
        "README.md is not the sheet scenario.yaml and scenario.json give: render it again with "
        "`scenario-tools render` rather than edit it",
    )


def test_the_sheet_shows_the_entry_s_policy_exceptions() -> None:
    """The maintainers' registry is part of what the sheet says: a granted exception changes it."""
    exception = PolicyException(ID, "POL-006", "/x", "a" * 64, "A reason long enough to show.")
    with_exception = dataclasses.replace(DATA, exceptions=(exception,))
    files = {YAML: METADATA, JSON: SCENARIO, CHANGELOG: LOG}
    sheet = render_sheet(METADATA, SCENARIO, (exception,))

    found = validate_entry(
        ENTRY,
        FakeSource({**files, README: sheet}),
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
        policy=with_exception,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
    )

    assert "GEN-001" not in [code for code, _, _ in _codes(found)]  # the sheet shows it


def test_the_sheet_is_not_checked_while_scenario_yaml_breaks_its_schema() -> None:
    """Its own check says what is wrong; a sheet rendered from it would say nothing more."""
    broken = FakeSchema(SchemaViolation("/name", "required"))

    found = _validate({YAML: METADATA, JSON: SCENARIO, README: None}, schema=broken)

    assert "GEN-001" not in [code for code, _, _ in _codes(found)]


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
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
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
            {
                YAML: _changed(requires=requires),
                JSON: dict(SCENARIO, scenario_injects=[inject]),
                CHANGELOG: LOG,
            }
        ),
        schema=FakeSchema(),
        builtin=builtin,
        renormalised=_same,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
    )

    assert _codes(findings) == [("SCH-006", JSON, "/scenario_injects/0")]


def test_metadata_that_is_no_mapping_is_left_to_its_schema() -> None:
    findings = _validate({YAML: ["not", "a", "mapping"], JSON: SCENARIO})

    assert findings == ()  # the schema refuses it; nothing reads its fields


def test_the_metadata_is_checked_as_written_too_comments_included() -> None:
    source = FakeSource(
        {YAML: METADATA, JSON: SCENARIO, CHANGELOG: LOG}, raw={YAML: f"# a note {RLO}\n"}
    )

    findings = validate_entry(
        ENTRY,
        source,
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
    )

    assert _codes(findings) == [("IO-017", YAML, "")]


def test_a_hidden_character_written_in_the_metadata_is_reported_once() -> None:
    raw = {YAML: f"generated_by: x{RLO}\n"}
    source = FakeSource(
        {YAML: _changed(generated_by=f"x{RLO}"), JSON: SCENARIO, CHANGELOG: LOG}, raw=raw
    )

    findings = validate_entry(
        ENTRY,
        source,
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
    )

    assert _codes(findings) == [("IO-017", YAML, "")]
    assert findings[0].message.endswith(": remove it from the file")


def test_a_line_break_yaml_reads_but_a_reviewer_may_not_see_is_refused() -> None:
    raw = {YAML: f"# note{chr(0x2028)}name: Akira\n"}
    source = FakeSource({YAML: METADATA, JSON: SCENARIO, CHANGELOG: LOG}, raw=raw)

    findings = validate_entry(
        ENTRY,
        source,
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
    )

    assert _codes(findings) == [("IO-017", YAML, "")]


def test_a_renormalisation_refused_still_lets_the_metadata_be_cross_checked() -> None:
    def broken(document: object, external_id: str, path: str) -> bytes:
        raise UnsafeInputError("IO-014", "a chained scenario is not supported", JSON)

    findings = _validate({YAML: _changed(name="Other"), JSON: SCENARIO}, renormalised=broken)

    assert _codes(findings) == [("IO-014", JSON, ""), ("SCH-002", YAML, "/name")]


def test_a_source_link_to_a_private_host_is_refused_by_the_policy() -> None:
    metadata = _changed(sources=[{"url": "https://10.0.0.1/report.html", "tlp": "TLP:CLEAR"}])

    assert _codes(_validate({YAML: metadata, JSON: SCENARIO})) == [
        ("POL-001", YAML, "/sources/0/url")
    ]


def test_the_source_links_are_checked_only_once_the_metadata_meets_its_schema() -> None:
    metadata = _changed(sources=[{"url": "https://10.0.0.1/report.html", "tlp": "TLP:CLEAR"}])
    schema = FakeSchema(SchemaViolation("/severity", "not one of the severities"))

    assert _codes(_validate({YAML: metadata, JSON: SCENARIO}, schema=schema)) == [
        ("SCH-001", YAML, "/severity")
    ]


def test_a_file_that_is_not_the_entry_s_own_is_refused_by_the_policy() -> None:
    files = {YAML: METADATA, JSON: SCENARIO, f"{ENTRY}/report.pdf": b"%PDF"}

    assert _codes(_validate(files)) == [("POL-001", f"{ENTRY}/report.pdf", "")]


def test_the_entry_s_files_are_checked_even_when_its_metadata_is_refused() -> None:
    files = {
        YAML: UnsafeInputError("IO-002", "not YAML", YAML),
        JSON: SCENARIO,
        f"{ENTRY}/report.pdf": b"%PDF",
    }

    assert _codes(_validate(files)) == [
        ("IO-002", YAML, ""),
        ("POL-001", f"{ENTRY}/report.pdf", ""),
    ]


def test_a_recurrence_in_the_stored_scenario_is_refused_by_the_policy() -> None:
    scenario = copy.deepcopy(SCENARIO)
    scenario["scenario_information"]["scenario_recurrence"] = "0 0 8 * * MON"

    assert _codes(_validate({YAML: METADATA, JSON: scenario})) == [
        ("POL-002", JSON, "/scenario_information/scenario_recurrence")
    ]


def test_a_stored_scenario_the_readers_refuse_is_not_given_to_the_policy() -> None:
    files = {YAML: METADATA, JSON: UnsafeInputError("IO-006", "not JSON", JSON)}

    assert _codes(_validate(files)) == [("IO-006", JSON, "")]


def test_a_recurrence_is_refused_even_when_the_metadata_is_refused() -> None:
    scenario = copy.deepcopy(SCENARIO)
    scenario["scenario_information"]["scenario_recurrence"] = "0 0 8 * * MON"
    files = {YAML: UnsafeInputError("IO-002", "not YAML", YAML), JSON: scenario}

    assert _codes(_validate(files)) == [
        ("IO-002", YAML, ""),
        ("POL-002", JSON, "/scenario_information/scenario_recurrence"),
    ]


def test_an_entry_whose_path_a_finding_cannot_show_is_refused_without_reading_it() -> None:
    entry = "scenarios/techniques/a\\b"

    class Unread(FakeSource):
        def _read(self, path: str) -> object:
            raise AssertionError(f"{path} must not be read")

    source = Unread({f"{entry}/scenario.yaml": METADATA, f"{entry}/scenario.json": SCENARIO})
    findings = validate_entry(
        entry,
        source,
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
    )

    assert _codes(findings) == [("SCH-008", "scenarios/techniques", "")]


def _with_payload(**fields: Any) -> dict[str, Any]:
    scenario = copy.deepcopy(SCENARIO)
    payload = {"payload_type": "Command", "payload_name": "a", "command_content": "id", **fields}
    scenario["scenario_injects"] = [
        {"inject_injector_contract": {"injector_contract_payload": payload}}
    ]
    return scenario


def _payload_codes(findings: tuple[Finding, ...]) -> list[tuple[str, str, str]]:
    return [code for code in _codes(findings) if code[0].startswith("PAY")]


def test_a_payload_no_reference_names_is_refused() -> None:
    findings = _validate({YAML: METADATA, JSON: _with_payload()})

    assert _payload_codes(findings) == [
        (
            "PAY-001",
            JSON,
            "/scenario_injects/0/inject_injector_contract/injector_contract_payload"
            "/payload_external_id",
        )
    ]


def test_a_payload_named_by_its_reference_passes() -> None:
    bare = _with_payload()
    payload = bare["scenario_injects"][0]["inject_injector_contract"]["injector_contract_payload"]
    digest = payload_hash(payload, (), no_attached_files).hex
    identifier = derived_id(digest)
    named = _with_payload(payload_external_id=identifier)

    findings = _validate(
        {
            YAML: _changed(payloads=[{"id": identifier, "version": "1.0.0", "sha256": digest}]),
            JSON: named,
        }
    )

    assert _payload_codes(findings) == []


def test_references_are_checked_only_once_the_metadata_meets_its_schema() -> None:
    findings = _validate(
        {YAML: METADATA, JSON: _with_payload()},
        schema=FakeSchema(SchemaViolation("/payloads", "is not valid")),
    )

    assert _payload_codes(findings) == []


def test_a_payload_outside_an_inject_s_contract_is_refused() -> None:
    scenario = copy.deepcopy(SCENARIO)
    scenario["scenario_articles"] = [{"injector_contract_payload": {"payload_name": "a"}}]

    assert _payload_codes(_validate({YAML: METADATA, JSON: scenario})) == [
        ("PAY-004", JSON, "/scenario_articles/0")
    ]


class FakePrevious:
    """The base branch's copy of the catalogue, holding the entry or not."""

    def __init__(self, files: Mapping[str, object]) -> None:
        self.files = dict(files)

    def exists(self, path: str) -> bool:
        return any(name.startswith(f"{path}/") for name in self.files)

    def names(self, entry: str) -> frozenset[str]:
        return frozenset(
            path.rsplit("/", 1)[1] for path in self.files if path.startswith(f"{entry}/")
        )

    def read_yaml(self, path: str) -> object:
        value = self.files[path]
        if isinstance(value, UnsafeInputError):
            raise value
        return value

    def read_json(self, path: str) -> tuple[bytes, object]:
        return STORED, self.files[path]

    def external_ids(self) -> Mapping[str, tuple[str, ...]]:
        found: dict[str, tuple[str, ...]] = {}
        for path, value in sorted(self.files.items()):
            if path.endswith("/scenario.yaml") and isinstance(value, Mapping):
                entry = path.rsplit("/", 1)[0]
                found[value["external_id"]] = (*found.get(value["external_id"], ()), entry)
        return found


def _validate_after(previous: FakePrevious, metadata: dict[str, Any]) -> tuple[Finding, ...]:
    return validate_entry(
        ENTRY,
        FakeSource(
            {YAML: metadata, JSON: SCENARIO, CHANGELOG: f"## {metadata['version']} — 2026-10-14\n"}
        ),
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
        previous=previous,  # type: ignore[arg-type]
    )


def test_an_entry_is_compared_with_the_version_the_base_branch_holds() -> None:
    previous = FakePrevious({YAML: METADATA, JSON: SCENARIO})

    found = _validate_after(previous, _changed(name="Another name", version="1.0.0"))

    assert [code for code in _codes(found) if code[0].startswith("VER")] == [
        ("VER-001", YAML, "/version")
    ]
    assert _codes(_validate_after(previous, _changed(version="1.0.0"))) == []


def test_an_entry_the_base_branch_does_not_hold_is_new() -> None:
    assert _codes(_validate_after(FakePrevious({}), _changed(version="0.0.1"))) == []


OLD = "scenarios/ransomware/akira-old"


def test_an_entry_moved_is_compared_with_its_copy_where_the_base_branch_holds_it() -> None:
    """Moved, an entry keeps its external ID: a change never passes as a new entry's."""
    previous = FakePrevious(
        {
            f"{OLD}/scenario.yaml": METADATA,
            f"{OLD}/scenario.json": SCENARIO,
            "scenarios/x/y/scenario.yaml": _changed(external_id="other"),
        }
    )

    found = _validate_after(previous, _changed(name="Another name", version="0.0.1"))

    assert [code for code in _codes(found) if code[0].startswith("VER")] == [
        ("VER-002", YAML, "/version")
    ]
    assert _codes(_validate_after(previous, _changed(version="1.0.0"))) == []


@pytest.mark.parametrize("held", [{YAML: METADATA}, {JSON: SCENARIO}, {f"{ENTRY}/README.md": "x"}])
def test_a_base_copy_without_its_files_blocks(held: dict[str, object]) -> None:
    """Damaged on the base branch, an entry is never taken for a new one."""
    found = _validate_after(FakePrevious(held), METADATA)

    assert _codes(found) == [("VER-006", YAML, "")]


def test_a_moved_entry_held_twice_on_the_base_branch_is_compared_with_the_first() -> None:
    """Two entries sharing an external ID: a base branch the checks would have refused."""
    previous = FakePrevious(
        {
            f"{OLD}/scenario.yaml": METADATA,
            f"{OLD}/scenario.json": SCENARIO,
            f"{OLD}2/scenario.yaml": _changed(version="9.0.0"),
            f"{OLD}2/scenario.json": SCENARIO,
        }
    )

    assert _codes(_validate_after(previous, _changed(version="1.0.0"))) == []


def test_an_unreadable_changelog_still_lets_the_version_be_compared() -> None:
    """Its refusal blocks already; the version's findings come with it, not after its fix."""
    files = {
        YAML: _changed(version="0.0.1"),
        JSON: SCENARIO,
        CHANGELOG: UnsafeInputError("IO-013", "a link", CHANGELOG),
    }
    found = validate_entry(
        ENTRY,
        FakeSource(files),
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
        previous=FakePrevious({YAML: METADATA, JSON: SCENARIO}),  # type: ignore[arg-type]
    )

    assert [code for code, _, _ in _codes(found)] == ["VER-002", "IO-013"]


def test_a_previous_version_that_cannot_be_read_is_a_finding() -> None:
    refused = UnsafeInputError("IO-013", "a link", YAML)
    previous = FakePrevious({YAML: refused, JSON: SCENARIO})

    (finding,) = _validate_after(previous, METADATA)
    assert (finding.code, finding.path, finding.message) == (
        "IO-013",
        YAML,
        "the base branch's copy of this file cannot be read: a link",
    )


def test_a_changelog_that_cannot_be_read_is_a_finding() -> None:
    files = {
        YAML: METADATA,
        JSON: SCENARIO,
        CHANGELOG: UnsafeInputError("IO-013", "a link", CHANGELOG),
    }
    source = FakeSource(files)

    found = validate_entry(
        ENTRY,
        source,
        schema=FakeSchema(),
        builtin=BUILTIN,
        renormalised=_same,
        domains=DOMAINS,
        policy=DATA,
        agreed=AgreedIds({}),
        catalogue=held(SCENARIO),
    )

    assert _codes(found) == [("IO-013", CHANGELOG, "")]  # said once, by the texts' check


def test_a_missing_changelog_is_refused() -> None:
    assert _codes(_validate({YAML: METADATA, JSON: SCENARIO, CHANGELOG: None})) == [
        ("VER-004", CHANGELOG, "")
    ]
