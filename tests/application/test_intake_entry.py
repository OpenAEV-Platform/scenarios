"""Intake of an export into the catalogue: refused before anything is written when the request,
the catalogue or the metadata it completes says so; otherwise what to write, and what is left.

Characters are written by code point, never raw, so that this file holds none of them."""

import contextlib
import copy
import dataclasses
import datetime
import hashlib
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader, read_export
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.safe_readers import yaml_bytes
from scenario_tools.application.assign_payloads import payload_findings
from scenario_tools.application.intake_entry import (
    IntakeResult,
    intake_entry,
    intake_files,
    plan_document,
    write_intake,
)
from scenario_tools.application.prepare_entry import prepare_entry, renormaliser
from scenario_tools.domain.catalogue.intake import CatalogueEntry
from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.verification.payload_catalogue import Catalogue
from scenario_tools.domain.verification.payload_hash import embedded_payloads
from scenario_tools.domain.verification.payload_references import AgreedIds
from scenario_tools.domain.verification.payload_version import PayloadVersion
from scenario_tools.ports.errors import EnvironmentProblemError
from tests.support.catalogue import catalogue, held

ROOT = Path(__file__).parents[2]
EASM = read_export(ROOT / "tests" / "golden" / "exports" / "easm-scenario.zip")
DATA = YamlDataLoader(ROOT / "policy" / "data")
SCHEMA = JsonSchemaValidator(ROOT / "schemas")
DOMAINS = ("vulnerabilities", "intrusion-sets", "ransomware", "techniques")
ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
TODAY = datetime.date(2026, 10, 14)
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
        declared: dict[str, Any] | None = None,
    ) -> None:
        self._entries = entries
        self.stored = stored
        self.taken = taken
        self.declared = declared
        self.read: list[str] = []

    def entries(self) -> tuple[CatalogueEntry, ...]:
        return self._entries

    def exists(self, path: str) -> bool:
        return path in self.taken

    def read_json(self, path: str) -> tuple[bytes, object]:
        assert path == f"{ENTRY}/scenario.json"
        assert self.stored is not None
        return self.stored

    def names(self, entry: str) -> frozenset[str]:
        assert entry == ENTRY
        return frozenset({"scenario.yaml", "scenario.json"} if self.stored else {"scenario.yaml"})

    def read_yaml(self, path: str) -> object:
        assert path == f"{ENTRY}/scenario.yaml"  # an update reads the references it keeps
        self.read.append("document")
        return self.declared

    def read_text(self, path: str) -> str:
        assert path == f"{ENTRY}/scenario.yaml"  # the bytes an update replaces
        self.read.append("text")
        return yaml_bytes(self.declared).decode()

    def scenario_names(self) -> Mapping[str, tuple[str, ...]]:
        raise AssertionError("intake compares the entries themselves")

    def external_ids(self) -> Mapping[str, tuple[str, ...]]:
        raise AssertionError("intake never asks")


EMPTY = Catalogue.of([])


def _intake(
    request: Mapping[str, Any],
    source: FakeSource | None = None,
    export: Any = EASM,
    payloads: Catalogue = EMPTY,
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
        today=TODAY,
        payloads=payloads,
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
    assert {finding.path for finding in result.to_complete} == {
        f"{ENTRY}/scenario.yaml",
        f"{ENTRY}/CHANGELOG.md",
    }


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


def _stored(export: Any = EASM) -> FakeSource:
    first = _intake(NEW, export=export)
    assert first.scenario_json is not None
    name = export["scenario_information"]["scenario_name"]
    return FakeSource(
        (CatalogueEntry(ENTRY, ID, name),),
        (first.scenario_json, json.loads(first.scenario_json)),
        declared=first.metadata,
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
        ("SCH-007", f"{ENTRY}/scenario.yaml", "/version"),
        ("SCH-007", f"{ENTRY}/README.md", ""),
    ]
    assert "CHANGELOG.md" in result.to_complete[0].message
    assert result.to_complete[1].message == (
        "the sheet follows scenario.yaml: once it is complete, render it again with "
        "`scenario-tools render`"
    )
    assert result.sheet is None  # an update leaves the sheet to render once the version is raised


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

    assert list(files) == ["scenario.yaml", "CHANGELOG.md", "README.md", "scenario.json"]
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


def test_a_request_refused_after_its_schema_has_no_plan() -> None:
    result = _intake({**NEW, "domain": "malware"})
    assert result.request is not None
    assert result.refusals

    with pytest.raises(ValueError, match="no plan"):
        plan_document(result, {}, "f" * 40, ())


@pytest.mark.parametrize("key", ["slug", "domain", "external_id"])
def test_a_hidden_character_in_a_field_its_schema_bounds_is_said_as_hidden(key: str) -> None:
    result = _intake({**NEW, key: f"{NEW[key]}{chr(0x200B)}"})

    assert _codes(result.refusals) == [("IO-017", REQUEST, f"/{key}")]


def test_a_request_holding_a_hidden_character_is_refused_before_anything() -> None:
    result = _intake({**NEW, "generated_by": f"run {chr(0x202E)}42"})

    assert _codes(result.refusals) == [("IO-017", REQUEST, "/generated_by")]
    assert result.scenario_json is None


def test_an_issue_that_is_not_a_whole_number_is_refused() -> None:
    result = _intake({**NEW, "issue": 12.0})

    assert _codes(result.refusals) == [("SCH-001", REQUEST, "/issue")]


def test_an_update_of_an_entry_without_its_scenario_is_refused() -> None:
    name = EASM["scenario_information"]["scenario_name"]
    source = FakeSource((CatalogueEntry(ENTRY, ID, name),))

    result = _intake(UPDATE, source)

    assert _codes(result.refusals) == [("SCH-008", f"{ENTRY}/scenario.json", "")]


def test_an_update_keeps_the_bytes_it_replaces() -> None:
    source = _stored()

    result = _intake(UPDATE, source)

    assert source.stored is not None
    assert result.previous == {"scenario.json": source.stored[0]}
    assert _intake(NEW).previous is None  # a new entry replaces nothing


class _Log:
    def __init__(self, failing: str = "") -> None:
        self.events: list[object] = []
        self.published: bytes | None = None
        self.failing = failing  # the step that fails, if any

    def step(self, event: object, name: str) -> None:
        self.events.append(event)
        if self.failing == name:
            raise EnvironmentProblemError(f"{name} fails")


class _Written:
    def __init__(self, log: _Log) -> None:
        self.log = log

    def check(self) -> None:
        self.log.step("check", "check")


class _Writer:
    """As the repository writes: nothing to write writes nothing, and what was written is taken
    back when the block does not end."""

    def __init__(self, log: _Log) -> None:
        self.log = log

    @contextlib.contextmanager
    def writing(
        self, entry: str, files: Mapping[str, bytes], *, previous: Mapping[str, bytes] | None
    ) -> Iterator[_Written]:
        if not files:
            self.log.events.append("write nothing")
            yield _Written(self.log)
            return
        before = None if previous is None else dict(previous)
        self.log.step(("write", entry, tuple(files), before), "write")
        try:
            yield _Written(self.log)
        except BaseException:
            self.log.events.append("take back")
            raise
        self.log.events.append("kept")


class _Reservation:
    def __init__(self, log: _Log) -> None:
        self.log = log
        self.published = False

    def publish(self, data: bytes) -> None:
        self.log.step("publish", "publish")
        self.log.published = data
        self.published = True


class _Plan:
    """As the plan's place is: given back when the block ends before it is published, kept
    once it is."""

    def __init__(self, log: _Log) -> None:
        self.log = log

    @contextlib.contextmanager
    def reserving(self) -> Iterator[_Reservation]:
        self.log.step("reserve", "reserve")
        reservation = _Reservation(self.log)
        try:
            yield reservation
        except BaseException:
            if not reservation.published:
                self.log.events.append("give back")
            raise


def _write(
    result: IntakeResult, log: _Log, *, findings: tuple[Finding, ...] = ()
) -> tuple[Finding, ...]:
    def validate(entry: str) -> tuple[Finding, ...]:
        log.step(("validate", entry), "validate")
        return findings

    def render(metadata: dict[str, Any]) -> bytes:
        log.step("render", "render")
        return _render(metadata)

    def current() -> str:
        log.step("current", "current")
        return "f" * 40 if log.failing != "moved" else "e" * 40

    return write_intake(
        result,
        entries=_Writer(log),
        plan=_Plan(log),
        base="f" * 40,
        current=current,
        validate=validate,
        render=render,
    )


def test_an_entry_and_its_plan_are_written_in_one_go() -> None:
    log = _Log()
    blocking = Finding(
        "SCH-009", Severity.BLOCKING, f"{ENTRY}/scenario.yaml", "/description", "cut"
    )
    result = _intake(NEW)

    left = _write(result, log, findings=(blocking,))

    assert log.events == [
        "reserve",
        "render",
        (
            "write",
            ENTRY,
            ("scenario.yaml", "CHANGELOG.md", "README.md", "scenario.json"),
            None,
        ),  # a new one
        ("validate", ENTRY),
        "current",
        "check",
        "publish",
        "kept",
    ]
    assert left == (*result.to_complete, blocking)
    assert log.published is not None
    files = intake_files(result, _render)
    expected = plan_document(result, files, "f" * 40, (blocking,))
    assert json.loads(log.published) == expected
    assert log.published.endswith(b"\n")


def test_an_update_is_written_with_the_bytes_it_replaces() -> None:
    log = _Log()
    changed = copy.deepcopy(EASM)
    changed["scenario_information"]["scenario_subtitle"] = "A new subtitle"
    source = _stored()
    assert source.stored is not None

    _write(_intake(UPDATE, source, export=changed), log)

    write = log.events[1]  # an update renders no scenario.yaml
    assert write == ("write", ENTRY, ("scenario.json",), {"scenario.json": source.stored[0]})


def test_an_unchanged_update_still_has_its_plan_and_its_checks() -> None:
    log = _Log()

    _write(_intake(UPDATE, _stored()), log)

    assert log.events == [
        "reserve",
        "write nothing",
        ("validate", ENTRY),
        "current",
        "check",
        "publish",
    ]


_STEPS = {
    "reserve": "reserve",
    "render": "render",
    "write": (
        "write",
        ENTRY,
        ("scenario.yaml", "CHANGELOG.md", "README.md", "scenario.json"),
        None,
    ),
    "validate": ("validate", ENTRY),
    "current": "current",  # the checkout first, then what was written: a change meanwhile shows
    "check": "check",
    "publish": "publish",
}


@pytest.mark.parametrize("failing", list(_STEPS))
def test_a_run_stopped_before_its_plan_keeps_nothing(failing: str) -> None:
    log = _Log(failing)
    steps = list(_STEPS)
    reached = [_STEPS[step] for step in steps[: steps.index(failing) + 1]]
    written = steps.index(failing) > steps.index("write")  # the write itself failed whole
    undone = ["take back"] * written + ["give back"] * (failing != "reserve")

    with pytest.raises(EnvironmentProblemError, match=f"{failing} fails"):
        _write(_intake(NEW), log)

    assert log.events == [*reached, *undone]
    assert log.published is None


def test_a_refused_request_is_never_written() -> None:
    with pytest.raises(ValueError, match="refused"):
        _write(_intake({**NEW, "mode": "replace"}), _Log())


@pytest.mark.parametrize("name", [None, "", "   ", 7], ids=["missing", "empty", "blank", "number"])
@pytest.mark.parametrize("mode", ["new", "update"])
def test_an_export_without_a_scenario_name_is_refused(name: object, mode: str) -> None:
    nameless = copy.deepcopy(EASM)
    if name is None:
        del nameless["scenario_information"]["scenario_name"]
    else:
        nameless["scenario_information"]["scenario_name"] = name
    request = NEW if mode == "new" else {**UPDATE, "rewrite": True}

    result = _intake(request, _stored() if mode == "update" else None, export=nameless)

    assert _codes(result.refusals) == [("SCH-001", EXPORT, "/scenario_information/scenario_name")]


class _Lenient:
    """A schema the repository loosened: it lets anything through."""

    def validate(self, name: str, document: object) -> tuple[object, ...]:
        return () if name == "intake-request" else SCHEMA.validate(name, document)


@pytest.mark.parametrize(
    ("change", "pointer"),
    [({"slug": "a/b"}, "/slug"), ({"slug": "../../x"}, "/slug"), ({"domain": "../x"}, "/domain")],
    ids=["nested", "parent", "domain"],
)
def test_a_place_outside_the_catalogue_is_refused_whatever_the_schema(
    change: dict[str, Any], pointer: str
) -> None:
    result = intake_entry(
        EASM,
        {**NEW, **change},
        request_path=REQUEST,
        export_path=EXPORT,
        source=FakeSource(),
        data=DATA,
        schema=_Lenient(),  # type: ignore[arg-type]
        domains=(*DOMAINS, "../x"),
        today=TODAY,
        payloads=EMPTY,
    )

    assert _codes(result.refusals) == [("SCH-001", REQUEST, pointer)]


def test_a_request_that_is_no_mapping_is_refused_whatever_the_schema() -> None:
    result = intake_entry(
        EASM,
        ["mode", "new"],
        request_path=REQUEST,
        export_path=EXPORT,
        source=FakeSource(),
        data=DATA,
        schema=_Lenient(),  # type: ignore[arg-type]
        domains=DOMAINS,
        today=TODAY,
        payloads=EMPTY,
    )

    assert _codes(result.refusals) == [("SCH-001", REQUEST, "")]


def test_a_commit_that_changes_before_the_plan_takes_the_entry_back() -> None:
    log = _Log("moved")

    with pytest.raises(EnvironmentProblemError, match="commit changed"):
        _write(_intake(NEW), log)

    assert log.events[-3:] == ["current", "take back", "give back"]
    assert log.published is None


SALT = read_export(ROOT / "tests" / "golden" / "exports" / "salt-typhoon-cve-ttps-validation.zip")


def _catalogue_of(source: FakeSource) -> Catalogue:
    """The payload catalogue that holds the payloads of the entry ``source`` holds, as the
    intake that wrote it wrote their files."""
    assert source.stored is not None
    return catalogue(json.loads(source.stored[0]))


def _payloads(result: IntakeResult) -> list[dict[str, Any]]:
    assert result.metadata is not None
    return list(result.metadata["payloads"])


def test_a_new_payload_without_a_description_is_written_described_by_its_name() -> None:
    result = _intake(NEW, export=SALT)

    assert result.refusals == ()
    documents = [json.loads(data) for data in result.payload_files.values()]
    assert len(documents) == 11
    assert all(d["payload_description"] == d["payload_name"] for d in documents)


def test_a_new_entry_gives_each_payload_its_reference() -> None:
    result = _intake(NEW, export=SALT)

    assert result.scenario_json is not None
    assert len(_payloads(result)) == 11
    assert (
        payload_findings(
            result.metadata,
            json.loads(result.scenario_json),
            ENTRY,
            AgreedIds({}),
            held(json.loads(result.scenario_json)),
        )
        == ()
    )


def test_an_update_with_the_same_payloads_keeps_their_references_and_changes_nothing() -> None:
    source = _stored(SALT)
    result = _intake(UPDATE, source, export=SALT, payloads=_catalogue_of(source))

    assert (result.refusals, result.changed, result.metadata) == ((), False, None)
    assert result.payload_files == {}


def test_an_update_whose_payload_changed_gives_it_a_new_id_and_rewrites_scenario_yaml() -> None:
    source = _stored(SALT)
    assert source.declared is not None
    changed = copy.deepcopy(SALT)
    payloads = [
        inject["inject_injector_contract"]["injector_contract_payload"]
        for inject in changed["scenario_injects"]
        if (inject.get("inject_injector_contract") or {}).get("injector_contract_payload")
    ]
    payloads[0]["command_content"] += " # changed"

    result = _intake(UPDATE, source, export=changed)

    assert result.changed
    assert result.previous is not None
    assert set(result.previous) == {"scenario.yaml", "scenario.json"}
    before = {reference["id"] for reference in source.declared["payloads"]}
    after = {reference["id"] for reference in _payloads(result)}
    assert (len(before - after), len(after - before)) == (1, 1)
    assert result.scenario_json is not None
    assert (
        payload_findings(
            result.metadata,
            json.loads(result.scenario_json),
            ENTRY,
            AgreedIds({}),
            held(json.loads(result.scenario_json)),
        )
        == ()
    )


def test_an_update_whose_metadata_is_no_object_leaves_the_references_to_the_check() -> None:
    source = _stored(SALT)
    source.declared = None

    result = _intake(UPDATE, source, export=SALT)

    assert (result.refusals, result.metadata) == ((), None)


def test_an_update_whose_payload_cannot_be_hashed_leaves_it_to_the_check() -> None:
    source = _stored()
    changed = copy.deepcopy(SALT)
    changed["scenario_information"] = copy.deepcopy(EASM["scenario_information"])
    for inject in changed["scenario_injects"]:
        payload = (inject.get("inject_injector_contract") or {}).get("injector_contract_payload")
        if payload:
            payload["payload_detection_remediations"] = [{"detection_remediation_values": "x"}]

    result = _intake(UPDATE, source, export=changed)

    assert result.metadata is None


def test_an_update_reads_the_text_it_replaces_before_the_document_it_assigns() -> None:
    # A change in between then makes the writer refuse, never write over the newer file.
    source = _stored(SALT)

    _intake(UPDATE, source, export=SALT)

    assert source.read == ["text", "document"]


def test_a_new_entry_whose_payload_cannot_be_hashed_leaves_it_to_the_check() -> None:
    export = copy.deepcopy(SALT)
    for inject in export["scenario_injects"]:
        payload = (inject.get("inject_injector_contract") or {}).get("injector_contract_payload")
        if payload:
            payload["payload_detection_remediations"] = [{"detection_remediation_values": "x"}]

    result = _intake(NEW, export=export)

    assert result.refusals == ()
    assert result.scenario_json is not None
    assert _payloads(result) == []
    assert b'payload_external_id": "' not in result.scenario_json


class _BadRegistry:
    def load(self, name: str) -> Any:
        return {"payloads": "x"} if name == "payload-ids" else DATA.load(name)


def test_a_malformed_registry_is_an_environment_problem() -> None:
    refused = r"^policy data cannot be used: payload-ids: "
    with pytest.raises(EnvironmentProblemError, match=refused):
        intake_entry(
            SALT,
            dict(NEW),
            request_path=REQUEST,
            export_path=EXPORT,
            source=FakeSource(),
            data=_BadRegistry(),
            schema=SCHEMA,
            domains=DOMAINS,
            today=TODAY,
            payloads=EMPTY,
        )


def test_an_update_of_an_entry_without_scenario_yaml_leaves_the_references_to_the_check() -> None:
    source = _stored(SALT)
    source.names = lambda entry: frozenset({"scenario.json"})  # type: ignore[method-assign]

    result = _intake(UPDATE, source, export=SALT)

    assert (result.refusals, result.metadata, source.read) == ((), None, [])


def test_a_new_entry_starts_its_changelog_with_its_version_and_the_day() -> None:
    result = _intake(NEW)

    assert (
        result.changelog
        == (
            "# Changelog\n\n## 1.0.0 \u2014 2026-10-14\n\nFirst version in the catalogue.\n"
        ).encode()
    )
    assert list(intake_files(result, yaml_bytes)) == [
        "scenario.yaml",
        "CHANGELOG.md",
        "README.md",
        "scenario.json",
    ]
    assert result.sheet is not None
    assert result.sheet.decode().startswith("<!-- This sheet is generated")
    assert "\n# EASM Scenario\n" in result.sheet.decode()
    (note,) = (f for f in result.to_complete if f.path == f"{ENTRY}/CHANGELOG.md")
    assert (note.code, note.severity, note.field, note.message) == (
        "SCH-007",
        Severity.INFO,
        "",
        "a starting section for this version: say what it holds before the pull request",
    )


def test_an_update_leaves_the_changelog_to_its_author() -> None:
    result = _intake(UPDATE, _stored())

    assert result.changelog is None


def test_a_sheet_over_what_a_readme_may_hold_is_not_written() -> None:
    """The entry's check, run once the files are written, says why in the plan."""
    export = copy.deepcopy(EASM)
    export["scenario_injects"][0]["inject_title"] = "t" * 1_100_000

    result = _intake(NEW, export=export)

    assert result.refusals == ()
    assert result.sheet is None
    assert "README.md" not in intake_files(result, _render)


CHAINING = json.loads((ROOT / "tests" / "golden" / "chaining" / "two-steps.json").read_text())


def test_steps_the_update_no_longer_has_are_reported() -> None:
    smaller = copy.deepcopy(CHAINING)
    steps = smaller["scenario_workflow"]["workflow_steps"]
    steps[:] = [step for step in steps if not step["step_conditions"]]

    result = _intake(UPDATE, _stored(CHAINING), export=smaller)

    assert ("VER-012", f"{ENTRY}/scenario.json", "") in _codes(result.to_complete)
    assert any(f.message.startswith("step ") for f in result.to_complete)


def test_a_new_entry_from_a_workflow_starts_as_chained_and_needing_ee() -> None:
    result = _intake(NEW, export=CHAINING)
    assert result.refusals == ()
    assert result.metadata is not None
    assert (result.metadata["type"], result.metadata["requires"]["edition"]) == ("chained", "EE")


def _without_facets(export: Any) -> Any:
    bare = copy.deepcopy(export)
    for key in ("scenario_severity", "scenario_category", "scenario_main_focus"):
        bare["scenario_information"][key] = None
    return bare


FACETS = {"severity": "high", "category": "attack-scenario", "main_focus": "endpoint-protection"}


def test_a_new_entry_from_an_export_without_facets_takes_the_request_s() -> None:
    result = _intake({**NEW, **FACETS}, export=_without_facets(EASM))

    assert result.refusals == ()
    assert result.scenario_json is not None
    information = json.loads(result.scenario_json)["scenario_information"]
    assert (information["scenario_severity"], information["scenario_category"]) == (
        "high",
        "attack-scenario",
    )
    assert result.metadata is not None
    assert (result.metadata["severity"], result.metadata["main_focus"]) == (
        "high",
        "endpoint-protection",
    )


def test_a_new_entry_from_an_export_without_facets_and_a_request_without_is_refused() -> None:
    result = _intake(NEW, export=_without_facets(EASM))

    assert (result.scenario_json, result.metadata) == (None, None)
    assert [(f.code, f.path, f.field) for f in result.refusals] == [
        ("ITK-010", EXPORT, f"/scenario_information/{key}")
        for key in ("scenario_severity", "scenario_category", "scenario_main_focus")
    ]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("category", " attack-scenario"),
        ("main_focus", "endpoint "),
        ("main_focus", "two\nlines"),
        ("category", "two\u2028lines"),
    ],
    ids=["leading blank", "trailing blank", "line break", "line separator"],
)
def test_a_request_facet_that_is_not_one_clean_line_is_refused(key: str, value: str) -> None:
    result = _intake({**NEW, **FACETS, key: value}, export=_without_facets(EASM))

    assert [(f.code, f.path, f.field) for f in result.refusals] == [("SCH-001", REQUEST, f"/{key}")]


def test_an_update_from_an_export_without_facets_keeps_the_stored_ones() -> None:
    result = _intake(UPDATE, _stored(), export=_without_facets(EASM))

    assert result.refusals == ()
    assert not result.changed  # the stored facets, the same export otherwise: nothing to propose


def test_an_update_whose_request_changes_a_facet_writes_it_in_scenario_yaml_too() -> None:
    source = _stored()
    assert source.declared is not None
    request = {**UPDATE, "severity": "critical", "main_focus": "incident-response"}

    result = _intake(request, source, export=_without_facets(EASM))

    assert result.refusals == ()
    assert result.changed
    assert result.scenario_json is not None
    information = json.loads(result.scenario_json)["scenario_information"]
    assert information["scenario_severity"] == "critical"
    assert result.metadata is not None
    assert (result.metadata["severity"], result.metadata["main_focus"]) == (
        "critical",
        "incident-response",
    )
    assert result.metadata["category"] == source.declared["category"]  # kept, as stored
    assert result.previous is not None
    assert "scenario.yaml" in result.previous


def test_an_update_writes_a_facet_in_scenario_yaml_as_normalisation_stores_it() -> None:
    scenario_id = EASM["scenario_information"]["scenario_id"]
    request = {**UPDATE, "category": f"group-{scenario_id}"}  # an identifier normalisation maps

    result = _intake(request, _stored(), export=_without_facets(EASM))

    assert result.refusals == ()
    assert result.scenario_json is not None
    assert result.metadata is not None
    stored = json.loads(result.scenario_json)["scenario_information"]["scenario_category"]
    assert result.metadata["category"] == stored
    assert scenario_id not in stored


def _salt_payload(export: Any, position: int = 0) -> dict[str, Any]:
    injects = [i for i in export["scenario_injects"] if (i.get("inject_injector_contract") or {})]
    payload: dict[str, Any] = injects[position]["inject_injector_contract"][
        "injector_contract_payload"
    ]
    return payload


def _copy_of_salt() -> tuple[Any, str, str, Catalogue]:
    """SALT with its first payload edited as a copy of the catalogue's would be, its name, the
    slug of that payload, and the catalogue that holds SALT's payloads."""
    held_salt = catalogue(json.loads(_intake(NEW, export=SALT).scenario_json or b""))
    edited = copy.deepcopy(SALT)
    payload = _salt_payload(edited)
    payload["command_content"] += " # tuned"
    slug = next(v.slug for v in held_salt.by_hash.values() if v.name == payload["payload_name"])
    return edited, payload["payload_name"], slug, held_salt


def _with_files(base: Catalogue, files: Mapping[str, bytes]) -> Catalogue:
    """``base`` with the version ``files`` an intake wrote."""
    written = [
        PayloadVersion(path.split("/")[1], path.split("/")[2][: -len(".json")], path, json.loads(d))
        for path, d in files.items()
    ]
    return Catalogue.of([*base.by_hash.values(), *written])


def _at(stored: object, name: str) -> str:
    """The pointer of the one payload named ``name`` that ``stored`` embeds."""
    (pointer,) = (
        p.pointer
        for p in embedded_payloads(stored)
        if isinstance(p.payload, Mapping) and p.payload.get("payload_name") == name
    )
    return pointer


def _pointers(left: object, right: object, at: str = "") -> set[str]:
    """The pointers at which ``left`` and ``right`` differ."""
    if isinstance(left, dict) and isinstance(right, dict):
        found: set[str] = set()
        for key in left.keys() | right.keys():
            found |= _pointers(left.get(key), right.get(key), f"{at}/{key}")
        return found
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        return set().union(
            *(
                _pointers(a, b, f"{at}/{i}")
                for i, (a, b) in enumerate(zip(left, right, strict=True))
            )
        )
    return set() if left == right else {at}


def test_a_copy_claimed_as_based_on_a_catalogue_payload_is_its_next_version() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    claims = {"payloads": [{"name": name, "based_on": {"payload": slug}}]}

    result = _intake({**NEW, **claims}, export=edited, payloads=held_salt)

    assert result.refusals == ()
    path = f"payloads/{slug}/1.1.0.json"
    assert list(result.payload_files) == [path]
    assert result.payload_changes == {path: ("/command_content",)}
    assert json.loads(result.payload_files[path])["payload_name"] == f"{name} (1.1.0)"
    assert result.scenario_json is not None
    at = _at(json.loads(result.scenario_json), f"{name} (1.1.0)")
    assert ("PAY-010", f"{ENTRY}/scenario.json", at) in _codes(result.to_complete)
    body = plan_document(result, intake_files(result, _render), "0" * 40, ())["body"]
    assert f"- `{path}`: `/command_content`" in body


def test_the_claimed_copy_keeps_every_other_field_and_identifier_of_the_stored_scenario() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    claims = {"payloads": [{"name": name, "based_on": {"payload": slug}}]}
    plain = _intake(NEW, export=SALT, payloads=held_salt)

    result = _intake({**NEW, **claims}, export=edited, payloads=held_salt)

    at = _at(json.loads(result.scenario_json or b""), f"{name} (1.1.0)")
    assert _pointers(
        json.loads(plain.scenario_json or b""), json.loads(result.scenario_json or b"")
    ) == {f"{at}/command_content", f"{at}/payload_name", f"{at}/payload_external_id"}


def test_an_intake_run_again_once_its_new_version_is_written_writes_nothing_more() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    request = {**NEW, "payloads": [{"name": name, "based_on": {"payload": slug}}]}
    first = _intake(request, export=edited, payloads=held_salt)

    again = _intake(request, export=edited, payloads=_with_files(held_salt, first.payload_files))

    assert again.refusals == ()
    assert (again.payload_files, again.payload_changes) == ({}, {})
    assert again.scenario_json == first.scenario_json
    assert f"already there: {slug} 1.1.0" in {f.message for f in again.to_complete}


def test_a_claim_that_cannot_hold_is_refused_at_the_request() -> None:
    edited, name, _, held_salt = _copy_of_salt()
    claims = {"payloads": [{"name": name, "based_on": {"payload": "no-such-payload"}}]}

    result = _intake({**NEW, **claims}, export=edited, payloads=held_salt)

    assert _codes(result.refusals) == [("ITK-009", REQUEST, "/payloads/0/based_on/payload")]
    assert result.payload_files == {}


def test_a_requested_version_without_its_base_is_refused_by_the_schema() -> None:
    result = _intake({**NEW, "payloads": [{"name": "x", "version": "2.0.0"}]})

    assert [(f.code, f.path) for f in result.refusals] == [("SCH-001", REQUEST)]


def test_an_update_takes_claims_too() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    claims = {"payloads": [{"name": name, "based_on": {"payload": slug}, "version": "2.0.0"}]}

    result = _intake({**UPDATE, **claims}, _stored(SALT), export=edited, payloads=held_salt)

    assert result.refusals == ()
    assert list(result.payload_files) == [f"payloads/{slug}/2.0.0.json"]


def test_a_claim_on_a_payload_of_a_chaining_step_gives_it_a_new_version() -> None:
    held_steps = catalogue(json.loads(_intake(NEW, export=CHAINING).scenario_json or b""))
    edited = copy.deepcopy(CHAINING)
    for step in edited["scenario_workflow"]["workflow_steps"]:  # one payload, in both steps
        data = json.loads(step["step_data"])
        payload = data["inject_injector_contract"]["injector_contract_payload"]
        payload["command_content"] += " -ef"
        step["step_data"] = json.dumps(data)
    slug = next(v.slug for v in held_steps.by_hash.values() if v.name == payload["payload_name"])
    claims = {"payloads": [{"name": payload["payload_name"], "based_on": {"payload": slug}}]}

    result = _intake({**NEW, **claims}, export=edited, payloads=held_steps)

    assert result.refusals == ()
    assert list(result.payload_files) == [f"payloads/{slug}/1.1.0.json"]
    assert result.scenario_json is not None
    stored = json.loads(result.scenario_json)
    step_payload = stored["scenario_workflow"]["workflow_steps"][0]["step_data"][
        "inject_injector_contract"
    ]["injector_contract_payload"]
    assert step_payload["payload_name"] == f"{payload['payload_name']} (1.1.0)"


def test_a_claimed_copy_takes_the_id_its_new_content_has_in_the_scenario_and_its_file() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    claims = {"payloads": [{"name": name, "based_on": {"payload": slug}}]}

    result = _intake({**NEW, **claims}, export=edited, payloads=held_salt)

    stored = json.loads(result.scenario_json or b"")
    (written,) = (json.loads(data) for data in result.payload_files.values())
    (embedded,) = (
        p.payload
        for p in embedded_payloads(stored)
        if isinstance(p.payload, Mapping) and p.payload.get("payload_name") == f"{name} (1.1.0)"
    )
    assert embedded["payload_external_id"] == written["payload_external_id"]
    assert written["payload_external_id"] not in {v.identifier for v in held_salt.by_hash.values()}


def test_an_update_whose_ids_cannot_be_assigned_still_writes_each_copy_under_its_name() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    source = _stored(SALT)
    source.declared = ["not a mapping"]  # type: ignore[assignment]
    claims = {"payloads": [{"name": name, "based_on": {"payload": slug}}]}

    result = _intake({**UPDATE, **claims}, source, export=edited, payloads=held_salt)

    assert result.refusals == ()
    assert list(result.payload_files) == [f"payloads/{slug}/1.1.0.json"]
    names = {
        p.payload.get("payload_name")
        for p in embedded_payloads(json.loads(result.scenario_json or b""))
        if isinstance(p.payload, Mapping)
    }
    assert f"{name} (1.1.0)" in names
    assert name not in names


def test_a_claimed_copy_under_another_base_name_is_stored_as_normalisation_gives_it() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    _salt_payload(edited)["payload_name"] = f"Copy of {name}"
    claims = {"payloads": [{"name": f"Copy of {name}", "based_on": {"payload": slug}}]}

    result = _intake({**NEW, **claims}, export=edited, payloads=held_salt)

    assert result.refusals == ()
    assert list(result.payload_files) == [f"payloads/{slug}/1.1.0.json"]
    assert result.scenario_json is not None
    stored = json.loads(result.scenario_json)
    assert _at(stored, f"{name} (1.1.0)")
    assert renormaliser(DATA)(stored, ID, f"{ENTRY}/scenario.json") == result.scenario_json
    plain = json.loads(_intake(NEW, export=SALT, payloads=held_salt).scenario_json or b"")
    assert sorted(i["inject_id"] for i in stored["scenario_injects"]) == sorted(
        i["inject_id"] for i in plain["scenario_injects"]
    )  # the injects keep their identifiers


def test_a_renamed_copy_whose_command_holds_its_own_id_matches_its_version_file() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    payload = _salt_payload(edited)
    payload["payload_name"] = f"Copy of {name}"
    payload["command_content"] += f" # {payload['payload_id']}"  # rewritten by normalisation
    claims = {"payloads": [{"name": f"Copy of {name}", "based_on": {"payload": slug}}]}

    result = _intake({**NEW, **claims}, export=edited, payloads=held_salt)

    assert result.refusals == ()
    assert result.scenario_json is not None
    stored = json.loads(result.scenario_json)
    with_files = _with_files(held_salt, result.payload_files)
    assert payload_findings(result.metadata, stored, ENTRY, AgreedIds({}), with_files.held()) == ()
    assert renormaliser(DATA)(stored, ID, f"{ENTRY}/scenario.json") == result.scenario_json


def _renamed_chaining() -> tuple[Any, dict[str, Any], Catalogue]:
    """The chaining export whose step payload is a changed copy named otherwise, the claim on
    it, and the catalogue that holds the original."""
    held_steps = catalogue(json.loads(_intake(NEW, export=CHAINING).scenario_json or b""))
    edited = copy.deepcopy(CHAINING)
    for step in edited["scenario_workflow"]["workflow_steps"]:  # one payload, in both steps
        data = json.loads(step["step_data"])
        payload = data["inject_injector_contract"]["injector_contract_payload"]
        original = payload["payload_name"]
        payload["payload_name"] = f"Copy of {original}"
        payload["command_content"] += " -ef"
        step["step_data"] = json.dumps(data)
    slug = next(v.slug for v in held_steps.by_hash.values() if v.name == original)
    claim = {"name": f"Copy of {original}", "based_on": {"payload": slug}}
    return edited, claim, held_steps


def test_an_update_from_the_same_renamed_chaining_export_keeps_its_steps() -> None:
    edited, claim, held_steps = _renamed_chaining()
    first = _intake({**NEW, "payloads": [claim]}, export=edited, payloads=held_steps)
    assert first.scenario_json is not None
    name = CHAINING["scenario_information"]["scenario_name"]
    source = FakeSource(
        (CatalogueEntry(ENTRY, ID, name),),
        (first.scenario_json, json.loads(first.scenario_json)),
        declared=first.metadata,
    )

    again = _intake(
        {**UPDATE, "payloads": [claim]},
        source,
        export=edited,
        payloads=_with_files(held_steps, first.payload_files),
    )

    assert again.refusals == ()
    assert (again.changed, again.payload_files) == (False, {})
    assert "VER-012" not in {f.code for f in again.to_complete}


def test_an_intake_run_again_with_an_asked_version_finds_a_renamed_copy_already_there() -> None:
    edited, name, slug, held_salt = _copy_of_salt()
    payload = _salt_payload(edited)
    payload["payload_name"] = f"Copy of {name}"
    payload["command_content"] += f" # {payload['payload_id']}"  # rewritten from the base name
    claim = {"name": f"Copy of {name}", "based_on": {"payload": slug}, "version": "2.0.0"}
    request = {**NEW, "payloads": [claim]}
    first = _intake(request, export=edited, payloads=held_salt)
    assert list(first.payload_files) == [f"payloads/{slug}/2.0.0.json"]

    again = _intake(request, export=edited, payloads=_with_files(held_salt, first.payload_files))

    assert again.refusals == ()
    assert again.payload_files == {}
    assert again.scenario_json == first.scenario_json
    assert f"already there: {slug} 2.0.0" in {f.message for f in again.to_complete}


def test_a_claim_after_one_resolved_by_its_name_is_still_found_at_its_place() -> None:
    held_salt = catalogue(json.loads(_intake(NEW, export=SALT).scenario_json or b""))
    edited = copy.deepcopy(SALT)
    there, changed = _salt_payload(edited, 0), _salt_payload(edited, 1)
    names = (there["payload_name"], changed["payload_name"])
    slugs = [next(v.slug for v in held_salt.by_hash.values() if v.name == n) for n in names]
    held_there = next(v for v in held_salt.by_hash.values() if v.name == names[0])
    there["payload_name"] = f"Copy of {names[0]}"  # the catalogue's content, renamed
    there["payload_description"] = held_there.document["payload_description"]
    changed["payload_name"] = f"Copy of {names[1]}"
    changed["command_content"] += " # tuned"
    claims = [
        {"name": f"Copy of {names[0]}", "based_on": {"payload": slugs[0]}},
        {"name": f"Copy of {names[1]}", "based_on": {"payload": slugs[1]}, "version": "1.0.0"},
    ]

    result = _intake({**NEW, "payloads": claims}, export=edited, payloads=held_salt)

    assert _codes(result.refusals) == [("ITK-009", REQUEST, "/payloads/1/version")]


def test_an_update_finds_the_names_its_claims_adopt_before_matching_its_previous_version() -> None:
    calls: list[str] = []

    def prepare(form: Any, *arguments: Any, **options: Any) -> Any:
        calls.append("previous" if options.get("previous") is not None else "alone")
        return prepare_entry(form, *arguments, **options)

    edited, claim, held_steps = _renamed_chaining()
    first = _intake({**NEW, "payloads": [claim]}, export=edited, payloads=held_steps)
    assert first.scenario_json is not None
    source = FakeSource(
        (CatalogueEntry(ENTRY, ID, CHAINING["scenario_information"]["scenario_name"]),),
        (first.scenario_json, json.loads(first.scenario_json)),
        declared=first.metadata,
    )
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("scenario_tools.application.intake_entry.prepare_entry", prepare)
        _intake({**UPDATE, "payloads": [claim]}, source, export=edited, payloads=held_steps)

    assert calls == ["alone", "previous"]  # matched once, with the names adopted


def test_what_the_names_are_found_on_never_refuses_the_request() -> None:
    """The form the adopted names are found on has no previous version and no version asked
    for: a payload refused there may be valid in the final form, which alone decides."""

    def prepare(form: Any, *arguments: Any, **options: Any) -> Any:
        prepared = prepare_entry(form, *arguments, **options)
        if options.get("previous") is not None:
            return prepared
        stored = json.loads(prepared.scenario_json)
        _salt_payload(stored, 1)["command_content"] += " # only here"  # its name is taken
        return dataclasses.replace(prepared, scenario_json=stored_form(stored))

    edited, name, slug, held_salt = _copy_of_salt()
    claims = {"payloads": [{"name": name, "based_on": {"payload": slug}}]}
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("scenario_tools.application.intake_entry.prepare_entry", prepare)
        result = _intake({**UPDATE, **claims}, _stored(SALT), export=edited, payloads=held_salt)

    assert result.refusals == ()
    assert list(result.payload_files) == [f"payloads/{slug}/1.1.0.json"]


def test_a_renamed_copy_of_a_long_named_payload_takes_the_version_asked_for() -> None:
    long = "L" * 192
    exported = copy.deepcopy(SALT)
    _salt_payload(exported)["payload_name"] = long
    held_long = catalogue(json.loads(_intake(NEW, export=exported).scenario_json or b""))
    first = next(v for v in held_long.by_hash.values() if v.name == long)
    later = {
        **first.document,
        "payload_name": f"{long} (1.9.0)",
        "command_content": f"{first.document['command_content']} # 1.9.0",
        "payload_external_id": "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b",
    }
    path = f"payloads/{first.slug}/1.9.0.json"
    held = Catalogue.of(
        [*held_long.by_hash.values(), PayloadVersion(first.slug, "1.9.0", path, later)]
    )
    edited = copy.deepcopy(exported)
    payload = _salt_payload(edited)
    payload["payload_name"] = f"Copy of {long}"[:200]
    payload["command_content"] += " # tuned"
    claim = {
        "name": payload["payload_name"],
        "based_on": {"payload": first.slug},
        "version": "2.0.0",
    }

    result = _intake({**NEW, "payloads": [claim]}, export=edited, payloads=held)

    assert result.refusals == ()
    assert list(result.payload_files) == [f"payloads/{first.slug}/2.0.0.json"]
    stored = json.loads(result.scenario_json or b"")
    assert renormaliser(DATA)(stored, ID, f"{ENTRY}/scenario.json") == result.scenario_json


def test_a_renamed_copy_already_there_claimed_twice_is_refused() -> None:
    held_salt = catalogue(json.loads(_intake(NEW, export=SALT).scenario_json or b""))
    edited = copy.deepcopy(SALT)
    there = _salt_payload(edited)
    held_there = next(v for v in held_salt.by_hash.values() if v.name == there["payload_name"])
    claim = {"name": f"Copy of {there['payload_name']}", "based_on": {"payload": held_there.slug}}
    there["payload_name"] = claim["name"]
    there["payload_description"] = held_there.document["payload_description"]

    result = _intake({**NEW, "payloads": [claim, claim]}, export=edited, payloads=held_salt)

    assert ("ITK-009", REQUEST, "/payloads/1/name") in _codes(result.refusals)
