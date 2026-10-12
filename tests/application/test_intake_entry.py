"""Intake of an export into the catalogue: refused before anything is written when the request,
the catalogue or the metadata it completes says so; otherwise what to write, and what is left.

Characters are written by code point, never raw, so that this file holds none of them."""

import contextlib
import copy
import hashlib
import json
from collections.abc import Iterator, Mapping
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
    write_intake,
)
from scenario_tools.domain.catalogue.intake import CatalogueEntry
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.errors import EnvironmentProblemError

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
        assert entry == ENTRY
        return frozenset({"scenario.yaml", "scenario.json"} if self.stored else {"scenario.yaml"})

    def read_yaml(self, path: str) -> object:
        raise AssertionError("intake never asks")

    def read_text(self, path: str) -> str:
        raise AssertionError("intake never asks")

    def scenario_names(self) -> Mapping[str, tuple[str, ...]]:
        raise AssertionError("intake compares the entries themselves")

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
        ("write", ENTRY, ("scenario.yaml", "scenario.json"), None),  # a new one
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
    "write": ("write", ENTRY, ("scenario.yaml", "scenario.json"), None),
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
    )

    assert _codes(result.refusals) == [("SCH-001", REQUEST, "")]


def test_a_commit_that_changes_before_the_plan_takes_the_entry_back() -> None:
    log = _Log("moved")

    with pytest.raises(EnvironmentProblemError, match="commit changed"):
        _write(_intake(NEW), log)

    assert log.events[-3:] == ["current", "take back", "give back"]
    assert log.published is None
