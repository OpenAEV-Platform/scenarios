"""Schema validation with jsonschema, format checking included (research R6)."""

import copy
import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.jsonschema_validator import (
    JsonSchemaValidator,
    ecma_to_python,
    json_pointer,
)
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT
from scenario_tools.ports.schema import SchemaViolation

SCHEMAS = Path(__file__).parents[2] / "schemas"
SHA = "a" * 64

SCENARIO: dict[str, Any] = {
    "schema_version": 1,
    "external_id": "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
    "version": "1.0.0",
    "status": "VERIFIED",
    "name": "EASM Scenario",
    "description": "Discover and assess the external attack surface.",
    "severity": "medium",
    "category": "attack-scenario",
    "main_focus": "endpoint-protection",
    "type": "time-based",
    "platforms": ["Linux", "Windows"],
    "threat": {"ttps": ["T1595", "T1595.002"]},
    "sources": [{"url": "https://attack.mitre.org/techniques/T1595/", "tlp": "TLP:CLEAR"}],
    "requires": {
        "openaev": ">=3.261005",
        "edition": "CE",
        "injectors": ["nuclei"],
        "executors": [],
    },
    "payloads": [{"id": "easm-scan", "version": "1.0.0", "sha256": SHA}],
}
MANIFEST: dict[str, Any] = {
    "schema_version": 1,
    "repository": "OpenAEV-Platform/scenarios",
    "channel": "edge",
    "sequence": 1,
    "issued_at": "2026-10-08T10:00:00Z",
    "expires_at": "2026-11-07T10:00:00Z",
    "release": "2026.10.08.1",
    "items": [
        {
            "external_id": "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
            "version": "1.0.0",
            "status": "VERIFIED",
            "name": "EASM Scenario",
            "type": "time-based",
            "tabletop": False,
            "requires": {
                "openaev": ">=3.261005",
                "edition": "CE",
                "injectors": [],
                "executors": [],
            },
            "archive": {
                "name": "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42-1.0.0.zip",
                "sha256": SHA,
                "size": 10,
            },
            "payloads": [],
            "test_report": {"sha256": SHA, "release": "2026.10.08.1"},
            "approvals": {"pull_request": 12, "approvers": ["alice", "bob"]},
        }
    ],
}


@pytest.fixture(scope="module")
def validator() -> JsonSchemaValidator:
    return JsonSchemaValidator(SCHEMAS)


def _changed(
    document: dict[str, Any], change: Callable[[dict[str, Any]], object]
) -> dict[str, Any]:
    changed = copy.deepcopy(document)
    change(changed)
    return changed


def test_valid_documents_have_no_violation(validator: JsonSchemaValidator) -> None:
    assert validator.validate("scenario", SCENARIO) == ()
    assert validator.validate("manifest", MANIFEST) == ()


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (lambda d: d.pop("name"), ""),
        (lambda d: d.update(unexpected=1), "/unexpected"),
        (lambda d: d.update(schema_version=2), "/schema_version"),
        (lambda d: d.update(external_id="not-a-uuid"), "/external_id"),
        (lambda d: d.update(version="1.0"), "/version"),
        (lambda d: d.update(status="PUBLISHED"), "/status"),
        (lambda d: d.update(threat={}), "/threat"),
        (lambda d: d["threat"].update(cves=["CVE-24-1"]), "/threat/cves/0"),
        (lambda d: d["sources"][0].update(url="http://example.com/"), "/sources/0/url"),
        (lambda d: d["sources"][0].update(url="https://exa mple.com/"), "/sources/0/url"),
        (lambda d: d["sources"][0].update(tlp="TLP:GREEN"), "/sources/0/tlp"),
        (lambda d: d["payloads"][0].update(sha256=SHA.upper()), "/payloads/0/sha256"),
        (lambda d: d.update(relevance={"priority": 1.5}), "/relevance/priority"),
    ],
    ids=[
        "missing field",
        "unknown field",
        "schema version",
        "external id",
        "version",
        "status",
        "empty threat",
        "cve",
        "http source",
        "malformed uri",
        "tlp",
        "uppercase hash",
        "relevance range",
    ],
)
def test_scenario_violations_name_the_offending_value(
    validator: JsonSchemaValidator, change: Callable[[dict[str, Any]], object], pointer: str
) -> None:
    violations = validator.validate("scenario", _changed(SCENARIO, change))

    assert [violation.pointer for violation in violations] == [pointer]


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (lambda d: d.update(issued_at="2026-13-45T25:61:00Z"), "/issued_at"),
        (lambda d: d.update(expires_at="tomorrow"), "/expires_at"),
        (lambda d: d.update(sequence=0), "/sequence"),
        (
            lambda d: d["items"][0]["approvals"].update(approvers=["alice"]),
            "/items/0/approvals/approvers",
        ),
        (lambda d: d["items"][0]["archive"].update(name="x.zip"), "/items/0/archive/name"),
    ],
    ids=["issued at", "expires at", "sequence", "one approver", "archive name"],
)
def test_manifest_violations_name_the_offending_value(
    validator: JsonSchemaValidator, change: Callable[[dict[str, Any]], object], pointer: str
) -> None:
    violations = validator.validate("manifest", _changed(MANIFEST, change))

    assert [violation.pointer for violation in violations] == [pointer]


@pytest.mark.parametrize("constraint", [">=3.261005", "==3.261005.0", "~=3.26", ">3"])
def test_well_formed_platform_version_constraints_pass(
    validator: JsonSchemaValidator, constraint: str
) -> None:
    document = _changed(SCENARIO, lambda d: d["requires"].update(openaev=constraint))

    assert validator.validate("scenario", document) == ()


@pytest.mark.parametrize("constraint", [">=1.", ">=1..2", "==3...", ">=", ">=.1", "3.26"])
def test_malformed_platform_version_constraints_are_refused(
    validator: JsonSchemaValidator, constraint: str
) -> None:
    document = _changed(SCENARIO, lambda d: d["requires"].update(openaev=constraint))

    assert [v.pointer for v in validator.validate("scenario", document)] == ["/requires/openaev"]


@pytest.mark.parametrize("login", ["alice", "a-b", "a-b-c", "a1", "a" * 39])
def test_valid_github_logins_pass(validator: JsonSchemaValidator, login: str) -> None:
    document = _changed(MANIFEST, lambda d: d.update(release_approver=login))

    assert validator.validate("manifest", document) == ()


@pytest.mark.parametrize(
    "login", ["alice-", "-alice", "a--b", "a" * 40, "al ice", "", "Alice", "ALICE"]
)
def test_impossible_or_non_canonical_github_logins_are_refused(
    validator: JsonSchemaValidator, login: str
) -> None:
    document = _changed(MANIFEST, lambda d: d.update(release_approver=login))
    approvers = _changed(
        MANIFEST, lambda d: d["items"][0]["approvals"].update(approvers=["bob", login])
    )

    assert [v.pointer for v in validator.validate("manifest", document)] == ["/release_approver"]
    assert [v.pointer for v in validator.validate("manifest", approvers)] == [
        "/items/0/approvals/approvers/1"
    ]


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (lambda i: i["requires"].update(openaev=">=1."), "/items/0/requires/openaev"),
        (lambda i: i["requires"].update(injectors=[""]), "/items/0/requires/injectors/0"),
        (lambda i: i["requires"].update(executors=["a", "a"]), "/items/0/requires/executors"),
        (
            lambda i: i.update(payloads=[{"id": "-bad", "version": "1.0.0", "sha256": SHA}]),
            "/items/0/payloads/0/id",
        ),
    ],
    ids=["version constraint", "empty injector", "duplicate executor", "payload id"],
)
def test_the_manifest_is_as_strict_as_the_scenario_metadata(
    validator: JsonSchemaValidator, change: Callable[[dict[str, Any]], object], pointer: str
) -> None:
    document = _changed(MANIFEST, lambda d: change(d["items"][0]))

    assert [v.pointer for v in validator.validate("manifest", document)] == [pointer]


@pytest.mark.parametrize(
    "name",
    [
        "-" * 36 + "-1..zip",
        "5B9A2C84-3A0E-4C55-9A8C-2A6F0D7E1B42-1.0.0.zip",
        "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42-1.0.zip",
        "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42-01.0.0.zip",
        "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42-1.0.0.tar",
        "5b9a2c843a0e4c559a8c2a6f0d7e1b42-1.0.0.zip",
    ],
    ids=["dashes", "uppercase", "two-part version", "leading zero", "extension", "no hyphens"],
)
def test_malformed_archive_names_are_refused(validator: JsonSchemaValidator, name: str) -> None:
    document = _changed(MANIFEST, lambda d: d["items"][0]["archive"].update(name=name))

    assert [v.pointer for v in validator.validate("manifest", document)] == [
        "/items/0/archive/name"
    ]


@pytest.mark.parametrize(
    ("pattern", "translated"),
    [
        ("^a$", "^a\\Z"),
        ("^(?=.{1,39}$)a$", "^(?=.{1,39}\\Z)a\\Z"),
        ("^a\\$$", "^a\\$\\Z"),
        ("^[$]$", "^[$]\\Z"),
        ("^[\\]$]$", "^[\\]$]\\Z"),
        ("^[a$]$", "^[a$]\\Z"),
        ("^a", "^a"),
    ],
    ids=[
        "end",
        "lookahead",
        "escaped dollar",
        "class",
        "escaped bracket in class",
        "dollar later in class",
        "no end",
    ],
)
def test_ecma_end_anchors_are_translated(pattern: str, translated: str) -> None:
    assert ecma_to_python(pattern) == translated


@pytest.mark.parametrize(
    ("schema", "change", "pointer"),
    [
        ("scenario", lambda d: d.update(version="1.0.0\n"), "/version"),
        ("scenario", lambda d: d["threat"].update(cves=["CVE-2024-1234\n"]), "/threat/cves/0"),
        ("scenario", lambda d: d["threat"].update(ttps=["T1595\n"]), "/threat/ttps/0"),
        ("scenario", lambda d: d["requires"].update(openaev=">=3.261005\n"), "/requires/openaev"),
        (
            "scenario",
            lambda d: d.update(targets=[{"placeholder": "web\n", "description": "x"}]),
            "/targets/0/placeholder",
        ),
        ("scenario", lambda d: d["payloads"][0].update(sha256=SHA + "\n"), "/payloads/0/sha256"),
        ("scenario", lambda d: d["payloads"][0].update(id="easm-scan\n"), "/payloads/0/id"),
        ("manifest", lambda d: d.update(release="2026.10.08.1\n"), "/release"),
        ("manifest", lambda d: d.update(release_approver="alice\n"), "/release_approver"),
        (
            "manifest",
            lambda d: d["items"][0]["archive"].update(
                name="5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42-1.0.0.zip\n"
            ),
            "/items/0/archive/name",
        ),
        (
            "manifest",
            lambda d: d["items"][0]["test_report"].update(release="2026.10.08.1\n"),
            "/items/0/test_report/release",
        ),
    ],
    ids=[
        "version",
        "cve",
        "ttp",
        "constraint",
        "placeholder",
        "sha256",
        "payload id",
        "release",
        "login",
        "archive name",
        "report release",
    ],
)
def test_a_trailing_newline_is_refused(
    validator: JsonSchemaValidator,
    schema: str,
    change: Callable[[dict[str, Any]], object],
    pointer: str,
) -> None:
    document = _changed(SCENARIO if schema == "scenario" else MANIFEST, change)

    assert [v.pointer for v in validator.validate(schema, document)] == [pointer]


def test_pattern_properties_also_follow_ecma_anchors(tmp_path: Path) -> None:
    (tmp_path / "anchored.schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "patternProperties": {"^x$": {"type": "integer"}},
                "additionalProperties": False,
            }
        ),
        encoding="utf-8",
    )
    probe = JsonSchemaValidator(tmp_path)

    assert probe.validate("anchored", {"x": "not an integer"})[0].pointer == "/x"
    assert probe.validate("anchored", {"x\n": "text"}) == (
        SchemaViolation("/x\n", "unexpected property"),
    )


def _probe(tmp_path: Path, schema: dict[str, Any]) -> JsonSchemaValidator:
    (tmp_path / "probe.schema.json").write_text(json.dumps(schema), encoding="utf-8")
    return JsonSchemaValidator(tmp_path)


def test_additional_properties_given_as_a_schema_validate_the_extra_values(tmp_path: Path) -> None:
    probe = _probe(tmp_path, {"properties": {"a": {}}, "additionalProperties": {"type": "integer"}})

    assert probe.validate("probe", {"a": "x", "b": 1}) == ()
    assert [v.pointer for v in probe.validate("probe", {"a": "x", "b": "y"})] == ["/b"]


def test_property_keywords_ignore_values_that_are_not_objects(tmp_path: Path) -> None:
    probe = _probe(
        tmp_path, {"patternProperties": {"^x$": {"type": "integer"}}, "additionalProperties": False}
    )

    assert probe.validate("probe", ["x", 1]) == ()
    assert probe.validate("probe", "x") == ()


def test_one_account_cannot_count_as_two_approvers(validator: JsonSchemaValidator) -> None:
    document = _changed(
        MANIFEST, lambda d: d["items"][0]["approvals"].update(approvers=["alice", "ALICE"])
    )

    assert [v.pointer for v in validator.validate("manifest", document)] == [
        "/items/0/approvals/approvers/1"
    ]


def test_each_unexpected_property_is_reported_where_it_is(validator: JsonSchemaValidator) -> None:
    document = _changed(SCENARIO, lambda d: d.update({"zeta": 1, "a/b~c": 2}))
    nested = _changed(MANIFEST, lambda d: d["items"][0].update({"extra": True}))

    assert [v.pointer for v in validator.validate("scenario", document)] == ["/a~1b~0c", "/zeta"]
    assert [v.pointer for v in validator.validate("manifest", nested)] == ["/items/0/extra"]


def test_properties_allowed_by_a_pattern_are_not_unexpected(tmp_path: Path) -> None:
    (tmp_path / "extensible.schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "properties": {"a": {}},
                "patternProperties": {"^x-": {}},
                "additionalProperties": False,
            }
        ),
        encoding="utf-8",
    )

    violations = JsonSchemaValidator(tmp_path).validate("extensible", {"a": 1, "x-1": 2, "b": 3})

    assert [violation.pointer for violation in violations] == ["/b"]


def test_every_violation_is_reported_in_a_stable_order(validator: JsonSchemaValidator) -> None:
    # Eight violations at once: an unsorted result would only match by a 1 in 40,320 chance.
    broken = {
        "category": 1,
        "external_id": "x",
        "main_focus": 1,
        "schema_version": 2,
        "severity": "Y",
        "status": "X",
        "type": "Z",
        "version": "V",
    }
    document = _changed(SCENARIO, lambda d: d.update(broken))

    first = validator.validate("scenario", document)

    assert [violation.pointer for violation in first] == [f"/{name}" for name in sorted(broken)]
    assert validator.validate("scenario", document) == first


@pytest.mark.parametrize(
    ("path", "pointer"),
    [
        ([], ""),
        (["a"], "/a"),
        (["items", 0, "name"], "/items/0/name"),
        (["a/b", "c~d"], "/a~1b/c~0d"),
    ],
)
def test_json_pointers_follow_rfc_6901(path: list[str | int], pointer: str) -> None:
    assert json_pointer(path) == pointer


def test_a_long_value_is_not_echoed_in_full(validator: JsonSchemaValidator) -> None:
    document = _changed(SCENARIO, lambda d: d.update(name="x" * 5000))

    (violation,) = validator.validate("scenario", document)

    assert len(violation.message) <= MESSAGE_LIMIT


def test_an_unknown_schema_is_a_usage_error(validator: JsonSchemaValidator) -> None:
    with pytest.raises(KeyError):
        validator.validate("unknown", {})


def test_an_invalid_schema_is_refused_when_loading(tmp_path: Path) -> None:
    (tmp_path / "broken.schema.json").write_text('{"type": "not-a-type"}', encoding="utf-8")

    with pytest.raises(ValueError, match="broken"):
        JsonSchemaValidator(tmp_path)


# jsonschema silently skips a format whose validator is not installed: every format used by
# the schemas must really be checked.
FORMAT_SAMPLES = {
    "uuid": ("5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42", "5b9a2c84-3a0e-4c55-9a8c"),
    "uri": ("https://attack.mitre.org/", "https://exa mple.com/"),
    "date-time": ("2026-10-08T10:00:00Z", "2026-10-08 10:00"),
}


def _formats(node: object) -> Iterator[str]:
    if isinstance(node, dict):
        if isinstance(node.get("format"), str):
            yield node["format"]
        for child in node.values():
            yield from _formats(child)
    elif isinstance(node, list):
        for child in node:
            yield from _formats(child)


def test_every_format_used_by_the_schemas_is_really_checked(tmp_path: Path) -> None:
    used = {
        name
        for file in SCHEMAS.glob("*.schema.json")
        for name in _formats(json.loads(file.read_text(encoding="utf-8")))
    }
    assert used <= set(FORMAT_SAMPLES), f"no sample for {used - set(FORMAT_SAMPLES)}"
    for name in used:
        (tmp_path / f"{name}.schema.json").write_text(
            json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema", "format": name}),
            encoding="utf-8",
        )
    probe = JsonSchemaValidator(tmp_path)
    for name in used:
        valid, invalid = FORMAT_SAMPLES[name]
        assert probe.validate(name, valid) == (), name
        assert probe.validate(name, invalid) != (), name


# A pattern must mean the same in Python, which checks it here, and in ECMA-262, which other
# consumers of the schemas use. Only escapes and groups known to agree are allowed; anything else
# is refused, whether it means something else in one of them (\d matches every Unicode digit in
# Python, only 0-9 in ECMA-262) or exists in only one (\cA, \u{41}, \Z, lookbehind).
_ESCAPE_OR_GROUP = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|.)|\(\?(.)", re.DOTALL)
_PORTABLE_ESCAPES = frozenset("tnrfv.\\/-^$*+?()[]{}|")
_PORTABLE_GROUPS = frozenset(":=!")


def _non_portable(pattern: str) -> list[str]:
    found = []
    for match in _ESCAPE_OR_GROUP.finditer(pattern):
        escaped, group = match.groups()
        # A two-character or longer escape is \xHH or \uHHHH, the same in both.
        portable_escape = escaped is None or escaped in _PORTABLE_ESCAPES or len(escaped) > 1
        portable_group = group is None or group in _PORTABLE_GROUPS
        if not (portable_escape and portable_group):
            found.append(match.group())
    return found


def _patterns(node: object) -> Iterator[str]:
    if isinstance(node, dict):
        if isinstance(node.get("pattern"), str):
            yield node["pattern"]
        if isinstance(node.get("patternProperties"), dict):
            yield from node["patternProperties"]
        for child in node.values():
            yield from _patterns(child)
    elif isinstance(node, list):
        for child in node:
            yield from _patterns(child)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^\d+$",
        r"^\W",
        r"\s",
        r"\bword",
        r"(?<=a)b",
        r"(?<!a)b",
        r"(a)\1",
        r"(?P<name>a)",
        r"(?<name>a)\k<name>",
        r"\p{L}",
        r"(?i)abc",
        r"abc\Z",
        r"\cA",
        r"\u{41}",
        r"\x4",
        r"\q",
    ],
)
def test_the_guard_refuses_non_portable_constructs(pattern: str) -> None:
    assert _non_portable(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^[0-9]{4}$",
        r"^(?=.{1,39}$)[a-z]+(?:-[a-z]+)*$",
        r"(?!x)y",
        r"a\\d",
        r"\.",
        r"^https://",
        r"\x41\u00e9",
        r"\t\n\r\f\v",
        r"\/\-\^\$\*\+\?\(\)\[\]\{\}\|",
    ],
)
def test_the_guard_accepts_portable_constructs(pattern: str) -> None:
    assert _non_portable(pattern) == []


def test_the_guard_collects_patterns_and_pattern_property_names_at_any_depth() -> None:
    node = {
        "properties": {"a": {"pattern": "^x$"}},
        "patternProperties": {"^y": {"pattern": "w"}},
        "prefixItems": [{"pattern": "z"}],
    }

    assert sorted(_patterns(node)) == ["^x$", "^y", "w", "z"]


def test_every_pattern_of_the_schemas_means_the_same_in_python_and_ecma_262() -> None:
    patterns = [
        pattern
        for file in SCHEMAS.glob("*.schema.json")
        for pattern in _patterns(json.loads(file.read_text(encoding="utf-8")))
    ]
    assert patterns
    assert {pattern: _non_portable(pattern) for pattern in patterns if _non_portable(pattern)} == {}
    for pattern in patterns:
        re.compile(ecma_to_python(pattern))
