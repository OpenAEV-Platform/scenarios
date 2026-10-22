"""Schema validation with jsonschema, format checking included."""

import copy
import json
import re
import time
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import scenario_tools.adapters.jsonschema_validator as validator_module
from scenario_tools.adapters.jsonschema_validator import (
    VIOLATION_LIMIT,
    JsonSchemaValidator,
    ecma_to_python,
    json_pointer,
)
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT
from scenario_tools.ports.errors import EnvironmentProblemError
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
    "issued_at": "2026-10-08T10:00:00Z",
    "release": "2026.10.08.1",
    "items": [
        {
            "external_id": "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
            "version": "1.0.0",
            "status": "VERIFIED",
            "name": "EASM Scenario",
            "description": "Discover and assess the external attack surface.",
            "severity": "medium",
            "category": "attack-scenario",
            "main_focus": "endpoint-protection",
            "platforms": ["Generic"],
            "threat": {"ttps": ["T1595"]},
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
    "payloads": [],
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


CATALOGUE_FACETS = ("description", "severity", "category", "main_focus", "platforms", "threat")


@pytest.mark.parametrize("facet", CATALOGUE_FACETS)
def test_every_manifest_item_carries_the_catalogue_facets(
    validator: JsonSchemaValidator, facet: str
) -> None:
    document = _changed(MANIFEST, lambda d: d["items"][0].pop(facet))

    violations = validator.validate("manifest", document)

    assert [violation.pointer for violation in violations] == ["/items/0"]
    assert facet in violations[0].message


@pytest.mark.parametrize(
    ("schema", "document", "change", "pointer"),
    [
        ("scenario", SCENARIO, lambda d: d.update(platforms=[]), "/platforms"),
        ("manifest", MANIFEST, lambda d: d["items"][0].update(platforms=[]), "/items/0/platforms"),
    ],
    ids=["scenario", "manifest"],
)
def test_platforms_hold_at_least_one_value(
    validator: JsonSchemaValidator,
    schema: str,
    document: dict[str, Any],
    change: Callable[[dict[str, Any]], object],
    pointer: str,
) -> None:
    violations = validator.validate(schema, _changed(document, change))

    assert [violation.pointer for violation in violations] == [pointer]


@pytest.mark.parametrize(
    "external_id",
    [
        "5B9A2C84-3A0E-4C55-9A8C-2A6F0D7E1B42",
        "5b9a2c84-3a0e-4c55-9a8c-2A6F0D7E1B42",
        "{5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42}",
        "urn:uuid:5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
        "5b9a2c843a0e4c559a8c2a6f0d7e1b42",
    ],
    ids=["upper case", "mixed case", "braces", "urn", "no hyphens"],
)
def test_only_the_canonical_external_id_is_accepted(
    validator: JsonSchemaValidator, external_id: str
) -> None:
    scenario = _changed(SCENARIO, lambda d: d.update(external_id=external_id))
    manifest = _changed(MANIFEST, lambda d: d["items"][0].update(external_id=external_id))

    assert [v.pointer for v in validator.validate("scenario", scenario)] == ["/external_id"]
    assert [v.pointer for v in validator.validate("manifest", manifest)] == ["/items/0/external_id"]


@pytest.mark.parametrize("facet", [*CATALOGUE_FACETS, "external_id"])
def test_manifest_facets_are_defined_exactly_as_in_the_scenario_metadata(facet: str) -> None:
    scenario = json.loads((SCHEMAS / "scenario.schema.json").read_text(encoding="utf-8"))
    manifest = json.loads((SCHEMAS / "manifest.schema.json").read_text(encoding="utf-8"))

    assert manifest["$defs"]["item"]["properties"][facet] == scenario["properties"][facet]


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (lambda d: d.pop("name"), ""),
        (lambda d: d.update(unexpected=1), "/unexpected"),
        (lambda d: d.update(schema_version=2), "/schema_version"),
        (lambda d: d.update(external_id="not-a-uuid"), "/external_id"),
        (lambda d: d.update(version="1.0"), "/version"),
        (lambda d: d.update(version="1.0.1234567890"), "/version"),
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
        "version number of ten digits",
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
        (
            lambda d: d["items"][0]["approvals"].update(approvers=["alice", "alice"]),
            "/items/0/approvals/approvers",
        ),
        (lambda d: d["items"][0]["archive"].update(name="x.zip"), "/items/0/archive/name"),
    ],
    ids=["issued at", "an approver twice", "archive name"],
)
def test_manifest_violations_name_the_offending_value(
    validator: JsonSchemaValidator, change: Callable[[dict[str, Any]], object], pointer: str
) -> None:
    violations = validator.validate("manifest", _changed(MANIFEST, change))

    assert [violation.pointer for violation in violations] == [pointer]


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["items"][0].pop("test_report"),
        lambda d: d["items"][0]["approvals"].update(approvers=[]),
        lambda d: d["items"][0]["approvals"].update(approvers=["alice"]),
    ],
    ids=["no test report", "no approver", "one approver"],
)
def test_a_manifest_may_carry_no_test_report_and_fewer_approvers(
    validator: JsonSchemaValidator, change: Callable[[dict[str, Any]], object]
) -> None:
    """While the releases carry no test report, and while a pull request merged before reviews
    were required stays in the catalogue: what build checks, not the schema."""
    assert validator.validate("manifest", _changed(MANIFEST, change)) == ()


def test_a_manifest_version_is_bounded_as_a_scenario_version_is(
    validator: JsonSchemaValidator,
) -> None:
    """What the tools compare, nine digits at most for each number, is all a manifest holds."""
    manifest = json.loads((SCHEMAS / "manifest.schema.json").read_text(encoding="utf-8"))
    scenario = json.loads((SCHEMAS / "scenario.schema.json").read_text(encoding="utf-8"))
    beyond = _changed(MANIFEST, lambda d: d["items"][0].update(version="1000000000.0.0"))

    assert manifest["$defs"]["semver"] == scenario["$defs"]["semver"]
    assert [v.pointer for v in validator.validate("manifest", beyond)] == ["/items/0/version"]


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


# ECMA-262's wildcard matches anything but a line terminator; Python's also matches \r, U+2028
# and U+2029.
_DOT = r"[^\n\r\u2028\u2029]"


@pytest.mark.parametrize(
    ("pattern", "translated"),
    [
        ("^a$", "^a\\Z"),
        ("^(?=.{1,39}$)a$", f"^(?={_DOT}{{1,39}}\\Z)a\\Z"),
        ("^a\\$$", "^a\\$\\Z"),
        ("^[$]$", "^[$]\\Z"),
        ("^[\\]$]$", "^[\\]$]\\Z"),
        ("^[a$]$", "^[a$]\\Z"),
        ("^a", "^a"),
        ("a.b", f"a{_DOT}b"),
        ("a\\.b", "a\\.b"),
        ("[.]", "[.]"),
    ],
    ids=[
        "end",
        "lookahead",
        "escaped dollar",
        "class",
        "escaped bracket in class",
        "dollar later in class",
        "no end",
        "wildcard",
        "escaped dot",
        "dot in class",
    ],
)
def test_ecma_anchors_and_wildcards_are_translated(pattern: str, translated: str) -> None:
    assert ecma_to_python(pattern) == translated


@pytest.mark.parametrize("terminator", ["\n", "\r", "\u2028", "\u2029"])
def test_the_wildcard_never_matches_a_line_terminator(tmp_path: Path, terminator: str) -> None:
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "pattern": "^a.b$"}
    (tmp_path / "dot.schema.json").write_text(json.dumps(schema), encoding="utf-8")
    probe = JsonSchemaValidator(tmp_path)

    assert probe.validate("dot", "axb") == ()
    assert probe.validate("dot", f"a{terminator}b") != ()


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


# A pattern must mean the same in Python, which checks it here, and in every ECMA-262 engine,
# with or without the "u" flag. Patterns are held to the interoperable subset that JSON Schema
# 2020-12 recommends (Core, section 6.4), in ASCII only: literal characters, escaped
# metacharacters, non-empty classes, quantifiers + * ? {x} {x,} {x,y} and their lazy forms,
# anchors, plain groups and alternation. Anything else is refused, since it means something else
# in one of the engines (\d, ., {,5}, []) or exists in only one of them (lookbehind, a*+, \cA).
_SUBSET_TOKEN = re.compile(
    r"""
      \\[\\.^$*+?()\[\]{}|/]                         # escaped metacharacter
    | \[\^?(?!\^)(?:\\[\\\]\[^-]|[ -Z^-~])+\]        # non-empty class
    | (?:[*+?]|\{[0-9]+(?:,[0-9]*)?\})\??(?![*+?{])  # quantifier, maybe lazy, never possessive
    | \((?!\?) | [)|^$]                              # plain group, alternation, anchors
    | [A-Za-z0-9\ !"\#%&',/:;<=>@_`~-]               # literal character
    """,
    re.VERBOSE,
)


def _non_portable(pattern: str) -> list[str]:
    found, index = [], 0
    while index < len(pattern):
        token = _SUBSET_TOKEN.match(pattern, index)
        if token is None:
            found.append(pattern[index:])
            break
        index = token.end()
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
        r"(?=a)b",
        r"(?:a)",
        r"(a)\1",
        r"(?P<name>a)",
        r"(?<name>a)\k<name>",
        r"\p{L}",
        r"(?i)abc",
        r"abc\Z",
        r"\cA",
        r"\u{41}",
        r"\x41",
        r"\uD83D\uDE00",
        r"\t",
        r"a.b",
        r"a{,5}",
        r"a*+",
        r"a{2}+",
        r"[]a]",
        r"[^]",
        r"a{",
        r"a]",
        r"\-",
        "caf\u00e9",
        "\U0001f600",
        "a\nb",
    ],
)
def test_the_guard_refuses_what_is_outside_the_interoperable_subset(pattern: str) -> None:
    assert _non_portable(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^[0-9]{4}$",
        r"^[a-z0-9]+(-[a-z0-9]+)*$",
        r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
        r"^[A-Za-z0-9:._-]*$",
        r"^[^abc]+?$",
        r"a*?b??c{2}d{2,}?e{2,3}",
        r"^https://",
        r"^(>=|>|==|~=)[0-9]+$",
        r"a\\d",
        r"\.\\\/\^\$\*\+\?\(\)\[\]\{\}\|",
        r"[\]\[\\\^\-]",
    ],
)
def test_the_guard_accepts_the_interoperable_subset(pattern: str) -> None:
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
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for pattern in patterns:
            re.compile(ecma_to_python(pattern))


@pytest.mark.parametrize(
    ("field", "value"), [("sequence", 1), ("expires_at", "2026-11-07T10:00:00Z")]
)
def test_a_manifest_carries_no_field_that_only_signing_would_protect(
    validator: JsonSchemaValidator, field: str, value: object
) -> None:
    # Values the earlier schema accepted: the refusal comes from the field itself.
    document = _changed(MANIFEST, lambda d: d.update({field: value}))

    assert [v.pointer for v in validator.validate("manifest", document)] == [f"/{field}"]


def _arrays(node: Any, pointer: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    """Every array schema, wherever it sits: under an object, or in a list of subschemas such
    as ``oneOf`` or ``prefixItems``."""
    if isinstance(node, dict):
        if node.get("type") == "array":
            yield pointer, node
        for key, child in node.items():
            yield from _arrays(child, f"{pointer}/{key}")
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from _arrays(child, f"{pointer}/{index}")


def test_the_array_walk_reaches_lists_of_subschemas() -> None:
    schema = {"oneOf": [{"type": "array"}, {"prefixItems": [{"type": "array"}]}]}

    assert [pointer for pointer, _ in _arrays(schema)] == ["/oneOf/0", "/oneOf/1/prefixItems/0"]


@pytest.mark.parametrize("schema", ["scenario", "manifest", "intake-request", "channel"])
def test_every_list_has_a_bound(schema: str) -> None:
    document = json.loads((SCHEMAS / f"{schema}.schema.json").read_text(encoding="utf-8"))

    unbounded = [pointer for pointer, node in _arrays(document) if "maxItems" not in node]

    assert unbounded == []


def test_a_list_past_its_bound_is_refused(validator: JsonSchemaValidator) -> None:
    many = [{"placeholder": f"target-{n:03}", "description": "a host"} for n in range(101)]
    targets = _changed(SCENARIO, lambda d: d.__setitem__("targets", many))

    pointers = [violation.pointer for violation in validator.validate("scenario", targets)]

    assert pointers == ["/targets"]
    assert validator.validate("scenario", _changed(targets, lambda d: d["targets"].pop())) == ()


def test_the_violations_reported_are_capped(validator: JsonSchemaValidator) -> None:
    items = _changed(MANIFEST, lambda d: d.__setitem__("items", [{}] * 500))

    assert len(validator.validate("manifest", items)) == VIOLATION_LIMIT


def test_a_manifest_of_a_million_items_is_refused_quickly(validator: JsonSchemaValidator) -> None:
    items = _changed(MANIFEST, lambda d: d.__setitem__("items", [{}] * 1_000_000))

    started = time.monotonic()
    violations = validator.validate("manifest", items)

    assert violations
    assert time.monotonic() - started < 1


def test_the_cap_holds_when_one_error_names_many_values(validator: JsonSchemaValidator) -> None:
    # One error about unexpected properties gives one violation per property.
    extra = {f"extra_{n:03}": n for n in range(150)}
    document = _changed(SCENARIO, lambda d: d.update(extra))

    assert len(validator.validate("scenario", document)) == VIOLATION_LIMIT


def test_the_validator_stops_once_it_has_enough(
    validator: JsonSchemaValidator, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each error the validator produces is turned into violations once: count them.
    errors: list[object] = []
    original = validator_module._violations

    def counted(error: Any, budget: int) -> Any:
        errors.append(error)
        return original(error, budget)

    monkeypatch.setattr(validator_module, "_violations", counted)
    validator.validate("manifest", _changed(MANIFEST, lambda d: d.__setitem__("items", [{}] * 500)))

    assert len(errors) <= VIOLATION_LIMIT


@pytest.mark.parametrize("schema", ["scenario", "manifest", "intake-request", "channel"])
def test_every_bound_is_checked_before_the_items(schema: str) -> None:
    # jsonschema checks keywords in their order: the size first, so an oversized list fails
    # before its items are walked.
    document = json.loads((SCHEMAS / f"{schema}.schema.json").read_text(encoding="utf-8"))

    for pointer, node in _arrays(document):
        keys = [key for key in node if key in ("maxItems", "minItems", "uniqueItems", "items")]
        assert keys[0] == "maxItems", pointer


def test_an_oversized_list_of_valid_items_is_refused_quickly(
    validator: JsonSchemaValidator,
) -> None:
    items = _changed(MANIFEST, lambda d: d.__setitem__("items", d["items"] * 200_000))

    started = time.monotonic()
    violations = validator.validate("manifest", items)

    assert [(v.pointer, v.message) for v in violations] == [
        ("/items", "has 200000 items, more than 10000")  # the list itself is never written out
    ]
    assert time.monotonic() - started < 0.2


def test_unexpected_properties_are_counted_within_the_cap(
    validator: JsonSchemaValidator,
) -> None:
    extra = {f"extra_{n:07}": n for n in range(1_000_000)}
    document = _changed(SCENARIO, lambda d: d.update(extra))

    started = time.monotonic()
    violations = validator.validate("scenario", document)

    assert len(violations) == VIOLATION_LIMIT
    assert time.monotonic() - started < 0.2  # only the names reported are looked at


def test_a_reference_the_schemas_cannot_resolve_is_the_environment_s_fault(
    tmp_path: Path,
) -> None:
    (tmp_path / "broken.schema.json").write_text(
        '{"$schema": "https://json-schema.org/draft/2020-12/schema", "$ref": "missing.json"}'
    )

    with pytest.raises(EnvironmentProblemError, match="cannot be resolved"):
        JsonSchemaValidator(tmp_path).validate("broken", {})


INTAKE = {
    "mode": "new",
    "external_id": "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
    "domain": "ransomware",
    "slug": "akira-crisis",
    "threat": {"ttps": ["T1486"]},
    "sources": [{"url": "https://example.org", "tlp": "TLP:CLEAR"}],
    "generated_by": "run 42",
    "issue": 12,
}


def test_an_intake_request_is_valid(validator: JsonSchemaValidator) -> None:
    assert validator.validate("intake-request", INTAKE) == ()
    update = {key: INTAKE[key] for key in ("external_id", "domain", "slug", "issue")}
    assert validator.validate("intake-request", {**update, "mode": "update", "rewrite": True}) == ()


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        ({"mode": "replace"}, "/mode"),
        ({"external_id": "5B9A2C84-3A0E-4C55-9A8C-2A6F0D7E1B42"}, "/external_id"),
        ({"slug": "Akira_Crisis"}, "/slug"),
        ({"issue": 0}, "/issue"),
        ({"extra": 1}, "/extra"),
    ],
    ids=["mode", "external id", "slug", "issue", "extra field"],
)
def test_an_intake_request_outside_its_schema_is_refused(
    validator: JsonSchemaValidator, change: dict[str, object], pointer: str
) -> None:
    assert pointer in {
        v.pointer for v in validator.validate("intake-request", {**INTAKE, **change})
    }


def test_a_new_entry_needs_threat_and_sources_and_an_update_takes_none(
    validator: JsonSchemaValidator,
) -> None:
    bare = {key: value for key, value in INTAKE.items() if key not in ("threat", "sources")}
    assert validator.validate("intake-request", bare)
    assert validator.validate("intake-request", {**INTAKE, "mode": "update"})


def test_a_new_entry_request_cannot_ask_for_a_rewrite(validator: JsonSchemaValidator) -> None:
    assert validator.validate("intake-request", {**INTAKE, "rewrite": True})


def test_a_channel_pointer_the_domain_writes_meets_its_schema(
    validator: JsonSchemaValidator,
) -> None:
    from scenario_tools.domain.release.channel import ChannelPointer, pointer_document

    pointer = pointer_document(ChannelPointer("stable", "2026.10.16.1", "a" * 64))

    assert validator.validate("channel", pointer) == ()
    assert [v.pointer for v in validator.validate("channel", {**pointer, "release": "x"})] == [
        "/release"
    ]


PAYLOAD_VERSION: dict[str, Any] = {
    "payload": "process-discovery-ps",
    "version": "1.1.0",
    "sha256": SHA,
    "openaev_id": "13973155-b166-4bbf-a34a-6b74c0d92957",
    "file": {"name": "process-discovery-ps-1.1.0.json", "sha256": SHA, "size": 1024},
}


def test_a_manifest_lists_its_payload_versions(validator: JsonSchemaValidator) -> None:
    document = {**MANIFEST, "payloads": [PAYLOAD_VERSION]}

    assert validator.validate("manifest", document) == ()


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        ({"file": {**PAYLOAD_VERSION["file"], "size": 262_145}}, "/payloads/0/file/size"),
        ({"file": {**PAYLOAD_VERSION["file"], "name": "../x.json"}}, "/payloads/0/file/name"),
        ({"payload": "Process Discovery"}, "/payloads/0/payload"),
        ({"openaev_id": "Upper-Case"}, "/payloads/0/openaev_id"),
        ({"domains": []}, "/payloads/0/domains"),
    ],
    ids=["size", "name", "slug", "id", "unknown field"],
)
def test_a_payload_version_out_of_its_definition_is_refused(
    validator: JsonSchemaValidator, change: dict[str, Any], pointer: str
) -> None:
    document = {**MANIFEST, "payloads": [{**PAYLOAD_VERSION, **change}]}

    assert [v.pointer for v in validator.validate("manifest", document)] == [pointer]


def test_a_manifest_without_its_payload_list_is_refused(validator: JsonSchemaValidator) -> None:
    document = {key: value for key, value in MANIFEST.items() if key != "payloads"}

    assert [v.pointer for v in validator.validate("manifest", document)] == [""]
