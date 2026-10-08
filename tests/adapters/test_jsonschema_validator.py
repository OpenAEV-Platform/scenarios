"""Schema validation with jsonschema, format checking included (research R6)."""

import copy
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.jsonschema_validator import (
    MESSAGE_LIMIT,
    JsonSchemaValidator,
    json_pointer,
)

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


@pytest.mark.parametrize("login", ["alice", "a-b", "a-b-c", "A1", "a" * 39])
def test_valid_github_logins_pass(validator: JsonSchemaValidator, login: str) -> None:
    document = _changed(MANIFEST, lambda d: d.update(release_approver=login))

    assert validator.validate("manifest", document) == ()


@pytest.mark.parametrize("login", ["alice-", "-alice", "a--b", "a" * 40, "al ice", ""])
def test_impossible_github_logins_are_refused(validator: JsonSchemaValidator, login: str) -> None:
    document = _changed(MANIFEST, lambda d: d.update(release_approver=login))
    approvers = _changed(
        MANIFEST, lambda d: d["items"][0]["approvals"].update(approvers=["bob", login])
    )

    assert [v.pointer for v in validator.validate("manifest", document)] == ["/release_approver"]
    assert [v.pointer for v in validator.validate("manifest", approvers)] == [
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
