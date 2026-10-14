"""Justified exceptions: the maintainers' registry lets a blocking finding of a few rules through
as information, for one field of one version of one entry, and an exception that covers nothing
blocks."""

import dataclasses
from typing import Any

import pytest

from scenario_tools.domain.policy.exceptions import (
    EXCEPTABLE,
    REGISTRY,
    PolicyException,
    exceptions_from_document,
)
from scenario_tools.domain.policy.registry import policy_findings
from scenario_tools.domain.policy.rule import EntryContent
from scenario_tools.domain.shared.finding import Severity, shorten
from tests.domain.policy.cases import CASES, DATA, ENTRY, PAYLOAD, timed

ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
OTHER = "0f6a8d2e-1b3c-4d5e-8f90-a1b2c3d4e5f6"
SHA = "a" * 64
NEWER = "b" * 64
COMMAND = f"{PAYLOAD}/command_content"
WHY = "the product is named to check that the simulation stops at the query"
EXCEPTION: dict[str, Any] = {
    "entry": ID,
    "code": "POL-006",
    "field": COMMAND,
    "sha256": SHA,
    "justification": WHY,
}


def identified(
    content: EntryContent, external_id: object = ID, sha256: str | None = SHA
) -> EntryContent:
    """``content`` with an external ID, and its stored scenario.json with the hash ``sha256``."""
    return dataclasses.replace(
        content,
        declared={**(content.declared or {}), "external_id": external_id},
        stored_sha256=sha256,
    )


def data_with(*exceptions: dict[str, Any]) -> Any:
    return dataclasses.replace(
        DATA, exceptions=exceptions_from_document({"exceptions": list(exceptions)})
    )


def found(content: EntryContent, *exceptions: dict[str, Any]) -> list[tuple[str, Severity, str]]:
    return [
        (finding.code, finding.severity, finding.field)
        for finding in policy_findings(data_with(*exceptions), content)
    ]


# The registry


def test_only_four_rules_can_be_excepted() -> None:
    assert frozenset({"POL-004", "POL-005", "POL-006", "POL-009"}) == EXCEPTABLE
    assert REGISTRY == "policy/data/exceptions.yaml"


def test_the_registry_gives_its_exceptions_in_order() -> None:
    second = {**EXCEPTION, "code": "POL-004"}

    assert exceptions_from_document({"exceptions": [EXCEPTION, second]}) == (
        PolicyException(ID, "POL-006", COMMAND, SHA, WHY),
        PolicyException(ID, "POL-004", COMMAND, SHA, WHY),
    )
    assert exceptions_from_document({"exceptions": []}) == ()


SHAPE = "exceptions: #0: an exception is an entry, a code, a field, a sha256 and a justification"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (None, "exceptions: the document must be a mapping holding exceptions"),
        ({}, "exceptions: the document must be a mapping holding exceptions"),
        ({"exceptions": {}}, "exceptions: the document must be a mapping holding exceptions"),
        ({"exceptions": [], "y": 1, "x": 1}, "exceptions: unknown keys x, y"),
        ({"exceptions": ["x"]}, SHAPE),
        ({"exceptions": [{**EXCEPTION, "file": "scenario.json"}]}, SHAPE),
        ({"exceptions": [{k: v for k, v in EXCEPTION.items() if k != "sha256"}]}, SHAPE),
        (
            {"exceptions": [EXCEPTION, {**EXCEPTION, "sha256": NEWER}]},
            "exceptions: #1: each entry, code and field once",
        ),
        (
            {"exceptions": [{**EXCEPTION, "entry": OTHER}, EXCEPTION, EXCEPTION]},
            "exceptions: #2: each entry, code and field once",
        ),
    ],
)
def test_a_malformed_registry_is_refused(document: object, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        exceptions_from_document(document)


@pytest.mark.parametrize("change", [{"entry": OTHER}, {"code": "POL-004"}, {"field": ""}])
def test_an_exception_is_one_entry_code_and_field(change: dict[str, Any]) -> None:
    assert len(exceptions_from_document({"exceptions": [EXCEPTION, {**EXCEPTION, **change}]})) == 2


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("entry", ID.upper(), "an entry is the external ID of a scenario, a UUID in lower case"),
        ("entry", f"{ID}\n", "an entry is the external ID of a scenario, a UUID in lower case"),
        ("entry", 1, "an entry is the external ID of a scenario, a UUID in lower case"),
        ("code", "POL-003", "a code is one of POL-004, POL-005, POL-006, POL-009"),
        ("code", "POL-010", "a code is one of POL-004, POL-005, POL-006, POL-009"),
        ("code", "SCH-001", "a code is one of POL-004, POL-005, POL-006, POL-009"),
        ("code", None, "a code is one of POL-004, POL-005, POL-006, POL-009"),
        ("code", ["POL-004"], "a code is one of POL-004, POL-005, POL-006, POL-009"),
        (
            "field",
            "scenario_injects",
            "a field is the JSON pointer a finding reports in scenario.json",
        ),
        ("field", "/a\nb", "a field is the JSON pointer a finding reports in scenario.json"),
        (
            "field",
            "/" + "a" * 300,
            "a field is the JSON pointer a finding reports in scenario.json",
        ),
        ("field", 1, "a field is the JSON pointer a finding reports in scenario.json"),
        ("sha256", SHA.upper(), "a sha256 is the hash of the entry's scenario.json, in lower case"),
        ("sha256", SHA[1:], "a sha256 is the hash of the entry's scenario.json, in lower case"),
        ("sha256", f"{SHA}\n", "a sha256 is the hash of the entry's scenario.json, in lower case"),
        ("sha256", None, "a sha256 is the hash of the entry's scenario.json, in lower case"),
        ("justification", "", "a justification says why, in one line of 20 to 200 characters"),
        (
            "justification",
            "too short",
            "a justification says why, in one line of 20 to 200 characters",
        ),
        (
            "justification",
            " " * 30,
            "a justification says why, in one line of 20 to 200 characters",
        ),
        (
            "justification",
            "x" * 201,
            "a justification says why, in one line of 20 to 200 characters",
        ),
        (
            "justification",
            f"{WHY}\nmore",
            "a justification says why, in one line of 20 to 200 characters",
        ),
        ("justification", None, "a justification says why, in one line of 20 to 200 characters"),
    ],
)
def test_an_exception_out_of_its_form_is_refused(field: str, value: object, message: str) -> None:
    with pytest.raises(ValueError, match=f"^exceptions: #1: {message}$"):
        exceptions_from_document({"exceptions": [EXCEPTION, {**EXCEPTION, field: value}]})


def test_the_limits_of_a_field_and_a_justification_are_allowed() -> None:
    """A pointer of 300 characters at most: a finding reports it whole, never shortened."""
    longest = {**EXCEPTION, "field": "/" + "a" * 299, "justification": "x" * 200}
    shortest = {**EXCEPTION, "field": "", "justification": "x" * 20}

    assert len(exceptions_from_document({"exceptions": [longest, shortest]})) == 2


def test_an_exception_built_in_code_is_checked_as_the_registry_checks_it() -> None:
    """None can be built that the registry would refuse: a rule outside the four, say."""
    with pytest.raises(ValueError, match=r"^a code is one of"):
        PolicyException(ID, "POL-010", COMMAND, SHA, WHY)


# Applying the exceptions


def test_an_exception_turns_its_finding_into_information_with_its_justification() -> None:
    failing = identified(CASES["POL-006"][1])

    (finding,) = policy_findings(data_with(EXCEPTION), failing)

    assert (finding.code, finding.severity, finding.path, finding.field) == (
        "POL-006",
        Severity.INFO,
        f"{ENTRY}/scenario.json",
        COMMAND,
    )
    assert finding.message.startswith(f"excepted by the maintainers ({WHY}): this text names")


@pytest.mark.parametrize("code", sorted(EXCEPTABLE))
def test_each_rule_that_can_be_excepted_is(code: str) -> None:
    failing = identified(CASES[code][1])
    (blocking,) = policy_findings(DATA, failing)
    exception = {**EXCEPTION, "code": code, "field": blocking.field}

    (finding,) = policy_findings(data_with(exception), failing)

    assert (finding.code, finding.severity, finding.field) == (code, Severity.INFO, blocking.field)
    assert finding.message == shorten(f"excepted by the maintainers ({WHY}): {blocking.message}")


@pytest.mark.parametrize(
    "change",
    [{"entry": OTHER}, {"code": "POL-004"}, {"field": f"{PAYLOAD}/payload_name"}, {"field": ""}],
)
def test_an_exception_covers_its_entry_code_and_field_only(change: dict[str, Any]) -> None:
    failing = identified(CASES["POL-006"][1])
    unused = [] if "entry" in change else [("POL-011", Severity.BLOCKING, "/exceptions/0")]

    assert found(failing, {**EXCEPTION, **change}) == [
        ("POL-006", Severity.BLOCKING, COMMAND),
        *unused,
    ]


def test_an_exception_covers_the_version_of_scenario_json_it_names_only() -> None:
    """A payload changed under the exception's field is another content: it blocks again, and
    the maintainers review the change before they give the exception its new hash."""
    changed = identified(CASES["POL-006"][1], sha256=NEWER)

    (blocking, unused) = policy_findings(data_with(EXCEPTION), changed)

    assert (blocking.code, blocking.severity, blocking.field) == (
        "POL-006",
        Severity.BLOCKING,
        COMMAND,
    )
    assert (unused.code, unused.severity, unused.path, unused.field, unused.message) == (
        "POL-011",
        Severity.BLOCKING,
        REGISTRY,
        "/exceptions/0",
        f"this exception of POL-006 for {ENTRY} covers no finding: its scenario.json changed "
        f"(sha256 now {NEWER}), or the breach is gone or moved; review the change and give the "
        "exception that hash, or remove it",
    )


def test_an_entry_whose_scenario_json_has_no_hash_takes_no_exception() -> None:
    unread = identified(CASES["POL-006"][1], sha256=None)

    (blocking, unused) = policy_findings(data_with(EXCEPTION), unread)

    assert (blocking.code, blocking.severity) == ("POL-006", Severity.BLOCKING)
    assert unused.code == "POL-011"
    assert "(sha256 now unknown)" in unused.message


def test_an_exception_that_matches_no_finding_blocks() -> None:
    """A breach fixed or a field moved ends the exception: none outlives what it covers."""
    passing = identified(CASES["POL-006"][0])
    other = {**EXCEPTION, "entry": OTHER}

    assert found(passing, other, EXCEPTION) == [("POL-011", Severity.BLOCKING, "/exceptions/1")]


def test_an_exception_of_another_entry_is_never_reported_for_this_one() -> None:
    passing = identified(CASES["POL-006"][0])

    assert found(passing, {**EXCEPTION, "entry": OTHER}) == []


@pytest.mark.parametrize(
    "content",
    [
        dataclasses.replace(CASES["POL-006"][1], stored_sha256=SHA),
        dataclasses.replace(CASES["POL-006"][1], declared=None, stored_sha256=SHA),
        dataclasses.replace(CASES["POL-006"][1], declared=[ID], stored_sha256=SHA),  # type: ignore[arg-type]
        identified(CASES["POL-006"][1], external_id=["x"]),
    ],
    ids=["no external id", "no metadata", "metadata of another shape", "an id that is no text"],
)
def test_an_entry_without_a_readable_external_id_takes_no_exception(
    content: EntryContent,
) -> None:
    assert found(content, EXCEPTION) == [("POL-006", Severity.BLOCKING, COMMAND)]


def test_an_informative_finding_is_never_excepted() -> None:
    """Only a blocking finding is excepted: an exception left on a breach since made informative
    covers nothing, and says so."""
    heavy = identified(timed((0, True), (90, True), payload_type="Executable"))
    (information,) = [f for f in policy_findings(DATA, heavy) if f.code == "POL-009"]
    exception = {**EXCEPTION, "code": "POL-009", "field": information.field}

    result = [
        (f.code, f.severity, f.message)
        for f in policy_findings(data_with(exception), heavy)
        if f.code in {"POL-009", "POL-011"}
    ]

    assert result[0] == ("POL-009", Severity.INFO, information.message)
    assert [code for code, _, _ in result] == ["POL-009", "POL-011"]


def test_no_exception_leaves_the_findings_as_they_are() -> None:
    failing = identified(CASES["POL-006"][1])

    assert policy_findings(data_with(), failing) == policy_findings(DATA, failing)
