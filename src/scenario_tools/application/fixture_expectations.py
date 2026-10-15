"""What verifying each release fixture must give, as ``expected.json`` holds it: written by
``conformance build``, read back by ``conformance run``, and by any consumer of the fixtures."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

DESCRIPTION = (
    "Release fixtures: each directory is a release, its manifest.json beside its archives. "
    "Verified with the manifest's schema, and as an approved release when approved is true, each "
    "must give the findings listed, by code, path and field; for an archive refused as unsafe, "
    "cause is the IO code its message starts with. A fixture with no finding is accepted."
)
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


@dataclass(frozen=True)
class ExpectedFinding:
    """A finding verifying a fixture must give: its code, path and field, and for an archive
    refused as unsafe, the ``IO`` code its message starts with."""

    code: str
    path: str
    field: str = ""
    cause: str | None = None


@dataclass(frozen=True)
class Expectation:
    """A fixture, by its name, and the findings verifying it must give, none when it is
    accepted; ``approved`` verifies it as an approved release."""

    name: str
    description: str
    findings: tuple[ExpectedFinding, ...]
    approved: bool = False


def expectations_document(expectations: Sequence[Expectation]) -> dict[str, Any]:
    """``expectations`` as ``expected.json`` holds them."""
    return {
        "description": DESCRIPTION,
        "fixtures": [
            {
                "name": expected.name,
                "description": expected.description,
                "approved": expected.approved,
                "accepted": not expected.findings,
                "findings": [
                    {"code": f.code, "path": f.path, "field": f.field, "cause": f.cause}
                    for f in expected.findings
                ],
            }
            for expected in expectations
        ],
    }


def _malformed(why: str) -> ValueError:
    return ValueError(f"expected.json: {why}")


def _text(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise _malformed(f"{what} must be a text")
    return value


def _finding(value: object, fixture: str) -> ExpectedFinding:
    if not isinstance(value, Mapping):
        raise _malformed(f"a finding of {fixture} must be an object")
    code, path, field = (
        _text(value.get(key), f"the {key} of a finding of {fixture}")
        for key in ("code", "path", "field")
    )
    cause = value.get("cause")
    if cause is not None:
        cause = _text(cause, f"the cause of a finding of {fixture}")
    return ExpectedFinding(code, path, field, cause)


def _expectation(value: object, seen: set[str]) -> Expectation:
    if not isinstance(value, Mapping):
        raise _malformed("each fixture must be an object")
    name = _text(value.get("name"), "the name of a fixture")
    if not _NAME.fullmatch(name):
        raise _malformed(f"{name!r} is not a fixture name")
    if name in seen:
        raise _malformed(f"the fixture {name} is listed twice")
    seen.add(name)
    description = _text(value.get("description"), f"the description of {name}")
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise _malformed(f"the findings of {name} must be a list")
    expected = tuple(_finding(found, name) for found in findings)
    approved = value.get("approved")
    if not isinstance(approved, bool):
        raise _malformed(f"approved, for {name}, must be true or false")
    if value.get("accepted") is not (not expected):
        raise _malformed(f"{name} is accepted exactly when it lists no finding")
    return Expectation(name, description, expected, approved)


def expectations_from_document(document: object) -> tuple[Expectation, ...]:
    """The expectations ``expected.json`` holds; ``ValueError`` when it is out of shape."""
    fixtures = document.get("fixtures") if isinstance(document, Mapping) else None
    if not isinstance(fixtures, list):
        raise _malformed("its fixtures must be a list")
    seen: set[str] = set()
    return tuple(_expectation(fixture, seen) for fixture in fixtures)
