"""What verifying each release fixture must give, as expected.json holds it."""

from typing import Any

import pytest

from scenario_tools.application.fixture_expectations import (
    Expectation,
    ExpectedFinding,
    expectations_document,
    expectations_from_document,
)

EXPECTATIONS = (
    Expectation("accepted", "Accepted.", (), approved=True),
    Expectation(
        "unsafe",
        "Unsafe.",
        (ExpectedFinding("VRF-007", "a.zip", "", "IO-010"), ExpectedFinding("VRF-006", "b")),
    ),
)


def test_the_expectations_read_back_are_those_written() -> None:
    document = expectations_document(EXPECTATIONS)

    assert expectations_from_document(document) == EXPECTATIONS
    assert [case["accepted"] for case in document["fixtures"]] == [True, False]


def _case(**fields: Any) -> dict[str, Any]:
    case: dict[str, Any] = {
        "name": "a",
        "description": "A.",
        "approved": False,
        "accepted": True,
        "findings": [],
    }
    return {"fixtures": [{**case, **fields}]}


FINDING = {"code": "VRF-006", "path": "a.zip", "field": "", "cause": None}


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ([], "its fixtures must be a list"),
        ({"fixtures": {}}, "its fixtures must be a list"),
        ({"fixtures": ["a"]}, "each fixture must be an object"),
        (_case(name="../a"), "'../a' is not a fixture name"),
        (_case(name="a\n"), "'a\\n' is not a fixture name"),
        (
            {"fixtures": [*_case()["fixtures"], *_case()["fixtures"]]},
            "the fixture a is listed twice",
        ),
        (_case(description=1), "the description of a must be a text"),
        (_case(findings={}), "the findings of a must be a list"),
        (_case(findings=["x"]), "a finding of a must be an object"),
        (_case(findings=[{**FINDING, "path": 1}]), "the path of a finding of a must be a text"),
        (_case(findings=[{**FINDING, "cause": 1}]), "the cause of a finding of a must be a text"),
        (_case(approved="yes"), "approved, for a, must be true or false"),
        (_case(accepted=False), "a is accepted exactly when it lists no finding"),
        (
            _case(findings=[FINDING], accepted=True),
            "a is accepted exactly when it lists no finding",
        ),
    ],
)
def test_expectations_out_of_shape_are_refused(document: object, why: str) -> None:
    with pytest.raises(ValueError, match=r"^expected\.json: ") as error:
        expectations_from_document(document)
    assert str(error.value) == f"expected.json: {why}"
