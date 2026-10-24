"""The external ID an entry is prepared under, and every way it is refused."""

from pathlib import Path

import pytest

from scenario_tools.application.entry_external_id import entry_external_id
from scenario_tools.ports.errors import UsageProblemError

METADATA = Path("scenarios/techniques/easm/scenario.yaml")
DECLARED = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
OTHER = "00000000-0000-4000-8000-000000000009"


def test_the_declared_id_is_taken() -> None:
    assert entry_external_id(METADATA, DECLARED, None) == DECLARED


def test_the_declared_id_given_again_is_taken() -> None:
    assert entry_external_id(METADATA, DECLARED, DECLARED) == DECLARED


def test_the_given_id_is_taken_for_a_first_preparation() -> None:
    assert entry_external_id(METADATA, None, OTHER) == OTHER


def test_a_given_id_that_contradicts_the_declared_one_is_refused() -> None:
    with pytest.raises(UsageProblemError) as refused:
        entry_external_id(METADATA, DECLARED, OTHER)
    assert str(refused.value) == f"--external-id contradicts {METADATA}: '{DECLARED}'"


@pytest.mark.parametrize("declared", [DECLARED.upper(), "not a uuid", 7, ["x"]])
def test_a_declared_id_that_is_no_canonical_uuid_is_refused(declared: object) -> None:
    with pytest.raises(UsageProblemError) as refused:
        entry_external_id(METADATA, declared, None)
    assert str(refused.value) == (
        f"the external_id of {METADATA} is not a UUID in lower case with hyphens: {declared!r}"
    )


@pytest.mark.parametrize("given", [None, DECLARED.upper(), f"{DECLARED}x", ""])
def test_a_first_preparation_without_a_canonical_uuid_is_refused(given: str | None) -> None:
    with pytest.raises(UsageProblemError) as refused:
        entry_external_id(METADATA, None, given)
    assert str(refused.value) == (
        "give --external-id, a UUID in lower case with hyphens, for a first preparation"
    )
