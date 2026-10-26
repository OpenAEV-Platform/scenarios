"""What normalisation says, word for word, when an export or the previous version it is given is
not a document it can read: each refusal says what it expected."""

import copy
from typing import Any

import pytest

from scenario_tools.domain.catalogue.export_reading import ExportStructureError
from scenario_tools.domain.catalogue.normalisation import normalise
from tests.domain.catalogue.test_normalisation import EXPORT, EXTERNAL_ID, RULES


def _refused(export: object, previous: object = None) -> ExportStructureError:
    with pytest.raises(ExportStructureError) as error:
        normalise(export, EXTERNAL_ID, RULES, previous=previous)
    return error.value


def _with(key: str, value: object) -> dict[str, Any]:
    export = copy.deepcopy(EXPORT)
    export[key] = value
    return export


@pytest.mark.parametrize(
    ("export", "what"),
    [
        ([], "not a JSON object"),
        (_with("scenario_information", []), "scenario_information must be an object"),
        (_with("scenario_objectives", [{"a": 1}]), "objectives are not supported yet"),
        (_with("scenario_lessons_questions", [{"a": 1}]), "lessons are not supported yet"),
    ],
    ids=["not an object", "information", "objectives", "lessons"],
)
def test_an_export_normalisation_cannot_read_is_refused_saying_why(
    export: object, what: str
) -> None:
    error = _refused(export)

    assert (error.code, error.origin, error.what) == ("IO-014", "export", what)


def test_a_previous_version_that_is_no_object_is_refused_as_the_previous_version() -> None:
    error = _refused(copy.deepcopy(EXPORT), previous=[])

    assert (error.code, error.origin, error.what) == (
        "IO-014",
        "previous",
        "the previous version must be a JSON object",
    )
