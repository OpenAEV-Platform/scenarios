"""The injects of a stored scenario, read through one walk.

Every check that reads injects reads them here, each with the JSON pointer it is reported at and
the part it comes from, so that a part that holds injects is never missed by one check and read
by another. The walk is lenient: a part of another shape, or an item that is not an object, yields
nothing, and a check that must refuse such a shape refuses it itself.
"""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

INJECTS = "scenario_injects"


class Origin(Enum):
    """The part an inject comes from."""

    INJECT = "inject"


@dataclass(frozen=True, slots=True)
class StoredInject:
    """An inject of a stored scenario, with the JSON pointer it is reported at."""

    pointer: str
    inject: Mapping[str, Any]
    origin: Origin


def inject_pointer(index: int) -> str:
    """The JSON pointer of the inject at ``index`` of the injects part."""
    return f"/{INJECTS}/{index}"


def injects(stored: object) -> Iterator[StoredInject]:
    """Every inject of ``stored`` that is an object, in order."""
    part = stored.get(INJECTS) if isinstance(stored, Mapping) else None
    if not isinstance(part, list):
        return
    for index, inject in enumerate(part):
        if isinstance(inject, Mapping):
            yield StoredInject(inject_pointer(index), inject, Origin.INJECT)
