"""No recurrence: the importer reads the recurrence fields of a scenario and would schedule it on
the platform that imports it, which a shared scenario never does. A field holding any value but
``null`` is one, an empty text included, since the importer reads it."""

from collections.abc import Iterator, Mapping

from scenario_tools.domain.catalogue.structure import INFORMATION
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.shared.finding import Severity

RECURRENCE_FIELDS = ("scenario_recurrence", "scenario_recurrence_start", "scenario_recurrence_end")


def violations(document: object, path: str) -> Iterator[Violation]:
    """A violation for each recurrence field with a value in the stored scenario ``document``,
    found at ``path``; a document not shaped like a scenario is left to its own check."""
    information = document.get(INFORMATION) if isinstance(document, Mapping) else None
    if not isinstance(information, Mapping):
        return
    for field in RECURRENCE_FIELDS:
        if information.get(field) is not None:
            yield Violation(
                path,
                f"/{INFORMATION}/{field}",
                f"{field} is set: the importer would schedule the scenario, which the catalogue "
                "never does",
            )


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    return violations(content.stored, f"{content.directory}/scenario.json")


RULE = Rule(
    "POL-002",
    Severity.BLOCKING,
    "A stored scenario has no recurrence: no recurrence field holds a value.",
    _check,
)
