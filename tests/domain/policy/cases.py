"""One passing and one failing entry for every policy rule, as every rule must have."""

from typing import Any

from scenario_tools.domain.policy.rule import EntryContent

ENTRY = "scenarios/techniques/easm"
OWN_FILES = frozenset({"scenario.yaml", "scenario.json"})
METADATA: dict[str, Any] = {
    "sources": [{"url": "https://attack.mitre.org/techniques/T1595/", "tlp": "TLP:CLEAR"}]
}
SCENARIO: dict[str, Any] = {"scenario_information": {"scenario_name": "EASM"}}


def content(
    *,
    files: frozenset[str] = OWN_FILES,
    declared: Any = METADATA,
    stored: object = SCENARIO,
) -> EntryContent:
    return EntryContent(ENTRY, files, declared, stored)


def with_source(url: str) -> EntryContent:
    return content(declared={"sources": [{"url": url, "tlp": "TLP:CLEAR"}]})


def with_recurrence(field: str, value: object) -> EntryContent:
    return content(stored={"scenario_information": {"scenario_name": "EASM", field: value}})


CASES: dict[str, tuple[EntryContent, EntryContent]] = {
    "POL-001": (content(), with_source("https://10.0.0.1/report.html")),
    "POL-002": (content(), with_recurrence("scenario_recurrence", "0 0 8 * * MON")),
}
