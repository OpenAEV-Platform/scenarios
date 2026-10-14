"""Diff an entry: what changed since its previous version, the entry as the base branch holds it,
each change where it is and the version it needs, as `validate` classifies it. Informative: the
version itself is `validate`'s to judge."""

from collections.abc import Mapping

from scenario_tools.application.previous_version import previous_version
from scenario_tools.domain.shared.finding import Finding, Severity, reportable
from scenario_tools.domain.verification.versioning import diff_findings
from scenario_tools.ports.errors import UnsafeInputError
from scenario_tools.ports.repository import EntrySource

_UNREAD = (
    "this entry cannot be compared: its scenario.yaml or its scenario.json is missing or is not "
    "an object; validate says why"
)


def diff_entry(entry: str, source: EntrySource, previous: EntrySource) -> tuple[Finding, ...]:
    """The diff of the entry at ``entry``, a directory relative to the repository, with its
    previous version, which ``previous`` reads; a file the readers refuse is a finding."""
    if not reportable(entry):  # none of its files could be named in a finding: none is read
        return ()
    metadata_path = f"{entry}/scenario.yaml"
    try:
        names = source.names(entry)
        metadata = source.read_yaml(metadata_path) if "scenario.yaml" in names else None
        stored = source.read_json(f"{entry}/scenario.json")[1] if "scenario.json" in names else None
    except UnsafeInputError as error:
        return (Finding(error.code, Severity.BLOCKING, error.path, "", error.message),)
    if not isinstance(metadata, Mapping) or not isinstance(stored, Mapping):
        return (Finding("VER-014", Severity.INFO, entry, "", _UNREAD),)
    try:
        before = previous_version(entry, metadata.get("external_id"), previous)
    except UnsafeInputError as error:
        message = f"the base branch's copy of this file cannot be read: {error.message}"
        return (Finding(error.code, Severity.BLOCKING, error.path, "", message),)
    return diff_findings(before, metadata, stored, entry=entry)
