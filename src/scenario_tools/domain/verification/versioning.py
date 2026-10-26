"""Versioning. An entry's version is raised as its change needs, against its previous version,
the entry as the base branch holds it: a change of what the entry holds raises the version, so
that a merged version never changes content. The change is read field by field; a field no rule
names needs a major version. Inject identifiers stay from one version to the next, a new payload
is pointed out to the reviewer, and the changelog has one section per version, newest first."""

from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.catalogue.structure import CONTRACT, PAYLOAD, contracts_with_payloads
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.stored import INJECTS, STEP_DATA, STEPS, WORKFLOW
from scenario_tools.domain.verification.entry_changes import (
    BUMP_LEVELS,
    CONTRACT_ID,
    INJECT_ID,
    INJECT_TITLE,
    PAYLOAD_EXTERNAL_ID,
    STEP_ID,
    Bump,
    LocatedChange,
    by_identifier,
    changes,
    declared_bump,
    located_changes,
    parsed_version,
    required_bump,
)


def _least(previous: tuple[int, int, int], bump: Bump) -> str:
    major, minor, patch = previous
    if bump is Bump.MAJOR:
        return f"{major + 1}.0.0"
    if bump is Bump.MINOR:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def blocking(code: str, path: str, field: str, message: str) -> Finding:
    return Finding(code, Severity.BLOCKING, path, field, message)


def _payload_ids(stored: object) -> Iterator[tuple[str, str]]:
    for pointer, _, contract in contracts_with_payloads(stored):
        payload = contract[PAYLOAD]
        identifier = payload.get(PAYLOAD_EXTERNAL_ID) if isinstance(payload, Mapping) else None
        if isinstance(identifier, str):
            yield f"{pointer}/{CONTRACT}/{PAYLOAD}/{PAYLOAD_EXTERNAL_ID}", identifier


def _new_payloads(previous: object, stored: object, path: str) -> Iterator[Finding]:
    known = {identifier for _, identifier in _payload_ids(previous)}
    for field, identifier in _payload_ids(stored):
        if identifier in known:
            continue
        known.add(identifier)
        yield Finding(
            "POL-008",
            Severity.INFO,
            path,
            field,
            "a payload this scenario did not run before: review what it runs",
        )


def _contract_id(item: Mapping[str, Any]) -> object:
    contract = item.get(CONTRACT)
    return contract.get(CONTRACT_ID) if isinstance(contract, Mapping) else None


def _same_injects(previous: object, current: object, path: str) -> Iterator[Finding]:
    """An inject added that has the contract and the title of an inject removed: the same
    inject under a new identifier. Injects not shaped as a list by identifier are a change
    already, of a major version."""
    old, new = by_identifier(previous, INJECT_ID), by_identifier(current, INJECT_ID)
    if not old or not new:
        return
    # a list, not a set: a title or a contract ID of any shape is compared, never hashed
    removed = [
        (_contract_id(old[key]), old[key].get(INJECT_TITLE)) for key in old if key not in new
    ]
    for index, identifier in enumerate(
        new
    ):  # in the order of the list, as ``by_identifier`` keeps it
        item = new[identifier]
        if identifier not in old and (_contract_id(item), item.get(INJECT_TITLE)) in removed:
            yield blocking(
                "VER-003",
                path,
                f"/{INJECTS}/{index}/{INJECT_ID}",
                "this inject has the contract and the title of an inject of the previous "
                "version, under a new ID: its ID must stay; prepare the entry with `normalize "
                "--previous` or `intake`, or give a new inject another title",
            )


def _step_runs(step: Mapping[str, Any]) -> tuple[object, object]:
    """What a step runs, as a step re-added is recognised by: its contract and its title."""
    data = step.get(STEP_DATA)
    data = data if isinstance(data, Mapping) else {}
    return _contract_id(data), data.get(INJECT_TITLE)


def _same_steps(previous: object, current: object, path: str) -> Iterator[Finding]:
    """A step added that runs the contract and has the title of a step removed: the same step
    under a new identifier. A workflow or steps of another shape are a major change already."""
    if not isinstance(previous, Mapping) or not isinstance(current, Mapping):
        return
    old, new = (
        by_identifier(previous.get(STEPS), STEP_ID),
        by_identifier(current.get(STEPS), STEP_ID),
    )
    if not old or not new:
        return
    removed = [_step_runs(old[key]) for key in old if key not in new]
    for index, identifier in enumerate(new):
        if identifier not in old and _step_runs(new[identifier]) in removed:
            yield blocking(
                "VER-003",
                path,
                f"/{WORKFLOW}/{STEPS}/{index}/{STEP_ID}",
                "this step runs the contract and has the title of a step of the previous version, "
                "under a new ID: its ID must stay; prepare the entry with `normalize --previous` "
                "or `intake`, or give a new step another title",
            )


def versioning_findings(
    previous: tuple[object, object] | None,
    metadata: Mapping[str, Any],
    stored: Mapping[str, Any],
    *,
    metadata_path: str,
    scenario_path: str,
) -> tuple[Finding, ...]:
    """What keeps this version of an entry from following ``previous``, its metadata and its
    stored scenario as the base branch holds them, ``None`` for a new entry."""
    previous_stored = previous[1] if previous is not None else None
    news = tuple(_new_payloads(previous_stored, stored, scenario_path))
    if previous is None:
        return news
    old = previous[0] if isinstance(previous[0], Mapping) else {}
    findings: list[Finding] = []
    if old and old.get("external_id") != metadata.get("external_id"):
        findings.append(
            blocking(
                "VER-005",
                metadata_path,
                "/external_id",
                "the external ID of an entry never changes: a new scenario is a new entry",
            )
        )
    before = parsed_version(old.get("version"))
    if before is None or not isinstance(previous_stored, Mapping):
        findings.append(
            blocking(
                "VER-006",
                metadata_path,
                "",
                "the base branch's copy of this entry cannot be compared: its scenario.yaml or "
                "its scenario.json is missing, or it has no valid version; a maintainer fixes the "
                "base branch first",
            )
        )
        return (*findings, *news)
    declared = declared_bump(old["version"], metadata.get("version"))
    required = required_bump(changes(old, previous_stored, metadata, stored))
    if declared is None:
        findings.append(
            blocking(
                "VER-002",
                metadata_path,
                "/version",
                f"the version is lower than the previous one, {old['version']}: a "
                "version never decreases",
            )
        )
    elif declared < required.bump:
        findings.append(
            blocking(
                "VER-001",
                metadata_path,
                "/version",
                f"this change needs a {BUMP_LEVELS[required.bump]} version "
                f"({required.reason}): raise "
                f"the version to {_least(before, required.bump)} at least, and add its section "
                "on top of CHANGELOG.md",
            )
        )
    findings.extend(_same_injects(previous_stored.get(INJECTS), stored.get(INJECTS), scenario_path))
    findings.extend(_same_steps(previous_stored.get(WORKFLOW), stored.get(WORKFLOW), scenario_path))
    return (*findings, *news)


_UNCOMPARED = (
    "the base branch's copy of this entry cannot be compared: its scenario.yaml or its "
    "scenario.json is missing, or it has no valid version"
)

_LISTED = 30  # the changes an entry's diff lists: the least version always comes first


def _listed(located: LocatedChange, entry: str) -> Finding:
    level = BUMP_LEVELS[located.change.bump]
    named = f" (ID {located.item})" if located.item else ""
    message = f"{located.change.reason}: needs a {level} version{named}"
    return Finding("VER-013", Severity.INFO, f"{entry}/{located.file}", located.field, message)


def diff_findings(
    previous: tuple[object, object] | None,
    metadata: Mapping[str, Any],
    stored: Mapping[str, Any],
    *,
    entry: str,
) -> tuple[Finding, ...]:
    """The semantic diff of the entry at ``entry`` with ``previous``, its metadata and its stored
    scenario as the base branch holds them, ``None`` for a new entry, as information: first the
    least version the changes need, at the entry, so that a report cut at its limit keeps it, with
    how many changes are not listed; then each change, where it is, the version it needs and the
    inject or item it concerns, the ``_LISTED`` that need the most. Never a value."""

    def least(message: str) -> Finding:
        return Finding("VER-014", Severity.INFO, entry, "", message)

    if previous is None:
        return (least("a new entry: the base branch holds no previous version to compare with"),)
    old, old_stored = previous
    if not isinstance(old, Mapping) or not isinstance(old_stored, Mapping):
        return (least(_UNCOMPARED),)
    before = parsed_version(old.get("version"))
    if before is None:
        return (least(_UNCOMPARED),)
    found = located_changes(old, old_stored, metadata, stored)
    # The ones that need the most, in the order found among equals: a major one is never left out.
    ranked = sorted(found, key=lambda located: located.change.bump, reverse=True)
    listed = tuple(_listed(located, entry) for located in ranked[:_LISTED])
    required = required_bump([located.change for located in found])
    if required.bump is Bump.NONE:
        return (least("nothing changed that needs a new version"), *listed)
    given = metadata.get("version")
    declared = declared_bump(old["version"], given)
    verdict = "enough" if declared is not None and declared >= required.bump else "too low"
    summary = (
        f"these changes need {_least(before, required.bump)} at least, a "
        f"{BUMP_LEVELS[required.bump]} version ({required.reason}), from {old['version']}; "
        "the entry "
        f"gives {given if parsed_version(given) else 'no valid version'}: {verdict}"
    )
    if len(found) > _LISTED:
        summary += f"; {len(found) - _LISTED} more changes, not listed"
    return (least(summary), *listed)


def released_version_findings(
    entry: str, external_id: str, version: str, sha256: str, released: Mapping[tuple[str, str], str]
) -> tuple[Finding, ...]:
    """What the previous release says against this version of the scenario: ``VER-020`` when
    it holds the version with another archive than ``sha256``, as a released version never
    changes; ``VER-002`` when it holds a higher version, as a version never decreases.
    ``released`` gives each archive hash by external ID and version."""
    where = f"{entry}/scenario.yaml"
    before = released.get((external_id, version))
    if before is not None and before != sha256:
        message = (
            f"version {version} was released with another archive, and a released version "
            "never changes: raise the version"
        )
        return (Finding("VER-020", Severity.BLOCKING, where, "/version", message),)
    current = parsed_version(version)
    higher = [
        (found, text)
        for (other, text) in released
        if other == external_id and (found := parsed_version(text)) is not None
    ]
    if current is None or not higher:
        return ()
    top, text = max(higher)
    if current >= top:
        return ()
    message = f"version {version} is lower than {text}, already released: a version never decreases"
    return (Finding("VER-002", Severity.BLOCKING, where, "/version", message),)
