"""What changed in an entry since its previous version, field by field, and how far each change
raises the version: a field no rule names needs a major version. A version is three numbers, read
as numbers."""

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from scenario_tools.domain.catalogue.structure import CONTRACT, PAYLOAD
from scenario_tools.domain.shared.stored import INJECTS, STEP_DATA, STEPS, WORKFLOW


class Bump(IntEnum):
    """How far a version is raised, the least first."""

    NONE = 0
    PATCH = 1
    MINOR = 2
    MAJOR = 3


@dataclass(frozen=True)
class Change:
    """A change between two versions, with the bump it needs and why, in a few words."""

    bump: Bump
    reason: str


BUMP_LEVELS = {Bump.MAJOR: "major", Bump.MINOR: "minor", Bump.PATCH: "patch"}
VERSION_NUMBER = "(0|[1-9][0-9]{0,8})"  # nine digits at most: read as a number, never a long run
_VERSION = re.compile(rf"{VERSION_NUMBER}\.{VERSION_NUMBER}\.{VERSION_NUMBER}")

# scenario.yaml; the payloads follow those of scenario.json, the external ID never changes
_NOT_COMPARED = frozenset({"version", "payloads", "external_id"})
_METADATA_MAJOR = {
    "requires": "its requirements changed",
    "targets": "its targets changed",
    "type": "its type changed",
}
_METADATA_PATCH = frozenset(
    {
        "name",
        "description",
        "severity",
        "category",
        "main_focus",
        "platforms",
        "threat",
        "sources",
        "status",
        "generated_by",
        "relevance",
    }
)

# scenario.json
_INFORMATION, _USERS = "scenario_information", "scenario_users"
_INFORMATION_PATCH = frozenset(
    {
        "scenario_name",
        "scenario_description",
        "scenario_subtitle",
        "scenario_message_header",
        "scenario_message_footer",
        "scenario_category",
        "scenario_main_focus",
        "scenario_severity",
        "scenario_tags",
        "scenario_lessons_enabled",
        "scenario_lessons_anonymized",
    }
)
_CHAIN = Change(Bump.MAJOR, "an inject's place in the chain changed")
_TARGETS = Change(Bump.MAJOR, "an inject's targets changed")
_CONTENT = Change(Bump.MINOR, "an inject's content changed")
_TEXT = Change(Bump.PATCH, "an inject's text changed")
_INJECT_FIELDS = {
    "inject_depends_on": _CHAIN,
    "inject_depends_duration": _CHAIN,
    "inject_enabled": _CHAIN,
    "inject_teams": _TARGETS,
    "inject_all_teams": _TARGETS,
    "inject_documents": _CONTENT,
    "inject_title": _TEXT,
    "inject_description": _TEXT,
    "inject_tags": _TEXT,
    "inject_country": _TEXT,
    "inject_city": _TEXT,
}
_CONTENT_FIELD = "inject_content"
_CONTENT_TARGETS = ("target_selector", "target_property_selector", "targets")
_CONTRACT_CHANGED = Change(Bump.MAJOR, "an inject's contract changed")
_PAYLOAD_CHANGED = Change(Bump.MINOR, "an inject's payload changed")
CONTRACT_ID = "injector_contract_id"
_COLLECTIONS = {
    "scenario_teams": "team_id",
    "scenario_articles": "article_id",
    "scenario_channels": "channel_id",
    "scenario_challenges": "challenge_id",
    "scenario_documents": "document_id",
    "scenario_variables": "variable_id",
    "scenario_organizations": "organization_id",
    "scenario_tags": "tag_id",
}
_STEP_ADDED = Change(Bump.MAJOR, "a step added")
_STEP_REMOVED = Change(Bump.MAJOR, "a step removed")
_CONDITIONS_CHANGED = Change(Bump.MAJOR, "a step's conditions changed")
_STEP_INJECT_CHANGED = Change(Bump.MAJOR, "a step's inject changed")
_WORKFLOW_CONDITIONS_CHANGED = Change(Bump.MAJOR, "a workflow's conditions changed")
_SETTING_CHANGED = Change(Bump.MINOR, "a workflow setting changed")
STEP_ID = "step_id"
_STEP_CONDITIONS = frozenset({"step_conditions", "step_condition_executed"})
_WORKFLOW_CONDITIONS = "workflow_standalone_conditions"
_TEXT_ENDINGS = ("_name", "_description", "_tags")
INJECT_ID, INJECT_TITLE = "inject_id", "inject_title"
PAYLOAD_EXTERNAL_ID = "payload_external_id"


def parsed_version(text: object) -> tuple[int, int, int] | None:
    match = _VERSION.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        return None
    return int(match[1]), int(match[2]), int(match[3])


def declared_bump(previous: object, version: object) -> Bump | None:
    """How far ``version`` raises ``previous``; ``None`` when it is lower or not a version."""
    before, after = parsed_version(previous), parsed_version(version)
    if before is None or after is None or after < before:
        return None
    if after[0] != before[0]:
        return Bump.MAJOR
    if after[1] != before[1]:
        return Bump.MINOR
    if after[2] != before[2]:
        return Bump.PATCH
    return Bump.NONE


def required_bump(found: Sequence[Change]) -> Change:
    """The change that needs the highest bump, the first of them; none when nothing changed."""
    required = Change(Bump.NONE, "")
    for change in found:
        if change.bump > required.bump:
            required = change
    return required


_ABSENT = object()


def _at(mapping: Mapping[str, Any], key: str) -> object:
    """The value of ``key``, or a marker when the mapping does not hold it: a key added or
    removed is a change even when its value is null."""
    return mapping.get(key, _ABSENT)


def _same(first: object, second: object) -> bool:
    """Equal and of the same types at every depth: ``True == 1 == 1.0`` in Python, never for
    the platform that reads the scenario."""
    if type(first) is not type(second):
        return False
    match first, second:
        case Mapping(), Mapping():
            return first.keys() == second.keys() and all(_same(first[k], second[k]) for k in first)
        case list(), list():
            return len(first) == len(second) and all(map(_same, first, second))
    return first == second


_YAML, _JSON = "scenario.yaml", "scenario.json"


@dataclass(frozen=True)
class LocatedChange:
    """A change where it is: the file of the entry, the pointer of what changed in it as it is
    now, and the identifier of the inject or the item it concerns, if any: a reviewer finds an
    inject by it, and a removed one is no longer where a pointer could name it."""

    change: Change
    file: str
    field: str
    item: str = ""


def _segment(key: object) -> str:
    """A key as a segment of a JSON pointer (RFC 6901)."""
    return "/" + str(key).replace("~", "~0").replace("/", "~1")


def _metadata_changes(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> Iterator[LocatedChange]:
    for key in sorted(set(before) | set(after)):
        if key in _NOT_COMPARED or _same(_at(before, key), _at(after, key)):
            continue
        if key in _METADATA_MAJOR:
            change = Change(Bump.MAJOR, _METADATA_MAJOR[key])
        elif key in _METADATA_PATCH:
            change = Change(Bump.PATCH, f"its {key} changed")
        else:
            change = Change(Bump.MAJOR, f"its {key} changed")
        yield LocatedChange(change, _YAML, _segment(key))


def by_identifier(items: object, key: str) -> dict[str, Mapping[str, Any]] | None:
    """The items of a collection by their identifier, in the order of the list; ``None`` when
    it is not shaped as one. A collection absent or null holds no item."""
    if items is None or items is _ABSENT:
        return {}
    if not isinstance(items, list):
        return None
    found: dict[str, Mapping[str, Any]] = {}
    for item in items:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get(key), str)
            or item[key] in found
        ):
            return None  # an identifier held twice: one of its items would be compared, not both
        found[item[key]] = item
    return found


def _membership(
    what: str, pointer: str, old: Mapping[str, Any], new: Mapping[str, Any]
) -> Iterator[LocatedChange]:
    """The items removed, by their identifier, then the items added, where they now are."""
    for identifier in old:
        if identifier not in new:
            yield LocatedChange(Change(Bump.MAJOR, f"{what} removed"), _JSON, pointer, identifier)
    for index, identifier in enumerate(new):
        if identifier not in old:
            added = Change(Bump.MINOR, f"{what} added")
            yield LocatedChange(added, _JSON, f"{pointer}/{index}", identifier)


def _contract_changes(
    before: object, after: object, pointer: str, item: str
) -> Iterator[LocatedChange]:
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        yield LocatedChange(_CONTRACT_CHANGED, _JSON, pointer, item)
        return
    if not _same(_at(before, CONTRACT_ID), _at(after, CONTRACT_ID)):
        yield LocatedChange(_CONTRACT_CHANGED, _JSON, pointer + _segment(CONTRACT_ID), item)
    if not _same(_at(before, PAYLOAD), _at(after, PAYLOAD)):
        yield LocatedChange(_PAYLOAD_CHANGED, _JSON, pointer + _segment(PAYLOAD), item)
    rest = {key for key in set(before) | set(after) if key not in (CONTRACT_ID, PAYLOAD)}
    if any(not _same(_at(before, key), _at(after, key)) for key in rest):
        yield LocatedChange(_CONTRACT_CHANGED, _JSON, pointer, item)


def _without_targets(content: object) -> object:
    if not isinstance(content, Mapping):
        return content
    return {key: value for key, value in content.items() if key not in _CONTENT_TARGETS}


def _content_changes(
    before: object, after: object, pointer: str, item: str
) -> Iterator[LocatedChange]:
    """An inject's content: the targets it holds are its targets, the rest its content."""
    old = before if isinstance(before, Mapping) else {}
    new = after if isinstance(after, Mapping) else {}
    if any(not _same(_at(old, key), _at(new, key)) for key in _CONTENT_TARGETS):
        yield LocatedChange(_TARGETS, _JSON, pointer, item)
    if not _same(_without_targets(before), _without_targets(after)):
        yield LocatedChange(_CONTENT, _JSON, pointer, item)


def _inject_changes(
    before: Mapping[str, Any], after: Mapping[str, Any], pointer: str, item: str
) -> Iterator[LocatedChange]:
    for key in sorted(set(before) | set(after)):
        old, new = _at(before, key), _at(after, key)
        if _same(old, new):
            continue
        at = pointer + _segment(key)
        if key == CONTRACT:
            yield from _contract_changes(old, new, at, item)
        elif key == _CONTENT_FIELD:
            yield from _content_changes(old, new, at, item)
        else:
            change = _INJECT_FIELDS.get(key, Change(Bump.MAJOR, f"an inject's {key} changed"))
            yield LocatedChange(change, _JSON, at, item)


def _injects(before: object, after: object) -> Iterator[LocatedChange]:
    old, new = by_identifier(before, INJECT_ID), by_identifier(after, INJECT_ID)
    pointer = _segment(INJECTS)
    if old is None or new is None:
        yield LocatedChange(Change(Bump.MAJOR, f"its {INJECTS} changed"), _JSON, pointer)
        return
    yield from _membership("an inject", pointer, old, new)
    for index, identifier in enumerate(new):
        if identifier in old:
            at = f"{pointer}/{index}"
            yield from _inject_changes(old[identifier], new[identifier], at, identifier)


def _step_changes(
    before: Mapping[str, Any], after: Mapping[str, Any], pointer: str, step: str
) -> Iterator[LocatedChange]:
    """What changed in one step: what it waits for (major), its inject, classed field by field as
    an inject is, and the rest of the step (minor)."""
    for key in sorted(set(before) | set(after)):
        old, new = _at(before, key), _at(after, key)
        if _same(old, new):
            continue
        at = pointer + _segment(key)
        if key in _STEP_CONDITIONS:
            yield LocatedChange(_CONDITIONS_CHANGED, _JSON, at, step)
        elif key == STEP_DATA:
            if isinstance(old, Mapping) and isinstance(new, Mapping):
                yield from _inject_changes(old, new, at, step)
            else:  # an inject of another shape, as an inject is
                yield LocatedChange(_STEP_INJECT_CHANGED, _JSON, at, step)
        else:
            yield LocatedChange(Change(Bump.MINOR, f"a step's {key} changed"), _JSON, at, step)


def _steps(before: object, after: object, pointer: str) -> Iterator[LocatedChange]:
    old, new = by_identifier(before, STEP_ID), by_identifier(after, STEP_ID)
    if old is None or new is None or not isinstance(before, list) or not isinstance(after, list):
        yield LocatedChange(Change(Bump.MAJOR, f"its {STEPS} changed"), _JSON, pointer)
        return
    for identifier in old:
        if identifier not in new:
            yield LocatedChange(_STEP_REMOVED, _JSON, pointer, identifier)
    for index, identifier in enumerate(new):
        at = f"{pointer}/{index}"
        if identifier not in old:
            yield LocatedChange(_STEP_ADDED, _JSON, at, identifier)
        else:
            yield from _step_changes(old[identifier], new[identifier], at, identifier)


def _workflow(before: object, after: object) -> Iterator[LocatedChange]:
    """What changed in a workflow: its steps, then each setting (minor)."""
    pointer = _segment(WORKFLOW)
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        yield LocatedChange(Change(Bump.MAJOR, f"its {WORKFLOW} changed"), _JSON, pointer)
        return
    for key in sorted(set(before) | set(after)):
        old, new = _at(before, key), _at(after, key)
        if _same(old, new):
            continue
        if key == STEPS:
            yield from _steps(old, new, pointer + _segment(key))
        elif key == _WORKFLOW_CONDITIONS:
            yield LocatedChange(_WORKFLOW_CONDITIONS_CHANGED, _JSON, pointer + _segment(key))
        else:
            yield LocatedChange(_SETTING_CHANGED, _JSON, pointer + _segment(key))


def _information(before: object, after: object) -> Iterator[LocatedChange]:
    pointer = _segment(_INFORMATION)
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        yield LocatedChange(Change(Bump.MAJOR, f"its {_INFORMATION} changed"), _JSON, pointer)
        return
    for key in sorted(set(before) | set(after)):
        if not _same(_at(before, key), _at(after, key)):
            bump = Bump.PATCH if key in _INFORMATION_PATCH else Bump.MAJOR
            yield LocatedChange(Change(bump, f"its {key} changed"), _JSON, pointer + _segment(key))


def _collection(part: str, before: object, after: object) -> Iterator[LocatedChange]:
    old, new = by_identifier(before, _COLLECTIONS[part]), by_identifier(after, _COLLECTIONS[part])
    pointer = _segment(part)
    if old is None or new is None:
        yield LocatedChange(Change(Bump.MAJOR, f"its {part} changed"), _JSON, pointer)
        return
    yield from _membership(f"an item of {part}", pointer, old, new)
    for index, identifier in enumerate(new):
        if identifier not in old:
            continue
        first, second = old[identifier], new[identifier]
        differing = {
            key for key in set(first) | set(second) if not _same(_at(first, key), _at(second, key))
        }
        if not differing:
            continue
        if all(key.endswith(_TEXT_ENDINGS) for key in differing):
            change = Change(Bump.PATCH, f"an item of {part} changed its text")
        else:
            change = Change(Bump.MINOR, f"an item of {part} changed")
        yield LocatedChange(change, _JSON, f"{pointer}/{index}", identifier)


def _stored_changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> Iterator[LocatedChange]:
    for part in sorted(set(before) | set(after)):
        old, new = _at(before, part), _at(after, part)
        if part == _USERS or _same(old, new):
            continue
        if part == INJECTS:
            yield from _injects(old, new)
        elif part == _INFORMATION:
            yield from _information(old, new)
        elif part in _COLLECTIONS:
            yield from _collection(part, old, new)
        elif part == WORKFLOW:
            yield from _workflow(old, new)
        else:
            yield LocatedChange(Change(Bump.MAJOR, f"its {part} changed"), _JSON, _segment(part))


def located_changes(
    previous_metadata: Mapping[str, Any],
    previous_stored: Mapping[str, Any],
    metadata: Mapping[str, Any],
    stored: Mapping[str, Any],
) -> list[LocatedChange]:
    """Every change from the previous version to this one, where it is, in the order found:
    ``scenario.yaml`` then ``scenario.json``, each part in the order of its keys, and the
    injects and items in the order of their list."""
    return [
        *_metadata_changes(previous_metadata, metadata),
        *_stored_changes(previous_stored, stored),
    ]


def changes(
    previous_metadata: Mapping[str, Any],
    previous_stored: Mapping[str, Any],
    metadata: Mapping[str, Any],
    stored: Mapping[str, Any],
) -> list[Change]:
    """The changes from the previous version to this one, each kind once, in the order found."""
    found: list[Change] = []
    for located in located_changes(previous_metadata, previous_stored, metadata, stored):
        if located.change not in found:
            found.append(located.change)
    return found
