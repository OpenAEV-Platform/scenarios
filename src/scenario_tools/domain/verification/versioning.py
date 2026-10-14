"""Versioning. An entry's version is raised as its change needs, against its previous version,
the entry as the base branch holds it: a change of what the entry holds raises the version, so
that a merged version never changes content. The change is read field by field; a field no rule
names needs a major version. Inject identifiers stay from one version to the next, a new payload
is pointed out to the reviewer, and the changelog has one section per version, newest first."""

import datetime
import itertools
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from scenario_tools.domain.catalogue.structure import (
    CONTRACT,
    INJECTS,
    PAYLOAD,
    contracts_with_payloads,
)
from scenario_tools.domain.shared.finding import Finding, Severity


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


_LEVELS = {Bump.MAJOR: "major", Bump.MINOR: "minor", Bump.PATCH: "patch"}
_NUMBER = "(0|[1-9][0-9]{0,8})"  # nine digits at most: read as a number, never a long run
_VERSION = re.compile(rf"{_NUMBER}\.{_NUMBER}\.{_NUMBER}")

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
_CONTRACT_ID = "injector_contract_id"
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
_TEXT_ENDINGS = ("_name", "_description", "_tags")
_INJECT_ID, _TITLE = "inject_id", "inject_title"
_EXTERNAL_ID = "payload_external_id"


def _version(text: object) -> tuple[int, int, int] | None:
    match = _VERSION.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        return None
    return int(match[1]), int(match[2]), int(match[3])


def declared_bump(previous: object, version: object) -> Bump | None:
    """How far ``version`` raises ``previous``; ``None`` when it is lower or not a version."""
    before, after = _version(previous), _version(version)
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


def _metadata_changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> Iterator[Change]:
    for key in sorted(set(before) | set(after)):
        if key in _NOT_COMPARED or _same(before.get(key), after.get(key)):
            continue
        if key in _METADATA_MAJOR:
            yield Change(Bump.MAJOR, _METADATA_MAJOR[key])
        elif key in _METADATA_PATCH:
            yield Change(Bump.PATCH, f"its {key} changed")
        else:
            yield Change(Bump.MAJOR, f"its {key} changed")


def _by_id(items: object, key: str) -> dict[str, Mapping[str, Any]] | None:
    """The items of a collection by their identifier; ``None`` when it is not shaped as one."""
    if items is None:
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


def _membership(what: str, old: Mapping[str, Any], new: Mapping[str, Any]) -> Iterator[Change]:
    if set(old) - set(new):
        yield Change(Bump.MAJOR, f"{what} removed")
    if set(new) - set(old):
        yield Change(Bump.MINOR, f"{what} added")


def _contract_changes(before: object, after: object) -> Iterator[Change]:
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        yield _CONTRACT_CHANGED
        return
    if not _same(before.get(_CONTRACT_ID), after.get(_CONTRACT_ID)):
        yield _CONTRACT_CHANGED
    if not _same(before.get(PAYLOAD), after.get(PAYLOAD)):
        yield _PAYLOAD_CHANGED
    rest = {key for key in set(before) | set(after) if key not in (_CONTRACT_ID, PAYLOAD)}
    if any(not _same(before.get(key), after.get(key)) for key in rest):
        yield _CONTRACT_CHANGED


def _without_targets(content: object) -> object:
    if not isinstance(content, Mapping):
        return content
    return {key: value for key, value in content.items() if key not in _CONTENT_TARGETS}


def _content_changes(before: object, after: object) -> Iterator[Change]:
    """An inject's content: the targets it holds are its targets, the rest its content."""
    old = before if isinstance(before, Mapping) else {}
    new = after if isinstance(after, Mapping) else {}
    if any(not _same(old.get(key), new.get(key)) for key in _CONTENT_TARGETS):
        yield _TARGETS
    if not _same(_without_targets(before), _without_targets(after)):
        yield _CONTENT


def _inject_changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> Iterator[Change]:
    for key in sorted(set(before) | set(after)):
        if _same(before.get(key), after.get(key)):
            continue
        if key == CONTRACT:
            yield from _contract_changes(before.get(key), after.get(key))
        elif key == _CONTENT_FIELD:
            yield from _content_changes(before.get(key), after.get(key))
        else:
            yield _INJECT_FIELDS.get(key, Change(Bump.MAJOR, f"an inject's {key} changed"))


def _injects(before: object, after: object) -> Iterator[Change]:
    old, new = _by_id(before, _INJECT_ID), _by_id(after, _INJECT_ID)
    if old is None or new is None:
        yield Change(Bump.MAJOR, f"its {INJECTS} changed")
        return
    yield from _membership("an inject", old, new)
    for identifier in sorted(set(old) & set(new)):
        yield from _inject_changes(old[identifier], new[identifier])


def _information(before: object, after: object) -> Iterator[Change]:
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        yield Change(Bump.MAJOR, f"its {_INFORMATION} changed")
        return
    for key in sorted(set(before) | set(after)):
        if not _same(before.get(key), after.get(key)):
            bump = Bump.PATCH if key in _INFORMATION_PATCH else Bump.MAJOR
            yield Change(bump, f"its {key} changed")


def _collection(part: str, before: object, after: object) -> Iterator[Change]:
    old, new = _by_id(before, _COLLECTIONS[part]), _by_id(after, _COLLECTIONS[part])
    if old is None or new is None:
        yield Change(Bump.MAJOR, f"its {part} changed")
        return
    yield from _membership(f"an item of {part}", old, new)
    for identifier in sorted(set(old) & set(new)):
        first, second = old[identifier], new[identifier]
        differing = {
            key for key in set(first) | set(second) if not _same(first.get(key), second.get(key))
        }
        if not differing:
            continue
        if all(key.endswith(_TEXT_ENDINGS) for key in differing):
            yield Change(Bump.PATCH, f"an item of {part} changed its text")
        else:
            yield Change(Bump.MINOR, f"an item of {part} changed")


def _stored_changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> Iterator[Change]:
    for part in sorted(set(before) | set(after)):
        old, new = before.get(part), after.get(part)
        if part == _USERS or _same(old, new):
            continue
        if part == INJECTS:
            yield from _injects(old, new)
        elif part == _INFORMATION:
            yield from _information(old, new)
        elif part in _COLLECTIONS:
            yield from _collection(part, old, new)
        else:
            yield Change(Bump.MAJOR, f"its {part} changed")


def changes(
    previous_metadata: Mapping[str, Any],
    previous_stored: Mapping[str, Any],
    metadata: Mapping[str, Any],
    stored: Mapping[str, Any],
) -> list[Change]:
    """The changes from the previous version to this one, each kind once, in the order found."""
    found: list[Change] = []
    for change in (
        *_metadata_changes(previous_metadata, metadata),
        *_stored_changes(previous_stored, stored),
    ):
        if change not in found:
            found.append(change)
    return found


def _least(previous: tuple[int, int, int], bump: Bump) -> str:
    major, minor, patch = previous
    if bump is Bump.MAJOR:
        return f"{major + 1}.0.0"
    if bump is Bump.MINOR:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _blocking(code: str, path: str, field: str, message: str) -> Finding:
    return Finding(code, Severity.BLOCKING, path, field, message)


def _payload_ids(stored: object) -> Iterator[tuple[str, str]]:
    for pointer, _, contract in contracts_with_payloads(stored):
        payload = contract[PAYLOAD]
        identifier = payload.get(_EXTERNAL_ID) if isinstance(payload, Mapping) else None
        if isinstance(identifier, str):
            yield f"{pointer}/{CONTRACT}/{PAYLOAD}/{_EXTERNAL_ID}", identifier


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
    return contract.get(_CONTRACT_ID) if isinstance(contract, Mapping) else None


def _same_injects(previous: object, current: object, path: str) -> Iterator[Finding]:
    """An inject added that has the contract and the title of an inject removed: the same
    inject under a new identifier. Injects not shaped as a list by identifier are a change
    already, of a major version."""
    old, new = _by_id(previous, _INJECT_ID), _by_id(current, _INJECT_ID)
    if not old or not new:
        return
    # a list, not a set: a title or a contract ID of any shape is compared, never hashed
    removed = [(_contract_id(old[key]), old[key].get(_TITLE)) for key in old if key not in new]
    for index, identifier in enumerate(new):  # in the order of the list, as ``_by_id`` keeps it
        item = new[identifier]
        if identifier not in old and (_contract_id(item), item.get(_TITLE)) in removed:
            yield _blocking(
                "VER-003",
                path,
                f"/{INJECTS}/{index}/{_INJECT_ID}",
                "this inject has the contract and the title of an inject of the previous "
                "version, under a new ID: its ID must stay; prepare the entry with `normalize "
                "--previous` or `intake`, or give a new inject another title",
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
            _blocking(
                "VER-005",
                metadata_path,
                "/external_id",
                "the external ID of an entry never changes: a new scenario is a new entry",
            )
        )
    before = _version(old.get("version"))
    if before is None or not isinstance(previous_stored, Mapping):
        findings.append(
            _blocking(
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
            _blocking(
                "VER-002",
                metadata_path,
                "/version",
                f"the version is lower than the previous one, {old['version']}: a "
                "version never decreases",
            )
        )
    elif declared < required.bump:
        findings.append(
            _blocking(
                "VER-001",
                metadata_path,
                "/version",
                f"this change needs a {_LEVELS[required.bump]} version ({required.reason}): raise "
                f"the version to {_least(before, required.bump)} at least, and add its section "
                "on top of CHANGELOG.md",
            )
        )
    findings.extend(_same_injects(previous_stored.get(INJECTS), stored.get(INJECTS), scenario_path))
    return (*findings, *news)


_HEADING = re.compile(  # a hyphen, an en dash or an em dash: they look alike
    rf"## {_NUMBER}\.{_NUMBER}\.{_NUMBER} [-\u2013\u2014] ([0-9]{{4}})-([0-9]{{2}})-([0-9]{{2}})"
)
_LINES = re.compile(r"\r\n|\r|\n")  # Markdown's line endings, never the other breaks of Unicode
_FENCES = ("```", "~~~")


def _section(line: str) -> tuple[tuple[int, int, int], datetime.date] | None:
    match = _HEADING.fullmatch(line.rstrip(" \t"))
    if match is None:
        return None
    try:
        day = datetime.date(int(match[4]), int(match[5]), int(match[6]))
    except ValueError:
        return None
    return (int(match[1]), int(match[2]), int(match[3])), day


def _headings(text: str) -> Iterator[tuple[int, str]]:
    """The level-2 headings of a Markdown text, by line number, none in a fenced block. Read as
    a changelog writes them: an indented heading, a setext one or a fence closed by another
    kind of fence is read otherwise than Markdown renders it, and leaves a section unchecked."""
    fenced = False
    for number, line in enumerate(_LINES.split(text), 1):
        if line.startswith(_FENCES):
            fenced ^= True
        elif not fenced and line.startswith("## "):
            yield number, line


def changelog_findings(text: str | None, version: str, path: str) -> tuple[Finding, ...]:
    """What keeps ``CHANGELOG.md``, at ``path``, from holding one ``## <version> — <date>``
    section per version, newest first, the first being ``version``."""
    if text is None:
        return (
            _blocking(
                "VER-004",
                path,
                "",
                "CHANGELOG.md is missing: add a `## <version> — <YYYY-MM-DD>` section for each "
                "version, newest first",
            ),
        )
    sections: list[tuple[int, tuple[int, int, int], datetime.date]] = []
    for number, line in _headings(text):
        section = _section(line)
        if section is None:
            return (
                _blocking(
                    "VER-004",
                    path,
                    "",
                    f"line {number}: a level-2 heading opens a version's section, `## <version> — "
                    "<YYYY-MM-DD>` with a valid date; other headings take `###`",
                ),
            )
        sections.append((number, *section))
    if not sections:
        return (
            _blocking(
                "VER-004",
                path,
                "",
                f"CHANGELOG.md has no section: add `## {version} — <YYYY-MM-DD>` for this version",
            ),
        )
    if sections[0][1] != _version(version):
        return (
            _blocking(
                "VER-004",
                path,
                "",
                f"the first section must be this version, {version}, newest first",
            ),
        )
    for (_, above, above_day), (number, below, below_day) in itertools.pairwise(sections):
        if below >= above:
            return (
                _blocking(
                    "VER-004",
                    path,
                    "",
                    f"line {number}: each section's version is lower than the one above",
                ),
            )
        if below_day > above_day:
            return (
                _blocking(
                    "VER-004",
                    path,
                    "",
                    f"line {number}: each section's date is no later than the one above",
                ),
            )
    return ()
