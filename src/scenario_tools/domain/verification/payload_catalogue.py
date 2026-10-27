"""The payload catalogue, ``payloads/``, as a tree of files and as an index of its versions.

The tree holds one folder per payload, named by its slug, and in each folder one file per version,
named by its semantic version; nothing else, and no link. Every version of a payload has one base
name, and no two payloads share a slug or a base name, compared as scenario names are; no two
versions share an ID or a hash. The index is built only from versions that keep these rules, so
that a lookup by ID, by hash, by slug or by base name never has to choose. Every finding is
``PAY-009``, with a fixed message, never a value of the files."""

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, auto

from scenario_tools.domain.catalogue.intake import name_key
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.payload_names import SEMVER, version_key
from scenario_tools.domain.verification.payload_hash import UnhashablePayloadError
from scenario_tools.domain.verification.payload_references import HeldVersions, PayloadReference
from scenario_tools.domain.verification.payload_version import (
    VERSION_FILE_LIMIT,
    PayloadVersion,
    ordered,
)

_SLUG = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_SLUG_LIMIT = 64
_VERSION_FILE = re.compile(rf"({SEMVER})\.json")

ENTRY_NOT_FOLDER = "the catalogue holds payload folders only"
FOLDER_NOT_SLUG = (
    "a payload folder is named by its slug: lower-case letters and digits in runs joined by "
    "single hyphens, at most 64 characters"
)
ENTRY_NOT_VERSION_FILE = "a payload folder holds version files only, each named <version>.json"
ENTRY_SPECIAL = "the catalogue holds no link and no special file"
OVER_SIZE = f"a version file is at most {VERSION_FILE_LIMIT} bytes"
FOLDER_WITHOUT_VERSION = "a payload folder holds at least one version"
OUT_OF_SCHEMA = "this value is out of schemas/payload.schema.json"
BASE_NAME_DIFFERS = "every version of a payload has the base name of its other versions"
BASE_NAME_TAKEN = "another payload of the catalogue has this base name: give each payload its own"
ID_TWICE = "another payload of the catalogue has this ID: an ID names one payload"
ID_NOT_THE_PAYLOAD_S = (
    "a version after the first carries its payload's ID, the ID of its first version"
)
HASH_TWICE = "another version of the catalogue has this content: a content is one version"
VERSION_CHANGED = (
    "a version file the base branch holds never changes: put it back, and add the change as a "
    "new version"
)
VERSION_REMOVED = "a version file the base branch holds is never removed: put it back"
VERSION_NOT_HIGHER = (
    "a new version is higher than every version the base branch holds for this payload"
)


class EntryKind(Enum):
    FOLDER = auto()
    FILE = auto()
    SPECIAL = auto()  # a link, never followed, or anything but a regular file or a folder


@dataclass(frozen=True)
class TreeEntry:
    """An entry under ``payloads/``: its path as parts, its kind and, for a file, its size."""

    path: tuple[str, ...]
    kind: EntryKind
    size: int


@dataclass(frozen=True)
class VersionPlace:
    """Where the file of a version is: its folder's slug, its version and its path."""

    slug: str
    version: str
    path: str


def is_slug(name: str) -> bool:
    """Whether ``name`` can name a payload folder: kebab-case, at most 64 characters."""
    return _SLUG.fullmatch(name) is not None and len(name) <= _SLUG_LIMIT


def _blocking(path: str, field: str, message: str) -> Finding:
    return Finding("PAY-009", Severity.BLOCKING, path, field, message)


def _entry_refusal(entry: TreeEntry) -> str | None:
    if entry.kind is EntryKind.SPECIAL:
        return ENTRY_SPECIAL
    if len(entry.path) == 1:
        if entry.kind is not EntryKind.FOLDER:
            return ENTRY_NOT_FOLDER
        name = entry.path[0]
        return None if is_slug(name) else FOLDER_NOT_SLUG
    if len(entry.path) > 2:
        return ENTRY_NOT_VERSION_FILE
    if entry.kind is not EntryKind.FILE or not _VERSION_FILE.fullmatch(entry.path[1]):
        return ENTRY_NOT_VERSION_FILE
    return OVER_SIZE if entry.size > VERSION_FILE_LIMIT else None


def layout(
    root: str, entries: Iterable[TreeEntry]
) -> tuple[tuple[Finding, ...], tuple[VersionPlace, ...]]:
    """The findings on the layout of the catalogue at ``root``, given its ``entries``, and where
    the version files to read are. An entry inside a refused folder is not reported again."""
    findings: list[Finding] = []
    places: list[VersionPlace] = []
    refused: set[str] = set()  # the folders refused
    folders: list[str] = []
    for entry in sorted(entries, key=lambda found: found.path):
        if entry.path[0] in refused:
            continue
        message = _entry_refusal(entry)
        if message is not None:
            if len(entry.path) == 1:
                refused.add(entry.path[0])
            findings.append(_blocking("/".join((root, *entry.path)), "", message))
        elif len(entry.path) == 1:
            folders.append(entry.path[0])
        else:
            where = "/".join((root, *entry.path))
            places.append(VersionPlace(entry.path[0], entry.path[1].removesuffix(".json"), where))
    held = {place.slug for place in places}
    findings += [
        _blocking(f"{root}/{folder}", "", FOLDER_WITHOUT_VERSION)
        for folder in folders
        if folder not in held
    ]
    ordered_places = sorted(places, key=lambda p: (p.slug, version_key(p.version)))
    return tuple(findings), tuple(ordered_places)


def schema_findings(path: str, pointers: Iterable[str]) -> tuple[Finding, ...]:
    """One finding per violation of the payload schema, at its pointer; the validator's message
    may quote a value, so the finding's is fixed."""
    return tuple(_blocking(path, pointer, OUT_OF_SCHEMA) for pointer in pointers)


def _digest(version: PayloadVersion) -> str | None:
    try:
        return version.digest()
    except UnhashablePayloadError:
        return None  # its own finding says so


def catalogue_findings(
    versions: Sequence[PayloadVersion], own: frozenset[tuple[str, str, str]] = frozenset()
) -> tuple[Finding, ...]:
    """What keeps ``versions``, read in order of folder and version, from forming a catalogue:
    the base name and the ID each version shares with its payload's first, unless ``own`` lists
    it as keeping the ID its content has, and the base name, ID and hash no two payloads or
    versions share; reported where it is used again."""
    findings = list(_collisions(versions))
    firsts: dict[str, PayloadVersion] = {}  # the first version of each payload, by slug
    for version in ordered(versions):
        first = firsts.setdefault(version.slug, version)
        if (
            version is not first
            and (version.slug, version.version, _digest(version)) not in own
            and version.identifier != first.identifier
        ):
            findings.append(
                Finding(
                    "PAY-003",
                    Severity.BLOCKING,
                    version.path,
                    "/payload_external_id",
                    ID_NOT_THE_PAYLOAD_S,
                )
            )
    return tuple(findings)


def _collisions(versions: Sequence[PayloadVersion]) -> tuple[Finding, ...]:
    """The base name each version shares with its payload's others, and the base name, ID and
    hash no two payloads or versions share: what an index of the versions needs."""
    findings: list[Finding] = []
    bases: dict[str, str] = {}  # the base name of each payload, by slug
    owners: dict[str, str] = {}  # the payload of each base name, by its key
    id_owners: dict[str, str] = {}  # the payload of each ID
    hashes: set[str] = set()
    for version in ordered(versions):
        base = bases.setdefault(version.slug, version.base_name)
        if version.base_name != base:
            findings.append(_blocking(version.path, "/payload_name", BASE_NAME_DIFFERS))
        elif owners.setdefault(name_key(base), version.slug) != version.slug:
            findings.append(_blocking(version.path, "/payload_name", BASE_NAME_TAKEN))
        if id_owners.setdefault(version.identifier, version.slug) != version.slug:
            findings.append(_blocking(version.path, "/payload_external_id", ID_TWICE))
        digest = _digest(version)
        if digest is not None and digest in hashes:
            findings.append(_blocking(version.path, "", HASH_TWICE))
        if digest is not None:
            hashes.add(digest)
    return tuple(findings)


class CatalogueCollisionError(ValueError):
    """The versions given share a base name, an ID or a hash, or one cannot be hashed: no index
    is built on them."""


@dataclass(frozen=True)
class Catalogue:
    """The versions of the catalogue by ID and version, every version under each ID and of each
    slug (in version order), by hash, and the slug of each base name, by its key."""

    by_key: Mapping[tuple[str, str], PayloadVersion]
    by_id: Mapping[str, tuple[PayloadVersion, ...]]
    by_hash: Mapping[str, PayloadVersion]
    by_slug: Mapping[str, tuple[PayloadVersion, ...]]
    by_base_name: Mapping[str, str]

    @classmethod
    def of(cls, versions: Sequence[PayloadVersion]) -> "Catalogue":
        """The index of ``versions``, which must keep the rules of the catalogue."""
        if _collisions(versions):
            raise CatalogueCollisionError("the versions do not form a catalogue")
        by_slug: dict[str, list[PayloadVersion]] = {}
        by_id: dict[str, list[PayloadVersion]] = {}
        by_hash: dict[str, PayloadVersion] = {}
        for version in ordered(versions):
            by_slug.setdefault(version.slug, []).append(version)
            by_id.setdefault(version.identifier, []).append(version)
            digest = _digest(version)
            if digest is None:
                raise CatalogueCollisionError("a version cannot be hashed: it has no place by hash")
            by_hash[digest] = version
        return cls(
            by_key={(version.identifier, version.version): version for version in versions},
            by_id={identifier: tuple(found) for identifier, found in by_id.items()},
            by_hash=by_hash,
            by_slug={slug: tuple(found) for slug, found in by_slug.items()},
            by_base_name={name_key(found[0].base_name): slug for slug, found in by_slug.items()},
        )

    def held(self) -> HeldVersions:
        """The versions of the catalogue as the references that name them."""
        return HeldVersions.of(
            [
                PayloadReference(version.identifier, version.version, digest)
                for digest, version in self.by_hash.items()
            ]
        )


def immutability_findings(
    base: Mapping[tuple[str, str], bytes], current: Mapping[tuple[str, str], bytes], root: str
) -> tuple[Finding, ...]:
    """What the catalogue ``current`` does to the ``base`` branch's, each by slug and version
    with its file's bytes, at ``root``: ``VER-022`` for each version the base holds that is
    edited or removed, its folder with it or not; ``VER-023`` for each new version that is not
    higher than every version the base holds for its payload. Several new versions are allowed
    when each is."""
    findings = []
    for slug, version in sorted(base, key=lambda key: (key[0], version_key(key[1]))):
        path = f"{root}/{slug}/{version}.json"
        if (slug, version) not in current:
            findings.append(Finding("VER-022", Severity.BLOCKING, path, "", VERSION_REMOVED))
        elif current[(slug, version)] != base[(slug, version)]:
            findings.append(Finding("VER-022", Severity.BLOCKING, path, "", VERSION_CHANGED))
    highest: dict[str, tuple[int, ...]] = {}
    for slug, version in base:
        highest[slug] = max(highest.get(slug, ()), version_key(version))
    added = sorted(current.keys() - base.keys(), key=lambda key: (key[0], version_key(key[1])))
    for slug, version in added:
        if slug in highest and version_key(version) <= highest[slug]:
            path = f"{root}/{slug}/{version}.json"
            findings.append(Finding("VER-023", Severity.BLOCKING, path, "", VERSION_NOT_HIGHER))
    return tuple(findings)
