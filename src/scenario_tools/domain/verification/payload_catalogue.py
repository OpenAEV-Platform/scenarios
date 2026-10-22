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
from scenario_tools.domain.shared.payload_names import SEMVER
from scenario_tools.domain.verification.payload_hash import UnhashablePayloadError
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
ID_TWICE = "another version of the catalogue has this ID: an ID names one version"
HASH_TWICE = "another version of the catalogue has this content: a content is one version"


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


def _blocking(path: str, field: str, message: str) -> Finding:
    return Finding("PAY-009", Severity.BLOCKING, path, field, message)


def _entry_refusal(entry: TreeEntry) -> str | None:
    if entry.kind is EntryKind.SPECIAL:
        return ENTRY_SPECIAL
    if len(entry.path) == 1:
        if entry.kind is not EntryKind.FOLDER:
            return ENTRY_NOT_FOLDER
        name = entry.path[0]
        return None if _SLUG.fullmatch(name) and len(name) <= _SLUG_LIMIT else FOLDER_NOT_SLUG
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
    ordered_places = sorted(
        places, key=lambda p: (p.slug, tuple(int(part) for part in p.version.split(".")))
    )
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


def catalogue_findings(versions: Sequence[PayloadVersion]) -> tuple[Finding, ...]:
    """What keeps ``versions``, read in order of folder and version, from forming a catalogue:
    the base name each version shares with its payload's others, and the slug, base name, ID and
    hash no two payloads or versions share; reported where it is used again."""
    findings: list[Finding] = []
    bases: dict[str, str] = {}  # the base name of each payload, by slug
    owners: dict[str, str] = {}  # the payload of each base name, by its key
    ids: set[str] = set()
    hashes: set[str] = set()
    for version in ordered(versions):
        base = bases.setdefault(version.slug, version.base_name)
        if version.base_name != base:
            findings.append(_blocking(version.path, "/payload_name", BASE_NAME_DIFFERS))
        elif owners.setdefault(name_key(base), version.slug) != version.slug:
            findings.append(_blocking(version.path, "/payload_name", BASE_NAME_TAKEN))
        if version.identifier in ids:
            findings.append(_blocking(version.path, "/payload_external_id", ID_TWICE))
        ids.add(version.identifier)
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
    """The versions of the catalogue by ID, by hash, by slug (in version order) and the slug of
    each base name, by its key."""

    by_id: Mapping[str, PayloadVersion]
    by_hash: Mapping[str, PayloadVersion]
    by_slug: Mapping[str, tuple[PayloadVersion, ...]]
    by_base_name: Mapping[str, str]

    @classmethod
    def of(cls, versions: Sequence[PayloadVersion]) -> "Catalogue":
        """The index of ``versions``, which must keep the rules of the catalogue."""
        if catalogue_findings(versions):
            raise CatalogueCollisionError("the versions do not form a catalogue")
        by_slug: dict[str, list[PayloadVersion]] = {}
        by_hash: dict[str, PayloadVersion] = {}
        for version in ordered(versions):
            by_slug.setdefault(version.slug, []).append(version)
            digest = _digest(version)
            if digest is None:
                raise CatalogueCollisionError("a version cannot be hashed: it has no place by hash")
            by_hash[digest] = version
        return cls(
            by_id={version.identifier: version for version in versions},
            by_hash=by_hash,
            by_slug={slug: tuple(found) for slug, found in by_slug.items()},
            by_base_name={name_key(found[0].base_name): slug for slug, found in by_slug.items()},
        )
