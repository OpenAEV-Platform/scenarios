"""The payload references of an entry. A payload has one ID, the same for all its versions, and
the platform tells its versions apart by the ID and the version. So each payload a scenario
embeds carries the ID its content has: the ID of the payload whose version file of ``payloads/``
holds that content, or, for a content no file holds, the one derived from its hash, a UUID v5,
unless the reviewed registry ``policy/data/payload-ids.yaml`` agrees another ID for that very
hash. The ID cannot be taken from another payload, nor kept by a content of no version of its
own. One reference of ``scenario.yaml`` gives the ID with the hash and the version of the file
that holds that content, which the references are checked against, and a scenario embeds one
version of a payload."""

import copy
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.identifiers import NS_OPENAEV_SCENARIOS, stable_id
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.verification.payload_hash import (
    EmbeddedPayload,
    FileHash,
    UnhashablePayloadError,
    embedded_payloads,
    payload_hash,
)

_EXTERNAL_ID = "payload_external_id"
_RUN = "run `scenario-tools payloads --assign`"
_ID = re.compile(r"[a-z0-9][a-z0-9:._-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ENTRY_KEYS = frozenset({"id", "name", "sha256"})
TWO_VERSIONS = (
    "another payload of the scenario is another version of this payload: a scenario embeds one "
    "version of a payload"
)


def derived_id(digest: str) -> str:
    """The ID of a payload's content: a UUID v5 of its hash, the same in every scenario."""
    return stable_id(NS_OPENAEV_SCENARIOS, "payload-content", digest)


@dataclass(frozen=True)
class AgreedId:
    """An ID the registry agrees for one content, with the name of the payload it names."""

    id: str
    name: str


@dataclass(frozen=True)
class AgreedIds:
    """The IDs the reviewed registry agrees, each for one content, by its hash, and the versions
    published before a payload kept one ID for all its versions, which keep the ID their content
    has. An agreed ID is never a UUID v5, so that it can never be the ID derived from another
    content."""

    by_hash: Mapping[str, AgreedId]
    own: frozenset[tuple[str, str, str]] = frozenset()

    @classmethod
    def from_document(cls, document: object) -> "AgreedIds":
        """Read the payload-ids data document: entries of an ID, a name and a hash, each ID and
        each hash once, so that one content has one ID; and, under ``own_ids``, the payload,
        version and content hash of each version that keeps its own ID, each once."""
        if not isinstance(document, Mapping) or not isinstance(document.get("payloads"), list):
            raise ValueError("payload-ids: the document must be a mapping holding payloads")
        unknown = sorted(str(key) for key in document if key not in {"payloads", "own_ids"})
        if unknown:
            raise ValueError(f"payload-ids: unknown keys {', '.join(unknown)}")
        by_hash: dict[str, AgreedId] = {}
        ids: set[str] = set()
        for entry in document["payloads"]:
            agreed, digest = _entry(entry)
            if agreed.id in ids:
                raise ValueError("payload-ids: each id once")
            if digest in by_hash:
                raise ValueError("payload-ids: each sha256 once: one content has one ID")
            ids.add(agreed.id)
            by_hash[digest] = agreed
        return cls(by_hash, _own_ids(document.get("own_ids", [])))

    def keeps_own_id(self, payload: str, version: str, digest: str) -> bool:
        """Whether the ``version`` of ``payload``, of content hash ``digest``, keeps the ID its
        content has, rather than its payload's: listed with this very content."""
        return (payload, version, digest) in self.own

    def id_for(self, digest: str) -> str:
        """The ID of the content whose hash is ``digest``."""
        agreed = self.by_hash.get(digest)
        return agreed.id if agreed is not None else derived_id(digest)


def _own_ids(listed: object) -> frozenset[tuple[str, str, str]]:
    if not isinstance(listed, list):
        raise ValueError("payload-ids: own_ids must be a list")
    own: set[tuple[str, str, str]] = set()
    for entry in listed:
        if not isinstance(entry, Mapping) or set(entry) != {"payload", "version", "sha256"}:
            raise ValueError("payload-ids: own_ids lists a payload, a version and a sha256, each")
        payload, version, digest = entry["payload"], entry["version"], entry["sha256"]
        if not isinstance(payload, str) or not payload or not isinstance(version, str):
            raise ValueError("payload-ids: own_ids gives a payload and a version as text")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("payload-ids: own_ids gives a sha256 of 64 lower-case digits")
        if (payload, version, digest) in own:
            raise ValueError("payload-ids: own_ids lists each version once")
        own.add((payload, version, digest))
    return frozenset(own)


def _is_derived_form(identifier: str) -> bool:
    try:
        return uuid.UUID(identifier).version == 5
    except ValueError:
        return False


def _entry(entry: object) -> tuple[AgreedId, str]:
    if not isinstance(entry, Mapping) or set(entry) != _ENTRY_KEYS:
        raise ValueError("payload-ids: each payload is an id, a name and a sha256")
    identifier, name, digest = entry["id"], entry["name"], entry["sha256"]
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise ValueError(
            "payload-ids: an id is lower-case letters, digits and ':._-', starting with a letter "
            "or a digit, at most 128 characters"
        )
    if _is_derived_form(identifier):
        raise ValueError(
            "payload-ids: an id is never a UUID v5, the form of the IDs derived from contents"
        )
    if not isinstance(name, str) or not name:
        raise ValueError("payload-ids: a name is a text")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError("payload-ids: a sha256 is 64 hexadecimal digits in lower case")
    return AgreedId(identifier, name), digest


@dataclass(frozen=True)
class PayloadReference:
    """A reference of ``scenario.yaml``: a payload's ID, its version and its hash."""

    id: str
    version: str
    sha256: str


@dataclass(frozen=True)
class HeldVersions:
    """The versions the payload catalogue holds, each as the reference that names it: by its ID
    and version, every version under each ID in the order given, and by hash."""

    by_key: Mapping[tuple[str, str], PayloadReference]
    by_id: Mapping[str, tuple[PayloadReference, ...]]
    by_hash: Mapping[str, PayloadReference]

    @classmethod
    def of(cls, versions: Sequence[PayloadReference]) -> "HeldVersions":
        by_id: dict[str, tuple[PayloadReference, ...]] = {}
        for version in versions:
            by_id[version.id] = (*by_id.get(version.id, ()), version)
        return cls(
            {(version.id, version.version): version for version in versions},
            by_id,
            {version.sha256: version for version in versions},
        )


@dataclass(frozen=True)
class Assignment:
    """A scenario whose payloads carry their IDs, with the references that name them, sorted by
    ID; or, when a payload cannot be hashed, the refusals and nothing else."""

    stored: Mapping[str, Any] | None
    references: tuple[PayloadReference, ...]
    refusals: tuple[Finding, ...]


@dataclass(frozen=True)
class _Hashed:
    embedded: EmbeddedPayload
    payload: Any  # a payload that could be hashed is a JSON object
    digest: str


def declared_references(metadata: object) -> tuple[PayloadReference, ...]:
    """The references ``scenario.yaml`` declares; an item not shaped as one names nothing, so
    that the payload it was meant to name is refused as unnamed."""
    items = metadata.get("payloads") if isinstance(metadata, Mapping) else None
    if not isinstance(items, list):
        return ()
    return tuple(
        PayloadReference(item["id"], item["version"], item["sha256"])
        for item in items
        if isinstance(item, Mapping)
        and all(isinstance(item.get(key), str) for key in ("id", "version", "sha256"))
    )


def _blocking(code: str, path: str, field: str, message: str) -> Finding:
    return Finding(code, Severity.BLOCKING, path, field, message)


def _carried(payload: object) -> object:
    return payload.get(_EXTERNAL_ID) if isinstance(payload, Mapping) else None


def unhashable_findings(stored: object, files: FileHash, scenario: str) -> tuple[Finding, ...]:
    """A blocking finding for each payload ``stored``, at ``scenario``, embeds that cannot be
    hashed, as the reference checks give it."""
    return tuple(_hashed(stored, files, scenario)[1])


def _hashed(
    stored: object, files: FileHash, scenario: str
) -> tuple[list[_Hashed], list[Finding], set[str]]:
    """Each embedded payload with its hash; a finding for each one that cannot be hashed, and
    the IDs those carry, so that their references are not said to name nothing."""
    hashed: list[_Hashed] = []
    refused: list[Finding] = []
    carried: set[str] = set()
    for embedded in embedded_payloads(stored):
        try:
            digest = payload_hash(embedded.payload, embedded.attack_patterns, files).hex
        except UnhashablePayloadError as error:
            refused.append(
                _blocking(
                    error.code,
                    scenario,
                    embedded.locate(error),
                    f"this payload cannot be hashed without guessing: {error.reason}",
                )
            )
            identifier = _carried(embedded.payload)
            if isinstance(identifier, str):
                carried.add(identifier)
            continue
        hashed.append(_Hashed(embedded, embedded.payload, digest))
    return hashed, refused, carried


def _expected_id(digest: str, agreed: AgreedIds, catalogue: HeldVersions) -> str:
    """The ID a payload of hash ``digest`` carries: its payload's, from the version of the
    catalogue that has this content; the ID of its content for a content no version has."""
    held = catalogue.by_hash.get(digest)
    return held.id if held is not None else agreed.id_for(digest)


def _unnamed(scenario: str, field: str) -> Finding:
    return _blocking(
        "PAY-001", scenario, field, f"no reference of scenario.yaml names this payload: {_RUN}"
    )


def _conflicts(hashed: list[_Hashed], agreed: AgreedIds, scenario: str) -> list[Finding]:
    """A payload whose name is not the one the registry gives its content, and a payload that
    shares its name with another of another content: a reviewer reads a payload by its name."""
    conflicts: list[Finding] = []
    names: dict[str, str] = {}
    for item in hashed:
        name = item.payload.get("payload_name")
        field = f"{item.embedded.pointer}/payload_name"
        entry = agreed.by_hash.get(item.digest)
        if entry is not None and name != entry.name:
            conflicts.append(
                _blocking(
                    "PAY-003",
                    scenario,
                    field,
                    "policy/data/payload-ids.yaml agrees this content's ID under another name: "
                    "correct the name there, to the payload's",
                )
            )
        if isinstance(name, str) and names.setdefault(name, item.digest) != item.digest:
            conflicts.append(
                _blocking(
                    "PAY-007",
                    scenario,
                    field,
                    "another payload of the scenario has this name, with another content: give "
                    "each payload its own name",
                )
            )
    return conflicts


_NOT_IN_CATALOGUE = (
    "this payload is in no version file of payloads/: run `scenario-tools intake` to add it"
)


def _held(
    reference: PayloadReference, index: int, catalogue: HeldVersions, metadata: str
) -> list[Finding]:
    """Why ``reference``, the reference at ``index``, names no version the catalogue holds: no
    file has its ID, or the file with its ID is another version or has another hash."""
    held = catalogue.by_key.get((reference.id, reference.version))
    if reference.id not in catalogue.by_id:
        message, field = "no version file of payloads/ has this ID", "id"
    elif held is None:
        message, field = "the version file with this ID is another version", "version"
    elif held.sha256 != reference.sha256:
        message, field = "the version file with this ID has another hash", "sha256"
    else:
        return []
    return [_blocking("PAY-008", metadata, f"/payloads/{index}/{field}", f"{message}: {_RUN}")]


def reference_findings(
    stored: object,
    references: Sequence[PayloadReference],
    *,
    agreed: AgreedIds,
    catalogue: HeldVersions,
    scenario: str,
    metadata: str,
    files: FileHash,
) -> tuple[Finding, ...]:
    """What keeps the payloads of ``stored``, at ``scenario``, from carrying the IDs their
    contents have, each given with its hash by one of ``references``, in ``metadata``, and each
    reference from naming a version the ``catalogue`` holds, with its version and its hash."""
    hashed, findings, used = _hashed(stored, files, scenario)
    findings += _conflicts(hashed, agreed, scenario)
    by_id: dict[str, tuple[int, PayloadReference]] = {}
    for index, reference in enumerate(references):
        if reference.id in by_id:  # the first counts
            findings.append(
                _blocking(
                    "PAY-002",
                    metadata,
                    f"/payloads/{index}/id",
                    "two references give this ID: each payload has one reference",
                )
            )
            continue
        by_id[reference.id] = (index, reference)
        findings.extend(_held(reference, index, catalogue, metadata))
    stale: set[int] = set()
    contents: dict[str, str] = {}  # the content of each ID the scenario's payloads carry
    for item in hashed:
        identifier = item.payload.get(_EXTERNAL_ID)
        field = f"{item.embedded.pointer}/{_EXTERNAL_ID}"
        expected = _expected_id(item.digest, agreed, catalogue)
        used.add(expected)  # its own reference names it, whatever it carries
        if item.digest not in catalogue.by_hash:
            findings.append(_blocking("PAY-008", scenario, field, _NOT_IN_CATALOGUE))
        if not isinstance(identifier, str):
            findings.append(_unnamed(scenario, field))
            continue
        used.add(identifier)
        if identifier != expected:
            findings.append(
                _blocking(
                    "PAY-003",
                    scenario,
                    field,
                    "this ID is not the one its content has: the ID of the payload whose version "
                    "has this content in payloads/, or, for a content no version has, the ID "
                    "derived from its hash or the one policy/data/payload-ids.yaml agrees for "
                    f"it; {_RUN}",
                )
            )
            continue
        if contents.setdefault(identifier, item.digest) != item.digest:
            findings.append(_blocking("PAY-002", scenario, field, TWO_VERSIONS))
            continue
        if identifier not in by_id:
            findings.append(_unnamed(scenario, field))
            continue
        index, reference = by_id[identifier]
        if reference.sha256 != item.digest and index not in stale:
            stale.add(index)
            findings.append(
                _blocking(
                    "PAY-002",
                    metadata,
                    f"/payloads/{index}/sha256",
                    f"this hash is not the hash of the payload the reference names: {_RUN}",
                )
            )
    findings.extend(
        _blocking(
            "PAY-006",
            metadata,
            f"/payloads/{index}",
            f"this reference names no payload the scenario embeds: {_RUN}, which drops it",
        )
        for identifier, (index, _) in by_id.items()
        if identifier not in used
    )
    return tuple(findings)


def assign(
    stored: Mapping[str, Any],
    *,
    agreed: AgreedIds,
    catalogue: HeldVersions,
    files: FileHash,
    scenario: str,
) -> Assignment:
    """Give each payload of ``stored``, a parsed JSON document, the ID its content has, and the
    references that name them, each with the version of the catalogue's file that holds it;
    nothing when a payload cannot be hashed or is in no file of the ``catalogue``."""
    assigned = copy.deepcopy(dict(stored))
    hashed, refused, _ = _hashed(assigned, files, scenario)
    refused += _conflicts(hashed, agreed, scenario)
    refused += [
        _blocking("PAY-008", scenario, f"{item.embedded.pointer}/{_EXTERNAL_ID}", _NOT_IN_CATALOGUE)
        for item in hashed
        if item.digest not in catalogue.by_hash
    ]
    if refused:
        return Assignment(None, (), tuple(refused))
    given: dict[str, str] = {}
    for item in hashed:
        identifier = catalogue.by_hash[item.digest].id
        if given.setdefault(identifier, item.digest) != item.digest:
            field = f"{item.embedded.pointer}/{_EXTERNAL_ID}"
            refused.append(_blocking("PAY-002", scenario, field, TWO_VERSIONS))
        item.payload[_EXTERNAL_ID] = identifier
    if refused:
        return Assignment(None, (), tuple(refused))
    references = tuple(
        PayloadReference(identifier, catalogue.by_hash[digest].version, digest)
        for identifier, digest in sorted(given.items())
    )
    return Assignment(assigned, references, ())
