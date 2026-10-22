"""One version of a payload of the catalogue, as its file ``payloads/<slug>/<version>.json``
holds it.

The file holds the payload's fields under the names the platform exports, its techniques by
external ID, its domains and the ID of this version. Its hash is the canonical payload hash of its
fields without the ID, the techniques and the domains, the techniques passed as those of the
contract an exported scenario holds them on: so it is the hash of the same payload embedded in a
scenario. Its ID is the one its content has: the ID the registry agrees for that hash, otherwise
the one derived from it. Its name carries its version, but for the first; the file is stored as
the repository stores every file, its sets sorted. A finding names a field, never its value."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.payload_names import FIRST_VERSION, base_name, versioned_name
from scenario_tools.domain.verification.payload_hash import (
    FileHash,
    UnhashablePayloadError,
    payload_hash,
    text_order,
)
from scenario_tools.domain.verification.payload_references import AgreedIds

VERSION_FILE_LIMIT = 256 * 1024  # bytes of a version file, the one bound of the catalogue
_ID = "payload_external_id"
_NAME = "payload_name"
_TECHNIQUES = "payload_attack_patterns"
_DOMAINS = "payload_domains"
_DOMAIN_NAME = "domain_name"
_NOT_HASHED = frozenset({_ID, _TECHNIQUES, _DOMAINS})
_TEXT_SETS = ("payload_platforms", "payload_expectations")
_SECURITY_PLATFORMS = "payload_expected_security_platforms"

ID_NOT_ITS_CONTENT = (
    "this ID is not the one this version's content has (the ID derived from its hash, or the one "
    "policy/data/payload-ids.yaml agrees for it)"
)
REGISTRY_OTHER_NAME = (
    "policy/data/payload-ids.yaml agrees this content's ID under another name: correct the name "
    "there, to this version's"
)
NAME_SUFFIX_ON_FIRST = (
    "the first version carries the payload's plain name: a version in its name belongs to the "
    "file of that version"
)
NAME_NO_SUFFIX = "a version after the first ends its name with ' (<version>)', its own version"
SET_NOT_SORTED = (
    "a set is stored sorted, as the hash sorts it: techniques, platforms, expectations and "
    "security platforms by their text, domains by their name"
)
NOT_STORED_FORM = (
    "the file is not in the repository's stored form: UTF-8, sorted keys, two-space indent, a "
    "final newline"
)
NOT_HASHABLE = "this payload cannot be hashed by the canonical form"


_ATTACHED: dict[str, str] = {}  # a version file attaches no file
_NO_FILES: FileHash = _ATTACHED.get


@dataclass(frozen=True)
class PayloadVersion:
    """The version ``version`` of the payload of the folder ``slug``, whose file is at ``path``
    and holds ``document``, a document its schema accepts."""

    slug: str
    version: str
    path: str
    document: Mapping[str, Any]

    @property
    def name(self) -> str:
        name: str = self.document[_NAME]
        return name

    @property
    def base_name(self) -> str:
        return base_name(self.name)

    @property
    def identifier(self) -> str:
        identifier: str = self.document[_ID]
        return identifier

    @property
    def techniques(self) -> tuple[str, ...]:
        return tuple(self.document[_TECHNIQUES])

    @property
    def domains(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.document.get(_DOMAINS, ()))

    def hash_input(self) -> tuple[dict[str, Any], tuple[str, ...]]:
        """What the canonical payload hash reads of this version: its fields without its ID, its
        techniques and its domains, and its techniques as a contract's."""
        fields = {key: value for key, value in self.document.items() if key not in _NOT_HASHED}
        return fields, self.techniques

    def digest(self) -> str:
        """The hash of this version, as the hash of the same payload embedded in a scenario; an
        ``UnhashablePayloadError`` when the canonical form cannot read it."""
        fields, techniques = self.hash_input()
        return payload_hash(fields, techniques, _NO_FILES).hex


def _blocking(code: str, version: PayloadVersion, field: str, message: str) -> Finding:
    return Finding(code, Severity.BLOCKING, version.path, field, message)


def _unsorted(items: Sequence[object]) -> bool:
    """Whether ``items`` are not in the order the canonical form sorts texts in."""
    return list(items) != sorted(items, key=lambda item: text_order(str(item)))


def _sorted_sets(version: PayloadVersion) -> list[Finding]:
    document = version.document
    sets: list[tuple[str, Sequence[object]]] = [
        (f"/{_TECHNIQUES}", version.techniques),
        (f"/{_DOMAINS}", [domain[_DOMAIN_NAME] for domain in version.domains]),
        *((f"/{key}", document.get(key, ())) for key in _TEXT_SETS),
        *(
            (f"/{_SECURITY_PLATFORMS}/{expectation}", platforms)
            for expectation, platforms in document.get(_SECURITY_PLATFORMS, {}).items()
        ),
    ]
    return [
        _blocking("PAY-009", version, pointer, SET_NOT_SORTED)
        for pointer, items in sets
        if _unsorted(items)
    ]


def _name(version: PayloadVersion) -> list[Finding]:
    if version.version == FIRST_VERSION and version.base_name != version.name:
        return [_blocking("PAY-009", version, f"/{_NAME}", NAME_SUFFIX_ON_FIRST)]
    if version.name != versioned_name(version.base_name, version.version):
        return [_blocking("PAY-009", version, f"/{_NAME}", NAME_NO_SUFFIX)]
    return []


def _identity(version: PayloadVersion, agreed: AgreedIds) -> list[Finding]:
    try:
        digest = version.digest()
    except UnhashablePayloadError:
        return [_blocking("PAY-009", version, "", NOT_HASHABLE)]
    if version.identifier != agreed.id_for(digest):
        return [_blocking("PAY-003", version, f"/{_ID}", ID_NOT_ITS_CONTENT)]
    entry = agreed.by_hash.get(digest)
    if entry is not None and entry.name != version.name:  # a first version's is its base name
        return [_blocking("PAY-003", version, f"/{_NAME}", REGISTRY_OTHER_NAME)]
    return []


def version_findings(
    version: PayloadVersion, data: bytes, agreed: AgreedIds
) -> tuple[Finding, ...]:
    """What keeps ``version``, whose file holds the bytes ``data``, from being a version of the
    catalogue: its stored form, its sorted sets, its name and its ID, by the IDs ``agreed``."""
    found: list[Finding] = []
    if data != stored_form(version.document):
        found.append(_blocking("PAY-009", version, "", NOT_STORED_FORM))
    found += _sorted_sets(version)
    found += _name(version)
    found += _identity(version, agreed)
    return tuple(found)


def ordered(versions: Sequence[PayloadVersion]) -> list[PayloadVersion]:
    """``versions`` by folder, then by version in semantic order."""
    return sorted(
        versions, key=lambda v: (v.slug, tuple(int(part) for part in v.version.split(".")))
    )
