"""The verdict intake gives each payload a stored scenario embeds, by the hash of its content:
already in the catalogue, under the version that has that hash; or a new payload, written as the
first version of a folder of its own, its slug proposed from its base name. A new payload whose
slug or base name another payload of the catalogue has is refused: a reviewer could not tell the
two apart."""

import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from scenario_tools.domain.catalogue.intake import name_key
from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.payload_names import FIRST_VERSION, base_name
from scenario_tools.domain.verification.payload_catalogue import Catalogue, is_slug
from scenario_tools.domain.verification.payload_hash import (
    UnhashablePayloadError,
    embedded_payloads,
    payload_hash,
    text_order,
)
from scenario_tools.domain.verification.payload_references import AgreedIds
from scenario_tools.domain.verification.payload_version import (
    VERSION_FILE_LIMIT,
    PayloadVersion,
    version_findings,
)

_SLUG_LIMIT = 64
_ATTACHED: dict[str, str] = {}  # an embedded payload's attached files are not read yet
_INSTANCE = frozenset(
    {
        "payload_id",
        "payload_external_id",
        "payload_source",
        "payload_status",
        "payload_collector_type",
        "payload_author_user",
        "payload_author_team",
        "payload_author_organization",
        "payload_tags",
        "payload_created_at",
        "payload_updated_at",
        "listened",
    }
)
_INSTANCE_ENDINGS = ("_id", "_tags", "_created_at", "_updated_at")
_TEXT_SETS = ("payload_platforms", "payload_expectations")
_SECURITY_PLATFORMS = "payload_expected_security_platforms"
_DOMAINS = "payload_domains"
BASE_NAME_TAKEN = (
    "the catalogue's payload {payload} has this payload's base name or slug, with another "
    "content: rename this payload"
)
TAKEN_IN_EXPORT = (
    "another new payload of this export, {payload}, has this payload's base name or slug, with "
    "another content: rename one of them"
)
NO_SLUG = (
    "this payload's name gives no slug, the name of its folder (letters and digits, at most 64 "
    "characters): rename this payload"
)
SUFFIXED = (
    "a new payload is its version 1.0.0, whose name carries no ' (<version>)' suffix: rename "
    "this payload"
)
OUT_OF_SCHEMA = (
    "this payload's version file would be out of schemas/payload.schema.json: complete the "
    "payload in OpenAEV and export again"
)
OVER_SIZE = (
    f"this payload's version file would be over {VERSION_FILE_LIMIT} bytes: shorten the payload "
    "in OpenAEV and export again"
)
NOT_KEPT = "this payload cannot be written as a version file of the same content"


def proposed_slug(name: str) -> str:
    """The slug proposed for a payload named ``name``: its base name in lower case, ASCII letters
    and digits, every run of other characters one hyphen, at most 64 characters."""
    ascii_name = unicodedata.normalize("NFKD", base_name(name)).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")
    return slug[:_SLUG_LIMIT].rstrip("-")


def _empty(value: object) -> bool:
    return value is None or (isinstance(value, str | list | Mapping) and not value)


def _cleaned(value: Any) -> Any:
    """``value`` with no identifier, tag or date of the instance at any depth, and no null or
    empty value (``false`` and ``0`` are kept)."""
    if isinstance(value, Mapping):
        kept = {
            key: _cleaned(item)
            for key, item in value.items()
            if key not in _INSTANCE and not str(key).endswith(_INSTANCE_ENDINGS)
        }
        return {key: item for key, item in kept.items() if not _empty(item)}
    if isinstance(value, list):
        return [_cleaned(item) for item in value]
    return value


def version_document(
    payload: Mapping[str, Any], techniques: Sequence[object], identifier: str
) -> dict[str, Any]:
    """The first version file of ``payload``, embedded with the ``techniques`` of its contract,
    under ``identifier``: cleaned, its sets sorted."""
    document: dict[str, Any] = _cleaned(payload)
    for key in _TEXT_SETS:
        if isinstance(document.get(key), list):
            document[key] = sorted(document[key], key=lambda item: text_order(str(item)))
    platforms = document.get(_SECURITY_PLATFORMS)
    if isinstance(platforms, Mapping):
        document[_SECURITY_PLATFORMS] = {
            key: sorted(items, key=lambda item: text_order(str(item)))
            if isinstance(items, list)
            else items
            for key, items in platforms.items()
        }
    domains = document.get(_DOMAINS)
    if isinstance(domains, list):
        document[_DOMAINS] = sorted(
            domains,
            key=lambda d: text_order(str(d.get("domain_name"))) if isinstance(d, Mapping) else (),
        )
    document["payload_attack_patterns"] = sorted({str(t) for t in techniques}, key=text_order)
    document["payload_external_id"] = identifier
    return document


_PATH = "scenario.json"


def _not_kept(
    version: PayloadVersion, digest: str, agreed: AgreedIds, accepted: Callable[[object], bool]
) -> str | None:
    """Why ``version``, made from an embedded payload of hash ``digest``, cannot be written as
    its first version file: the checks `validate-payloads` makes of a file, run before it is."""
    if version.name != base_name(version.name):
        return SUFFIXED
    document = dict(version.document)
    data = stored_form(document)
    if len(data) > VERSION_FILE_LIMIT:
        return OVER_SIZE
    if not accepted(document):  # the checks of a file read it as its schema shapes it
        return OUT_OF_SCHEMA
    # The checks of a file say first whether it can be hashed: only then is its hash compared.
    if version_findings(version, data, agreed) or version.digest() != digest:
        return NOT_KEPT
    return None


def verdicts(
    stored: object,
    catalogue: Catalogue,
    agreed: AgreedIds,
    *,
    accepted: Callable[[object], bool],
    scenario: str = _PATH,
) -> tuple[tuple[Finding, ...], dict[str, PayloadVersion]]:
    """The verdict on each payload ``stored`` embeds, at ``scenario``, as information, and the
    version files of the new ones, by hash; a new payload whose name or slug is taken, or whose
    file the catalogue would refuse (``accepted`` says whether its schema takes a document), is
    a blocking finding instead, and no file is given for it."""
    findings: list[Finding] = []
    new: dict[str, PayloadVersion] = {}
    named: dict[str, str] = {}  # the slug of each new payload, by its base name's key
    slugs: set[str] = set()  # the slugs of the new payloads
    for embedded in embedded_payloads(stored):
        payload = embedded.payload
        if not isinstance(payload, Mapping):
            continue
        try:
            digest = payload_hash(payload, embedded.attack_patterns, _ATTACHED.get).hex
        except UnhashablePayloadError:
            continue  # the reference checks say why
        held = catalogue.by_hash.get(digest)
        if held is not None:
            message = f"already there: {held.slug} {held.version}"
            findings.append(Finding("PAY-010", Severity.INFO, scenario, embedded.pointer, message))
            continue
        if digest in new:  # the same payload embedded again: one file
            message = f"new payload: {new[digest].slug} {FIRST_VERSION}"
            findings.append(Finding("PAY-010", Severity.INFO, scenario, embedded.pointer, message))
            continue
        name = payload.get("payload_name")
        slug = proposed_slug(name) if isinstance(name, str) else ""
        if not isinstance(name, str) or not is_slug(slug):  # no folder can be named for it
            findings.append(
                Finding("PAY-009", Severity.BLOCKING, scenario, embedded.pointer, NO_SLUG)
            )
            continue
        key = name_key(base_name(name))
        taken = catalogue.by_base_name.get(key) or (slug if slug in catalogue.by_slug else None)
        sibling = named.get(key) or (slug if slug in slugs else None)
        if taken is not None or sibling is not None:
            if taken is not None:
                message = BASE_NAME_TAKEN.format(payload=taken)
            else:
                message = TAKEN_IN_EXPORT.format(payload=sibling)
            findings.append(
                Finding("PAY-009", Severity.BLOCKING, scenario, embedded.pointer, message)
            )
            continue
        document = version_document(payload, embedded.attack_patterns, agreed.id_for(digest))
        version = PayloadVersion(
            slug, FIRST_VERSION, f"payloads/{slug}/{FIRST_VERSION}.json", document
        )
        refused = _not_kept(version, digest, agreed, accepted)
        if refused is not None:
            findings.append(
                Finding("PAY-009", Severity.BLOCKING, scenario, embedded.pointer, refused)
            )
            continue
        new[digest] = version
        named[key] = slug
        slugs.add(slug)
        message = f"new payload: {slug} {FIRST_VERSION}"
        findings.append(Finding("PAY-010", Severity.INFO, scenario, embedded.pointer, message))
    return tuple(findings), new
