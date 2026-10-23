"""The verdict intake gives each payload a stored scenario embeds, by the hash of its content:
already in the catalogue, under the version that has that hash; or a new payload, written as the
first version of a folder of its own, its slug proposed from its base name. A new payload whose
slug or base name another payload of the catalogue has is refused: a reviewer could not tell the
two apart."""

import copy
import json
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.intake import name_key
from scenario_tools.domain.catalogue.structure import CONTRACT, contracts_with_payloads
from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.payload_names import (
    FIRST_VERSION,
    base_name,
    version_key,
    versioned_name,
)
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
    "content: rename this payload, or say in the request that it is based on that payload "
    "(based_on)"
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
NEW_PAYLOADS_LIMIT = 100  # the new payloads one intake writes, each in a folder held open
TOO_MANY_NEW = (
    f"this export holds more than {NEW_PAYLOADS_LIMIT} new payloads, which one intake writes at "
    "most: add some of its payloads to the catalogue with an earlier intake"
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


def contract_domains(contract: Mapping[str, Any]) -> list[dict[str, str]]:
    """The domains a contract's own copy declares, by name and colour, as a version file holds
    them: an export holds a payload's domains on its contract, never on the payload. None when
    the copy names none, or not as normalisation reads it."""
    copy = contract.get("convertedContent")
    if copy is None and isinstance(contract.get("injector_contract_content"), str):
        try:
            copy = json.loads(contract["injector_contract_content"])
        except ValueError:
            return []
    domains = copy.get("domains") if isinstance(copy, Mapping) else None
    if not isinstance(domains, list):
        return []
    return [
        {"domain_color": domain["domain_color"], "domain_name": domain["domain_name"]}
        for domain in domains
        if isinstance(domain, Mapping)
        and isinstance(domain.get("domain_name"), str)
        and isinstance(domain.get("domain_color"), str)
    ]


def version_document(
    payload: Mapping[str, Any],
    techniques: Sequence[object],
    identifier: str,
    declared: Sequence[Mapping[str, str]] = (),
) -> dict[str, Any]:
    """The first version file of ``payload``, embedded with the ``techniques`` of its contract,
    under ``identifier``, with the domains its contract ``declared`` when it carries none:
    cleaned, its sets sorted."""
    document: dict[str, Any] = _cleaned(payload)
    if not document.get(_DOMAINS) and declared:
        document[_DOMAINS] = [dict(domain) for domain in declared]
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
    if version.version == FIRST_VERSION and version.name != base_name(version.name):
        return SUFFIXED  # a later version's name is checked with the rest of its file, below
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


@dataclass(frozen=True)
class Claim:
    """What a request says of one payload the export embeds, by its name: the catalogue payload
    it was made from, the version of it that was duplicated (the latest when absent), and the
    version wanted for it. A hint: every one is checked, and none decides."""

    name: str
    based_on: str | None = None
    based_version: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class Verdicts:
    """The verdicts on the payloads a stored scenario embeds: the findings, the version files to
    write by hash, the name each claimed copy takes by its pointer, and, for each new version
    of a payload, the pointers of the fields that differ from the version it was based on."""

    findings: tuple[Finding, ...]
    versions: dict[str, PayloadVersion]
    renames: dict[str, str]
    changes: dict[str, tuple[str, ...]]


CLAIMED_TWICE = "this payload is claimed twice: claim each payload once"
CLAIM_NAMES_NOTHING = "this claim names no payload the export embeds"
NO_SUCH_PAYLOAD = "based_on names no payload of the catalogue"
NO_SUCH_VERSION = "based_on names a version {payload} does not have"
NOT_HIGHER = (
    "the version asked for is not higher than {payload} {version}, the highest the catalogue holds"
)
CLAIM_IGNORED = "this payload is already in the catalogue: the claim is ignored"
STALE_BASE = "based on {payload} {version}, whereas the latest version is {payload} {latest}"
CARRIED_ID = (
    "this payload carries the ID of {payload} {version} but another content: it is treated as "
    "changed"
)
_REQUEST = "request.yaml"
_HASHED_OUT = frozenset({"payload_name", "payload_external_id"})


def _next_minor(version: str) -> str:
    major, minor, _ = version_key(version)
    return f"{major}.{minor + 1}.0"


def _changed(base: Mapping[str, Any], new: Mapping[str, Any]) -> tuple[str, ...]:
    """The pointers of the fields of ``new`` that differ from ``base``, its name and ID aside,
    never a value."""
    keys = (set(base) | set(new)) - _HASHED_OUT
    return tuple(f"/{key}" for key in sorted(keys) if base.get(key) != new.get(key))


class _Pass:
    """One pass of the verdicts over a stored scenario: what it found, and what it holds of the
    new payloads and versions so far, so that one is written once and two never take one place."""

    def __init__(
        self,
        catalogue: Catalogue,
        agreed: AgreedIds,
        accepted: Callable[[object], bool],
        scenario: str,
        request: str,
        contracts: Mapping[str, Mapping[str, Any]],
    ) -> None:
        self.catalogue, self.agreed, self.accepted = catalogue, agreed, accepted
        self.contracts = contracts  # each contract that holds a payload, by its pointer
        self.scenario, self.request = scenario, request
        self.findings: list[Finding] = []
        self.versions: dict[str, PayloadVersion] = {}
        self.renames: dict[str, str] = {}
        self.changes: dict[str, tuple[str, ...]] = {}
        self.named: dict[str, str] = {}  # the slug of each new payload, by its base name's key
        self.slugs: set[str] = set()  # the slugs of the new payloads
        self.claimed: dict[str, tuple[str, str]] = {}  # a claimed copy's name and verdict, by hash
        self.highest: dict[str, str] = {}  # the highest version each payload has so far

    def info(self, pointer: str, message: str) -> None:
        self.findings.append(Finding("PAY-010", Severity.INFO, self.scenario, pointer, message))

    def hint(self, pointer: str, message: str) -> None:
        self.findings.append(Finding("PAY-011", Severity.INFO, self.scenario, pointer, message))

    def refuse(self, pointer: str, message: str) -> None:
        self.findings.append(Finding("PAY-009", Severity.BLOCKING, self.scenario, pointer, message))

    def refuse_claim(self, field: str, message: str) -> None:
        refused = Finding("ITK-009", Severity.BLOCKING, self.request, field, message)
        if refused not in self.findings:  # a claim is refused once, however many copies it names
            self.findings.append(refused)

    def latest(self, slug: str) -> str:
        held = self.catalogue.by_slug[slug][-1].version
        return self.highest.get(slug, held)

    def kept(self, version: PayloadVersion, digest: str, pointer: str) -> bool:
        refused = _not_kept(version, digest, self.agreed, self.accepted)
        if refused is not None:
            self.refuse(pointer, refused)
        return refused is None

    def claim(
        self, embedded: Any, payload: Mapping[str, Any], digest: str, claim: Claim, index: int
    ) -> None:
        """The verdict on a payload claimed to be based on a catalogue payload: one of its
        versions under that version's name, or the next version of it."""
        pointer, slug = embedded.pointer, claim.based_on or ""
        if slug not in self.catalogue.by_slug:
            self.refuse_claim(f"/payloads/{index}/based_on/payload", NO_SUCH_PAYLOAD)
            return
        held = self.catalogue.by_slug[slug]
        base_version = claim.based_version or held[-1].version
        base = next((v for v in held if v.version == base_version), None)
        if base is None:
            message = NO_SUCH_VERSION.format(payload=slug)
            self.refuse_claim(f"/payloads/{index}/based_on/version", message)
            return
        if digest in self.claimed:  # the same copy embedded again: one verdict, one file
            name, message = self.claimed[digest]
            self.renames[pointer] = name
            self.info(pointer, message)
            return
        for version in held:  # idempotent: a copy of one of its versions is that version
            renamed = {**payload, "payload_name": version.name}
            if (
                payload_hash(renamed, embedded.attack_patterns, _ATTACHED.get).hex
                == version.digest()
            ):
                message = f"already there: {slug} {version.version}"
                self.renames[pointer] = version.name
                self.claimed[digest] = (version.name, message)
                self.info(pointer, message)
                return
        latest = self.latest(slug)
        if claim.version is not None and version_key(claim.version) <= version_key(latest):
            message = NOT_HIGHER.format(payload=slug, version=latest)
            self.refuse_claim(f"/payloads/{index}/version", message)
            return
        if base_version != held[-1].version:
            message = STALE_BASE.format(payload=slug, version=base_version, latest=held[-1].version)
            self.hint(pointer, message)
        number = claim.version or _next_minor(latest)
        name = versioned_name(base.base_name, number)
        renamed = {**payload, "payload_name": name}
        new_digest = payload_hash(renamed, embedded.attack_patterns, _ATTACHED.get).hex
        domains = contract_domains(self.contracts[embedded.contract])
        document = version_document(
            renamed, embedded.attack_patterns, self.agreed.id_for(new_digest), domains
        )
        version = PayloadVersion(slug, number, f"payloads/{slug}/{number}.json", document)
        if not self.kept(version, new_digest, pointer):
            return
        message = f"new version: {slug} {number} (based on {slug} {base_version})"
        self.versions[new_digest] = version
        self.highest[slug] = number
        self.renames[pointer] = name
        self.claimed[digest] = (name, message)
        self.changes[version.path] = _changed(base.document, document)
        self.info(pointer, message)

    def unclaimed(self, embedded: Any, payload: Mapping[str, Any], digest: str) -> None:
        """The verdict on a payload no claim names: a new payload, its first version."""
        pointer = embedded.pointer
        if digest in self.versions:  # the same payload embedded again: one file
            self.info(pointer, f"new payload: {self.versions[digest].slug} {FIRST_VERSION}")
            return
        name = payload.get("payload_name")
        slug = proposed_slug(name) if isinstance(name, str) else ""
        if not isinstance(name, str) or not is_slug(slug):  # no folder can be named for it
            self.refuse(pointer, NO_SLUG)
            return
        key = name_key(base_name(name))
        taken = self.catalogue.by_base_name.get(key) or (
            slug if slug in self.catalogue.by_slug else None
        )
        sibling = self.named.get(key) or (slug if slug in self.slugs else None)
        if taken is not None:
            self.refuse(pointer, BASE_NAME_TAKEN.format(payload=taken))
            return
        if sibling is not None:
            self.refuse(pointer, TAKEN_IN_EXPORT.format(payload=sibling))
            return
        domains = contract_domains(self.contracts[embedded.contract])
        document = version_document(
            payload, embedded.attack_patterns, self.agreed.id_for(digest), domains
        )
        version = PayloadVersion(
            slug, FIRST_VERSION, f"payloads/{slug}/{FIRST_VERSION}.json", document
        )
        if not self.kept(version, digest, pointer):
            return
        self.versions[digest] = version
        self.named[key] = slug
        self.slugs.add(slug)
        self.info(pointer, f"new payload: {slug} {FIRST_VERSION}")


def claimed_verdicts(
    stored: object,
    catalogue: Catalogue,
    agreed: AgreedIds,
    *,
    accepted: Callable[[object], bool],
    claims: Sequence[Claim] = (),
    scenario: str = _PATH,
    request: str = _REQUEST,
) -> Verdicts:
    """The verdict on each payload ``stored`` embeds, at ``scenario``, as information, by its
    hash: already there, a new version of the payload a claim of the request, at ``request``,
    says it is based on, or a new payload. A claimed copy is looked up first under the name of
    each version of its payload, so that a run again finds what an earlier run wrote. A claim
    that cannot hold is refused (``ITK-009``); a hint is ``PAY-011``. A new payload whose name or
    slug is taken, or whose file the catalogue would refuse (``accepted`` says whether its
    schema takes a document), is a blocking finding instead, and no file is given for it."""
    contracts = {
        f"{at}/{CONTRACT}": contract for at, _, contract in contracts_with_payloads(stored)
    }
    run = _Pass(catalogue, agreed, accepted, scenario, request, contracts)
    by_name: dict[str, int] = {}
    for position, claim in enumerate(claims):
        if claim.name in by_name:
            run.refuse_claim(f"/payloads/{position}/name", CLAIMED_TWICE)
        else:
            by_name[claim.name] = position
    named: set[int] = set()
    for embedded in embedded_payloads(stored):
        payload = embedded.payload
        if not isinstance(payload, Mapping):
            continue
        try:
            digest = payload_hash(payload, embedded.attack_patterns, _ATTACHED.get).hex
        except UnhashablePayloadError:
            continue  # the reference checks say why
        name = payload.get("payload_name")
        index: int | None = by_name.get(name) if isinstance(name, str) else None
        if index is not None:
            named.add(index)
        carried = catalogue.by_id.get(str(payload.get("payload_external_id")))
        if carried is not None and carried.digest() != digest:
            message = CARRIED_ID.format(payload=carried.slug, version=carried.version)
            run.hint(embedded.pointer, message)
        held = catalogue.by_hash.get(digest)
        if held is not None:
            run.info(embedded.pointer, f"already there: {held.slug} {held.version}")
            if index is not None and claims[index].based_on is not None:
                run.hint(embedded.pointer, CLAIM_IGNORED)
            continue
        if index is not None and claims[index].based_on is not None:
            run.claim(embedded, payload, digest, claims[index], index)
        else:
            run.unclaimed(embedded, payload, digest)
    for position in sorted(set(by_name.values()) - named):
        run.refuse_claim(f"/payloads/{position}/name", CLAIM_NAMES_NOTHING)
    if len(run.versions) > NEW_PAYLOADS_LIMIT:
        too_many = (Finding("PAY-009", Severity.BLOCKING, scenario, "", TOO_MANY_NEW),)
        return Verdicts(too_many, {}, {}, {})
    return Verdicts(tuple(run.findings), run.versions, run.renames, run.changes)


def renamed(stored: Mapping[str, Any], renames: Mapping[str, str]) -> dict[str, Any]:
    """A copy of ``stored`` whose payload at each pointer of ``renames`` takes its new name; the
    pointers are those the verdicts give, of payloads ``stored`` embeds."""
    document = copy.deepcopy(dict(stored))
    for pointer, name in renames.items():
        node: Any = document
        for part in pointer.lstrip("/").split("/"):
            node = node[int(part)] if isinstance(node, list) else node[part]
        node["payload_name"] = name
    return document


def verdicts(
    stored: object,
    catalogue: Catalogue,
    agreed: AgreedIds,
    *,
    accepted: Callable[[object], bool],
    scenario: str = _PATH,
) -> tuple[tuple[Finding, ...], dict[str, PayloadVersion]]:
    """The verdicts of ``claimed_verdicts`` without a claim: the findings and the version files
    of the new payloads, by hash."""
    found = claimed_verdicts(stored, catalogue, agreed, accepted=accepted, scenario=scenario)
    return found.findings, found.versions
