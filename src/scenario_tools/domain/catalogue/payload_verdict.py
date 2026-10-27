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
from dataclasses import dataclass, field
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
from scenario_tools.domain.shared.stored import injects_replaced
from scenario_tools.domain.verification.payload_catalogue import Catalogue, is_slug
from scenario_tools.domain.verification.payload_hash import (
    PAYLOAD_INSTANCE_FIELDS,
    EmbeddedPayload,
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
_INSTANCE = PAYLOAD_INSTANCE_FIELDS | {"listened"}
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
    declared = contract.get("convertedContent")
    if declared is None and isinstance(contract.get("injector_contract_content"), str):
        try:
            declared = json.loads(contract["injector_contract_content"])
        except ValueError:
            return []
    domains = declared.get("domains") if isinstance(declared, Mapping) else None
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
    position: int | None = None  # its place in the request, when not its place in the list


@dataclass(frozen=True)
class Verdicts:
    """The verdicts on the payloads a stored scenario embeds: the findings, the version files to
    write by hash, the name each claimed copy takes by its pointer, for each new version of a
    payload, the pointers of the fields that differ from the version it was based on, and the
    base name of the catalogue payload each claim names, by the pointer of its copy, whatever
    else the claim's verdict is."""

    findings: tuple[Finding, ...]
    versions: dict[str, PayloadVersion]
    renames: dict[str, str]
    changes: dict[str, tuple[str, ...]]
    bases: dict[str, str] = field(default_factory=dict)


CLAIMED_TWICE = "this payload is claimed twice: claim each payload once"
CLAIM_NAMES_NOTHING = "this claim names no payload the export embeds"
NO_SUCH_PAYLOAD = "based_on names no payload of the catalogue"
NO_SUCH_VERSION = "based_on names a version {payload} does not have"
NOT_HIGHER = (
    "the version asked for is not higher than {payload} {version}, the highest the catalogue holds"
)
GIVEN_TWICE = "the version asked for is given to another payload of this export already"
TWO_CONTENTS = "this claim names payloads with different contents: give each copy a name of its own"
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
        self.contents: dict[int, str] = {}  # the hash each claim names, by its position
        self.bases: dict[str, str] = {}  # the base name each claimed copy follows, by pointer

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
        if self.contents.setdefault(index, digest) != digest:
            self.refuse_claim(f"/payloads/{index}/name", TWO_CONTENTS)
            return
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
        self.bases[pointer] = base.base_name  # its identifiers follow it, whatever comes next
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
        # A version asked for is judged against the catalogue alone, whatever order the
        # export's payloads come in; this run only must not give it twice.
        if claim.version is not None and version_key(claim.version) <= version_key(
            held[-1].version
        ):
            message = NOT_HIGHER.format(payload=slug, version=held[-1].version)
            self.refuse_claim(f"/payloads/{index}/version", message)
            return
        if claim.version is not None and any(
            v.slug == slug and v.version == claim.version for v in self.versions.values()
        ):
            self.refuse_claim(f"/payloads/{index}/version", GIVEN_TWICE)
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
        self.highest[slug] = max(number, latest, key=version_key)  # never back
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
    at = [i if claim.position is None else claim.position for i, claim in enumerate(claims)]
    by_name = _claims_by_name(run, claims, at)
    named: set[int] = set()
    for embedded in embedded_payloads(stored):
        payload = embedded.payload
        if not isinstance(payload, Mapping):
            continue
        name = payload.get("payload_name")
        index: int | None = by_name.get(name) if isinstance(name, str) else None
        if index is not None:  # named, even by a payload the reference checks refuse
            named.add(index)
        claim = None if index is None else (claims[index], at[index])
        _judge(run, catalogue, embedded, payload, claim)
    for position in sorted(set(by_name.values()) - named):
        run.refuse_claim(f"/payloads/{at[position]}/name", CLAIM_NAMES_NOTHING)
    if len(run.versions) > NEW_PAYLOADS_LIMIT:
        too_many = (Finding("PAY-009", Severity.BLOCKING, scenario, "", TOO_MANY_NEW),)
        return Verdicts(too_many, {}, {}, {}, run.bases)
    return Verdicts(tuple(run.findings), run.versions, run.renames, run.changes, run.bases)


def _claims_by_name(run: _Pass, claims: Sequence[Claim], at: list[int]) -> dict[str, int]:
    """The position of the claim of each name; a name claimed twice is refused."""
    by_name: dict[str, int] = {}
    for position, claim in enumerate(claims):
        if claim.name in by_name:
            run.refuse_claim(f"/payloads/{at[position]}/name", CLAIMED_TWICE)
        else:
            by_name[claim.name] = position
    return by_name


def _judge(
    run: _Pass,
    catalogue: Catalogue,
    embedded: EmbeddedPayload,
    payload: Mapping[str, Any],
    claim: tuple[Claim, int] | None,
) -> None:
    """The verdict on one embedded payload, with the claim that names it and its position."""
    try:
        digest = payload_hash(payload, embedded.attack_patterns, _ATTACHED.get).hex
    except UnhashablePayloadError:
        return  # the reference checks say why
    carried = catalogue.by_id.get(str(payload.get("payload_external_id")), ())
    if carried and all(version.digest() != digest for version in carried):
        message = CARRIED_ID.format(payload=carried[-1].slug, version=carried[-1].version)
        run.hint(embedded.pointer, message)
    based = claim if claim is not None and claim[0].based_on is not None else None
    held = catalogue.by_hash.get(digest)
    if held is not None:
        run.info(embedded.pointer, f"already there: {held.slug} {held.version}")
        if based is not None:
            if run.contents.setdefault(based[1], digest) != digest:
                run.refuse_claim(f"/payloads/{based[1]}/name", TWO_CONTENTS)
            run.hint(embedded.pointer, CLAIM_IGNORED)
        return
    if based is not None:
        run.claim(embedded, payload, digest, based[0], based[1])
    else:
        run.unclaimed(embedded, payload, digest)


def names_held(stored: object, catalogue: Catalogue) -> frozenset[str]:
    """The names of the payloads ``stored`` embeds whose content the catalogue holds as it is."""
    found: set[str] = set()
    for embedded in embedded_payloads(stored):
        payload = embedded.payload
        name = payload.get("payload_name") if isinstance(payload, Mapping) else None
        if not isinstance(payload, Mapping) or not isinstance(name, str):
            continue
        try:
            digest = payload_hash(payload, embedded.attack_patterns, _ATTACHED.get).hex
        except UnhashablePayloadError:
            continue
        if digest in catalogue.by_hash:
            found.add(name)
    return frozenset(found)


def named_at(stored: Mapping[str, Any], pointer: str) -> object:
    """The name of the payload at ``pointer`` in ``stored``, a pointer the verdicts give."""
    node: Any = stored
    for part in pointer.lstrip("/").split("/"):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node.get("payload_name")


def export_renamed(export: object, names: Mapping[str, str]) -> object:
    """A copy of ``export`` in which every payload named by a key of ``names`` takes its value,
    in its injects and in the data of its chaining steps alike: a claimed copy takes its name
    before the export is normalised, so that what normalisation derives from a name follows
    it. A payload without a description keeps the one normalisation gives it, its first name.
    Only the payloads of contracts are renamed: an inject's content, its arguments, is never
    read nor rewritten."""
    return injects_replaced(export, lambda inject: _inject_renamed(inject, names))


def _inject_renamed(inject: object, names: Mapping[str, str]) -> object:
    """``inject`` with its contract's payload renamed."""
    contract = inject.get(_CONTRACT_KEY) if isinstance(inject, Mapping) else None
    if not isinstance(inject, Mapping) or not isinstance(contract, Mapping):
        return inject
    payload = _payload_renamed(contract.get(_PAYLOAD_KEY), names)
    if payload is contract.get(_PAYLOAD_KEY):
        return inject
    return {**inject, _CONTRACT_KEY: {**contract, _PAYLOAD_KEY: payload}}


_CONTRACT_KEY = "inject_injector_contract"
_PAYLOAD_KEY = "injector_contract_payload"


def _payload_renamed(payload: object, names: Mapping[str, str]) -> object:
    """``payload``, a contract's payload, under its new name when ``names`` gives one."""
    name = payload.get("payload_name") if isinstance(payload, Mapping) else None
    if not isinstance(payload, Mapping) or not isinstance(name, str) or name not in names:
        return payload
    copied = {**payload, "payload_name": names[name]}
    described = copied.get("payload_description")
    if described is None or (isinstance(described, str) and not described.strip()):
        copied["payload_description"] = name  # as normalisation describes it, by its name
    return copied


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
