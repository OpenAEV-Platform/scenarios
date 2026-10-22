"""A release's own output, verified as a consumer would before it is published: the manifest
meets its schema, each archive is the one the manifest lists, by its size and its SHA-256, and
holds a scenario with only the parts of a stored scenario, each payload of which sits inside an
inject's contract and is listed by its ID with the canonical hash its content has; and one payload
ID names one version and one hash across the release. What ``build`` checks on the commit it
builds, the scenario's facts, its normalised form and the policy, is not checked again here."""

import hashlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from scenario_tools.domain.catalogue import archive as stored_scenario
from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.verification.payload_hash import (
    FileHash,
    UnhashablePayloadError,
    embedded_payloads,
    payload_hash,
)
from scenario_tools.domain.verification.payload_version import content_digest

MANIFEST = "manifest.json"
_EXTERNAL_ID = "payload_external_id"
_OUTSIDE = (
    "the archive embeds a payload outside an inject's contract, where no reference can name it"
)


def _refused(code: str, path: str, field: str, message: str) -> Finding:
    return Finding(code, Severity.BLOCKING, path, field, message)


def manifest_findings(
    violations: Iterable[tuple[str, str]], document: Mapping[str, Any], *, approved: bool
) -> tuple[Finding, ...]:
    """``VRF-009`` for each place, by its pointer and with why, where the manifest
    ``document`` does not meet its schema, and when an ``approved`` one does not name its
    release approver."""
    findings = [
        _refused("VRF-009", MANIFEST, pointer, f"does not meet the manifest's schema: {why}")
        for pointer, why in violations
    ]
    if approved and "release_approver" not in document:
        message = "an approved manifest names its release approver"
        findings.append(_refused("VRF-009", MANIFEST, "/release_approver", message))
    return tuple(findings)


def item_findings(items: Iterable[Mapping[str, Any]]) -> tuple[Finding, ...]:
    """``VRF-009`` for each item of a manifest that meets its schema but lists a scenario
    already listed, or names its archive after another scenario or version than its own."""
    findings = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        external_id, version = str(item["external_id"]), str(item["version"])
        if external_id in seen:
            message = f"the scenario {external_id} is listed twice"
            findings.append(_refused("VRF-009", MANIFEST, f"/items/{index}", message))
            continue
        seen.add(external_id)
        name = str(item["archive"]["name"])
        if name != f"{external_id}-{version}.zip":
            message = f"the archive of {external_id} {version} is named {name}"
            findings.append(_refused("VRF-009", MANIFEST, f"/items/{index}/archive/name", message))
    return tuple(findings)


def shared_payload_findings(items: Iterable[Mapping[str, Any]]) -> tuple[Finding, ...]:
    """``VRF-008`` for each payload an item lists with another version or hash than the first
    item listing it, that item included: a platform that holds a payload by its ID does not read
    it again, so one ID names one content across the release."""
    findings = []
    first: dict[str, tuple[int, tuple[str, str]]] = {}
    for index, item in enumerate(items):
        for position, payload in enumerate(item["payloads"]):
            payload_id = str(payload["id"])
            listed = (str(payload["version"]), str(payload["sha256"]))
            at, known = first.setdefault(payload_id, (index, listed))
            if known != listed:
                message = (
                    f"the payload {payload_id} is listed with another version or hash than in "
                    f"/items/{at}: a platform holding this payload by its ID would not read the "
                    "other content"
                )
                field = f"/items/{index}/payloads/{position}"
                findings.append(_refused("VRF-008", MANIFEST, field, message))
    return tuple(findings)


def archive_findings(item: Mapping[str, Any], data: bytes | None) -> tuple[Finding, ...]:
    """``VRF-006`` when the archive of ``item`` is missing, or ``data``, its bytes, are not of
    the size and the SHA-256 the manifest lists."""
    listed = item["archive"]
    name = str(listed["name"])
    if data is None:
        return (_refused("VRF-006", name, "", "the archive the manifest lists is missing"),)
    if len(data) != listed["size"]:
        message = f"{len(data)} bytes, where the manifest lists {listed['size']}"
        return (_refused("VRF-006", name, "", message),)
    if hashlib.sha256(data).hexdigest() != listed["sha256"]:
        return (_refused("VRF-006", name, "", "its SHA-256 is not the one the manifest lists"),)
    return ()


def payload_content_findings(
    item: Mapping[str, Any], stored: object, files: FileHash
) -> tuple[Finding, ...]:
    """``VRF-007`` when the scenario ``stored`` in the archive of ``item`` has a part outside the
    closed list ``build`` enforces, or is not structured as an export; otherwise
    ``VRF-008`` for each payload it embeds outside an inject's contract, or without being listed,
    or with another content than the canonical hash listed, and for each payload listed but not
    embedded; ``files`` gives the hash of an attached file, if it can."""
    name = str(item["archive"]["name"])
    twice = []
    listed: dict[str, str] = {}
    for payload in item["payloads"]:
        listed_id = str(payload["id"])
        if listed_id in listed:
            message = f"the manifest lists the payload {listed_id} twice"
            twice.append(_refused("VRF-008", name, "", message))
        listed[listed_id] = str(payload["sha256"])
    if twice:  # which of the two hashes a consumer reads is not known: none is checked
        return tuple(twice)
    try:  # its findings are the payloads outside an inject's contract
        outside = stored_scenario.archive_findings(stored, name)
    except ExportStructureError as error:
        return (_refused("VRF-007", name, "", f"{error.code}: {error}"),)
    findings = [_refused("VRF-008", found.path, found.field, _OUTSIDE) for found in outside]
    embedded: set[str] = set()
    for found in embedded_payloads(stored):
        payload_id = found.payload.get(_EXTERNAL_ID) if isinstance(found.payload, Mapping) else None
        if not isinstance(payload_id, str) or not payload_id:
            message = "the archive embeds a payload without its ID, which the manifest cannot list"
            findings.append(_refused("VRF-008", name, found.pointer, message))
            continue
        embedded.add(payload_id)
        if payload_id not in listed:
            message = (
                f"the archive embeds the payload {payload_id}, which the manifest does not list"
            )
            findings.append(_refused("VRF-008", name, found.pointer, message))
            continue
        try:
            digest = payload_hash(found.payload, found.attack_patterns, files).hex
        except UnhashablePayloadError as error:
            message = f"the payload {payload_id} cannot be hashed: {error}"
            findings.append(_refused("VRF-008", name, found.locate(error), message))
            continue
        if digest != listed[payload_id]:
            message = (
                f"the payload {payload_id} has another content than the hash the manifest lists"
            )
            findings.append(_refused("VRF-008", name, found.pointer, message))
    for payload_id in sorted(listed.keys() - embedded):
        message = f"the manifest lists the payload {payload_id}, which the archive does not embed"
        findings.append(_refused("VRF-008", name, "", message))
    return tuple(findings)


def payload_list_findings(payloads: Iterable[Mapping[str, Any]]) -> tuple[Finding, ...]:
    """``VRF-008`` for each payload version of the manifest's list whose ID is listed before
    with another payload, version, hash or file, whose content is listed before under another
    ID, or
    which is listed before itself: one ID names one version file, and one content one ID.
    ``VRF-006`` for a version whose file is not named ``<payload>-<version>.json``."""
    findings = []
    seen: set[tuple[str, str]] = set()
    by_id: dict[str, tuple[int, tuple[str, str, str]]] = {}
    by_hash: dict[str, tuple[int, str]] = {}
    for index, entry in enumerate(payloads):
        payload, version = str(entry["payload"]), str(entry["version"])
        identifier, sha256 = str(entry["openaev_id"]), str(entry["sha256"])
        listed = (payload, version, sha256)  # its file is named by the first two
        at, known = by_id.setdefault(identifier, (index, listed))
        first, owner = by_hash.setdefault(sha256, (index, identifier))
        if known != listed:
            message = (
                f"the payload ID {identifier} is listed with another payload, version, hash or "
                f"file than in /payloads/{at}"
            )
            findings.append(_refused("VRF-008", MANIFEST, f"/payloads/{index}", message))
        elif owner != identifier:
            message = f"this content is listed under another ID in /payloads/{first}"
            findings.append(_refused("VRF-008", MANIFEST, f"/payloads/{index}", message))
        elif (payload, version) in seen:
            message = f"{payload} {version} is listed twice"
            findings.append(_refused("VRF-008", MANIFEST, f"/payloads/{index}", message))
        seen.add((payload, version))
        name = str(entry["file"]["name"])
        if name != f"{payload}-{version}.json":
            message = f"the file of {payload} {version} is named {name}"
            field = f"/payloads/{index}/file/name"
            findings.append(_refused("VRF-006", MANIFEST, field, message))
    return tuple(findings)


def payload_reference_findings(
    items: Iterable[Mapping[str, Any]], payloads: Iterable[Mapping[str, Any]]
) -> tuple[Finding, ...]:
    """``VRF-008`` for each payload an item references by an ID, a version and a hash that no
    payload version of the manifest's list has."""
    listed = {
        (str(entry["openaev_id"]), str(entry["version"]), str(entry["sha256"]))
        for entry in payloads
    }
    message = "the release lists no payload version with this ID, version and hash"
    return tuple(
        _refused("VRF-008", MANIFEST, f"/items/{index}/payloads/{position}", message)
        for index, item in enumerate(items)
        for position, payload in enumerate(item["payloads"])
        if (str(payload["id"]), str(payload["version"]), str(payload["sha256"])) not in listed
    )


def _file_digest(document: Mapping[str, Any]) -> str | None:
    """The content hash of the version file holding ``document``; none when it cannot be
    hashed, whatever a file of the release may hold."""
    techniques = document.get("payload_attack_patterns")
    if not isinstance(techniques, list):  # read as a list of techniques, whatever it holds
        return None
    try:
        return content_digest(document)
    except UnhashablePayloadError:
        return None


def payload_file_findings(
    entry: Mapping[str, Any], data: bytes | None, read: Callable[[bytes], object]
) -> tuple[Finding, ...]:
    """``VRF-006`` when the file of the payload version ``entry`` is missing, or ``data``, its
    bytes, are not of the size and the SHA-256 the manifest lists; otherwise ``VRF-008`` when
    ``read`` cannot read them, or their content has another hash or another ID than listed."""
    listed = entry["file"]
    name = str(listed["name"])
    if data is None:
        return (_refused("VRF-006", name, "", "the payload file the manifest lists is missing"),)
    if len(data) != listed["size"]:
        message = f"{len(data)} bytes, where the manifest lists {listed['size']}"
        return (_refused("VRF-006", name, "", message),)
    if hashlib.sha256(data).hexdigest() != listed["sha256"]:
        return (_refused("VRF-006", name, "", "its SHA-256 is not the one the manifest lists"),)
    try:
        document = read(data)
    except ValueError as error:
        return (_refused("VRF-008", name, "", f"its content cannot be read: {error}"),)
    unhashable = (_refused("VRF-008", name, "", "its content cannot be hashed"),)
    if not isinstance(document, Mapping):
        return unhashable
    digest = _file_digest(document)
    if digest is None:
        return unhashable
    if digest != entry["sha256"]:
        message = "its content has another hash than the one the manifest lists"
        return (_refused("VRF-008", name, "", message),)
    if document.get(_EXTERNAL_ID) != entry["openaev_id"]:
        message = "it holds another ID than the openaev_id the manifest lists"
        return (_refused("VRF-008", name, "", message),)
    return ()
