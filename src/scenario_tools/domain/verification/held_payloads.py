"""What installing a scenario would reuse on a platform: the payloads it already holds under the
identifiers the scenario's archive gives them.

The platform's import reuses, without comparing it, a contract it holds under the contract ID an
inject names, or the contract of a payload it holds under the payload's external ID. Each such
payload must have the content the archive embeds, by the canonical hash, or installing would run
another payload than the one released. The techniques are taken from the archive on both sides:
they do not change what runs. Any export is read, not only a release: a step's inject may be JSON
text, as the platform exports it, and an embedded payload may not be hashable.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.normalisation import decoded_step_data
from scenario_tools.domain.catalogue.structure import CONTRACT, PAYLOAD, contracts_with_payloads
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.stored import steps_decoded
from scenario_tools.domain.verification.payload_hash import (
    UnhashablePayloadError,
    embedded_payloads,
    payload_hash,
)

CONTRACT_ID = "injector_contract_id"
EXTERNAL_ID = "payload_external_id"

OTHER_PAYLOAD = (
    "the platform holds another payload under this {by}: importing would run it instead of the "
    "one released; remove or rename it on the platform, then install again"
)
NO_PAYLOAD = (
    "the platform holds a contract without a payload under this contract ID: importing would "
    "use it instead of the payload released; remove it on the platform, then install again"
)
NOT_HASHED = (
    "this payload cannot be hashed, and the platform holds one under its {by}: they cannot be "
    "compared; make the archive's payload one that can be hashed, then install again"
)
UNREADABLE_STEP = (
    "this step's inject is JSON text that cannot be read: what importing it would reuse on the "
    "platform cannot be told"
)
UNCOMPARABLE = (
    "the platform holds a payload under this {by} that cannot be hashed: it cannot be told from "
    "the one released; check it on the platform, then install again"
)


@dataclass(frozen=True)
class HeldContract:
    """A contract the platform holds under an ID, with its payload, ``None`` when it has none."""

    payload: object | None


def identifiers(stored: object) -> tuple[frozenset[str], frozenset[str]]:
    """The contract IDs and the payload external IDs the payloads ``stored`` embeds are given."""
    contracts: set[str] = set()
    external: set[str] = set()
    for _, _, contract in contracts_with_payloads(steps_decoded(stored, decoded_step_data)[0]):
        contract_id = contract.get(CONTRACT_ID)
        if isinstance(contract_id, str):
            contracts.add(contract_id)
        payload = contract.get(PAYLOAD)
        external_id = payload.get(EXTERNAL_ID) if isinstance(payload, Mapping) else None
        if isinstance(external_id, str):
            external.add(external_id)
    return frozenset(contracts), frozenset(external)


def reuse_findings(
    stored: object,
    contracts: Mapping[str, HeldContract],
    payloads: Mapping[str, object],
    path: str,
) -> tuple[Finding, ...]:
    """A blocking finding (``OAV-002``) for each payload ``stored``, the archive at ``path``,
    embeds that the platform would replace on import: one it holds under the contract ID, in
    ``contracts``, or under the payload's external ID, in ``payloads``, with other content. A
    payload the platform holds under neither is created by the import: nothing to say."""
    stored, unreadable = steps_decoded(stored, decoded_step_data)
    found = [_finding(path, pointer, UNREADABLE_STEP) for pointer in unreadable]
    contract_of = {
        f"{pointer}/{CONTRACT}": contract
        for pointer, _, contract in contracts_with_payloads(stored)
    }
    for embedded in embedded_payloads(stored):
        contract = contract_of[embedded.contract]  # each embedded payload sits in a contract
        reused = _held(contract, embedded.payload, contracts, payloads)
        if reused is None:
            continue
        held, by = reused
        try:
            digest = payload_hash(embedded.payload, embedded.attack_patterns, _no_files).hex
        except UnhashablePayloadError:
            found.append(_finding(path, embedded.pointer, NOT_HASHED.format(by=by)))
            continue
        if isinstance(held, HeldContract) and held.payload is None:
            found.append(_finding(path, embedded.pointer, NO_PAYLOAD))
            continue
        other = held.payload if isinstance(held, HeldContract) else held
        try:
            same = payload_hash(other, embedded.attack_patterns, _no_files).hex == digest
        except UnhashablePayloadError:
            found.append(_finding(path, embedded.pointer, UNCOMPARABLE.format(by=by)))
            continue
        if not same:
            found.append(_finding(path, embedded.pointer, OTHER_PAYLOAD.format(by=by)))
    return tuple(found)


def _held(
    contract: Mapping[str, Any],
    payload: object,
    contracts: Mapping[str, HeldContract],
    payloads: Mapping[str, object],
) -> tuple[HeldContract | object, str] | None:
    """What the import would reuse for ``payload``, in the order it looks: the contract under its
    contract ID, then a payload under its external ID. For a step whose payload has output
    parsers, the import looks past a held contract whose payload has none: such a contract never
    has the archive's hash, which counts the parsers, so it is reported before that."""
    contract_id = contract.get(CONTRACT_ID)
    if isinstance(contract_id, str) and contract_id in contracts:
        return contracts[contract_id], "contract ID"
    external_id = payload.get(EXTERNAL_ID) if isinstance(payload, Mapping) else None
    if isinstance(external_id, str) and external_id in payloads:
        return payloads[external_id], "payload external ID"
    return None


def _no_files(document: str) -> str | None:
    return None  # a payload with a file is refused by the archive's checks


def _finding(path: str, field: str, message: str) -> Finding:
    return Finding("OAV-002", Severity.BLOCKING, path, field, message)
