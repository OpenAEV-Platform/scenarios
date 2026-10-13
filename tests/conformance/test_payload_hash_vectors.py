"""The shared test vectors of the canonical payload hash: the repository reproduces each one, as
the platform must. They were written from the specification, not from this code."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.domain.verification.payload_hash import (
    UnhashablePayloadError,
    canonical_payload,
    payload_hash,
)

VECTORS: list[dict[str, Any]] = json.loads(
    (Path(__file__).parents[2] / "conformance" / "payload-hash.json").read_text(encoding="utf-8")
)["vectors"]
ACCEPTED = [vector for vector in VECTORS if "sha256" in vector]
REFUSED = [vector for vector in VECTORS if "refused" in vector]


def _files(vector: dict[str, Any]) -> Any:
    return lambda document: vector["files"].get(document)


def test_the_vectors_cover_every_payload_type_and_every_refusal() -> None:
    assert {vector["payload"]["payload_type"] for vector in ACCEPTED} == {
        "Command",
        "Executable",
        "FileDrop",
        "DnsResolution",
        "NetworkTraffic",
        "AiAttack",
    }
    assert len(REFUSED) == 10


def test_each_vector_hashes_its_own_canonical_text() -> None:
    for vector in ACCEPTED:
        digest = hashlib.sha256(vector["canonical"].encode("utf-8")).hexdigest()
        assert digest == vector["sha256"], vector["name"]


@pytest.mark.parametrize("vector", ACCEPTED, ids=lambda vector: vector["name"])
def test_an_accepted_vector_gives_its_canonical_text_and_hash(vector: dict[str, Any]) -> None:
    canonical = canonical_payload(vector["payload"], vector["attack_patterns"], _files(vector))

    assert jcs(canonical).decode("utf-8") == vector["canonical"]
    assert (
        str(payload_hash(vector["payload"], vector["attack_patterns"], _files(vector)))
        == (vector["sha256"])
    )


@pytest.mark.parametrize("vector", REFUSED, ids=lambda vector: vector["name"])
def test_a_refused_vector_is_refused_at_its_field(vector: dict[str, Any]) -> None:
    with pytest.raises(UnhashablePayloadError) as error:
        canonical_payload(vector["payload"], vector["attack_patterns"], _files(vector))

    assert error.value.field == vector["refused"]
