"""The payload catalogue a test's scenarios need: a version file for each payload they embed,
made as `intake` makes the first version of a new payload, so that a test of another rule reads
the catalogue as agreeing."""

from collections.abc import Callable
from pathlib import Path

import yaml

from scenario_tools.domain.catalogue.payload_verdict import claimed_verdicts
from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.shared.finding import Finding
from scenario_tools.domain.verification.payload_catalogue import Catalogue
from scenario_tools.domain.verification.payload_references import AgreedIds, HeldVersions
from scenario_tools.domain.verification.payload_version import PayloadVersion

NONE = AgreedIds({})


def verdicts(
    stored: object,
    catalogue: Catalogue,
    agreed: AgreedIds,
    *,
    accepted: Callable[[object], bool],
) -> tuple[tuple[Finding, ...], dict[str, PayloadVersion]]:
    """The verdicts of ``claimed_verdicts`` without a claim: the findings and the version files
    of the new payloads, by hash."""
    found = claimed_verdicts(stored, catalogue, agreed, accepted=accepted)
    return found.findings, found.versions


def versions(*stored: object, agreed: AgreedIds = NONE) -> list[PayloadVersion]:
    """The version 1.0.0 of each payload the ``stored`` scenarios embed, each once."""
    found: dict[str, PayloadVersion] = {}
    for document in stored:
        _, new = verdicts(document, Catalogue.of([]), agreed, accepted=lambda _: True)
        found.update(new)
    return list(found.values())


def catalogue(*stored: object, agreed: AgreedIds = NONE) -> Catalogue:
    return Catalogue.of(versions(*stored, agreed=agreed))


def held(*stored: object, agreed: AgreedIds = NONE) -> HeldVersions:
    return catalogue(*stored, agreed=agreed).held()


def write_catalogue(root: Path, *stored: object) -> None:
    """Write under ``root/payloads`` the version files of the payloads the ``stored`` scenarios
    embed, with the IDs the repository's registry agrees, if it has one."""
    registry = root / "policy" / "data" / "payload-ids.yaml"
    agreed = (
        AgreedIds.from_document(yaml.safe_load(registry.read_text("utf-8")))
        if registry.is_file()
        else NONE
    )
    for version in versions(*stored, agreed=agreed):
        path = root / version.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(stored_form(dict(version.document)))
