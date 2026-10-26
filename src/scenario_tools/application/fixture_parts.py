"""The parts the release fixtures are made of: their payload, scenarios with and without a workflow,
manifest items, manifests and releases, all the same bytes on every build."""

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scenario_tools.application.assign_payloads import no_attached_files
from scenario_tools.application.fixture_expectations import Expectation, ExpectedFinding
from scenario_tools.domain.release.manifest import PayloadFile, payload_entry
from scenario_tools.domain.shared.canonical import jcs, stored_form
from scenario_tools.domain.shared.stored import STEP_DATA, STEPS, WORKFLOW
from scenario_tools.domain.verification.payload_hash import payload_hash
from scenario_tools.domain.verification.payload_references import derived_id

EXPECTED = "expected.json"
MANIFEST = "manifest.json"
PASSWORD = b"infected"  # the attachments' shared password, which is public
BOMB_SIZE = 101 * 1024 * 1024  # beyond the 100 MiB a verifier extracts
UNDECLARED_SIZE = 2 * 1024 * 1024  # what a bomb inflates to beyond the 1 KiB it declares
CROWD = 1001  # entries, beyond the 1,000 a verifier reads
FIRST, SECOND = "5f0c7a3e-1b2d-4c8e-9f60-0a1b2c3d4e5f", "6a1d8b4f-2c3e-4d9f-8a71-1b2c3d4e5f60"
CHAINED = "7b2e9c5a-3d4f-4e0a-9b82-2c3d4e5f6071"  # a scenario in chaining
FIRST_STEP, SECOND_STEP = (
    "00000000-0000-4000-8000-0000000000a1",
    "00000000-0000-4000-8000-0000000000b1",
)
TECHNIQUE = "T1059"
PAYLOAD_POINTER = "/scenario_injects/0/inject_injector_contract/injector_contract_payload"


@dataclass(frozen=True)
class Fixture:
    """A release, by its files, and what verifying it must give."""

    expectation: Expectation
    files: Mapping[str, bytes]

    @property
    def name(self) -> str:
        return self.expectation.name


def make_fixture(
    name: str,
    description: str,
    files: Mapping[str, bytes],
    *findings: ExpectedFinding,
    approved: bool = False,
) -> Fixture:
    return Fixture(Expectation(name, description, findings, approved), files)


def fixture_payload(command: str = "echo fixture") -> dict[str, Any]:
    """A payload of the fixtures, carrying the ID its content has."""
    payload: dict[str, Any] = {
        "command_content": command,
        "command_executor": "sh",
        "payload_description": "Prints a word, and does nothing else.",
        "payload_elevation_required": False,
        "payload_execution_arch": "ALL_ARCHITECTURES",
        "payload_expectations": ["PREVENTION"],
        "payload_name": "Fixture command",
        "payload_platforms": ["Linux"],
        "payload_type": "Command",
    }
    payload["payload_external_id"] = derived_id(fixture_hash(payload))
    return payload


def fixture_hash(payload: Mapping[str, Any]) -> str:
    return payload_hash(payload, [TECHNIQUE], no_attached_files).hex


SLUG = "fixture-command"


def fixture_version(
    payload: Mapping[str, Any], version: str = "1.0.0", slug: str = SLUG
) -> tuple[dict[str, Any], bytes]:
    """The manifest entry of ``payload`` as the version ``version`` of the payload ``slug``, and
    its file's bytes, as the catalogue stores it."""
    document = {**payload, "payload_attack_patterns": [TECHNIQUE]}
    data = stored_form(document)
    found = PayloadFile(
        slug, version, fixture_hash(payload), str(payload["payload_external_id"]), data
    )
    return payload_entry(found), data


Catalogue = Sequence[tuple[Mapping[str, Any], bytes]]
CATALOGUE: Catalogue = (fixture_version(fixture_payload()),)  # the fixture payload, the one version


def fixture_scenario(
    external_id: str, *payloads: Mapping[str, Any], **parts: Any
) -> dict[str, Any]:
    """A stored scenario, one inject running each payload, with ``parts`` added or replaced."""
    injects = [
        {
            "inject_title": f"Run {payload['payload_name']}",
            "inject_injector_contract": {
                "injector_contract_attack_patterns": [{"attack_pattern_external_id": TECHNIQUE}],
                "injector_contract_payload": dict(payload),
            },
        }
        for payload in payloads
    ]
    information = {"scenario_name": f"Fixture {external_id[:8]}", "scenario_severity": "low"}
    return {"scenario_information": information, "scenario_injects": injects, **parts}


def fixture_step(identifier: str, payload: Mapping[str, Any], *awaited: str) -> dict[str, Any]:
    """A step running ``payload``, after the steps ``awaited``: only what ``verify`` reads, not
    every field an export carries."""
    condition = f"{identifier[:-1]}c"  # the step's ID, its last digit changed
    return {
        "step_id": identifier,
        "step_action_class": "INJECT_EXECUTION",
        "step_conditions": [
            {
                "condition_id": condition,
                "condition_type": "DEPEND_ON",
                "condition_value": step,
                "condition_is_root": True,
                "condition_parent_id": None,
                "condition_step_from_id": None,
            }
            for step in awaited
        ],
        STEP_DATA: {
            "inject_title": f"Run {payload['payload_name']}",
            "inject_injector_contract": {
                "injector_contract_attack_patterns": [{"attack_pattern_external_id": TECHNIQUE}],
                "injector_contract_payload": dict(payload),
            },
        },
    }


def chained_scenario(
    first: Mapping[str, Any], second: Mapping[str, Any], **parts: Any
) -> dict[str, Any]:
    """A stored scenario in chaining: two steps, the second waiting for the first."""
    information = {"scenario_name": f"Fixture {CHAINED[:8]}", "scenario_severity": "low"}
    workflow = {
        "workflow_safe_mode_enabled": True,
        STEPS: [fixture_step(FIRST_STEP, first), fixture_step(SECOND_STEP, second, FIRST_STEP)],
    }
    return {
        "scenario_information": information,
        "scenario_injects": [],
        WORKFLOW: workflow,
        **parts,
    }


def fixture_item(
    external_id: str, archive: bytes, payloads: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """The manifest item, at version 1.0.0, of a scenario whose archive is ``archive``."""
    return {
        "approvals": {"approvers": ["fixture-maintainer"], "pull_request": 1},
        "archive": {
            "name": f"{external_id}-1.0.0.zip",
            "sha256": hashlib.sha256(archive).hexdigest(),
            "size": len(archive),
        },
        "category": "attack-scenario",
        "description": "A scenario of the release fixtures, never meant to run.",
        "external_id": external_id,
        "main_focus": "endpoint-protection",
        "name": f"Fixture {external_id[:8]}",
        "payloads": [
            {"id": p["payload_external_id"], "version": "1.0.0", "sha256": fixture_hash(p)}
            for p in payloads
        ],
        "platforms": ["Linux"],
        "requires": {"edition": "CE", "executors": [], "injectors": [], "openaev": ">=3.261005.0"},
        "severity": "low",
        "status": "VERIFIED",
        "tabletop": False,
        "threat": {"ttps": [TECHNIQUE]},
        "type": "time-based",
        "version": "1.0.0",
    }


def fixture_manifest(
    items: Sequence[Mapping[str, Any]], catalogue: Catalogue = CATALOGUE, **fields: Any
) -> bytes:
    document = {
        "schema_version": 1,
        "repository": "OpenAEV-Platform/scenarios",
        "channel": "edge",
        "issued_at": "2026-01-01T00:00:00Z",
        "release": "2026.01.01.1",
        "items": sorted(items, key=lambda item: str(item["external_id"])),
        "payloads": [entry for entry, _ in catalogue],
        **fields,
    }
    return jcs(document)


def fixture_carried(catalogue: Catalogue = CATALOGUE) -> dict[str, bytes]:
    """The payload files of ``catalogue``, by their names."""
    return {str(entry["file"]["name"]): data for entry, data in catalogue}


def fixture_release(
    items: Sequence[tuple[Mapping[str, Any], bytes]],
    catalogue: Catalogue = CATALOGUE,
    beside: Mapping[str, bytes] | None = None,
) -> dict[str, bytes]:
    """The files of a release whose items are listed with their archives, and the versions of
    ``catalogue`` with their files, and the files ``beside`` them that nothing lists."""
    files = {str(item["archive"]["name"]): archive for item, archive in items}
    manifest = fixture_manifest([item for item, _ in items], catalogue)
    return {MANIFEST: manifest, **files, **fixture_carried(catalogue), **(beside or {})}
