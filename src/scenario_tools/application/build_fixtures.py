"""The release fixtures: one release accepted as ``build`` writes it, and one release for each way
``verify`` refuses one, with what verifying each must give. They need no secret and are the same
bytes on every build, so that a consumer can check its own verifier against them.

Each fixture is a release, in a directory of its own: ``manifest.json`` and the archives beside
it. ``expected.json``, beside the directories, says what verifying each must give."""

import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scenario_tools.application.assign_payloads import no_attached_files
from scenario_tools.application.fixture_expectations import (
    Expectation,
    ExpectedFinding,
    expectations_document,
)
from scenario_tools.domain.release.manifest import PayloadFile, payload_entry
from scenario_tools.domain.shared.canonical import jcs, stored_form
from scenario_tools.domain.shared.stored import STEP_DATA, STEPS, WORKFLOW
from scenario_tools.domain.verification.payload_hash import payload_hash
from scenario_tools.domain.verification.payload_references import derived_id
from scenario_tools.ports.archive import ArchiveBuilder, FixtureArchives

EXPECTED = "expected.json"
MANIFEST = "manifest.json"
PASSWORD = b"infected"  # the attachments' shared password, which is public
BOMB_SIZE = 101 * 1024 * 1024  # beyond the 100 MiB a verifier extracts
UNDECLARED_SIZE = 2 * 1024 * 1024  # what a bomb inflates to beyond the 1 KiB it declares
CROWD = 1001  # entries, beyond the 1,000 a verifier reads
FIRST, SECOND = "5f0c7a3e-1b2d-4c8e-9f60-0a1b2c3d4e5f", "6a1d8b4f-2c3e-4d9f-8a71-1b2c3d4e5f60"
CHAINED = "7b2e9c5a-3d4f-4e0a-9b82-2c3d4e5f6071"  # a scenario in chaining
_FIRST_STEP, _SECOND_STEP = (
    "00000000-0000-4000-8000-0000000000a1",
    "00000000-0000-4000-8000-0000000000b1",
)
_TECHNIQUE = "T1059"
_CONTRACT = "/scenario_injects/0/inject_injector_contract/injector_contract_payload"


@dataclass(frozen=True)
class Fixture:
    """A release, by its files, and what verifying it must give."""

    expectation: Expectation
    files: Mapping[str, bytes]

    @property
    def name(self) -> str:
        return self.expectation.name


def _fixture(
    name: str,
    description: str,
    files: Mapping[str, bytes],
    *findings: ExpectedFinding,
    approved: bool = False,
) -> Fixture:
    return Fixture(Expectation(name, description, findings, approved), files)


def _payload(command: str = "echo fixture") -> dict[str, Any]:
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
    payload["payload_external_id"] = derived_id(_hash(payload))
    return payload


def _hash(payload: Mapping[str, Any]) -> str:
    return payload_hash(payload, [_TECHNIQUE], no_attached_files).hex


_SLUG = "fixture-command"


def _version(
    payload: Mapping[str, Any], version: str = "1.0.0", slug: str = _SLUG
) -> tuple[dict[str, Any], bytes]:
    """The manifest entry of ``payload`` as the version ``version`` of the payload ``slug``, and
    its file's bytes, as the catalogue stores it."""
    document = {**payload, "payload_attack_patterns": [_TECHNIQUE]}
    data = stored_form(document)
    found = PayloadFile(slug, version, _hash(payload), str(payload["payload_external_id"]), data)
    return payload_entry(found), data


Catalogue = Sequence[tuple[Mapping[str, Any], bytes]]
_CATALOGUE: Catalogue = (_version(_payload()),)  # the fixture payload, the one version


def _scenario(external_id: str, *payloads: Mapping[str, Any], **parts: Any) -> dict[str, Any]:
    """A stored scenario, one inject running each payload, with ``parts`` added or replaced."""
    injects = [
        {
            "inject_title": f"Run {payload['payload_name']}",
            "inject_injector_contract": {
                "injector_contract_attack_patterns": [{"attack_pattern_external_id": _TECHNIQUE}],
                "injector_contract_payload": dict(payload),
            },
        }
        for payload in payloads
    ]
    information = {"scenario_name": f"Fixture {external_id[:8]}", "scenario_severity": "low"}
    return {"scenario_information": information, "scenario_injects": injects, **parts}


def _step(identifier: str, payload: Mapping[str, Any], *awaited: str) -> dict[str, Any]:
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
                "injector_contract_attack_patterns": [{"attack_pattern_external_id": _TECHNIQUE}],
                "injector_contract_payload": dict(payload),
            },
        },
    }


def _chained(first: Mapping[str, Any], second: Mapping[str, Any], **parts: Any) -> dict[str, Any]:
    """A stored scenario in chaining: two steps, the second waiting for the first."""
    information = {"scenario_name": f"Fixture {CHAINED[:8]}", "scenario_severity": "low"}
    workflow = {
        "workflow_safe_mode_enabled": True,
        STEPS: [_step(_FIRST_STEP, first), _step(_SECOND_STEP, second, _FIRST_STEP)],
    }
    return {
        "scenario_information": information,
        "scenario_injects": [],
        WORKFLOW: workflow,
        **parts,
    }


def _item(
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
            {"id": p["payload_external_id"], "version": "1.0.0", "sha256": _hash(p)}
            for p in payloads
        ],
        "platforms": ["Linux"],
        "requires": {"edition": "CE", "executors": [], "injectors": [], "openaev": ">=3.261005.0"},
        "severity": "low",
        "status": "VERIFIED",
        "tabletop": False,
        "threat": {"ttps": [_TECHNIQUE]},
        "type": "time-based",
        "version": "1.0.0",
    }


def _manifest(
    items: Sequence[Mapping[str, Any]], catalogue: Catalogue = _CATALOGUE, **fields: Any
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


def _carried(catalogue: Catalogue = _CATALOGUE) -> dict[str, bytes]:
    """The payload files of ``catalogue``, by their names."""
    return {str(entry["file"]["name"]): data for entry, data in catalogue}


def _release(
    items: Sequence[tuple[Mapping[str, Any], bytes]],
    catalogue: Catalogue = _CATALOGUE,
    beside: Mapping[str, bytes] | None = None,
) -> dict[str, bytes]:
    """The files of a release whose items are listed with their archives, and the versions of
    ``catalogue`` with their files, and the files ``beside`` them that nothing lists."""
    files = {str(item["archive"]["name"]): archive for item, archive in items}
    manifest = _manifest([item for item, _ in items], catalogue)
    return {MANIFEST: manifest, **files, **_carried(catalogue), **(beside or {})}


class FixtureBuilder:
    """The fixtures, from the archives ``build`` writes and those written by hand."""

    def __init__(self, builder: ArchiveBuilder, archives: FixtureArchives) -> None:
        self._builder, self._archives = builder, archives
        self._payload = _payload()
        self._changed = dict(self._payload, command_content="echo changed")  # its ID kept
        self._item, self._archive = self._entry(FIRST)
        self._name = str(self._item["archive"]["name"])
        self._scenario = jcs(_scenario(FIRST, self._payload))

    def fixtures(self) -> tuple[Fixture, ...]:
        """The accepted release first, then each refusal, family by family."""
        return (
            self._accepted(),
            *self._archives_listed(),
            *self._archives_unsafe(),
            *self._payloads(),
            *self._payload_files(),
            *self._chaining(),
            *self._manifests(),
        )

    def _built(self, scenario: Mapping[str, Any], attachments: bytes | None = None) -> bytes:
        return self._builder.build(jcs(scenario), attachments)

    def _entry(
        self,
        external_id: str,
        scenario: Mapping[str, Any] | None = None,
        payloads: Sequence[Mapping[str, Any]] | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        """An item and its archive: by default, the scenario embedding the fixture payload,
        listed."""
        held = scenario if scenario is not None else _scenario(external_id, self._payload)
        archive = self._built(held)
        listed = payloads if payloads is not None else [self._payload]
        return _item(external_id, archive, listed), archive

    def _holding(self, archive: bytes) -> dict[str, bytes]:
        """The release of one item whose archive, listed as it is, is ``archive``."""
        return _release([(_item(FIRST, archive, [self._payload]), archive)])

    def _unsafe(self, name: str, description: str, archive: bytes, cause: str) -> Fixture:
        expected = ExpectedFinding("VRF-007", self._name, "", cause)
        return _fixture(name, description, self._holding(archive), expected)

    def _accepted(self) -> Fixture:
        attachments = self._archives.attachments({"notes.txt": b"Fixture notes.\n"}, PASSWORD)
        with_attachments = self._built(_scenario(SECOND, self._payload), attachments)
        items = [
            (self._item, self._archive),
            (_item(SECOND, with_attachments, [self._payload]), with_attachments),
        ]
        files = {
            MANIFEST: _manifest(
                [item for item, _ in items], release_approver="fixture-release-approver"
            ),
            **{str(item["archive"]["name"]): archive for item, archive in items},
            **_carried(),
        }
        return _fixture(
            "accepted",
            "An approved release of two scenarios sharing one payload, one with attachments.",
            files,
            approved=True,
        )

    def _archives_listed(self) -> list[Fixture]:
        def listed_with(**fields: Any) -> dict[str, Any]:
            item = copy.deepcopy(self._item)
            item["archive"].update(fields)
            return item

        another = hashlib.sha256(b"another archive").hexdigest()
        refused = ExpectedFinding("VRF-006", self._name)
        return [
            _fixture(
                "archive-sha256",
                "An archive whose SHA-256 is not the one the manifest lists.",
                _release([(listed_with(sha256=another), self._archive)]),
                refused,
            ),
            _fixture(
                "archive-size",
                "An archive whose size is not the one the manifest lists.",
                _release([(listed_with(size=len(self._archive) + 1), self._archive)]),
                refused,
            ),
            _fixture(
                "archive-missing",
                "An archive the manifest lists, missing.",
                {MANIFEST: _manifest([self._item]), **_carried()},
                refused,
            ),
            _fixture(
                "file-not-listed",
                "A file beside the archives that the manifest does not list.",
                _release([(self._item, self._archive)], beside={"notes.txt": b"Not listed.\n"}),
                ExpectedFinding("VRF-006", "notes.txt"),
            ),
        ]

    def _archives_unsafe(self) -> list[Fixture]:
        scenario, stored = self._scenario, self._archives.stored
        crowd = [(f"extra-{index:04}.txt", b"", b"") for index in range(CROWD - 1)]
        other_password = self._archives.attachments({"notes.txt": b"Notes.\n"}, b"another")
        return [
            self._unsafe(
                "path-traversal",
                "An archive whose scenario entry leaves the extraction directory.",
                stored([("../scenario.json", scenario, b"Scenario")]),
                "IO-010",
            ),
            self._unsafe(
                "decompression-bomb",
                "An archive under 1 MiB whose scenario entry is over 100 MiB once inflated.",
                self._archives.bomb("scenario.json", b"Scenario", BOMB_SIZE),
                "IO-008",
            ),
            self._unsafe(
                "decompression-bomb-undeclared",
                "An archive whose scenario entry inflates beyond the size it declares.",
                self._archives.bomb("scenario.json", b"Scenario", UNDECLARED_SIZE, declared=1024),
                "IO-008",
            ),
            self._unsafe(
                "too-many-entries",
                "An archive of more than 1,000 entries.",
                stored([("scenario.json", scenario, b"Scenario"), *crowd]),
                "IO-009",
            ),
            self._unsafe(
                "entry-link",
                "An archive whose attachments entry is a symbolic link.",
                stored(
                    [("scenario.json", scenario, b"Scenario"), ("attachments.zip", b"/etc", b"")],
                    links=frozenset({"attachments.zip"}),
                ),
                "IO-011",
            ),
            self._unsafe(
                "entry-twice",
                "An archive holding two entries of one name.",
                stored([("scenario.json", scenario, b"Scenario")] * 2),
                "IO-012",
            ),
            self._unsafe(
                "entry-not-built",
                "An archive holding an entry build never writes.",
                stored([("scenario.json", scenario, b"Scenario"), ("run.sh", b"exit 0\n", b"")]),
                "IO-014",
            ),
            self._unsafe(
                "attachments-password",
                "Attachments encrypted with another password than the shared one.",
                self._built(_scenario(FIRST, self._payload), other_password),
                "IO-007",
            ),
            self._unsafe(
                "scenario-part",
                "A scenario with a part outside the closed list of a stored scenario.",
                self._built(_scenario(FIRST, self._payload, scenario_exercises=[{}])),
                "IO-014",
            ),
        ]

    def _payloads(self) -> list[Fixture]:
        payload, changed = self._payload, self._changed
        unnamed = {key: value for key, value in payload.items() if key != "payload_external_id"}
        unhashable = dict(payload, payload_platforms="Linux")
        carried = {"scenario_name": "Fixture", "carried": {"injector_contract_payload": payload}}
        return [
            _fixture(
                "payload-content",
                "A payload whose content is not the one the hash listed for its ID describes.",
                _release([self._entry(FIRST, _scenario(FIRST, changed))]),
                ExpectedFinding("VRF-008", self._name, _CONTRACT),
            ),
            _fixture(
                "payload-not-listed",
                "A payload embedded in an archive that the manifest does not list.",
                _release([self._entry(FIRST, payloads=[])]),
                ExpectedFinding("VRF-008", self._name, _CONTRACT),
            ),
            _fixture(
                "payload-not-embedded",
                "A payload the manifest lists that the archive does not embed.",
                _release([self._entry(FIRST, _scenario(FIRST))]),
                ExpectedFinding("VRF-008", self._name),
            ),
            _fixture(
                "payload-without-id",
                "A payload embedded without its ID, which no manifest can list.",
                _release([self._entry(FIRST, _scenario(FIRST, unnamed), payloads=[])]),
                ExpectedFinding("VRF-008", self._name, _CONTRACT),
            ),
            _fixture(
                "payload-unhashable",
                "A payload whose canonical hash cannot be computed.",
                _release([self._entry(FIRST, _scenario(FIRST, unhashable))]),
                ExpectedFinding("VRF-008", self._name, f"{_CONTRACT}/payload_platforms"),
            ),
            _fixture(
                "payload-listed-twice",
                "A payload an item lists twice.",
                _release([self._entry(FIRST, payloads=[payload, payload])]),
                ExpectedFinding("VRF-008", self._name),
            ),
            _fixture(
                "payload-outside-contract",
                "A payload outside an inject's contract, which no reference names.",
                _release(
                    [self._entry(FIRST, _scenario(FIRST, payload, scenario_information=carried))]
                ),
                ExpectedFinding("VRF-008", self._name, "/scenario_information/carried"),
            ),
            _fixture(
                "payload-two-contents",
                "One payload ID listed with two contents by two scenarios of the release.",
                _release(
                    [
                        (self._item, self._archive),
                        self._entry(SECOND, _scenario(SECOND, changed), payloads=[changed]),
                    ]
                ),
                ExpectedFinding("VRF-008", MANIFEST, "/items/1/payloads/0"),
            ),
        ]

    def _payload_files(self) -> list[Fixture]:
        payload, changed = self._payload, self._changed
        entry, data = _version(payload)
        name = str(entry["file"]["name"])
        other_bytes = data.replace(b"Prints a word", b"Prints a verb")
        relisted = copy.deepcopy(entry)
        relisted["file"].update(sha256=hashlib.sha256(other_bytes).hexdigest())
        relisted["file"].update(size=len(other_bytes))
        other_id = stored_form({**json.loads(data), "payload_external_id": "another-id"})
        listed_id = copy.deepcopy(entry)
        listed_id["file"].update(sha256=hashlib.sha256(other_id).hexdigest(), size=len(other_id))
        misnamed = copy.deepcopy(entry)
        misnamed["file"]["name"] = "fixture-command-2.0.0.json"
        later, later_data = _version(payload, "1.1.0")
        copied, copied_data = _version({**payload, "payload_external_id": "copied"}, slug="copied")
        domains = {**payload, "payload_domains": [{"domain_name": "Endpoint"}]}
        again, again_data = _version(domains, slug="again")
        unused_payload = {**changed, "payload_name": "Unused", "payload_external_id": "unused"}
        unused, unused_data = _version(unused_payload, slug="unused")
        listed = [(self._item, self._archive)]
        return [
            _fixture(
                "catalogue-accepted",
                "A release whose payload catalogue lists a version used by a time-based scenario "
                "and a step of a scenario in chaining, and a version no scenario uses.",
                _release(
                    [(self._item, self._archive), self._chained_entry()],
                    [(entry, data), (unused, unused_data)],
                ),
            ),
            _fixture(
                "payload-file-missing",
                "A payload file the manifest lists, missing.",
                {key: value for key, value in _release(listed).items() if key != name},
                ExpectedFinding("VRF-006", name),
            ),
            _fixture(
                "payload-file-sha256",
                "A payload file whose bytes are not the ones the manifest lists.",
                _release(listed, [(entry, other_bytes)]),
                ExpectedFinding("VRF-006", name),
            ),
            _fixture(
                "payload-file-content",
                "A payload file listed by its bytes whose content has another hash than listed.",
                _release(listed, [(relisted, other_bytes)]),
                ExpectedFinding("VRF-008", name),
            ),
            _fixture(
                "payload-file-id",
                "A payload file listed by its bytes that holds another ID than listed.",
                _release(listed, [(listed_id, other_id)]),
                ExpectedFinding("VRF-008", name),
            ),
            _fixture(
                "payload-file-name",
                "A payload file named after another version than its own.",
                _release(listed, [(misnamed, data)]),
                ExpectedFinding("VRF-006", MANIFEST, "/payloads/0/file/name"),
            ),
            _fixture(
                "payload-version-twice",
                "A payload version the manifest lists twice.",
                _release(listed, [(entry, data), (entry, data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/payloads/1"),
            ),
            _fixture(
                "payload-id-two-versions",
                "One payload ID listed with two versions.",
                _release(listed, [(entry, data), (later, later_data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/payloads/1"),
            ),
            _fixture(
                "payload-content-two-ids",
                "One payload content listed under two IDs.",
                _release(listed, [(entry, data), (copied, copied_data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/payloads/1"),
            ),
            _fixture(
                "payload-id-two-files",
                "One payload ID listed at one version and hash with two files.",
                _release(listed, [(again, again_data), (entry, data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/payloads/1"),
            ),
            _fixture(
                "payload-version-not-listed",
                "An item that references a payload version the release does not list.",
                _release(listed, [(unused, unused_data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/items/0/payloads/0"),
            ),
            _fixture(
                "payload-file-not-listed",
                "A payload file beside the archives that the manifest lists nowhere.",
                _release(listed, beside={"unused-1.0.0.json": unused_data}),
                ExpectedFinding("VRF-006", "unused-1.0.0.json"),
            ),
        ]

    def _chained_entry(
        self,
        scenario: Mapping[str, Any] | None = None,
        payloads: Sequence[Mapping[str, Any]] | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        """The item and archive of the scenario in chaining: by default, both steps running the
        fixture payload, listed once."""
        held = scenario if scenario is not None else _chained(self._payload, self._payload)
        archive = self._built(held)
        listed = payloads if payloads is not None else [self._payload]
        item = _item(CHAINED, archive, listed)
        item["type"] = "chained"
        item["requires"] = {**item["requires"], "edition": "EE"}
        return item, archive

    def _chaining(self) -> list[Fixture]:
        payload, changed = self._payload, self._changed
        name = f"{CHAINED}-1.0.0.zip"
        steps = f"/{WORKFLOW}/{STEPS}"
        first = f"{steps}/0/{STEP_DATA}/inject_injector_contract/injector_contract_payload"
        second = f"{steps}/1/{STEP_DATA}/inject_injector_contract/injector_contract_payload"
        hidden = copy.deepcopy(_chained(payload, payload))
        hidden[WORKFLOW][STEPS][0][STEP_DATA]["inject_content"] = {
            "carried": {"injector_contract_payload": payload}
        }
        as_text = copy.deepcopy(_chained(payload, payload))
        for step in as_text[WORKFLOW][STEPS]:
            step[STEP_DATA] = json.dumps(step[STEP_DATA])
        return [
            _fixture(
                "chaining-accepted",
                "A release of a scenario in chaining, two steps one after the other, sharing its "
                "payload with a time-based scenario.",
                _release([(self._item, self._archive), self._chained_entry()]),
            ),
            _fixture(
                "chaining-payload-not-listed",
                "A scenario in chaining whose steps embed a payload the manifest does not list.",
                _release([self._chained_entry(payloads=[])]),
                ExpectedFinding("VRF-008", name, first),
                ExpectedFinding("VRF-008", name, second),
            ),
            _fixture(
                "chaining-payload-content",
                "A step whose payload is not the one the hash listed for its ID describes.",
                _release([self._chained_entry(_chained(changed, payload))]),
                ExpectedFinding("VRF-008", name, first),
            ),
            _fixture(
                "chaining-payload-outside-contract",
                "A step that carries a payload outside its contract, which no reference names.",
                _release([self._chained_entry(hidden)]),
                ExpectedFinding("VRF-008", name, f"{steps}/0/{STEP_DATA}/inject_content/carried"),
            ),
            _fixture(
                "chaining-workflow-shape",
                "A scenario in chaining whose steps are not a list.",
                _release(
                    [self._chained_entry({**_chained(payload, payload), WORKFLOW: {STEPS: ""}})]
                ),
                ExpectedFinding("VRF-007", name, "", "IO-014"),
            ),
            _fixture(
                "chaining-step-data-text",
                "A scenario in chaining whose steps keep their data as text, as an export writes "
                "it, which would hide their payloads from a reader of objects.",
                _release([self._chained_entry(as_text)]),
                ExpectedFinding("VRF-007", name, "", "IO-014"),
            ),
            _fixture(
                "chaining-scenario-part",
                "A scenario in chaining that also holds a part outside the closed list of a stored "
                "scenario: the workflow does not open the list.",
                _release(
                    [self._chained_entry(_chained(payload, payload, scenario_exercises=[{}]))]
                ),
                ExpectedFinding("VRF-007", name, "", "IO-014"),
            ),
        ]

    def _manifests(self) -> list[Fixture]:
        item, archive, name = self._item, self._archive, self._name
        renamed = copy.deepcopy(item)
        renamed["archive"]["name"] = f"{FIRST}-2.0.0.zip"
        return [
            _fixture(
                "manifest-schema",
                "A manifest that does not meet its schema: an unknown channel.",
                {MANIFEST: _manifest([item], channel="nightly"), name: archive, **_carried()},
                ExpectedFinding("VRF-009", MANIFEST, "/channel"),
            ),
            _fixture(
                "approver-missing",
                "A release verified as approved whose manifest names no release approver.",
                _release([(item, archive)]),
                ExpectedFinding("VRF-009", MANIFEST, "/release_approver"),
                approved=True,
            ),
            _fixture(
                "scenario-twice",
                "A manifest listing one scenario twice.",
                {MANIFEST: _manifest([item, item]), name: archive, **_carried()},
                ExpectedFinding("VRF-009", MANIFEST, "/items/1"),
            ),
            _fixture(
                "archive-name",
                "An archive named after another version than its item's.",
                {MANIFEST: _manifest([renamed]), f"{FIRST}-2.0.0.zip": archive, **_carried()},
                ExpectedFinding("VRF-009", MANIFEST, "/items/0/archive/name"),
            ),
        ]


def release_fixtures(builder: ArchiveBuilder, archives: FixtureArchives) -> tuple[Fixture, ...]:
    """The fixtures, the accepted release first, then each refusal."""
    return FixtureBuilder(builder, archives).fixtures()


def fixture_files(fixtures: Sequence[Fixture]) -> dict[str, bytes]:
    """Every file of the fixtures, by its path: each fixture's in its directory, and
    ``expected.json`` beside them."""
    files = {
        f"{fixture.name}/{name}": data
        for fixture in fixtures
        for name, data in fixture.files.items()
    }
    document = expectations_document([fixture.expectation for fixture in fixtures])
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    return {**files, EXPECTED: text.encode("utf-8")}
