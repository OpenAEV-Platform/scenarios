"""The release fixtures: one release accepted as ``build`` writes it, and one release for each way
``verify`` refuses one, with what verifying each must give. They need no secret and are the same
bytes on every build, so that a consumer can check its own verifier against them.

Each fixture is a release, in a directory of its own: ``manifest.json`` and the archives beside
it. ``expected.json``, beside the directories, says what verifying each must give."""

import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from scenario_tools.application.fixture_expectations import ExpectedFinding, expectations_document
from scenario_tools.application.fixture_parts import (
    BOMB_SIZE,
    CHAINED,
    CROWD,
    EXPECTED,
    FIRST,
    MANIFEST,
    PASSWORD,
    PAYLOAD_POINTER,
    SECOND,
    UNDECLARED_SIZE,
    Fixture,
    chained_scenario,
    fixture_carried,
    fixture_item,
    fixture_manifest,
    fixture_payload,
    fixture_release,
    fixture_scenario,
    fixture_version,
    make_fixture,
)
from scenario_tools.domain.shared.canonical import jcs, stored_form
from scenario_tools.domain.shared.stored import STEP_DATA, STEPS, WORKFLOW
from scenario_tools.ports.archive import ArchiveBuilder, FixtureArchives


class FixtureBuilder:
    """The fixtures, from the archives ``build`` writes and those written by hand."""

    def __init__(self, builder: ArchiveBuilder, archives: FixtureArchives) -> None:
        self._builder, self._archives = builder, archives
        self._payload = fixture_payload()
        self._changed = dict(self._payload, command_content="echo changed")  # its ID kept
        self._item, self._archive = self._entry(FIRST)
        self._name = str(self._item["archive"]["name"])
        self._scenario = jcs(fixture_scenario(FIRST, self._payload))

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
        held = scenario if scenario is not None else fixture_scenario(external_id, self._payload)
        archive = self._built(held)
        listed = payloads if payloads is not None else [self._payload]
        return fixture_item(external_id, archive, listed), archive

    def _holding(self, archive: bytes) -> dict[str, bytes]:
        """The release of one item whose archive, listed as it is, is ``archive``."""
        return fixture_release([(fixture_item(FIRST, archive, [self._payload]), archive)])

    def _unsafe(self, name: str, description: str, archive: bytes, cause: str) -> Fixture:
        expected = ExpectedFinding("VRF-007", self._name, "", cause)
        return make_fixture(name, description, self._holding(archive), expected)

    def _accepted(self) -> Fixture:
        attachments = self._archives.attachments({"notes.txt": b"Fixture notes.\n"}, PASSWORD)
        with_attachments = self._built(fixture_scenario(SECOND, self._payload), attachments)
        items = [
            (self._item, self._archive),
            (fixture_item(SECOND, with_attachments, [self._payload]), with_attachments),
        ]
        files = {
            MANIFEST: fixture_manifest(
                [item for item, _ in items], release_approver="fixture-release-approver"
            ),
            **{str(item["archive"]["name"]): archive for item, archive in items},
            **fixture_carried(),
        }
        return make_fixture(
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
            make_fixture(
                "archive-sha256",
                "An archive whose SHA-256 is not the one the manifest lists.",
                fixture_release([(listed_with(sha256=another), self._archive)]),
                refused,
            ),
            make_fixture(
                "archive-size",
                "An archive whose size is not the one the manifest lists.",
                fixture_release([(listed_with(size=len(self._archive) + 1), self._archive)]),
                refused,
            ),
            make_fixture(
                "archive-missing",
                "An archive the manifest lists, missing.",
                {MANIFEST: fixture_manifest([self._item]), **fixture_carried()},
                refused,
            ),
            make_fixture(
                "file-not-listed",
                "A file beside the archives that the manifest does not list.",
                fixture_release(
                    [(self._item, self._archive)], beside={"notes.txt": b"Not listed.\n"}
                ),
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
                self._built(fixture_scenario(FIRST, self._payload), other_password),
                "IO-007",
            ),
            self._unsafe(
                "scenario-part",
                "A scenario with a part outside the closed list of a stored scenario.",
                self._built(fixture_scenario(FIRST, self._payload, scenario_exercises=[{}])),
                "IO-014",
            ),
        ]

    def _payloads(self) -> list[Fixture]:
        payload, changed = self._payload, self._changed
        unnamed = {key: value for key, value in payload.items() if key != "payload_external_id"}
        unhashable = dict(payload, payload_platforms="Linux")
        carried = {"scenario_name": "Fixture", "carried": {"injector_contract_payload": payload}}
        return [
            make_fixture(
                "payload-content",
                "A payload whose content is not the one the hash listed for its ID describes.",
                fixture_release([self._entry(FIRST, fixture_scenario(FIRST, changed))]),
                ExpectedFinding("VRF-008", self._name, PAYLOAD_POINTER),
            ),
            make_fixture(
                "payload-not-listed",
                "A payload embedded in an archive that the manifest does not list.",
                fixture_release([self._entry(FIRST, payloads=[])]),
                ExpectedFinding("VRF-008", self._name, PAYLOAD_POINTER),
            ),
            make_fixture(
                "payload-not-embedded",
                "A payload the manifest lists that the archive does not embed.",
                fixture_release([self._entry(FIRST, fixture_scenario(FIRST))]),
                ExpectedFinding("VRF-008", self._name),
            ),
            make_fixture(
                "payload-without-id",
                "A payload embedded without its ID, which no manifest can list.",
                fixture_release(
                    [self._entry(FIRST, fixture_scenario(FIRST, unnamed), payloads=[])]
                ),
                ExpectedFinding("VRF-008", self._name, PAYLOAD_POINTER),
            ),
            make_fixture(
                "payload-unhashable",
                "A payload whose canonical hash cannot be computed.",
                fixture_release([self._entry(FIRST, fixture_scenario(FIRST, unhashable))]),
                ExpectedFinding("VRF-008", self._name, f"{PAYLOAD_POINTER}/payload_platforms"),
            ),
            make_fixture(
                "payload-listed-twice",
                "A payload an item lists twice.",
                fixture_release([self._entry(FIRST, payloads=[payload, payload])]),
                ExpectedFinding("VRF-008", self._name),
            ),
            make_fixture(
                "payload-outside-contract",
                "A payload outside an inject's contract, which no reference names.",
                fixture_release(
                    [
                        self._entry(
                            FIRST, fixture_scenario(FIRST, payload, scenario_information=carried)
                        )
                    ]
                ),
                ExpectedFinding("VRF-008", self._name, "/scenario_information/carried"),
            ),
            make_fixture(
                "payload-two-contents",
                "One payload ID listed with two contents by two scenarios of the release.",
                fixture_release(
                    [
                        (self._item, self._archive),
                        self._entry(SECOND, fixture_scenario(SECOND, changed), payloads=[changed]),
                    ]
                ),
                ExpectedFinding("VRF-008", MANIFEST, "/items/1/payloads/0"),
            ),
        ]

    def _payload_files(self) -> list[Fixture]:
        payload, changed = self._payload, self._changed
        entry, data = fixture_version(payload)
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
        later, later_data = fixture_version(payload, "1.1.0")
        copied, copied_data = fixture_version(
            {**payload, "payload_external_id": "copied"}, slug="copied"
        )
        domains = {**payload, "payload_domains": [{"domain_name": "Endpoint"}]}
        again, again_data = fixture_version(domains, slug="again")
        unused_payload = {**changed, "payload_name": "Unused", "payload_external_id": "unused"}
        unused, unused_data = fixture_version(unused_payload, slug="unused")
        listed = [(self._item, self._archive)]
        return [
            make_fixture(
                "catalogue-accepted",
                "A release whose payload catalogue lists a version used by a time-based scenario "
                "and a step of a scenario in chaining, and a version no scenario uses.",
                fixture_release(
                    [(self._item, self._archive), self._chained_entry()],
                    [(entry, data), (unused, unused_data)],
                ),
            ),
            make_fixture(
                "payload-file-missing",
                "A payload file the manifest lists, missing.",
                {key: value for key, value in fixture_release(listed).items() if key != name},
                ExpectedFinding("VRF-006", name),
            ),
            make_fixture(
                "payload-file-sha256",
                "A payload file whose bytes are not the ones the manifest lists.",
                fixture_release(listed, [(entry, other_bytes)]),
                ExpectedFinding("VRF-006", name),
            ),
            make_fixture(
                "payload-file-content",
                "A payload file listed by its bytes whose content has another hash than listed.",
                fixture_release(listed, [(relisted, other_bytes)]),
                ExpectedFinding("VRF-008", name),
            ),
            make_fixture(
                "payload-file-id",
                "A payload file listed by its bytes that holds another ID than listed.",
                fixture_release(listed, [(listed_id, other_id)]),
                ExpectedFinding("VRF-008", name),
            ),
            make_fixture(
                "payload-file-name",
                "A payload file named after another version than its own.",
                fixture_release(listed, [(misnamed, data)]),
                ExpectedFinding("VRF-006", MANIFEST, "/payloads/0/file/name"),
            ),
            make_fixture(
                "payload-version-twice",
                "A payload version the manifest lists twice.",
                fixture_release(listed, [(entry, data), (entry, data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/payloads/1"),
            ),
            make_fixture(
                "payload-id-two-versions",
                "One payload ID listed with two versions.",
                fixture_release(listed, [(entry, data), (later, later_data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/payloads/1"),
            ),
            make_fixture(
                "payload-content-two-ids",
                "One payload content listed under two IDs.",
                fixture_release(listed, [(entry, data), (copied, copied_data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/payloads/1"),
            ),
            make_fixture(
                "payload-id-two-files",
                "One payload ID listed at one version and hash with two files.",
                fixture_release(listed, [(again, again_data), (entry, data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/payloads/1"),
            ),
            make_fixture(
                "payload-version-not-listed",
                "An item that references a payload version the release does not list.",
                fixture_release(listed, [(unused, unused_data)]),
                ExpectedFinding("VRF-008", MANIFEST, "/items/0/payloads/0"),
            ),
            make_fixture(
                "payload-file-not-listed",
                "A payload file beside the archives that the manifest lists nowhere.",
                fixture_release(listed, beside={"unused-1.0.0.json": unused_data}),
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
        held = scenario if scenario is not None else chained_scenario(self._payload, self._payload)
        archive = self._built(held)
        listed = payloads if payloads is not None else [self._payload]
        item = fixture_item(CHAINED, archive, listed)
        item["type"] = "chained"
        item["requires"] = {**item["requires"], "edition": "EE"}
        return item, archive

    def _chaining(self) -> list[Fixture]:
        payload, changed = self._payload, self._changed
        name = f"{CHAINED}-1.0.0.zip"
        steps = f"/{WORKFLOW}/{STEPS}"
        first = f"{steps}/0/{STEP_DATA}/inject_injector_contract/injector_contract_payload"
        second = f"{steps}/1/{STEP_DATA}/inject_injector_contract/injector_contract_payload"
        hidden = copy.deepcopy(chained_scenario(payload, payload))
        hidden[WORKFLOW][STEPS][0][STEP_DATA]["inject_content"] = {
            "carried": {"injector_contract_payload": payload}
        }
        as_text = copy.deepcopy(chained_scenario(payload, payload))
        for step in as_text[WORKFLOW][STEPS]:
            step[STEP_DATA] = json.dumps(step[STEP_DATA])
        return [
            make_fixture(
                "chaining-accepted",
                "A release of a scenario in chaining, two steps one after the other, sharing its "
                "payload with a time-based scenario.",
                fixture_release([(self._item, self._archive), self._chained_entry()]),
            ),
            make_fixture(
                "chaining-payload-not-listed",
                "A scenario in chaining whose steps embed a payload the manifest does not list.",
                fixture_release([self._chained_entry(payloads=[])]),
                ExpectedFinding("VRF-008", name, first),
                ExpectedFinding("VRF-008", name, second),
            ),
            make_fixture(
                "chaining-payload-content",
                "A step whose payload is not the one the hash listed for its ID describes.",
                fixture_release([self._chained_entry(chained_scenario(changed, payload))]),
                ExpectedFinding("VRF-008", name, first),
            ),
            make_fixture(
                "chaining-payload-outside-contract",
                "A step that carries a payload outside its contract, which no reference names.",
                fixture_release([self._chained_entry(hidden)]),
                ExpectedFinding("VRF-008", name, f"{steps}/0/{STEP_DATA}/inject_content/carried"),
            ),
            make_fixture(
                "chaining-workflow-shape",
                "A scenario in chaining whose steps are not a list.",
                fixture_release(
                    [
                        self._chained_entry(
                            {**chained_scenario(payload, payload), WORKFLOW: {STEPS: ""}}
                        )
                    ]
                ),
                ExpectedFinding("VRF-007", name, "", "IO-014"),
            ),
            make_fixture(
                "chaining-step-data-text",
                "A scenario in chaining whose steps keep their data as text, as an export writes "
                "it, which would hide their payloads from a reader of objects.",
                fixture_release([self._chained_entry(as_text)]),
                ExpectedFinding("VRF-007", name, "", "IO-014"),
            ),
            make_fixture(
                "chaining-scenario-part",
                "A scenario in chaining that also holds a part outside the closed list of a stored "
                "scenario: the workflow does not open the list.",
                fixture_release(
                    [
                        self._chained_entry(
                            chained_scenario(payload, payload, scenario_exercises=[{}])
                        )
                    ]
                ),
                ExpectedFinding("VRF-007", name, "", "IO-014"),
            ),
        ]

    def _manifests(self) -> list[Fixture]:
        item, archive, name = self._item, self._archive, self._name
        renamed = copy.deepcopy(item)
        renamed["archive"]["name"] = f"{FIRST}-2.0.0.zip"
        return [
            make_fixture(
                "manifest-schema",
                "A manifest that does not meet its schema: an unknown channel.",
                {
                    MANIFEST: fixture_manifest([item], channel="nightly"),
                    name: archive,
                    **fixture_carried(),
                },
                ExpectedFinding("VRF-009", MANIFEST, "/channel"),
            ),
            make_fixture(
                "approver-missing",
                "A release verified as approved whose manifest names no release approver.",
                fixture_release([(item, archive)]),
                ExpectedFinding("VRF-009", MANIFEST, "/release_approver"),
                approved=True,
            ),
            make_fixture(
                "scenario-twice",
                "A manifest listing one scenario twice.",
                {MANIFEST: fixture_manifest([item, item]), name: archive, **fixture_carried()},
                ExpectedFinding("VRF-009", MANIFEST, "/items/1"),
            ),
            make_fixture(
                "archive-name",
                "An archive named after another version than its item's.",
                {
                    MANIFEST: fixture_manifest([renamed]),
                    f"{FIRST}-2.0.0.zip": archive,
                    **fixture_carried(),
                },
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
