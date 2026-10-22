"""The release fixtures: one release accepted as ``build`` writes it, and one for each way
``verify`` refuses one, with what verifying each must give."""

import json
from pathlib import PurePosixPath

import pytest

from scenario_tools.adapters.fixture_zip import HandmadeArchives
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.zip_archive import ZipArchiveBuilder
from scenario_tools.application.build_fixtures import EXPECTED, fixture_files, release_fixtures
from tests.interface.test_cli_build import ROOT

FIXTURES = release_fixtures(ZipArchiveBuilder(), HandmadeArchives())


def test_three_fixtures_are_accepted_and_every_other_is_refused_for_its_own_reason() -> None:
    accepted = [fixture.name for fixture in FIXTURES if not fixture.expectation.findings]

    assert accepted == ["accepted", "catalogue-accepted", "chaining-accepted"]
    assert len({fixture.name for fixture in FIXTURES}) == len(FIXTURES)
    assert all(fixture.expectation.description for fixture in FIXTURES)


def test_every_refusal_of_the_verifier_has_a_fixture() -> None:
    codes = {f.code for fixture in FIXTURES for f in fixture.expectation.findings}

    assert codes == {"VRF-006", "VRF-007", "VRF-008", "VRF-009"}


@pytest.mark.parametrize("name", ["accepted", "catalogue-accepted", "chaining-accepted"])
def test_an_accepted_release_meets_the_manifest_s_schema_and_lists_what_stands_beside_it(
    name: str,
) -> None:
    (accepted,) = [fixture for fixture in FIXTURES if fixture.name == name]
    manifest = json.loads(accepted.files["manifest.json"])

    assert JsonSchemaValidator(ROOT / "schemas").validate("manifest", manifest) == ()
    assert sorted(accepted.files) == sorted(
        [
            "manifest.json",
            *(item["archive"]["name"] for item in manifest["items"]),
            *(entry["file"]["name"] for entry in manifest["payloads"]),
        ]
    )


def test_the_catalogue_release_lists_a_version_no_scenario_uses() -> None:
    (accepted,) = [fixture for fixture in FIXTURES if fixture.name == "catalogue-accepted"]
    manifest = json.loads(accepted.files["manifest.json"])
    used = {payload["id"] for item in manifest["items"] for payload in item["payloads"]}

    assert [entry["openaev_id"] in used for entry in manifest["payloads"]] == [True, False]
    assert {item["type"] for item in manifest["items"]} == {"time-based", "chained"}


def test_the_files_are_each_fixture_s_in_its_own_directory_and_the_expectations_beside() -> None:
    files = fixture_files(FIXTURES)
    expected = json.loads(files[EXPECTED])

    assert [case["name"] for case in expected["fixtures"]] == [f.name for f in FIXTURES]
    for path in set(files) - {EXPECTED}:
        parts = PurePosixPath(path).parts
        assert len(parts) == 2
        assert parts[0] in {f.name for f in FIXTURES}


def test_the_fixtures_are_the_same_bytes_on_every_build() -> None:
    again = release_fixtures(ZipArchiveBuilder(), HandmadeArchives())

    assert fixture_files(again) == fixture_files(FIXTURES)
