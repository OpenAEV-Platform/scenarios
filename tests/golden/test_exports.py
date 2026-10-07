"""The reference OpenAEV exports used as test inputs are present, intact and as described."""

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

EXPORTS = Path(__file__).parent / "exports"
SOURCES = json.loads((EXPORTS / "sources.json").read_text(encoding="utf-8"))


def _scenario(archive: Path) -> dict[str, Any]:
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        assert len(names) == 1, names
        data: dict[str, Any] = json.loads(bundle.read(names[0]))
    return data


def test_sources_record_the_public_origin_and_licence() -> None:
    assert "https://github.com/OpenAEV-Platform/openaev" in SOURCES["origin"]
    assert SOURCES["licence"] == "Apache-2.0"


def test_sources_describe_the_export_conditions() -> None:
    assert SOURCES["openaev_version"]
    assert SOURCES["export_options"] == {
        "isWithTeams": True,
        "isWithPlayers": False,
        "isWithVariableValues": False,
        "isWithScopeDefinition": True,
    }


@pytest.mark.parametrize("entry", SOURCES["files"], ids=lambda entry: entry["name"])
def test_export_is_intact(entry: dict[str, str]) -> None:
    archive = EXPORTS / entry["name"]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == entry["sha256"]


@pytest.mark.parametrize("entry", SOURCES["files"], ids=lambda entry: entry["name"])
def test_export_is_a_starter_pack_scenario_without_users(entry: dict[str, str]) -> None:
    scenario = _scenario(EXPORTS / entry["name"])
    assert scenario["export_version"] == 1
    assert scenario["scenario_information"]["scenario_name"] == entry["scenario_name"]
    assert scenario["scenario_information"]["scenario_dependencies"] == ["STARTERPACK"]
    assert scenario["scenario_users"] == []


def test_every_archive_in_the_folder_is_described() -> None:
    described = {entry["name"] for entry in SOURCES["files"]}
    assert {path.name for path in EXPORTS.glob("*.zip")} == described
