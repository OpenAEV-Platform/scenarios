"""Normalisation of the starter-pack exports: no trace of the instance, the same bytes every run."""

import json
import re
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader, read_export
from scenario_tools.application.prepare_entry import prepare_entry

ROOT = Path(__file__).parents[2]
EXPORTS = ROOT / "tests" / "golden" / "exports"
NORMALISED = ROOT / "tests" / "golden" / "normalised"
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
# Fields that hold an identifier of the instance the export comes from.
_INSTANCE_KEYS = re.compile(
    r"scenario_id|inject_id|team_id|variable_id|payload_id|attack_pattern_id|phase_id"
    r"|injector_contract_payload_author(_organization)?"
)


def _prepare(export: Path) -> bytes:
    data = YamlDataLoader(ROOT / "policy" / "data")
    return prepare_entry(read_export(export), ENTRY_ID, data, path=export.name).scenario_json


def _instance_identifiers(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if _INSTANCE_KEYS.fullmatch(key) and isinstance(child, str):
                found.add(child)
            found |= _instance_identifiers(child)
    elif isinstance(value, list):
        for child in value:
            found |= _instance_identifiers(child)
    return found


@pytest.mark.parametrize("export", sorted(EXPORTS.glob("*.zip")), ids=lambda path: path.stem)
def test_a_starter_pack_export_normalises_to_its_reviewed_form(export: Path) -> None:
    assert _prepare(export) == (NORMALISED / f"{export.stem}.json").read_bytes()


@pytest.mark.parametrize("export", sorted(EXPORTS.glob("*.zip")), ids=lambda path: path.stem)
def test_no_identifier_of_the_source_instance_is_left(export: Path) -> None:
    identifiers = _instance_identifiers(read_export(export))
    text = _prepare(export).decode()

    assert identifiers
    assert sorted(identifier for identifier in identifiers if identifier in text) == []


@pytest.mark.parametrize("export", sorted(EXPORTS.glob("*.zip")), ids=lambda path: path.stem)
def test_normalising_twice_gives_the_same_bytes(export: Path) -> None:
    assert _prepare(export) == _prepare(export)


def test_the_reviewed_forms_are_stored_forms() -> None:
    for path in sorted(NORMALISED.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        assert text.endswith("}\n")
        assert (
            json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            == text
        )
