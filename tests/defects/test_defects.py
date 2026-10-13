"""Deliberate defects: for each, `validate` reports exactly the finding that names it.

Each defect is made from a real entry of the catalogue, EASM Scenario, by one change, in a
repository of the test's own, so that no defective file is ever committed. The entry as it is
passes with no finding; each change then makes exactly one check fail, and no other.
"""

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from scenario_tools.interface.cli import main

ROOT = Path(__file__).parents[2]
ENTRY = "scenarios/techniques/easm"
EXPORT = ROOT / "tests" / "golden" / "exports" / "easm-scenario.zip"
OTHER_ID = "0f0e0d0c-0b0a-4908-8706-050403020100"


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    for directory in ("policy", "schemas", ENTRY):
        shutil.copytree(ROOT / directory, root / directory)
    return root


def _validate(root: Path, *entries: str) -> tuple[int, list[tuple[str, str, str]]]:
    """The exit code, and every finding as code, severity and path, duplicates kept."""
    result = CliRunner().invoke(
        main, ["--format", "json", "validate", *(str(root / entry) for entry in entries)]
    )
    findings = json.loads(result.stdout)["findings"]
    return result.exit_code, sorted((f["code"], f["severity"], f["path"]) for f in findings)


def _metadata(root: Path, change: Callable[[dict[str, Any]], object], entry: str = ENTRY) -> None:
    path = root / entry / "scenario.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(yaml.safe_dump(document, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _scenario(root: Path, change: Callable[[dict[str, Any]], object], entry: str = ENTRY) -> None:
    path = root / entry / "scenario.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _first_contract(document: dict[str, Any]) -> dict[str, Any]:
    contract: dict[str, Any] = document["scenario_injects"][0]["inject_injector_contract"]
    return contract


def _yaml_text(root: Path, change: Callable[[str], str]) -> None:
    path = root / ENTRY / "scenario.yaml"
    path.write_text(change(path.read_text(encoding="utf-8")), encoding="utf-8")


def _linked(root: Path) -> None:
    path = root / ENTRY / "scenario.yaml"
    path.rename(root / "elsewhere.yaml")
    path.symlink_to(root / "elsewhere.yaml")


def _same_external_id(root: Path) -> None:
    shutil.copytree(root / ENTRY, root / "scenarios/techniques/easm-copy")
    renamed = "EASM Scenario copy"
    _metadata(root, lambda d: d.__setitem__("name", renamed), "scenarios/techniques/easm-copy")
    _scenario(
        root,
        lambda d: d["scenario_information"].__setitem__("scenario_name", renamed),
        "scenarios/techniques/easm-copy",
    )


def _same_name(root: Path) -> None:
    again = root / "scenarios/techniques/easm-again"
    again.mkdir()
    arguments = ["normalize", str(EXPORT), "--out", str(again), "--external-id", OTHER_ID]
    assert CliRunner().invoke(main, arguments).exit_code == 0
    shutil.copy(root / ENTRY / "scenario.yaml", again / "scenario.yaml")
    _metadata(
        root, lambda d: d.__setitem__("external_id", OTHER_ID), "scenarios/techniques/easm-again"
    )


DEFECTS: dict[str, Callable[[Path], object]] = {
    "SCH-001": lambda root: _metadata(root, lambda d: d.__setitem__("severity", "extreme")),
    "SCH-002": lambda root: _metadata(root, lambda d: d.__setitem__("name", "Another name")),
    "SCH-003": lambda root: _metadata(
        root, lambda d: d["requires"].__setitem__("injectors", ["openaev_nuclei"])
    ),
    "SCH-005": lambda root: _scenario(
        root,
        lambda d: _first_contract(d).__setitem__(
            "injector_contract_id", "11111111-1111-4111-8111-111111111111"
        ),
    ),
    "SCH-006": lambda root: _scenario(
        root, lambda d: _first_contract(d).__setitem__("injector_contract_labels", {"en": "x"})
    ),
    "SCH-008": lambda root: (root / ENTRY / "scenario.json").unlink(),
    "SCH-009": lambda root: _metadata(
        root, lambda d: d.__setitem__("description", d["description"] + " cut" + chr(0x2026))
    ),
    "GEN-002": lambda root: (root / ENTRY / "scenario.json").write_text(
        json.dumps(json.loads((root / ENTRY / "scenario.json").read_text()), indent=4) + "\n"
    ),
    "IO-001": lambda root: _yaml_text(root, lambda text: text + "#" + "x" * 300 * 1024 + "\n"),
    "IO-002": lambda root: _yaml_text(root, lambda text: "name: [unclosed\n"),
    "IO-003": lambda root: _yaml_text(
        root, lambda text: text.replace("severity: high", "severity: &s high\nalias: *s", 1)
    ),
    "IO-004": lambda root: _yaml_text(
        root, lambda text: text + "deep: " + "[" * 70 + "]" * 70 + "\n"
    ),
    "IO-005": lambda root: _yaml_text(root, lambda text: text + "name: twice\n"),
    "IO-006": lambda root: _yaml_text(root, lambda text: text + "relevance:\n  priority: .nan\n"),
    "IO-013": _linked,
    "IO-014": lambda root: _scenario(root, lambda d: d.pop("scenario_information")),
    "IO-017": lambda root: _metadata(
        root, lambda d: d.__setitem__("description", d["description"] + " x" + chr(0x202E))
    ),
    "POL-001": lambda root: _metadata(
        root, lambda d: d["sources"][0].__setitem__("url", "https://10.0.0.1/report.html")
    ),
    "POL-002": lambda root: _scenario(
        root,
        lambda d: d["scenario_information"].__setitem__("scenario_recurrence", "0 0 8 * * MON"),
    ),
}

TWO_ENTRIES: dict[str, tuple[Callable[[Path], object], tuple[str, ...]]] = {
    "SCH-010": (_same_external_id, (ENTRY, "scenarios/techniques/easm-copy")),
    "SCH-012": (_same_name, (ENTRY, "scenarios/techniques/easm-again")),
}


def test_the_entry_as_it_is_passes_with_no_finding(tmp_path: Path) -> None:
    assert _validate(_repository(tmp_path), ENTRY) == (0, [])


@pytest.mark.parametrize("code", sorted(DEFECTS))
def test_each_defect_makes_exactly_its_check_fail(tmp_path: Path, code: str) -> None:
    root = _repository(tmp_path)
    DEFECTS[code](root)

    exit_code, findings = _validate(root, ENTRY)
    assert exit_code == 1
    assert [(found, severity) for found, severity, _ in findings] == [(code, "blocking")]  # once
    assert findings[0][2].startswith(f"{ENTRY}/")


@pytest.mark.parametrize("code", sorted(TWO_ENTRIES))
def test_each_defect_between_two_entries_makes_exactly_its_check_fail(
    tmp_path: Path, code: str
) -> None:
    root = _repository(tmp_path)
    make, entries = TWO_ENTRIES[code]
    make(root)

    exit_code, findings = _validate(root, *entries)
    assert exit_code == 1
    assert findings == sorted((code, "blocking", f"{entry}/scenario.yaml") for entry in entries)


def test_a_file_copied_into_the_entry_makes_exactly_its_check_fail(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / ENTRY / "report.pdf").write_bytes(b"%PDF-1.7\n")

    assert _validate(root, ENTRY) == (1, [("POL-001", "blocking", f"{ENTRY}/report.pdf")])


def test_an_old_minimum_version_is_said_and_never_blocks(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    _metadata(root, lambda d: d["requires"].__setitem__("openaev", ">=3.0"))

    assert _validate(root, ENTRY) == (0, [("SCH-011", "info", f"{ENTRY}/scenario.yaml")])
