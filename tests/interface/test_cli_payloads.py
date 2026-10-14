"""The ``payloads`` command: the payload references of an entry, checked, or given with
``--assign``."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.interface.cli import main

ROOT = Path(__file__).parents[2]
NORMALISED = ROOT / "tests" / "golden" / "normalised"
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"  # the references were normalised with it
PAYLOADS = 11  # in the starter pack's CVE & TTPs scenario
CROWDOOR = 'Create a New Service "Crowdoor" - Salt Typhoon'
AGREED = "13973155-b166-4bbf-a34a-6b74c0d92957"


def _entry(tmp_path: Path, reference: str = "salt-typhoon-cve-ttps-validation") -> Path:
    """An entry in a repository with the policy data, as the reference was stored."""
    shutil.copytree(ROOT / "policy", tmp_path / "policy")
    entry = tmp_path / "scenarios" / "domain" / "entry"
    entry.mkdir(parents=True)
    shutil.copyfile(NORMALISED / f"{reference}.json", entry / "scenario.json")
    (entry / "scenario.yaml").write_text(
        f"external_id: {ENTRY_ID}\nname: Entry\npayloads: []\ntargets: []\n"
    )
    return entry


def _run(*arguments: str) -> tuple[int, Any]:
    result = CliRunner().invoke(main, ["--format", "json", *arguments])
    return result.exit_code, json.loads(result.stdout) if result.stdout.startswith("{") else result


def _codes(document: dict[str, Any]) -> list[str]:
    return sorted({finding["code"] for finding in document["findings"]})


def _embedded(entry: Path) -> list[dict[str, Any]]:
    stored = json.loads((entry / "scenario.json").read_bytes())
    return [
        inject["inject_injector_contract"]["injector_contract_payload"]
        for inject in stored["scenario_injects"]
        if (inject.get("inject_injector_contract") or {}).get("injector_contract_payload")
    ]


def test_an_entry_without_payload_passes(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")

    code, document = _run("payloads", str(entry))

    assert (code, document["findings"]) == (0, [])


def test_the_check_refuses_payloads_no_reference_names_and_writes_nothing(
    tmp_path: Path,
) -> None:
    entry = _entry(tmp_path)
    before = {name: (entry / name).read_bytes() for name in ("scenario.yaml", "scenario.json")}

    code, document = _run("payloads", str(entry))

    assert code == 1
    assert _codes(document) == ["PAY-001"]
    assert len(document["findings"]) == PAYLOADS
    assert {finding["path"] for finding in document["findings"]} == {
        "scenarios/domain/entry/scenario.json"
    }
    assert {name: (entry / name).read_bytes() for name in before} == before


def test_assign_writes_the_ids_in_both_files_and_the_entry_then_passes(tmp_path: Path) -> None:
    entry = _entry(tmp_path)

    code, document = _run("payloads", str(entry), "--assign")

    assert (code, document["findings"]) == (0, [])
    metadata = yaml.safe_load((entry / "scenario.yaml").read_text())
    assert list(metadata) == ["external_id", "name", "payloads", "targets"]  # kept in place
    assert len(metadata["payloads"]) == PAYLOADS
    assert {reference["version"] for reference in metadata["payloads"]} == {"1.0.0"}
    assert {payload["payload_external_id"] for payload in _embedded(entry)} == {
        reference["id"] for reference in metadata["payloads"]
    }
    assert _run("payloads", str(entry)) == (0, {"command": "payloads", "findings": [], "ok": True})


def test_assign_twice_changes_nothing(tmp_path: Path) -> None:
    entry = _entry(tmp_path)
    _run("payloads", str(entry), "--assign")
    once = {name: (entry / name).read_bytes() for name in ("scenario.yaml", "scenario.json")}

    _run("payloads", str(entry), "--assign")

    assert {name: (entry / name).read_bytes() for name in once} == once


def test_an_assigned_entry_is_still_what_normalisation_writes(tmp_path: Path) -> None:
    entry = _entry(tmp_path)
    _run("payloads", str(entry), "--assign")

    code, document = _run("archive", str(entry), "--out", str(tmp_path / "entry.zip"))

    # No GEN-002 and no PAY-*: what is left is what this export does that the catalogue refuses.
    assert code == 1
    assert not [c for c in _codes(document) if c == "GEN-002" or c.startswith("PAY-")]


def test_assign_gives_the_id_the_registry_agrees_for_a_content(tmp_path: Path) -> None:
    entry = _entry(tmp_path)
    _run("payloads", str(entry), "--assign")
    (crowdoor,) = (p for p in _embedded(entry) if p["payload_name"] == CROWDOOR)
    metadata = yaml.safe_load((entry / "scenario.yaml").read_text())
    (digest,) = (
        r["sha256"] for r in metadata["payloads"] if r["id"] == crowdoor["payload_external_id"]
    )
    (tmp_path / "policy" / "data" / "payload-ids.yaml").write_text(
        f"payloads:\n  - id: {AGREED}\n    name: '{CROWDOOR}'\n    sha256: {digest}\n"
    )

    code, document = _run("payloads", str(entry))  # the derived ID is no longer its content's

    assert code == 1
    assert [(f["code"], f["message"]) for f in document["findings"]] == [
        (
            "PAY-003",
            "this ID is not the one its content has (the ID derived from its hash, or the one "
            "policy/data/payload-ids.yaml agrees for it): a changed payload takes a new ID; run "
            "`scenario-tools payloads --assign`",
        )
    ]

    assert _run("payloads", str(entry), "--assign")[0] == 0
    (crowdoor,) = (p for p in _embedded(entry) if p["payload_name"] == CROWDOOR)
    assert crowdoor["payload_external_id"] == AGREED


@pytest.mark.parametrize("content", ["payloads: x\n", "payloads: [\n"], ids=["shape", "yaml"])
def test_a_malformed_registry_is_an_environment_error(tmp_path: Path, content: str) -> None:
    entry = _entry(tmp_path)
    (tmp_path / "policy" / "data" / "payload-ids.yaml").write_text(content)

    result = CliRunner().invoke(main, ["payloads", str(entry)])

    assert result.exit_code == 3
    assert "policy data cannot be used: " in result.output


def test_assign_writes_nothing_when_a_payload_cannot_be_hashed(tmp_path: Path) -> None:
    entry = _entry(tmp_path)
    stored = json.loads((entry / "scenario.json").read_bytes())
    for inject in stored["scenario_injects"]:
        payload = (inject.get("inject_injector_contract") or {}).get("injector_contract_payload")
        if payload:
            payload["payload_detection_remediations"] = [{"detection_remediation_values": "x"}]
            break
    (entry / "scenario.json").write_bytes(stored_form(stored))
    before = {name: (entry / name).read_bytes() for name in ("scenario.yaml", "scenario.json")}

    code, document = _run("payloads", str(entry), "--assign")

    assert (code, _codes(document)) == (1, ["PAY-005"])
    assert {name: (entry / name).read_bytes() for name in before} == before


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        ("scenario.yaml", "- a\n", ("SCH-001", "scenarios/domain/entry/scenario.yaml")),
        ("scenario.json", "[]\n", ("IO-014", "scenarios/domain/entry/scenario.json")),
    ],
)
def test_assign_refuses_a_file_that_is_no_object(
    tmp_path: Path, name: str, content: str, expected: tuple[str, str]
) -> None:
    entry = _entry(tmp_path)
    (entry / name).write_text(content)

    code, document = _run("payloads", str(entry), "--assign")

    assert code == 1
    assert [(f["code"], f["path"]) for f in document["findings"]] == [expected]


def test_an_entry_outside_a_repository_is_refused(tmp_path: Path) -> None:
    entry = tmp_path / "entry"
    entry.mkdir()

    code, _ = _run("payloads", str(entry))

    assert code == 3
