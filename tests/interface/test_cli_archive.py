"""The ``archive`` command: the import archive of an entry, written once every check passed."""

import io
import json
import shutil
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.interface.cli import main
from tests.adapters.test_safe_zip import ENCRYPTED

ROOT = Path(__file__).parents[2]
NORMALISED = ROOT / "tests" / "golden" / "normalised"
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"  # the references were normalised with it


def _entry(tmp_path: Path, reference: str) -> Path:
    """An entry in a repository with the policy data, as the references were stored."""
    if not (tmp_path / "policy").exists():
        shutil.copytree(ROOT / "policy", tmp_path / "policy")
    entry = tmp_path / "scenarios" / "domain" / "entry"
    entry.mkdir(parents=True)
    shutil.copyfile(NORMALISED / f"{reference}.json", entry / "scenario.json")
    (entry / "scenario.yaml").write_text(f"external_id: {ENTRY_ID}\n")
    return entry


def _edit(entry: Path, change: Callable[[dict[str, Any]], None]) -> None:
    document = json.loads((entry / "scenario.json").read_bytes())
    change(document)
    (entry / "scenario.json").write_bytes(stored_form(document))


def _run(*arguments: str) -> tuple[int, str, str]:
    result = CliRunner().invoke(main, list(arguments))
    return result.exit_code, result.stdout, result.stderr


@pytest.mark.parametrize(
    "reference", ["easm-scenario", "tabletop-exercise-akira-ransomware-crisis"]
)
def test_an_entry_without_payload_is_archived(tmp_path: Path, reference: str) -> None:
    entry = _entry(tmp_path, reference)
    out = tmp_path / "entry.zip"

    code, stdout, _ = _run("archive", str(entry), "--out", str(out))

    assert (code, stdout.strip()) == (0, "archive: ok")
    archive = zipfile.ZipFile(io.BytesIO(out.read_bytes()))
    assert archive.read("scenario.json") == (entry / "scenario.json").read_bytes()
    assert out.stat().st_mode & 0o777 == 0o644


def test_the_attachments_go_with_the_scenario(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "attachments.zip").write_bytes(ENCRYPTED)
    out = tmp_path / "entry.zip"

    code, _, _ = _run("archive", str(entry), "--out", str(out))

    assert code == 0
    assert zipfile.ZipFile(out).read("attachments.zip") == ENCRYPTED


def test_an_entry_with_payloads_waits_and_nothing_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    entry = _entry(tmp_path, "salt-typhoon-cve-ttps-validation")

    code, stdout, _ = _run(
        "--format", "json", "archive", str(entry.relative_to(tmp_path)), "--out", "entry.zip"
    )

    assert code == 1
    findings = json.loads(stdout)["findings"]
    assert {finding["code"] for finding in findings} == {"PAY-004"}
    assert {finding["path"] for finding in findings} == {"scenarios/domain/entry/scenario.json"}
    assert not (tmp_path / "entry.zip").exists()


def test_two_runs_write_the_same_bytes(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")

    for name in ("first.zip", "second.zip"):
        assert _run("archive", str(entry), "--out", str(tmp_path / name))[0] == 0
    assert (tmp_path / "first.zip").read_bytes() == (tmp_path / "second.zip").read_bytes()


def test_an_entry_without_scenario_is_an_environment_problem(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "scenario.json").unlink()

    code, stdout, _ = _run("archive", str(entry), "--out", str(tmp_path / "e.zip"))

    assert code == 3
    assert "cannot read" in stdout


def test_attachments_the_importer_could_not_open_are_refused(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "attachments.zip").write_bytes(b"not an archive")

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    assert [finding["code"] for finding in json.loads(stdout)["findings"]] == ["IO-007"]
    assert not (tmp_path / "e").exists()


@pytest.mark.parametrize("name", ["scenario.json", "attachments.zip", "scenario.yaml", "new.zip"])
def test_the_archive_is_never_written_inside_the_entry(tmp_path: Path, name: str) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "attachments.zip").write_bytes(ENCRYPTED)
    before = {path.name: path.read_bytes() for path in entry.iterdir()}

    code, stdout, stderr = _run("archive", str(entry), "--out", str(entry / name))

    assert code == 2
    assert stdout == ""
    assert "OUT may not be inside the entry" in stderr
    assert {path.name: path.read_bytes() for path in entry.iterdir()} == before


def test_a_stored_scenario_with_a_foreign_part_is_refused(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    _edit(entry, lambda document: document.update(exercise_information={}))

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    assert [finding["code"] for finding in json.loads(stdout)["findings"]] == ["IO-014"]
    assert not (tmp_path / "e").exists()


def test_an_archive_over_the_limit_is_reported_on_the_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    entry = _entry(tmp_path, "easm-scenario")
    monkeypatch.setattr("scenario_tools.interface.cli.ARCHIVE_LIMIT", 1000)

    _, stdout, _ = _run(
        "--format", "json", "archive", str(entry.relative_to(tmp_path)), "--out", "build/x/../e.zip"
    )

    [finding] = json.loads(stdout)["findings"]
    assert (finding["code"], finding["path"]) == ("IO-001", "build/e.zip")


def test_an_archive_the_checks_refuse_is_never_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    monkeypatch.setattr(
        "scenario_tools.interface.cli.ZipArchiveBuilder.build", lambda self, *args: b"not a zip"
    )

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    assert [finding["code"] for finding in json.loads(stdout)["findings"]] == ["IO-007"]
    assert not (tmp_path / "e").exists()


def test_a_stored_scenario_written_as_normalisation_writes_it_is_archived(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "tabletop-exercise-akira-ransomware-crisis")
    _edit(entry, lambda document: None)  # the helper the next test uses changes nothing itself

    assert _run("archive", str(entry), "--out", str(tmp_path / "e"))[0] == 0


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["scenario_users"].append({"user_email": "victim@example.net"}),
        lambda d: d["scenario_information"].update(scenario_mail_from="ceo@bank.example"),
        lambda d: d["scenario_teams"][0].update(team_users=["someone"]),
    ],
    ids=["a user", "a sender", "a team member"],
)
def test_a_stored_scenario_edited_by_hand_is_refused(tmp_path: Path, change: Any) -> None:
    # Normalisation would undo these edits: the stored file is not what it writes.
    entry = _entry(tmp_path, "tabletop-exercise-akira-ransomware-crisis")
    _edit(entry, change)

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    assert "GEN-002" in {finding["code"] for finding in json.loads(stdout)["findings"]}
    assert not (tmp_path / "e").exists()


def test_a_contract_the_platform_would_build_from_the_copy_is_refused(tmp_path: Path) -> None:
    # The references carry the STARTERPACK dependency: the importer would build an unknown
    # contract from the copy. Its facts cannot be established, so the archive refuses it.
    entry = _entry(tmp_path, "easm-scenario")
    unknown = "00000000-0000-4000-8000-0000000000ff"
    data = (entry / "scenario.json").read_text()
    (entry / "scenario.json").write_text(
        data.replace("93d27459-68d0-43b1-ad65-eacc3cfa5cf7", unknown)
    )

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    assert "SCH-005" in {finding["code"] for finding in json.loads(stdout)["findings"]}
    assert not (tmp_path / "e").exists()


def test_an_entry_outside_a_repository_is_an_environment_problem(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    shutil.rmtree(tmp_path / "policy")

    code, stdout, _ = _run("archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 3
    assert "no policy/data directory" in stdout


def test_an_entry_without_its_metadata_is_an_environment_problem(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "scenario.yaml").unlink()

    code, stdout, _ = _run("archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 3
    assert "scenario.yaml" in stdout


def test_an_external_id_not_canonical_is_refused(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "scenario.yaml").write_text(f"external_id: {ENTRY_ID.upper()}\n")

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    [finding] = json.loads(stdout)["findings"]
    assert (finding["code"], finding["field"]) == ("SCH-001", "/external_id")


def test_a_document_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "scenario.json").write_text("[]\n")

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    assert [finding["code"] for finding in json.loads(stdout)["findings"]] == ["IO-014"]


def test_unusable_recorded_contracts_are_an_environment_problem(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (tmp_path / "policy" / "data" / "builtin-contracts.yaml").write_text("contracts: {}\n")

    code, stdout, _ = _run("archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 3
    assert "policy data cannot be used: builtin-contracts" in stdout


def test_a_built_in_contract_copy_edited_by_hand_is_refused(tmp_path: Path) -> None:
    # Still a fixed point of normalisation, but an instance lacking the contract would build
    # it from this copy.
    entry = _entry(tmp_path, "easm-scenario")

    def change(document: dict[str, Any]) -> None:
        contract = document["scenario_injects"][0]["inject_injector_contract"]
        contract["injector_contract_needs_executor"] = True

    _edit(entry, change)

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    assert [finding["code"] for finding in json.loads(stdout)["findings"]] == ["SCH-006"]


def test_another_external_id_is_not_what_normalisation_writes(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "scenario.yaml").write_text("external_id: 00000000-0000-4000-8000-000000000001\n")

    code, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    assert code == 1
    [finding] = json.loads(stdout)["findings"]
    assert (finding["code"], finding["message"]) == (
        "GEN-002",
        "the file is not what normalisation writes for the external ID in scenario.yaml: it was "
        "edited by hand, or normalised with another external ID; normalise the export again "
        "with this one",
    )


def test_paths_are_reported_from_the_repository_wherever_the_command_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = _entry(tmp_path, "salt-typhoon-cve-ttps-validation")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    _, stdout, _ = _run("--format", "json", "archive", str(entry), "--out", str(tmp_path / "e"))

    paths = {finding["path"] for finding in json.loads(stdout)["findings"]}
    assert paths == {"scenarios/domain/entry/scenario.json"}


@pytest.mark.parametrize(
    ("reference", "external_id", "reported"),
    [
        ("salt-typhoon-cve-ttps-validation", ENTRY_ID, "scenario.json"),
        ("easm-scenario", "not-a-uuid", "scenario.yaml"),
    ],
    ids=["scenario", "metadata"],
)
def test_paths_are_reported_from_the_repository_when_the_entry_is_named_through_a_link(
    tmp_path: Path, reference: str, external_id: str, reported: str
) -> None:
    entry = _entry(tmp_path / "repository", reference)
    (entry / "scenario.yaml").write_text(f"external_id: {external_id}\n")
    alias = tmp_path / "alias"
    alias.symlink_to(entry, target_is_directory=True)

    _, stdout, _ = _run("--format", "json", "archive", str(alias), "--out", str(tmp_path / "e"))

    paths = {finding["path"] for finding in json.loads(stdout)["findings"]}
    assert paths == {f"scenarios/domain/entry/{reported}"}


def test_the_archive_is_never_written_inside_the_entry_however_named(tmp_path: Path) -> None:
    # Compared by file identity: a link to the entry, or another case on a case-insensitive
    # disk, still names the entry.
    entry = _entry(tmp_path, "easm-scenario")
    alias = tmp_path / "alias"
    alias.symlink_to(entry, target_is_directory=True)

    code, _, stderr = _run("archive", str(entry), "--out", str(alias / "scenario.json"))

    assert code == 2
    assert "OUT may not be inside the entry" in stderr


def test_an_entry_that_does_not_exist_is_an_environment_problem(tmp_path: Path) -> None:
    code, stdout, _ = _run("archive", str(tmp_path / "nowhere"), "--out", str(tmp_path / "e"))

    assert code == 3
    assert "no policy/data directory" in stdout


def test_the_archive_is_never_written_inside_the_entry_through_a_link_to_a_folder_of_it(
    tmp_path: Path,
) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (entry / "nested" / "child").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(entry / "nested", target_is_directory=True)

    code, _, stderr = _run("archive", str(entry), "--out", str(alias / "child" / "out.zip"))

    assert code == 2
    assert "OUT may not be inside the entry" in stderr
    assert not (entry / "nested" / "child" / "out.zip").exists()


def test_an_entry_named_through_a_loop_of_links_is_reported_not_raised(tmp_path: Path) -> None:
    _entry(tmp_path, "easm-scenario")
    loop = tmp_path / "loop"
    loop.symlink_to(loop)

    code, stdout, _ = _run("--format", "json", "archive", str(loop), "--out", str(tmp_path / "e"))

    assert code == 1
    assert [finding["code"] for finding in json.loads(stdout)["findings"]] == ["IO-013"]


def test_an_existing_directory_as_out_is_a_usage_error(tmp_path: Path) -> None:
    entry = _entry(tmp_path, "easm-scenario")
    (tmp_path / "out").mkdir()

    code, stdout, stderr = _run("archive", str(entry), "--out", str(tmp_path / "out"))

    assert (code, stdout) == (2, "")
    assert "OUT is a directory" in stderr


def test_hostile_content_cannot_flood_the_report(tmp_path: Path) -> None:
    # A key of a megabyte and five hundred refused injects stay a bounded report.
    entry = _entry(tmp_path, "easm-scenario")

    def change(document: dict[str, Any]) -> None:
        inject = document["scenario_injects"][0]
        unknown = json.loads(json.dumps(inject))
        unknown["inject_injector_contract"]["injector_contract_id"] = (
            "00000000-0000-4000-8000-00000000dead"
        )
        inject["inject_content"] = {"k" * 1_000_000: {"injector_contract_payload": {}}}
        copies = [dict(unknown, inject_id=f"00000000-0000-4000-8000-{n:012x}") for n in range(500)]
        document["scenario_injects"] = [inject, *copies]

    _edit(entry, change)

    code, stdout, _ = _run("archive", str(entry), "--out", str(tmp_path / "e"))

    lines = stdout.splitlines()
    assert code == 1
    assert len(lines) <= 102  # at most 101 findings, then the summary line
    assert max(len(line) for line in lines) < 1_000
    assert "more findings not shown" in stdout
