"""The intake command: an export and a request become an entry in place, with a plan a pull
request is opened from; a refused request leaves the repository as it was."""

import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.adapters.data_files import read_export
from scenario_tools.adapters.safe_readers import parse_yaml, yaml_bytes
from scenario_tools.domain.shared.title import check_pull_request_title
from scenario_tools.interface.cli import main

REPOSITORY = Path(__file__).parents[2]
EASM = REPOSITORY / "tests" / "golden" / "exports" / "easm-scenario.zip"
ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
ENTRY = "scenarios/techniques/easm"
NEW: dict[str, Any] = {
    "mode": "new",
    "external_id": ID,
    "domain": "techniques",
    "slug": "easm",
    "threat": {"ttps": ["T1595"]},
    "sources": [{"url": "https://attack.mitre.org/techniques/T1595/", "tlp": "TLP:CLEAR"}],
    "generated_by": "run 42",
    "issue": 12,
}


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - a fixed program, arguments of the test's own
        ["git", "-C", str(root), *arguments],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(tmp_path: Path, *, commit: bool = True) -> Path:
    """A repository of its own, with the policy data and schemas of this one, committed."""
    root = tmp_path / "repository"
    shutil.copytree(REPOSITORY / "policy" / "data", root / "policy" / "data")
    shutil.copytree(REPOSITORY / "schemas", root / "schemas")
    _git(root, "init", "-q")
    if commit:
        _git(root, "add", ".")
        _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
             "commit.gpgsign=false", "commit", "-q", "-m", "start")  # fmt: skip
    return root


def _request(tmp_path: Path, document: dict[str, Any], name: str = "request.yaml") -> Path:
    path = tmp_path / name
    path.write_bytes(yaml_bytes(document))
    return path


def _intake(
    monkeypatch: pytest.MonkeyPatch, root: Path, request: Path, plan: Path, export: Path = EASM
) -> Any:
    monkeypatch.chdir("/")  # the working directory plays no part
    arguments = ["--request", str(request), "--repo", str(root), "--plan", str(plan)]
    return CliRunner().invoke(main, ["--format", "json", "intake", str(export), *arguments])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_new_entry_is_written_in_place_with_its_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 0, result.output
    entry = root / ENTRY
    assert sorted(path.name for path in entry.iterdir()) == ["scenario.json", "scenario.yaml"]
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    assert (metadata["external_id"], metadata["threat"]) == (ID, NEW["threat"])
    document = json.loads(plan.read_text(encoding="utf-8"))
    assert document["base"] == _git(root, "rev-parse", "HEAD")
    assert document["changed"] is True
    assert document["files"] == [
        {"path": f"{ENTRY}/scenario.json", "sha256": _sha256(entry / "scenario.json")},
        {"path": f"{ENTRY}/scenario.yaml", "sha256": _sha256(entry / "scenario.yaml")},
    ]
    assert document["title"] == "feat(scenarios): add easm (#12)"
    assert check_pull_request_title(document["title"]) is None
    findings = json.loads(result.stdout)["findings"]
    assert {(f["code"], f["severity"]) for f in findings} == {("SCH-007", "info")}


def test_the_same_inputs_give_the_same_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    request = _request(tmp_path, NEW)
    first, second = tmp_path / "first.json", tmp_path / "second.json"

    assert _intake(monkeypatch, root, request, first).exit_code == 0
    shutil.rmtree(root / ENTRY)
    assert _intake(monkeypatch, root, request, second).exit_code == 0

    assert first.read_bytes() == second.read_bytes()


def test_an_update_with_the_same_export_writes_nothing_and_plans_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    assert _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "new.json").exit_code == 0
    before = (root / ENTRY / "scenario.json").read_bytes()
    update = {
        "mode": "update",
        "external_id": ID,
        "domain": "techniques",
        "slug": "easm",
        "issue": 13,
    }
    plan = tmp_path / "update.json"

    result = _intake(monkeypatch, root, _request(tmp_path, update, "update.yaml"), plan)

    assert result.exit_code == 0, result.output
    assert (root / ENTRY / "scenario.json").read_bytes() == before
    document = json.loads(plan.read_text(encoding="utf-8"))
    assert (document["changed"], document["files"]) == (False, [])
    assert "nothing to propose" in document["body"]


def test_a_refused_request_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    unknown = {
        "mode": "update",
        "external_id": ID,
        "domain": "techniques",
        "slug": "easm",
        "issue": 1,
    }

    result = _intake(monkeypatch, root, _request(tmp_path, unknown), plan)

    assert result.exit_code == 1, result.output
    assert [f["code"] for f in json.loads(result.stdout)["findings"]] == ["ITK-004"]
    assert not (root / "scenarios").exists()
    assert not plan.exists()


def test_a_plan_inside_the_entries_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), root / "scenarios" / "plan.json")

    assert result.exit_code == 2
    assert result.stdout == ""


def test_a_checkout_without_a_commit_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path, commit=False)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plan.json")

    assert result.exit_code == 3, result.output
    assert "commit" in json.loads(result.stdout)["error"]


def test_a_request_over_its_limit_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    request = tmp_path / "request.yaml"
    request.write_bytes(yaml_bytes(NEW) + b"# " + b"x" * (64 * 1024) + b"\n")

    result = _intake(monkeypatch, root, request, tmp_path / "plan.json")

    assert result.exit_code == 1, result.output
    assert [f["code"] for f in json.loads(result.stdout)["findings"]] == ["IO-001"]


def test_an_entry_is_never_written_through_a_link(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (tmp_path / "elsewhere").mkdir()
    (root / "scenarios").symlink_to(tmp_path / "elsewhere")

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plan.json")

    assert result.exit_code == 1, result.output
    assert [f["code"] for f in json.loads(result.stdout)["findings"]] == ["IO-013"]
    assert list((tmp_path / "elsewhere").iterdir()) == []


def _changed_export(tmp_path: Path) -> Path:
    """The EASM export with another subtitle, archived as the platform does."""
    export = tmp_path / "changed.zip"
    with zipfile.ZipFile(EASM) as source, zipfile.ZipFile(export, "w") as target:
        for info in source.infolist():
            data = source.read(info)
            if info.filename.endswith(".json"):
                document = json.loads(data)
                document["scenario_information"]["scenario_subtitle"] = "A new subtitle"
                data = json.dumps(document).encode()
            target.writestr(info, data)
    return export


def test_an_update_rewrites_scenario_json_only_and_plans_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    assert _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "new.json").exit_code == 0
    metadata = (root / ENTRY / "scenario.yaml").read_bytes()
    update = {
        "mode": "update",
        "external_id": ID,
        "domain": "techniques",
        "slug": "easm",
        "issue": 13,
    }
    plan = tmp_path / "update.json"

    result = _intake(
        monkeypatch,
        root,
        _request(tmp_path, update, "update.yaml"),
        plan,
        _changed_export(tmp_path),
    )

    assert result.exit_code == 0, result.output
    assert (root / ENTRY / "scenario.yaml").read_bytes() == metadata  # never rewritten
    document = json.loads(plan.read_text(encoding="utf-8"))
    assert document["title"] == "feat(scenarios): update easm (#13)"
    assert [item["path"] for item in document["files"]] == [f"{ENTRY}/scenario.json"]
    assert "/version" in document["body"]


def test_a_plan_reaching_the_entries_through_a_link_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / "scenarios").mkdir()
    (tmp_path / "plans").symlink_to(root / "scenarios")

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plans" / "plan.json")

    assert result.exit_code == 2
    assert list((root / "scenarios").iterdir()) == []


@pytest.mark.parametrize("which", ["export", "request"])
def test_inputs_inside_the_entries_are_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, which: str
) -> None:
    root = _repository(tmp_path)
    (root / "scenarios").mkdir()
    export, request = EASM, _request(tmp_path, NEW)
    if which == "export":
        export = root / "scenarios" / "export.zip"
        shutil.copy(EASM, export)
    else:
        request = _request(root / "scenarios", NEW)

    result = _intake(monkeypatch, root, request, tmp_path / "plan.json", export)

    assert result.exit_code == 2, result.output
    assert "never enter" in result.stderr


def test_a_blocking_finding_after_writing_keeps_the_files_and_says_so_in_the_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    salt = EASM.parent / "salt-typhoon-cve-ttps-validation.zip"
    request = {**NEW, "domain": "intrusion-sets", "slug": "salt-typhoon"}
    plan = tmp_path / "plan.json"

    result = _intake(monkeypatch, root, _request(tmp_path, request), plan, salt)

    assert result.exit_code == 1, result.output
    assert (root / "scenarios" / "intrusion-sets" / "salt-typhoon" / "scenario.yaml").exists()
    document = json.loads(plan.read_text(encoding="utf-8"))
    assert document["blocking"] == 1
    assert "SCH-009" in [f["code"] for f in json.loads(result.stdout)["findings"]]


def test_a_plan_that_cannot_be_written_stops_the_run_before_any_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "missing" / "plan.json")

    assert result.exit_code == 3, result.output
    assert not (root / "scenarios").exists()


def test_a_plan_already_there_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    plan.write_text("{}")

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 2
    assert "remove" in result.stderr
    assert not (root / "scenarios").exists()


def test_a_plan_that_appears_before_it_is_reserved_stops_the_run_unwritten(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"

    def racing(path: Path) -> object:
        plan.write_text("another run's")
        return read_export(path)

    monkeypatch.setattr("scenario_tools.interface.cli.read_export", racing)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert plan.read_text() == "another run's"
    assert not (root / "scenarios").exists()


def test_a_run_that_fails_after_reserving_its_plan_leaves_no_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path, commit=False)  # the commit cannot be read
    plan = tmp_path / "plan.json"

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert not plan.exists()
