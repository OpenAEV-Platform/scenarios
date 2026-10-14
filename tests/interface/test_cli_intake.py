"""The intake command: an export and a request become an entry in place, with a plan a pull
request is opened from; a refused request leaves the repository as it was."""

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import signal
import subprocess
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.adapters import plan as plan_module
from scenario_tools.adapters.data_files import read_export
from scenario_tools.adapters.git import uncommitted
from scenario_tools.adapters.places import is_hidden_name
from scenario_tools.adapters.safe_readers import parse_yaml, yaml_bytes
from scenario_tools.application import intake_entry
from scenario_tools.domain.shared.finding import Report
from scenario_tools.domain.shared.title import check_pull_request_title
from scenario_tools.interface import cli as cli_module
from scenario_tools.interface.cli import main
from scenario_tools.ports.errors import EnvironmentProblemError

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


@pytest.fixture(autouse=True)
def _no_git_config_of_the_machine(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git reads no configuration of the machine nor of its user, which could ignore or convert
    the files the tests write."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


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


def _commit(root: Path) -> None:
    """Commit what the checkout holds, as a maintainer does before running intake again."""
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "next")  # fmt: skip


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
    assert sorted(path.name for path in entry.iterdir()) == [
        "CHANGELOG.md",
        "README.md",
        "scenario.json",
        "scenario.yaml",
    ]
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    assert (metadata["external_id"], metadata["threat"]) == (ID, NEW["threat"])
    document = json.loads(plan.read_text(encoding="utf-8"))
    assert document["base"] == _git(root, "rev-parse", "HEAD")
    assert document["changed"] is True
    assert document["files"] == [
        {"path": f"{ENTRY}/CHANGELOG.md", "sha256": _sha256(entry / "CHANGELOG.md")},
        {"path": f"{ENTRY}/README.md", "sha256": _sha256(entry / "README.md")},
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
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    moved = shutil.copy(request, elsewhere / "other-name.yaml")
    export = shutil.copy(EASM, elsewhere / "export.zip")
    result = _intake(monkeypatch, root, Path(moved), second, Path(export))
    assert result.exit_code == 0, result.output

    assert first.read_bytes() == second.read_bytes()  # whatever the inputs' paths


def test_an_update_with_the_same_export_writes_nothing_and_plans_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    assert _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "new.json").exit_code == 0
    _commit(root)
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


@pytest.mark.parametrize("place", ["scenarios", "policy", "schemas", "policy/data"])
def test_a_plan_where_the_checkout_must_stay_committed_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, place: str
) -> None:
    root = _repository(tmp_path)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), root / place / "plan.json")

    assert result.exit_code == 2, result.output
    assert result.stdout == ""
    assert "scenarios/, policy/ or schemas/" in result.stderr
    assert not (root / "scenarios").exists()
    assert not (root / place / "plan.json").exists()


def test_a_plan_elsewhere_in_the_checkout_is_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), root / "plan.json")

    assert result.exit_code == 0, result.output
    assert (root / "plan.json").exists()


def test_a_restrictive_umask_still_writes_the_entry_and_its_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    request, plan = _request(tmp_path, NEW), tmp_path / "plan.json"

    umask = os.umask(0o777)  # nothing the run makes may be left closed to the run itself
    try:
        result = _intake(monkeypatch, root, request, plan)
    finally:
        os.umask(umask)

    assert result.exit_code == 0, result.output
    for directory in (root / ENTRY, (root / ENTRY).parent, root / "scenarios"):
        assert oct(directory.stat().st_mode & 0o777) == oct(0o755), directory
    assert oct(plan.stat().st_mode & 0o777) == oct(0o644)


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
    _commit(root)  # a link in the repository, committed

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
    _commit(root)
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


@pytest.mark.parametrize("place", ["scenarios", "policy", "schemas"])
@pytest.mark.parametrize("which", ["export", "request"])
def test_inputs_where_the_checkout_must_stay_committed_are_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, which: str, place: str
) -> None:
    root = _repository(tmp_path)
    (root / place).mkdir(exist_ok=True)
    export, request = EASM, _request(tmp_path, NEW)
    if which == "export":
        export = root / place / "export.zip"
        shutil.copy(EASM, export)
    else:
        request = _request(root / place, NEW)

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
    blocking = [
        f["code"] for f in json.loads(result.stdout)["findings"] if f["severity"] == "blocking"
    ]
    # The cut description, and what the starter-pack export does that the catalogue refuses:
    # four payloads that reach public hosts, four that change the endpoint without cleanup, and
    # two injects that run on the endpoint at the same second. The sender is normalised away.
    assert document["blocking"] == 10
    assert sorted(blocking) == ["POL-003"] * 4 + ["POL-005"] * 4 + ["POL-009"] + ["SCH-009"]


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
    plan.mkdir()  # whatever is there

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 2
    assert "something is already there" in result.stderr
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


def _unpublished(monkeypatch: pytest.MonkeyPatch) -> None:
    """The plan cannot be published, once the entry is written."""

    def failing(reservation: plan_module.Reservation, data: bytes) -> None:
        raise EnvironmentProblemError("cannot write the plan: No space left on device")

    monkeypatch.setattr(plan_module.Reservation, "publish", failing)


def test_a_plan_that_cannot_be_published_leaves_no_new_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    _unpublished(monkeypatch)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert not (root / ENTRY).exists()
    assert not plan.exists()


def test_a_plan_that_cannot_be_published_puts_an_update_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    assert _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "new.json").exit_code == 0
    _commit(root)
    stored = (root / ENTRY / "scenario.json").read_bytes()
    update = {"mode": "update", "external_id": ID, "domain": "techniques", "slug": "easm"}
    plan = tmp_path / "update.json"
    _unpublished(monkeypatch)

    result = _intake(
        monkeypatch,
        root,
        _request(tmp_path, {**update, "issue": 13}, "update.yaml"),
        plan,
        _changed_export(tmp_path),
    )

    assert result.exit_code == 3, result.output
    assert "No space left on device" in result.output  # the failure meant, nothing else
    assert (root / ENTRY / "scenario.json").read_bytes() == stored
    assert sorted(path.name for path in (root / ENTRY).iterdir()) == [
        "CHANGELOG.md",
        "README.md",
        "scenario.json",
        "scenario.yaml",
    ]
    assert not plan.exists()


def test_a_repository_another_run_holds_is_left_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    held = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)

        result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)
    finally:
        os.close(held)

    assert result.exit_code == 3, result.output
    assert "another run" in result.output
    assert not (root / "scenarios").exists()
    assert not plan.exists()


def test_a_plan_whose_directory_is_a_link_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (tmp_path / "real").mkdir()
    (tmp_path / "plans").symlink_to(tmp_path / "real")

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plans" / "plan.json")

    assert result.exit_code == 3, result.output
    assert list((tmp_path / "real").iterdir()) == []
    assert not (root / "scenarios").exists()


def test_a_reservation_that_cannot_be_removed_is_said_with_the_run_s_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    removed = os.unlink

    def failing(path: str, **options: Any) -> None:
        if path == plan.name or is_hidden_name(path):  # the reservation, or set aside
            raise OSError(13, "Permission denied")
        removed(path, **options)

    def unplanned(*arguments: Any) -> Any:  # the run fails once its plan is reserved
        monkeypatch.setattr(os, "unlink", failing)
        raise EnvironmentProblemError("the plan cannot be made")

    monkeypatch.setattr("scenario_tools.application.intake_entry.plan_document", unplanned)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "cannot take back plan.json" in result.output  # never where the run is
    assert "the plan cannot be made" in result.output  # what led to it, seen


def test_attributes_set_while_the_entry_is_written_get_no_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    planned = intake_entry.plan_document

    def converting(*arguments: Any) -> Any:  # outside the three directories: not a change seen
        (root / ".gitattributes").write_text(f"{ENTRY}/** text eol=crlf\n")
        return planned(*arguments)

    monkeypatch.setattr("scenario_tools.application.intake_entry.plan_document", converting)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "converts" in result.output
    assert not plan.exists()
    assert not (root / ENTRY).exists()


@pytest.mark.parametrize("read", ["uncommitted", "converting"])
def test_a_checkout_swapped_while_git_reads_it_is_seen_before_anything_is_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, read: str
) -> None:
    """git finds the checkout by its path: once it has read it, that path must still name the
    checkout held, or what git said is of another."""
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    reading = getattr(cli_module, read)
    swaps: list[str] = []

    def swapped(*arguments: Any) -> Any:
        found = reading(*arguments)
        if not swaps:  # another checkout, the same commit, in its place
            shutil.copytree(root, tmp_path / "other", symlinks=True)
            root.rename(tmp_path / "held")
            (tmp_path / "other").rename(root)
            swaps.append(read)
        return found

    def never(*arguments: Any, **options: Any) -> Any:
        raise AssertionError("nothing is written once the checkout is another")

    monkeypatch.setattr(f"scenario_tools.interface.cli.{read}", swapped)
    monkeypatch.setattr("scenario_tools.interface.cli.write_intake", never)
    if read == "uncommitted":  # seen once the commit and the changes are read, before the rest
        monkeypatch.setattr("scenario_tools.interface.cli.intake_entry", never)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "no longer names the repository this run holds" in result.output
    assert not plan.exists()
    assert not (tmp_path / "held" / ENTRY).exists()
    assert not (root / ENTRY).exists()


def test_a_repository_whose_path_names_another_meanwhile_gets_no_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    planned = intake_entry.plan_document

    def swapped(*arguments: Any) -> Any:
        root.rename(tmp_path / "held")
        (tmp_path / "other").mkdir()
        root.symlink_to(tmp_path / "other")
        return planned(*arguments)

    monkeypatch.setattr("scenario_tools.application.intake_entry.plan_document", swapped)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "no longer names" in result.output
    assert not plan.exists()
    assert not (tmp_path / "held" / ENTRY).exists()  # taken back from the repository held
    assert list((tmp_path / "other").iterdir()) == []


def test_an_entry_swapped_before_its_plan_gets_no_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    planned = intake_entry.plan_document
    entry = root / ENTRY

    def swapped(*arguments: Any) -> Any:
        entry.rename(entry.parent / "moved")
        entry.mkdir()
        return planned(*arguments)

    monkeypatch.setattr("scenario_tools.application.intake_entry.plan_document", swapped)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "put at its place meanwhile" in result.output  # ours is said, never removed
    assert not plan.exists()


def test_an_input_reaching_the_entries_through_a_link_and_back_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / "scenarios" / "techniques").mkdir(parents=True)
    request = root / "scenarios" / "request.yaml"
    request.write_bytes(yaml_bytes(NEW))
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "link").symlink_to(root / "scenarios" / "techniques")
    roundabout = tmp_path / "work" / "link" / ".." / "request.yaml"  # ".." taken physically

    result = _intake(monkeypatch, root, roundabout, tmp_path / "plan.json")

    assert result.exit_code == 2, result.output
    assert "scenarios/, policy/ or schemas/" in result.output


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_an_input_that_cannot_be_reached_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / "scenarios").mkdir()
    locked = tmp_path / "locked"
    locked.mkdir()
    request = _request(locked, NEW)
    locked.chmod(0o000)
    try:
        result = _intake(monkeypatch, root, request, tmp_path / "plan.json")
    finally:
        locked.chmod(0o755)

    assert result.exit_code == 3, result.output  # never a trace of the tool's own
    assert "Traceback" not in result.output


_STOPS = [signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT]


@pytest.mark.parametrize("stop", _STOPS, ids=lambda stop: signal.Signals(stop).name)
def test_a_run_asked_to_stop_while_writing_finishes_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stop: signal.Signals
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    planned = intake_entry.plan_document
    handlers = {name: signal.getsignal(name) for name in _STOPS}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())

    def stopped(*arguments: Any) -> Any:
        os.kill(os.getpid(), stop)  # as CI cancels a job, or a person presses Ctrl-C
        return planned(*arguments)

    monkeypatch.setattr("scenario_tools.application.intake_entry.plan_document", stopped)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 0, result.output  # never half way
    assert (root / ENTRY / "scenario.json").exists()
    assert json.loads(plan.read_text(encoding="utf-8"))["entry"] == ENTRY
    assert {name: signal.getsignal(name) for name in handlers} == handlers  # as they were
    assert signal.pthread_sigmask(signal.SIG_BLOCK, ()) == mask


@pytest.mark.parametrize("stop", _STOPS, ids=lambda stop: signal.Signals(stop).name)
@pytest.mark.parametrize("when", ["read_export", "head_commit"])
def test_a_run_asked_to_stop_before_writing_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stop: signal.Signals, when: str
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    handlers = {name: signal.getsignal(name) for name in _STOPS}
    real = getattr(cli_module, when)

    def stopped(path: Path) -> object:
        os.kill(os.getpid(), stop)
        return real(path)

    monkeypatch.setattr(f"scenario_tools.interface.cli.{when}", stopped)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert {name: signal.getsignal(name) for name in handlers} == handlers

    assert result.exit_code == 3, result.output
    assert "interrupted: nothing was written" in result.output
    assert not (root / "scenarios").exists()
    assert not plan.exists()


def test_paths_that_cannot_be_resolved_are_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    request = _request(tmp_path, NEW)
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()  # the working directory is no more: a relative path cannot be resolved
    arguments = ["--request", str(request), "--repo", str(root), "--plan", "plan.json"]

    result = CliRunner().invoke(main, ["--format", "json", "intake", str(EASM), *arguments])

    assert result.exit_code == 3, result.output
    assert "Traceback" not in result.output


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_repository_whose_entries_cannot_be_looked_at_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / "scenarios").mkdir()
    (root / "scenarios").chmod(0o000)
    plan = tmp_path / "plan.json"
    try:
        result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)
    finally:
        (root / "scenarios").chmod(0o755)

    assert result.exit_code == 3, result.output
    assert not plan.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_repository_that_cannot_be_reached_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    request = _request(tmp_path, NEW)
    plan = tmp_path / "plan.json"
    root.chmod(0o444)  # listed, but nothing in it can be looked at
    try:
        result = _intake(monkeypatch, root, request, plan)
    finally:
        root.chmod(0o755)

    assert result.exit_code == 3, result.output
    assert "Traceback" not in result.output
    assert not plan.exists()


def test_a_run_asked_to_stop_once_all_is_written_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    reported = Report

    def stopped(command: str, findings: Any) -> Any:
        if findings:  # the report of what was written, once it is all written
            os.kill(os.getpid(), signal.SIGTERM)
        return reported(command, findings)

    monkeypatch.setattr("scenario_tools.interface.cli.Report", stopped)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "its entry and its plan were written: both stand" in result.output
    assert plan.exists()
    assert (root / ENTRY / "scenario.json").exists()


def test_validate_needs_no_intake_schema(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _repository(tmp_path)
    assert _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "p.json").exit_code == 0
    (root / "schemas" / "intake-request.schema.json").unlink()
    _commit(root)

    result = CliRunner().invoke(main, ["--format", "json", "validate", str(root / ENTRY)])

    assert "schemas cannot be used" not in result.output
    assert result.exit_code in (0, 1), result.output  # the entry's own findings, if any
    again = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "again.json")
    assert again.exit_code == 3, again.output  # intake does
    assert "intake-request.schema.json is missing" in again.output


def test_a_run_asked_to_stop_as_its_writing_ends_says_all_stands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    held = cli_module._stop_requests_held

    @contextlib.contextmanager
    def then_stopped() -> Iterator[None]:
        with held():
            yield
        os.kill(os.getpid(), signal.SIGTERM)  # the moment the hold ends

    monkeypatch.setattr("scenario_tools.interface.cli._stop_requests_held", then_stopped)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "both stand" in result.output  # never "nothing was written"
    assert plan.exists()


def test_a_stop_already_ignored_stays_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    before = signal.signal(signal.SIGHUP, signal.SIG_IGN)  # as nohup runs it
    real = read_export

    def hung_up(path: Path) -> object:
        os.kill(os.getpid(), signal.SIGHUP)
        return real(path)

    monkeypatch.setattr("scenario_tools.interface.cli.read_export", hung_up)
    try:
        result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, before)

    assert result.exit_code == 0, result.output
    assert plan.exists()


def test_a_name_of_the_tool_s_own_in_the_catalogue_stops_an_intake(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    left = root / "scenarios" / "techniques" / ".scenario-tools-0123456789abcdef"
    left.mkdir(parents=True)
    (left / "scenario.yaml").write_text(f"external_id: {ID}\n")  # what a cut run may leave
    _commit(root)  # merged by mistake: never ignored

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plan.json")

    assert result.exit_code == 1, result.output
    assert "ITK-008" in result.output


def test_domains_that_cannot_be_used_are_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / "policy" / "data" / "domains.yaml").write_text("domains: []\n")
    (root / "scenarios" / "techniques" / "easm").mkdir(parents=True)
    _commit(root)

    intake = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plan.json")
    validate = CliRunner().invoke(main, ["validate", str(root / ENTRY)])

    for result in (intake, validate):
        assert result.exit_code == 3, result.output
        assert "policy data cannot be used" in result.output


def test_the_domains_are_the_repository_s_own(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / "policy" / "data" / "domains.yaml").write_text("domains: [custom]\n")
    _commit(root)

    refused = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "refused.json")
    accepted = _intake(
        monkeypatch, root, _request(tmp_path, {**NEW, "domain": "custom"}), tmp_path / "plan.json"
    )

    assert refused.exit_code == 1, refused.output
    assert "SCH-001" in refused.output
    assert "custom" in refused.output
    assert accepted.exit_code == 0, accepted.output
    validate = CliRunner().invoke(main, ["validate", str(root / "scenarios" / "custom" / "easm")])
    assert "SCH-008" not in validate.output  # the layout knows the repository's domains


def test_environment_errors_never_show_where_the_run_is(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "missing" / "plan.json"  # its directory is not there

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert str(tmp_path) not in result.output
    assert "cannot write missing" in result.output  # the directory that is not there, by name


@pytest.mark.parametrize(
    "change",
    ["scenarios/techniques/other/scenario.yaml", "policy/data/extra.yaml", "schemas/x.json"],
)
def test_a_checkout_with_uncommitted_changes_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, change: str
) -> None:
    root = _repository(tmp_path)
    (root / change).parent.mkdir(parents=True, exist_ok=True)
    (root / change).write_text("not committed")
    plan = tmp_path / "plan.json"

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert change in result.output
    assert "commit" in result.output
    assert not (root / ENTRY).exists()
    assert not plan.exists()


def test_changes_elsewhere_in_the_checkout_do_not_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / "notes.txt").write_text("not committed, and not the catalogue's")

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plan.json")

    assert result.exit_code == 0, result.output


def test_a_leftover_not_committed_is_told_as_a_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    assert _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "new.json").exit_code == 0
    _commit(root)
    left = root / ENTRY / ".scenario-tools-0123456789abcdef"
    left.write_bytes(b"{}")  # what a run killed while updating may leave

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plan.json")

    assert result.exit_code == 3, result.output
    assert ".scenario-tools-0123456789abcdef" in result.output
    _commit(root)  # merged by mistake: never ignored either
    again = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "again.json")
    assert again.exit_code == 1, again.output
    assert "ITK-008" in again.output


def test_a_commit_that_changes_while_the_checkout_is_checked_stops_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    told = uncommitted

    def then_moved(*arguments: Any) -> Any:
        found = told(*arguments)
        (root / "notes.txt").write_text("another commit")
        _commit(root)  # another checks out or commits meanwhile
        return found

    monkeypatch.setattr("scenario_tools.interface.cli.uncommitted", then_moved)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "changed while" in result.output
    assert not plan.exists()


def test_a_checkout_whose_files_git_converts_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / ".gitattributes").write_text("policy/** text eol=crlf\n")
    _commit(root)
    plan = tmp_path / "plan.json"

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "converts" in result.output
    assert not plan.exists()


@pytest.mark.parametrize("rule", ["scenarios/techniques/easm/** text eol=crlf", "*.yaml filter=x"])
def test_attributes_that_would_convert_the_files_to_write_are_refused_before_writing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, rule: str
) -> None:
    root = _repository(tmp_path)
    (root / ".gitattributes").write_text(f"{rule}\n")  # for files that do not exist yet
    _commit(root)
    plan = tmp_path / "plan.json"

    def never(*arguments: Any, **options: Any) -> Any:
        raise AssertionError("nothing may be written")

    monkeypatch.setattr("scenario_tools.interface.cli.write_intake", never)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "converts" in result.output
    assert not (root / "scenarios").exists()
    assert not plan.exists()


def test_a_filter_the_checkout_s_attributes_name_is_refused_before_it_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    (root / ".gitattributes").write_text("policy/** filter=x\n")
    _commit(root)
    marker = tmp_path / "ran"
    _git(root, "config", "filter.x.clean", f"touch {marker}; cat")
    domains = root / "policy" / "data" / "domains.yaml"
    os.utime(domains, (1, 1))  # a file git looks at again, through its filter

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plan.json")

    assert result.exit_code == 3, result.output
    assert "converts" in result.output
    assert not marker.exists()  # refused before git status could run it


def test_a_checkout_git_writes_with_other_line_ends_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    _git(root, "config", "core.autocrlf", "true")
    domains = root / "policy" / "data" / "domains.yaml"
    domains.write_bytes(domains.read_bytes().replace(b"\n", b"\r\n"))  # as git checks it out

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "plan.json")

    assert result.exit_code == 3, result.output
    assert "converts" in result.output


def test_an_input_that_cannot_be_read_is_said_without_where_it_is(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    missing = tmp_path / "elsewhere" / "missing.zip"
    (tmp_path / "plans").mkdir()  # the plan's place elsewhere: the export's is its own
    plan = tmp_path / "plans" / "p.json"

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan, missing)

    assert result.exit_code == 3, result.output
    assert str(tmp_path) not in result.output
    assert "missing.zip" in result.output


def test_a_commit_made_while_the_entry_is_written_gets_no_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    planned = intake_entry.plan_document

    def committed_meanwhile(*arguments: Any) -> Any:
        (root / "notes.txt").write_text("another commit")
        _git(root, "add", "notes.txt")
        _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
             "commit.gpgsign=false", "commit", "-q", "-m", "meanwhile")  # fmt: skip
        return planned(*arguments)

    monkeypatch.setattr(
        "scenario_tools.application.intake_entry.plan_document", committed_meanwhile
    )

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert "commit changed" in result.output
    assert not plan.exists()
    assert not (root / ENTRY).exists()  # taken back


@pytest.mark.parametrize(
    "changed", ["policy/data/domains.yaml", "scenarios/techniques/other/scenario.yaml"]
)
def test_a_catalogue_or_rules_changed_while_the_entry_is_written_gets_no_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, changed: str
) -> None:
    root = _repository(tmp_path)
    plan = tmp_path / "plan.json"
    planned = intake_entry.plan_document

    def changed_meanwhile(*arguments: Any) -> Any:
        (root / changed).parent.mkdir(parents=True, exist_ok=True)
        (root / changed).write_text("changed meanwhile")
        return planned(*arguments)

    planning = "scenario_tools.application.intake_entry.plan_document"
    monkeypatch.setattr(planning, changed_meanwhile)

    result = _intake(monkeypatch, root, _request(tmp_path, NEW), plan)

    assert result.exit_code == 3, result.output
    assert changed in result.output
    assert not plan.exists()
    assert not (root / ENTRY).exists()  # taken back


def test_metadata_changed_while_an_update_is_written_gets_no_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    assert _intake(monkeypatch, root, _request(tmp_path, NEW), tmp_path / "new.json").exit_code == 0
    _commit(root)
    stored = (root / ENTRY / "scenario.json").read_bytes()
    plan = tmp_path / "update.json"
    planned = intake_entry.plan_document

    def changed_meanwhile(*arguments: Any) -> Any:
        with (root / ENTRY / "scenario.yaml").open("a") as file:
            file.write("# changed meanwhile\n")  # the file the update does not write
        return planned(*arguments)

    planning = "scenario_tools.application.intake_entry.plan_document"
    monkeypatch.setattr(planning, changed_meanwhile)
    update = {"mode": "update", "external_id": ID, "domain": "techniques", "slug": "easm"}

    result = _intake(
        monkeypatch,
        root,
        _request(tmp_path, {**update, "issue": 13}, "update.yaml"),
        plan,
        _changed_export(tmp_path),
    )

    assert result.exit_code == 3, result.output
    assert f"{ENTRY}/scenario.yaml" in result.output
    assert not plan.exists()
    assert (root / ENTRY / "scenario.json").read_bytes() == stored  # put back
