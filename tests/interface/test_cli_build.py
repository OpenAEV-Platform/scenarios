"""The ``build`` command: every archive of the catalogue and the manifest, from a commit."""

import hashlib
import io
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.interface.cli import main
from tests.support.catalogue import write_catalogue
from tests.support.chaining import CHAINED, CHAINED_METADATA

ROOT = Path(__file__).parents[2]
EASM = "scenarios/techniques/easm"
EASM_ID = "3e2aa79f-9d73-48fd-839e-ccf1525b42e7"
ARCHIVE = f"{EASM_ID}-1.0.0.zip"
WHEN = "2026-10-30T11:15:02+02:00"


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - a fixed program, arguments of the test's own
        ["git", "-C", str(root), *arguments],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str, merged: str = ""
) -> Path:
    """A checkout holding this repository's rules, schemas and EASM entry, and ``extra``
    paths of it, committed at a set time; ``merged`` lists the pull requests merged before
    review, when given."""
    root = tmp_path / "repository"
    for path in ("policy", "schemas", EASM, *extra):
        shutil.copytree(ROOT / path, root / path)
    if merged:
        (root / "policy" / "data" / "merged-before-review.yaml").write_text(merged)
    monkeypatch.setenv("GIT_COMMITTER_DATE", WHEN)
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "start")  # fmt: skip
    return root


def _approvals(tmp_path: Path, approvers: list[str] | None = None) -> Path:
    """The approvals of the checkout's commit, as the release workflow collects them."""
    path = tmp_path / "approvals.json"
    entry = {"pull_request": 123, "approvers": ["alice"] if approvers is None else approvers}
    commit = _git(tmp_path / "repository", "rev-parse", "HEAD")
    path.write_text(json.dumps({"schema_version": 1, "commit": commit, "entries": {EASM: entry}}))
    return path


def _build(
    root: Path, approvals: Path, out: Path, previous: str = "none", channel: str = "edge"
) -> Any:
    return CliRunner().invoke(
        main,
        ["--format", "json", "build", "--repo", str(root), "--previous-release", previous,
         "--channel", channel, "--approvals", str(approvals), "--out", str(out)],
    )  # fmt: skip


def test_a_release_is_built_from_the_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 0, result.output
    assert sorted(path.name for path in out.iterdir()) == [ARCHIVE, "manifest.json"]
    data = (out / "manifest.json").read_bytes()
    document = json.loads(data)
    assert data == jcs(document)
    assert JsonSchemaValidator(ROOT / "schemas").validate("manifest", document) == ()
    assert (document["issued_at"], document["release"]) == ("2026-10-30T09:15:02Z", "2026.10.30.1")
    [item] = document["items"]
    archive = (out / ARCHIVE).read_bytes()
    assert item["archive"] == {
        "name": ARCHIVE,
        "sha256": hashlib.sha256(archive).hexdigest(),
        "size": len(archive),
    }
    assert item["approvals"] == {"pull_request": 123, "approvers": ["alice"]}
    assert item["tabletop"] is False  # EASM runs payloads on endpoints
    assert "test_report" not in item
    archived = tmp_path / "archived.zip"
    single = CliRunner().invoke(main, ["archive", str(root / EASM), "--out", str(archived)])
    assert single.exit_code == 0, single.output
    assert archive == archived.read_bytes()  # the code of archive, for every entry


def test_two_builds_of_a_commit_give_the_same_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = _approvals(tmp_path)

    for out in ("one", "two"):
        assert _build(root, approvals, tmp_path / out).exit_code == 0

    for name in (ARCHIVE, "manifest.json"):
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()


def test_a_release_holds_only_what_comes_from_the_catalogue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch, "tests/golden")
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 0, result.output
    assert sorted(path.name for path in out.iterdir()) == [ARCHIVE, "manifest.json"]
    items = json.loads((out / "manifest.json").read_bytes())["items"]
    assert [item["external_id"] for item in items] == [EASM_ID]
    archive = zipfile.ZipFile(io.BytesIO((out / ARCHIVE).read_bytes()))
    assert archive.namelist() == ["scenario.json"]
    assert archive.read("scenario.json") == (root / EASM / "scenario.json").read_bytes()


def test_a_checkout_with_uncommitted_changes_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    (root / EASM / "notes.txt").write_text("x")
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 3, result.output
    assert "not committed" in result.output
    assert not out.exists()


def test_an_entry_without_an_approver_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path, []), out)

    assert result.exit_code == 1, result.output
    assert [f["code"] for f in json.loads(result.output)["findings"]] == ["REL-002"]
    assert not out.exists()


def test_a_pull_request_listed_as_merged_before_review_needs_no_approver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listed = "pull_requests:\n  - number: 123\n    reason: merged before the rules\n"
    root = _repository(tmp_path, monkeypatch, merged=listed)

    result = _build(root, _approvals(tmp_path, []), tmp_path / "release")

    assert result.exit_code == 0, result.output


def test_a_released_version_whose_archive_changed_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = _approvals(tmp_path)
    assert _build(root, approvals, tmp_path / "first").exit_code == 0
    previous = json.loads((tmp_path / "first" / "manifest.json").read_bytes())
    previous["items"][0]["archive"]["sha256"] = "0" * 64
    previous["release"] = "2026.10.29.2"
    (tmp_path / "previous.json").write_bytes(jcs(previous))
    out = tmp_path / "release"

    result = _build(root, approvals, out, str(tmp_path / "previous.json"))

    assert result.exit_code == 1, result.output
    [finding] = json.loads(result.output)["findings"]
    assert (finding["code"], finding["path"]) == ("VER-020", f"{EASM}/scenario.yaml")
    assert not out.exists()


def test_a_release_after_the_previous_one_of_the_day_takes_the_next_rank(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = _approvals(tmp_path)
    assert _build(root, approvals, tmp_path / "first").exit_code == 0

    out = tmp_path / "second"
    result = _build(root, approvals, out, str(tmp_path / "first" / "manifest.json"))

    assert result.exit_code == 0, result.output
    assert json.loads((out / "manifest.json").read_bytes())["release"] == "2026.10.30.2"


def test_a_previous_release_that_is_no_manifest_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    path = tmp_path / "previous.json"
    path.write_text(json.dumps({"schema_version": 1}))
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out, str(path))

    assert result.exit_code == 3, result.output
    assert "the previous release's manifest does not meet its schema" in result.output
    assert not out.exists()


def test_a_previous_release_that_is_no_json_is_refused_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    path = tmp_path / "previous.json"
    path.write_text("not json")
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out, str(path))

    assert result.exit_code == 1, result.output
    [finding] = json.loads(result.output)["findings"]
    assert (finding["code"], finding["path"]) == ("IO-002", "previous.json")
    assert not out.exists()


@pytest.mark.parametrize(
    "document", [{"schema_version": 1}, [], {"schema_version": 1, "entries": {"x": 1}}]
)
def test_an_approvals_file_out_of_its_shape_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: Any
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = tmp_path / "approvals.json"
    approvals.write_text(json.dumps(document))
    out = tmp_path / "release"

    result = _build(root, approvals, out)

    assert result.exit_code == 3, result.output
    assert "approvals: the file is not as the release workflow writes it" in result.output
    assert not out.exists()


@pytest.mark.parametrize("place", ["inside", "taken"])
def test_the_output_is_a_new_or_empty_directory_outside_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, place: str
) -> None:
    root = _repository(tmp_path, monkeypatch)
    out = root / "release" if place == "inside" else tmp_path / "release"
    if place == "taken":
        out.mkdir()
        (out / "earlier.zip").write_text("x")

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 2, result.output


def test_an_empty_output_directory_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    out = tmp_path / "release"
    out.mkdir()

    assert _build(root, _approvals(tmp_path), out).exit_code == 0
    assert (out / "manifest.json").is_file()


def test_a_release_is_built_for_the_stable_channel_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out, channel="stable")

    assert result.exit_code == 0, result.output
    assert json.loads((out / "manifest.json").read_bytes())["channel"] == "stable"


def test_a_previous_release_of_another_channel_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = _approvals(tmp_path)
    assert _build(root, approvals, tmp_path / "first", channel="stable").exit_code == 0
    out = tmp_path / "release"

    result = _build(root, approvals, out, str(tmp_path / "first" / "manifest.json"))

    assert result.exit_code == 3, result.output
    assert "the previous release is on stable, not edge" in result.output
    assert not out.exists()


def test_an_output_whose_parent_is_missing_is_refused_before_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)

    result = _build(root, _approvals(tmp_path), tmp_path / "missing" / "release")

    assert result.exit_code == 2, result.output
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize("given", ["approvals", "previous"])
def test_an_input_inside_the_repository_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: str
) -> None:
    """A file of the checkout is the pull request's to write: never a release's input."""
    root = _repository(tmp_path, monkeypatch)
    inside = root / "inputs.json"
    inside.write_text("{}")
    approvals = inside if given == "approvals" else _approvals(tmp_path)
    previous = str(inside) if given == "previous" else "none"

    result = _build(root, approvals, tmp_path / "release", previous)

    assert result.exit_code == 2, result.output


def test_an_entry_without_its_metadata_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory of the catalogue is an entry, whatever it holds: never left out unsaid."""
    root = _repository(tmp_path, monkeypatch)
    (root / EASM / "scenario.yaml").unlink()
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "without")  # fmt: skip
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 1, result.output
    assert not out.exists()


def test_the_uncommitted_changes_are_said_for_the_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    (root / EASM / "notes.txt").write_text("x")

    result = _build(root, _approvals(tmp_path), tmp_path / "release")

    assert "so that the release describes its commit" in result.output


def test_a_released_scenario_that_no_entry_has_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = _approvals(tmp_path)
    assert _build(root, approvals, tmp_path / "first").exit_code == 0
    previous = json.loads((tmp_path / "first" / "manifest.json").read_bytes())
    gone = dict(previous["items"][0], external_id="9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f")
    gone["archive"] = dict(gone["archive"], name=f"{gone['external_id']}-1.0.0.zip")
    previous["items"].append(gone)
    (tmp_path / "previous.json").write_bytes(jcs(previous))
    out = tmp_path / "release"

    result = _build(root, approvals, out, str(tmp_path / "previous.json"))

    assert result.exit_code == 1, result.output
    assert [f["code"] for f in json.loads(result.output)["findings"]] == ["REL-003"]
    assert not out.exists()


def test_a_catalogue_without_an_entry_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    _git(root, "rm", "-q", "-r", "scenarios")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "empty")  # fmt: skip
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 3, result.output
    assert "no entry: nothing to release" in result.output
    assert not out.exists()


def test_an_output_that_is_a_link_is_refused_before_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    (tmp_path / "elsewhere").mkdir()
    out = tmp_path / "release"
    out.symlink_to(tmp_path / "elsewhere")

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 2, result.output
    assert list((tmp_path / "elsewhere").iterdir()) == []


def test_a_released_version_whose_status_changed_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = _approvals(tmp_path)
    assert _build(root, approvals, tmp_path / "first").exit_code == 0
    metadata = root / EASM / "scenario.yaml"
    metadata.write_text(metadata.read_text().replace("status: VERIFIED", "status: DEPRECATED"))
    assert CliRunner().invoke(main, ["render", str(root / EASM)]).exit_code == 0
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-am", "deprecated")  # fmt: skip
    out = tmp_path / "release"

    previous = str(tmp_path / "first" / "manifest.json")
    result = _build(root, _approvals(tmp_path), out, previous)

    assert result.exit_code == 1, result.output
    codes = [f["code"] for f in json.loads(result.output)["findings"]]
    assert "VER-020" in codes
    assert not out.exists()


def test_a_previous_release_listing_a_scenario_twice_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = _approvals(tmp_path)
    assert _build(root, approvals, tmp_path / "first").exit_code == 0
    previous = json.loads((tmp_path / "first" / "manifest.json").read_bytes())
    twice = dict(previous["items"][0], version="0.9.0")
    twice["archive"] = dict(twice["archive"], name=f"{EASM_ID}-0.9.0.zip")
    previous["items"].append(twice)
    (tmp_path / "previous.json").write_bytes(jcs(previous))
    out = tmp_path / "release"

    result = _build(root, approvals, out, str(tmp_path / "previous.json"))

    assert result.exit_code == 3, result.output
    assert f"the previous release lists {EASM_ID} twice" in result.output
    assert not out.exists()


def test_approvals_collected_at_another_commit_build_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    approvals = _approvals(tmp_path)
    (root / "README.md").write_text("x")
    _git(root, "add", "README.md")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "next")  # fmt: skip
    out = tmp_path / "release"

    result = _build(root, approvals, out)

    assert result.exit_code == 3, result.output
    assert "not at the commit built" in result.output
    assert not out.exists()


def _chained_entry(root: Path) -> None:
    """The hand-built scenario in chaining as an entry of ``root``, committed: its stored form,
    its metadata, the version files of its payloads, its payload references assigned and its
    sheet rendered."""
    entry = root / CHAINED
    entry.mkdir(parents=True)
    stored = ROOT / "tests" / "golden" / "chaining" / "two-steps.normalised.json"
    shutil.copyfile(stored, entry / "scenario.json")
    (entry / "scenario.yaml").write_text(CHAINED_METADATA)
    (entry / "CHANGELOG.md").write_text("# Changelog\n\n## 1.0.0 — 2026-10-22\n\nFirst version.\n")
    write_catalogue(root, json.loads(stored.read_bytes()))
    for command in (["payloads", str(entry), "--assign"], ["render", str(entry)]):
        result = CliRunner().invoke(main, command)
        assert result.exit_code == 0, result.output
    _git(root, "add", ".")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "chained")  # fmt: skip


def test_a_release_of_a_scenario_in_chaining_lists_its_steps_payloads_and_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch)
    _chained_entry(root)
    approvals = tmp_path / "approvals.json"
    approved = {"pull_request": 124, "approvers": ["alice"]}
    approvals.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "commit": _git(root, "rev-parse", "HEAD"),
                "entries": {EASM: approved, CHAINED: approved},
            }
        )
    )
    out = tmp_path / "release"

    result = _build(root, approvals, out)

    assert result.exit_code == 0, result.output
    document = json.loads((out / "manifest.json").read_bytes())
    (item,) = [item for item in document["items"] if item["type"] == "chained"]
    assert item["tabletop"] is False
    assert (item["requires"]["edition"], item["requires"]["injectors"]) == (
        "EE",
        ["openaev_implant"],
    )
    stored = json.loads(zipfile.ZipFile(out / item["archive"]["name"]).read("scenario.json"))
    steps = stored["scenario_workflow"]["workflow_steps"]
    embedded = {
        step["step_data"]["inject_injector_contract"]["injector_contract_payload"][
            "payload_external_id"
        ]
        for step in steps
    }
    assert [payload["id"] for payload in item["payloads"]] == sorted(embedded)  # listed once
    verified = CliRunner().invoke(
        main, ["verify", str(out / "manifest.json"), "--schemas", str(ROOT / "schemas")]
    )
    assert verified.exit_code == 0, verified.output


def test_a_release_lists_every_payload_version_and_carries_its_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch, "payloads")
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 0, result.output
    held = sorted(root.glob("payloads/*/*.json"))
    document = json.loads((out / "manifest.json").read_bytes())
    listed = {(entry["payload"], entry["version"]): entry for entry in document["payloads"]}
    assert sorted(listed) == sorted((path.parent.name, path.stem) for path in held)  # none used
    for path in held:
        entry = listed[(path.parent.name, path.stem)]
        assert (out / entry["file"]["name"]).read_bytes() == path.read_bytes()
    verified = CliRunner().invoke(
        main, ["verify", str(out / "manifest.json"), "--schemas", str(root / "schemas")]
    )
    assert verified.exit_code == 0, verified.output


def test_a_released_payload_version_whose_file_changed_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch, "payloads")
    approvals = _approvals(tmp_path)
    assert _build(root, approvals, tmp_path / "first").exit_code == 0
    previous = json.loads((tmp_path / "first" / "manifest.json").read_bytes())
    released = previous["payloads"][0]
    released["file"]["sha256"] = "0" * 64
    previous["release"] = "2026.10.29.2"
    (tmp_path / "previous.json").write_bytes(jcs(previous))
    out = tmp_path / "release"

    result = _build(root, approvals, out, str(tmp_path / "previous.json"))

    assert result.exit_code == 1, result.output
    [finding] = json.loads(result.output)["findings"]
    path = f"payloads/{released['payload']}/{released['version']}.json"
    assert (finding["code"], finding["path"]) == ("VER-021", path)
    assert not out.exists()


def test_a_payload_catalogue_its_checks_refuse_builds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch, "payloads")
    (root / "payloads" / "README.md").write_text("Not a payload.\n")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "stray")  # fmt: skip
    out = tmp_path / "release"

    result = _build(root, _approvals(tmp_path), out)

    assert result.exit_code == 1, result.output
    found = [(f["code"], f["path"]) for f in json.loads(result.output)["findings"]]
    assert found == [("PAY-009", "payloads/README.md")]
    assert not out.exists()


def test_two_builds_with_a_payload_catalogue_give_the_same_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, monkeypatch, "payloads")
    approvals = _approvals(tmp_path)

    for out in ("one", "two"):
        assert _build(root, approvals, tmp_path / out).exit_code == 0

    one = {path.name: path.read_bytes() for path in (tmp_path / "one").iterdir()}
    assert {path.name: path.read_bytes() for path in (tmp_path / "two").iterdir()} == one
    assert any(name.endswith(".json") and name != "manifest.json" for name in one)
