"""The ``approve`` command: the release approver added to a manifest that ``build`` wrote."""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.interface.cli import main
from tests.interface.test_cli_build import ROOT, _approvals, _build, _repository


def _release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = _repository(tmp_path, monkeypatch)
    out = tmp_path / "release"
    assert _build(root, _approvals(tmp_path), out).exit_code == 0
    return out


def _approve(manifest: Path, approver: str, out: Path) -> Any:
    arguments = ["--format", "json", "approve", str(manifest), "--approver", approver]
    return CliRunner().invoke(main, [*arguments, "--out", str(out)])


def test_the_approved_manifest_names_its_approver_and_verifies_as_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    built = json.loads((release / "manifest.json").read_bytes())
    out = tmp_path / "approved"

    result = _approve(release / "manifest.json", "laugiov", out)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["ok"] is True
    written = (out / "manifest.json").read_bytes()
    assert written == jcs({**built, "release_approver": "laugiov"})
    assert sorted(path.name for path in out.iterdir()) == ["manifest.json"]
    (release / "manifest.json").write_bytes(written)  # in place, as the release job puts it
    verified = CliRunner().invoke(
        main,
        [
            *("--format", "json", "verify", str(release / "manifest.json")),
            *("--schemas", str(ROOT / "schemas"), "--approved"),
        ],
    )
    assert verified.exit_code == 0, verified.output


def test_a_manifest_already_approved_is_not_approved_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    assert _approve(release / "manifest.json", "laugiov", tmp_path / "once").exit_code == 0

    result = _approve(tmp_path / "once" / "manifest.json", "alice", tmp_path / "twice")

    assert result.exit_code == 3, result.output
    assert "already names its approver" in result.output
    assert not (tmp_path / "twice").exists()


def test_an_approver_not_in_lower_case_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)

    result = _approve(release / "manifest.json", "Laugiov", tmp_path / "approved")

    assert result.exit_code == 2, result.output
    assert not (tmp_path / "approved").exists()


def test_the_approved_manifest_goes_to_a_new_or_empty_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    taken = tmp_path / "taken"
    taken.mkdir()
    (taken / "other").write_text("x")

    result = _approve(release / "manifest.json", "laugiov", taken)

    assert result.exit_code == 2, result.output
    assert sorted(path.name for path in taken.iterdir()) == ["other"]


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ([], "a manifest is an object"),
        ({"repository": "someone/else"}, "it is a manifest of another repository"),
    ],
)
def test_a_document_that_is_no_manifest_of_this_repository_is_refused(
    tmp_path: Path, document: Any, why: str
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(jcs(document))

    result = _approve(manifest, "laugiov", tmp_path / "approved")

    assert result.exit_code == 3, result.output
    assert why in result.output
    assert not (tmp_path / "approved").exists()


def test_an_empty_directory_takes_the_approved_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    (tmp_path / "approved").mkdir()

    result = _approve(release / "manifest.json", "laugiov", tmp_path / "approved")

    assert result.exit_code == 0, result.output
    assert (tmp_path / "approved" / "manifest.json").is_file()
