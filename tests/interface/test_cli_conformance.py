"""The conformance commands: the release fixtures written, then run through the verifier."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.interface.cli import main
from tests.interface.test_cli_build import ROOT


def _invoke(*arguments: str) -> Any:
    return CliRunner().invoke(main, ["--format", "json", *arguments])


def _build(out: Path) -> Any:
    return _invoke("conformance", "build", "--out", str(out))


def _run(fixtures: Path) -> Any:
    return _invoke("conformance", "run", str(fixtures), "--schemas", str(ROOT / "schemas"))


def _findings(result: Any) -> list[tuple[str, str]]:
    return [(f["code"], f["path"]) for f in json.loads(result.output)["findings"]]


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("fixtures") / "releases"
    result = _build(out)
    assert result.exit_code == 0, result.output
    return out


def _copy(built: Path, tmp_path: Path) -> Path:
    return Path(shutil.copytree(built, tmp_path / "releases"))


def test_the_fixtures_built_give_what_they_expect(built: Path) -> None:
    result = _run(built)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["ok"] is True


def test_the_fixtures_are_written_once_into_a_new_or_empty_directory(
    built: Path, tmp_path: Path
) -> None:
    (tmp_path / "empty").mkdir()

    assert _build(tmp_path / "empty").exit_code == 0
    assert _build(built).exit_code == 2
    assert _build(tmp_path / "missing" / "out").exit_code == 2


def test_a_fixture_that_no_longer_gives_what_it_expects_fails(built: Path, tmp_path: Path) -> None:
    fixtures = _copy(built, tmp_path)
    next((fixtures / "accepted").glob("*.zip")).write_bytes(b"altered")

    result = _run(fixtures)

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("CNF-001", "accepted")]


def test_a_directory_expected_json_does_not_name_fails(built: Path, tmp_path: Path) -> None:
    fixtures = _copy(built, tmp_path)
    (fixtures / "stray").mkdir()

    result = _run(fixtures)

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("CNF-002", "stray")]


def test_expectations_out_of_shape_are_refused_input(built: Path, tmp_path: Path) -> None:
    fixtures = _copy(built, tmp_path)
    (fixtures / "expected.json").write_text('{"fixtures": {}}')

    result = _run(fixtures)

    assert result.exit_code == 1, result.output
    ((code, path),) = _findings(result)
    assert (code, Path(path).name) == ("IO-014", "expected.json")


def test_a_fixtures_directory_that_does_not_exist_is_a_usage_error(tmp_path: Path) -> None:
    result = _run(tmp_path / "missing")

    assert result.exit_code == 2, result.output


def test_the_fixtures_are_never_written_through_a_link(built: Path, tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "empty")

    assert _build(tmp_path / "link").exit_code == 2
    assert not any((tmp_path / "empty").iterdir())


def test_a_fixture_directory_that_is_a_link_is_refused(built: Path, tmp_path: Path) -> None:
    fixtures = _copy(built, tmp_path)
    shutil.move(fixtures / "accepted", tmp_path / "elsewhere")
    (fixtures / "accepted").symlink_to(tmp_path / "elsewhere")

    result = _run(fixtures)

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("CNF-001", "accepted")]
    assert "IO-013" in json.loads(result.output)["findings"][0]["message"]


def test_a_fixture_that_is_a_file_is_refused_and_the_others_still_run(
    built: Path, tmp_path: Path
) -> None:
    fixtures = _copy(built, tmp_path)
    shutil.rmtree(fixtures / "accepted")
    (fixtures / "accepted").write_text("not a release")

    result = _run(fixtures)

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("CNF-001", "accepted")]
    assert "IO-013" in json.loads(result.output)["findings"][0]["message"]
