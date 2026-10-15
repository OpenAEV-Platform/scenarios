"""The release fixtures in conformance/releases: what conformance build writes, byte for byte,
and each gives what expected.json says when verified."""

from pathlib import Path

from click.testing import CliRunner

from scenario_tools.adapters.fixture_zip import HandmadeArchives
from scenario_tools.adapters.zip_archive import ZipArchiveBuilder
from scenario_tools.application.build_fixtures import fixture_files, release_fixtures
from scenario_tools.interface.cli import main

ROOT = Path(__file__).parents[2]
RELEASES = ROOT / "conformance" / "releases"


def test_the_fixtures_in_the_repository_are_those_the_tools_build() -> None:
    built = fixture_files(release_fixtures(ZipArchiveBuilder(), HandmadeArchives()))
    committed = {
        path.relative_to(RELEASES).as_posix(): path.read_bytes()
        for path in RELEASES.rglob("*")
        if path.is_file()
    }

    assert sorted(committed) == sorted(built), "run make fixtures"
    assert [path for path in built if committed[path] != built[path]] == [], "run make fixtures"


def test_the_fixtures_in_the_repository_give_what_they_expect() -> None:
    arguments = ["conformance", "run", str(RELEASES), "--schemas", str(ROOT / "schemas")]

    result = CliRunner().invoke(main, arguments)

    assert result.exit_code == 0, result.output
