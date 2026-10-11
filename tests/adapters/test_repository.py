"""Reading the repository's entries: never through a symbolic link, parent directories included,
within the input limits, every refusal naming the file by its path in the repository."""

import os
from pathlib import Path

import pytest

from scenario_tools.adapters import repository
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

ENTRY = "scenarios/ransomware/akira"


def _entry(root: Path, relative: str = ENTRY, external_id: str = "one") -> Path:
    directory = root / relative
    directory.mkdir(parents=True)
    (directory / "scenario.yaml").write_text(f"external_id: {external_id}\n")
    (directory / "scenario.json").write_text('{"a": 1}')
    (directory / "README.md").write_text("# Akira\n")
    return directory


def _refusal(error: pytest.ExceptionInfo[UnsafeInputError]) -> tuple[str, str]:
    return error.value.code, error.value.path


def test_an_entry_s_files_are_read_by_their_path_in_the_repository(tmp_path: Path) -> None:
    _entry(tmp_path)
    source = RepositoryEntries(tmp_path)

    assert source.names(ENTRY) == {"scenario.yaml", "scenario.json", "README.md"}
    assert source.read_yaml(f"{ENTRY}/scenario.yaml") == {"external_id": "one"}
    assert source.read_json(f"{ENTRY}/scenario.json") == (b'{"a": 1}', {"a": 1})
    assert source.read_text(f"{ENTRY}/README.md") == "# Akira\n"


def test_a_directory_of_the_path_that_is_a_link_is_never_followed(tmp_path: Path) -> None:
    _entry(tmp_path, "elsewhere/ransomware/akira")
    (tmp_path / "scenarios").symlink_to(tmp_path / "elsewhere")
    source = RepositoryEntries(tmp_path)

    with pytest.raises(UnsafeInputError) as error:
        source.read_yaml(f"{ENTRY}/scenario.yaml")
    assert _refusal(error) == ("IO-013", "scenarios")
    with pytest.raises(UnsafeInputError) as error:
        source.names(ENTRY)
    assert _refusal(error) == ("IO-013", "scenarios")


def test_an_entry_directory_that_is_a_link_is_never_followed(tmp_path: Path) -> None:
    _entry(tmp_path, "scenarios/ransomware/real")
    (tmp_path / ENTRY).symlink_to(tmp_path / "scenarios/ransomware/real")

    with pytest.raises(UnsafeInputError) as error:
        RepositoryEntries(tmp_path).names(ENTRY)
    assert _refusal(error) == ("IO-013", ENTRY)


def test_a_file_that_is_a_link_is_refused_by_its_path_in_the_repository(tmp_path: Path) -> None:
    directory = _entry(tmp_path)
    (directory / "README.md").unlink()
    (directory / "README.md").symlink_to(directory / "scenario.yaml")

    with pytest.raises(UnsafeInputError) as error:
        RepositoryEntries(tmp_path).read_text(f"{ENTRY}/README.md")
    assert _refusal(error) == ("IO-013", f"{ENTRY}/README.md")


@pytest.mark.parametrize(
    ("content", "code"),
    [(b"\xff\xfe", "IO-002"), (b"a" * (1024 * 1024 + 1), "IO-001")],
    ids=["not utf-8", "too large"],
)
def test_a_text_is_read_within_its_limit_and_as_utf_8(
    tmp_path: Path, content: bytes, code: str
) -> None:
    directory = _entry(tmp_path)
    (directory / "CHANGELOG.md").write_bytes(content)

    with pytest.raises(UnsafeInputError) as error:
        RepositoryEntries(tmp_path).read_text(f"{ENTRY}/CHANGELOG.md")
    assert _refusal(error) == (code, f"{ENTRY}/CHANGELOG.md")


def test_a_refused_document_names_its_path_in_the_repository(tmp_path: Path) -> None:
    directory = _entry(tmp_path)
    (directory / "scenario.json").write_text("{")

    with pytest.raises(UnsafeInputError) as error:
        RepositoryEntries(tmp_path).read_json(f"{ENTRY}/scenario.json")
    assert _refusal(error) == ("IO-002", f"{ENTRY}/scenario.json")


def test_a_missing_directory_is_the_environment_s_fault(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError):
        RepositoryEntries(tmp_path).names(ENTRY)


def test_every_entry_s_external_id_is_listed_with_its_directories(tmp_path: Path) -> None:
    _entry(tmp_path, ENTRY, "one")
    _entry(tmp_path, "scenarios/techniques/b", "two")
    _entry(tmp_path, "scenarios/techniques/a", "two")
    broken = _entry(tmp_path, "scenarios/techniques/broken", "three")
    (broken / "scenario.yaml").write_text("external_id: [")
    _entry(tmp_path, "scenarios/techniques/listed", "four")
    (tmp_path / "scenarios/techniques/listed/scenario.yaml").write_text("- a list\n")
    _entry(tmp_path, "scenarios/techniques/number", "5")
    (tmp_path / "scenarios/techniques/empty").mkdir()
    (tmp_path / "scenarios/techniques/file").write_text("not an entry")
    _entry(tmp_path, "outside/x/y", "five")
    (tmp_path / "scenarios/techniques/linked").symlink_to(tmp_path / "outside/x/y")

    assert RepositoryEntries(tmp_path).external_ids() == {
        "one": (ENTRY,),
        "two": ("scenarios/techniques/a", "scenarios/techniques/b"),
    }


def test_a_repository_without_entries_lists_no_external_id(tmp_path: Path) -> None:
    assert RepositoryEntries(tmp_path).external_ids() == {}
    _entry(tmp_path, "elsewhere/techniques/a", "one")
    (tmp_path / "scenarios").symlink_to(tmp_path / "elsewhere")  # never followed
    assert RepositoryEntries(tmp_path).external_ids() == {}


def test_the_external_ids_are_read_once_a_run(tmp_path: Path) -> None:
    _entry(tmp_path, ENTRY, "one")
    source = RepositoryEntries(tmp_path)
    first = source.external_ids()
    _entry(tmp_path, "scenarios/techniques/later", "two")

    assert source.external_ids() == first == {"one": (ENTRY,)}


def test_an_entry_that_cannot_be_read_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _entry(tmp_path)

    def unreadable(path: Path) -> object:
        raise EnvironmentProblemError(f"cannot read {path}: Permission denied")

    monkeypatch.setattr(repository, "read_yaml_file", unreadable)

    with pytest.raises(EnvironmentProblemError):
        RepositoryEntries(tmp_path).external_ids()


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_directory_that_cannot_be_read_is_the_environment_s_fault(tmp_path: Path) -> None:
    _entry(tmp_path)
    locked = tmp_path / "scenarios" / "techniques"
    locked.mkdir()
    locked.chmod(0)
    try:
        with pytest.raises(EnvironmentProblemError):
            RepositoryEntries(tmp_path).external_ids()
    finally:
        locked.chmod(0o755)


def test_an_entry_that_cannot_be_listed_is_the_environment_s_fault(tmp_path: Path) -> None:
    _entry(tmp_path)

    with pytest.raises(EnvironmentProblemError):  # a file, not a directory
        RepositoryEntries(tmp_path).names(f"{ENTRY}/scenario.yaml")


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_an_entry_that_cannot_be_searched_is_the_environment_s_fault(tmp_path: Path) -> None:
    directory = _entry(tmp_path)
    directory.chmod(0o644)  # listed, but its files cannot be looked at
    try:
        with pytest.raises(EnvironmentProblemError):
            RepositoryEntries(tmp_path).external_ids()
    finally:
        directory.chmod(0o755)
