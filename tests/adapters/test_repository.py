"""Reading the repository's entries: never through a symbolic link, parent directories included,
within the input limits, every refusal naming the file by its path in the repository."""

import fcntl
import os
from pathlib import Path

import pytest

from scenario_tools.adapters import repository
from scenario_tools.adapters.places import hidden_name
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.domain.catalogue.intake import CatalogueEntry
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
    with pytest.raises(UnsafeInputError) as error:
        RepositoryEntries(tmp_path).external_ids()
    assert _refusal(error) == ("IO-013", "scenarios")


def test_the_external_ids_are_read_once_a_run(tmp_path: Path) -> None:
    _entry(tmp_path, ENTRY, "one")
    source = RepositoryEntries(tmp_path)
    first = source.external_ids()
    _entry(tmp_path, "scenarios/techniques/later", "two")

    assert source.external_ids() == first == {"one": (ENTRY,)}
    assert source.external_ids() is first  # built once, however many entries are checked
    with pytest.raises(TypeError):
        first["two"] = ()  # type: ignore[index]  # shared, so never changed by a reader


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


def test_every_entry_is_listed_with_its_external_id_and_name(tmp_path: Path) -> None:
    directory = _entry(tmp_path, ENTRY, "one")
    (directory / "scenario.yaml").write_text("external_id: one\nname: Akira crisis\n")
    _entry(tmp_path, "scenarios/techniques/b", "two")  # no name: an empty one

    assert RepositoryEntries(tmp_path).entries() == (
        CatalogueEntry(ENTRY, "one", "Akira crisis"),
        CatalogueEntry("scenarios/techniques/b", "two", ""),
    )


def test_an_entry_whose_metadata_cannot_be_read_is_listed_as_such(tmp_path: Path) -> None:
    _entry(tmp_path, ENTRY, "one")
    unreadable = _entry(tmp_path, "scenarios/techniques/broken", "two")
    (unreadable / "scenario.yaml").write_text("external_id: [two\n")  # never parsed

    assert RepositoryEntries(tmp_path).entries() == (
        CatalogueEntry(ENTRY, "one", ""),
        CatalogueEntry("scenarios/techniques/broken", "", "", readable=False),
    )
    assert RepositoryEntries(tmp_path).external_ids() == {"one": (ENTRY,)}


def test_whether_a_path_exists_is_told_without_following_links(tmp_path: Path) -> None:
    _entry(tmp_path)
    source = RepositoryEntries(tmp_path)
    (tmp_path / "scenarios" / "techniques").mkdir()
    (tmp_path / "scenarios" / "techniques" / "linked").symlink_to(tmp_path / "nowhere")

    assert source.exists(ENTRY)
    assert not source.exists("scenarios/ransomware/other")
    assert source.exists("scenarios/techniques/linked")  # a dangling link is something there


def test_a_directory_of_the_tool_s_own_is_no_entry(tmp_path: Path) -> None:
    _entry(tmp_path, f"scenarios/ransomware/{hidden_name()}", "one")

    assert RepositoryEntries(tmp_path).entries() == ()


def test_any_other_hidden_directory_holding_metadata_is_an_entry(tmp_path: Path) -> None:
    _entry(tmp_path, "scenarios/ransomware/.akira", "one")

    assert RepositoryEntries(tmp_path).entries() == (
        CatalogueEntry("scenarios/ransomware/.akira", "one", ""),
    )


@pytest.mark.parametrize("level", ["domain", "entry"])
def test_an_entry_or_domain_that_is_a_link_is_unreadable(tmp_path: Path, level: str) -> None:
    _entry(tmp_path, "elsewhere/ransomware/akira", "one")
    if level == "domain":
        (tmp_path / "scenarios").mkdir()
        (tmp_path / "scenarios" / "ransomware").symlink_to(tmp_path / "elsewhere" / "ransomware")
        unread = "scenarios/ransomware"
    else:
        (tmp_path / "scenarios" / "ransomware").mkdir(parents=True)
        (tmp_path / ENTRY).symlink_to(tmp_path / "elsewhere" / "ransomware" / "akira")
        unread = ENTRY

    assert RepositoryEntries(tmp_path).entries() == (CatalogueEntry(unread, "", "", False),)


@pytest.mark.parametrize("text", ["", "- a list\n", "just text\n"], ids=["empty", "list", "text"])
def test_metadata_that_is_no_mapping_is_unreadable(tmp_path: Path, text: str) -> None:
    (_entry(tmp_path) / "scenario.yaml").write_text(text)

    assert RepositoryEntries(tmp_path).entries() == (CatalogueEntry(ENTRY, "", "", False),)


def test_an_entry_without_a_usable_external_id_still_holds_its_name(tmp_path: Path) -> None:
    directory = _entry(tmp_path, ENTRY, "one")
    (directory / "scenario.yaml").write_text("external_id: 5\nname: Akira crisis\n")

    source = RepositoryEntries(tmp_path)

    assert source.entries() == (CatalogueEntry(ENTRY, "", "Akira crisis"),)
    assert source.external_ids() == {}


def _hold(root: Path) -> None:
    with RepositoryEntries(root).locked():
        pass


def test_the_repository_is_held_by_one_run_at_a_time(tmp_path: Path) -> None:
    with (
        RepositoryEntries(tmp_path).locked(),
        pytest.raises(EnvironmentProblemError, match="another run"),
    ):
        _hold(tmp_path)
    _hold(tmp_path)  # released once the block ends


def test_a_repository_that_cannot_be_held_is_the_environment_s_fault(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError, match="cannot read"):
        _hold(tmp_path / "missing")


def test_a_lock_that_fails_otherwise_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(descriptor: int, operation: int) -> None:
        raise OSError(37, "No locks available")

    monkeypatch.setattr(fcntl, "flock", failing)

    with pytest.raises(EnvironmentProblemError, match="No locks available"):
        _hold(tmp_path)


# Links, and what is put at a place as it is made.


# A new entry.


# An update.


# What reads the entry by its path afterwards.


# What cannot be read or made, and what is left open.


def test_a_scenarios_directory_that_is_a_link_is_refused(tmp_path: Path) -> None:
    _entry(tmp_path, "elsewhere/ransomware/akira")
    (tmp_path / "scenarios").symlink_to(tmp_path / "elsewhere")

    with pytest.raises(UnsafeInputError) as error:
        RepositoryEntries(tmp_path).entries()
    assert _refusal(error) == ("IO-013", "scenarios")


def test_a_scenarios_that_is_no_directory_holds_no_entry(tmp_path: Path) -> None:
    (tmp_path / "scenarios").write_text("not a directory")

    assert RepositoryEntries(tmp_path).entries() == ()


def test_a_strict_reading_takes_the_tool_s_own_names_as_unreadable(tmp_path: Path) -> None:
    left = f"scenarios/ransomware/{hidden_name()}"
    _entry(tmp_path, left, "one")

    domain = f"scenarios/{hidden_name()}"
    _entry(tmp_path, f"{domain}/akira", "two")

    assert RepositoryEntries(tmp_path).entries() == ()
    assert set(RepositoryEntries(tmp_path, strict=True).entries()) == {
        CatalogueEntry(left, "", "", False),
        CatalogueEntry(domain, "", "", False),
    }


def test_an_entry_holding_a_name_of_the_tool_s_own_is_unreadable_read_strictly(
    tmp_path: Path,
) -> None:
    directory = _entry(tmp_path, ENTRY, "one")
    (directory / hidden_name()).write_bytes(b"{}")  # a version a cut update left aside

    assert RepositoryEntries(tmp_path).entries() == (CatalogueEntry(ENTRY, "one", ""),)
    assert RepositoryEntries(tmp_path, strict=True).entries() == (
        CatalogueEntry(ENTRY, "", "", False),
    )


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_an_entry_that_cannot_be_listed_read_strictly_is_the_environment_s_fault(
    tmp_path: Path,
) -> None:
    directory = _entry(tmp_path)
    directory.chmod(0o000)
    try:
        with pytest.raises(EnvironmentProblemError, match="cannot read"):
            RepositoryEntries(tmp_path, strict=True).entries()
    finally:
        directory.chmod(0o755)
