"""Reading the repository's entries: never through a symbolic link, parent directories included,
within the input limits, every refusal naming the file by its path in the repository."""

import os
from pathlib import Path

import pytest

from scenario_tools.adapters import repository
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


def test_every_entry_is_listed_with_its_external_id_and_name(tmp_path: Path) -> None:
    directory = _entry(tmp_path, ENTRY, "one")
    (directory / "scenario.yaml").write_text("external_id: one\nname: Akira crisis\n")
    _entry(tmp_path, "scenarios/techniques/b", "two")  # no name: an empty one

    assert RepositoryEntries(tmp_path).entries() == (
        CatalogueEntry(ENTRY, "one", "Akira crisis"),
        CatalogueEntry("scenarios/techniques/b", "two", ""),
    )


def test_whether_a_path_exists_is_told_without_following_links(tmp_path: Path) -> None:
    _entry(tmp_path)
    source = RepositoryEntries(tmp_path)
    (tmp_path / "scenarios" / "techniques").mkdir()
    (tmp_path / "scenarios" / "techniques" / "linked").symlink_to(tmp_path / "nowhere")

    assert source.exists(ENTRY)
    assert not source.exists("scenarios/ransomware/other")
    assert source.exists("scenarios/techniques/linked")  # a dangling link is something there


def test_an_entry_directory_is_made_without_following_links(tmp_path: Path) -> None:
    source = RepositoryEntries(tmp_path)

    made = source.make_directory("scenarios/ransomware/new-entry")

    assert made == tmp_path / "scenarios" / "ransomware" / "new-entry"
    assert made.is_dir()
    assert source.make_directory("scenarios/ransomware/new-entry") == made  # already there


@pytest.mark.parametrize("kind", ["link", "file"])
def test_an_entry_directory_is_never_made_through_a_link_or_a_file(
    tmp_path: Path, kind: str
) -> None:
    (tmp_path / "elsewhere").mkdir()
    if kind == "link":
        (tmp_path / "scenarios").symlink_to(tmp_path / "elsewhere")
    else:
        (tmp_path / "scenarios").write_text("not a directory")

    with pytest.raises(UnsafeInputError) as error:
        RepositoryEntries(tmp_path).make_directory("scenarios/ransomware/new-entry")
    assert _refusal(error) == ("IO-013", "scenarios")
    assert not (tmp_path / "elsewhere" / "ransomware").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_directory_that_cannot_be_made_is_the_environment_s_fault(tmp_path: Path) -> None:
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "scenarios").chmod(0o555)
    try:
        with pytest.raises(EnvironmentProblemError):
            RepositoryEntries(tmp_path).make_directory("scenarios/ransomware")
    finally:
        (tmp_path / "scenarios").chmod(0o755)


def test_nothing_is_where_a_directory_above_is_missing(tmp_path: Path) -> None:
    assert not RepositoryEntries(tmp_path).exists("scenarios/ransomware/akira")


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_directory_that_cannot_be_searched_cannot_be_made_into(tmp_path: Path) -> None:
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "scenarios").chmod(0o644)  # listed, but nothing in it can be looked at
    try:
        with pytest.raises(EnvironmentProblemError, match="cannot read"):
            RepositoryEntries(tmp_path).make_directory("scenarios/ransomware")
    finally:
        (tmp_path / "scenarios").chmod(0o755)


def test_a_new_entry_appears_whole(tmp_path: Path) -> None:
    source = RepositoryEntries(tmp_path)

    source.write_entry(ENTRY, {"scenario.yaml": b"a: 1\n", "scenario.json": b"{}"}, new=True)

    entry = tmp_path / ENTRY
    assert sorted(path.name for path in entry.iterdir()) == ["scenario.json", "scenario.yaml"]
    assert (entry / "scenario.yaml").read_bytes() == b"a: 1\n"
    assert oct(entry.stat().st_mode & 0o777) == oct(0o755)
    assert [path.name for path in entry.parent.iterdir()] == ["akira"]  # nothing else left


def test_a_new_entry_that_cannot_be_written_whole_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def failing(path: Path, data: bytes, *, create: bool = False) -> None:
        calls.append(path.name)
        if len(calls) == 2:
            raise EnvironmentProblemError("disk full")
        path.write_bytes(data)

    monkeypatch.setattr(repository, "write_output", failing)

    with pytest.raises(EnvironmentProblemError):
        RepositoryEntries(tmp_path).write_entry(
            ENTRY, {"scenario.yaml": b"a", "scenario.json": b"b"}, new=True
        )
    assert list((tmp_path / "scenarios" / "ransomware").iterdir()) == []


def test_a_new_entry_never_replaces_what_appeared_at_its_place(tmp_path: Path) -> None:
    (tmp_path / ENTRY).mkdir(parents=True)

    with pytest.raises(EnvironmentProblemError, match="already exists"):
        RepositoryEntries(tmp_path).write_entry(ENTRY, {"scenario.json": b"b"}, new=True)
    assert list((tmp_path / ENTRY).iterdir()) == []
    assert [path.name for path in (tmp_path / ENTRY).parent.iterdir()] == ["akira"]


def test_an_update_replaces_the_files_given(tmp_path: Path) -> None:
    directory = _entry(tmp_path)

    RepositoryEntries(tmp_path).write_entry(ENTRY, {"scenario.json": b"{}\n"}, new=False)

    assert (directory / "scenario.json").read_bytes() == b"{}\n"
    assert (directory / "scenario.yaml").read_text() == "external_id: one\n"


def test_a_place_that_cannot_be_reserved_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    made = Path.mkdir

    def failing(self: Path, *arguments: object, **options: object) -> None:
        if self.name == "akira":
            raise OSError(28, "No space left on device")
        made(self, *arguments, **options)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "mkdir", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot write"):
        RepositoryEntries(tmp_path).write_entry(ENTRY, {"scenario.json": b"b"}, new=True)
    assert list((tmp_path / "scenarios" / "ransomware").iterdir()) == []


def test_a_hidden_directory_left_by_an_interrupted_write_is_no_entry(tmp_path: Path) -> None:
    _entry(tmp_path, "scenarios/ransomware/.akira.k3j9", "one")

    assert RepositoryEntries(tmp_path).entries() == ()


def test_an_entry_without_a_usable_external_id_still_holds_its_name(tmp_path: Path) -> None:
    directory = _entry(tmp_path, ENTRY, "one")
    (directory / "scenario.yaml").write_text("external_id: 5\nname: Akira crisis\n")

    source = RepositoryEntries(tmp_path)

    assert source.entries() == (CatalogueEntry(ENTRY, "", "Akira crisis"),)
    assert source.external_ids() == {}
