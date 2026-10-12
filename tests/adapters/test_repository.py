"""Reading the repository's entries: never through a symbolic link, parent directories included,
within the input limits, every refusal naming the file by its path in the repository."""

import fcntl
import os
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters import data_files, repository
from scenario_tools.adapters.repository import LeftAsideError, RepositoryEntries
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


def _write(
    root: Path, files: dict[str, bytes], *, new: bool, source: RepositoryEntries | None = None
) -> None:
    with (source or RepositoryEntries(root)).writing(ENTRY, files, new=new):
        pass


def _interrupted(root: Path, files: dict[str, bytes], *, new: bool) -> bytes:
    """Write ``files``, then fail before the block ends: what ``scenario.json`` was meanwhile."""
    seen: list[bytes] = []

    def run() -> None:
        with RepositoryEntries(root).writing(ENTRY, files, new=new):
            seen.append((root / ENTRY / "scenario.json").read_bytes())
            raise RuntimeError("the plan cannot be written")

    with pytest.raises(RuntimeError):
        run()
    return seen[0]


@pytest.mark.parametrize("kind", ["link", "file"])
def test_an_entry_is_never_written_through_a_link_or_a_file(tmp_path: Path, kind: str) -> None:
    (tmp_path / "elsewhere").mkdir()
    if kind == "link":
        (tmp_path / "scenarios").symlink_to(tmp_path / "elsewhere")
    else:
        (tmp_path / "scenarios").write_text("not a directory")

    with pytest.raises(UnsafeInputError) as error:
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    assert _refusal(error) == ("IO-013", "scenarios")
    assert list((tmp_path / "elsewhere").iterdir()) == []


def test_an_existing_entry_that_is_a_link_is_never_written_through(tmp_path: Path) -> None:
    real = _entry(tmp_path, "scenarios/ransomware/real")
    (tmp_path / ENTRY).symlink_to(real)

    with pytest.raises(UnsafeInputError) as error:
        _write(tmp_path, {"scenario.json": b"{}"}, new=False)
    assert _refusal(error) == ("IO-013", ENTRY)
    assert (real / "scenario.json").read_text() == '{"a": 1}'


def test_a_directory_swapped_for_a_link_while_an_entry_is_written_is_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "scenarios" / "ransomware").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    made = os.mkdir

    def racing(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        if Path(path).name == "akira":  # its parent is swapped once it has been reached
            (tmp_path / "scenarios" / "ransomware").rename(tmp_path / "moved")
            (tmp_path / "scenarios" / "ransomware").symlink_to(tmp_path / "outside")
        made(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", racing)

    _write(tmp_path, {"scenario.json": b"{}"}, new=True)

    assert list((tmp_path / "outside").iterdir()) == []
    assert (tmp_path / "moved" / "akira" / "scenario.json").read_bytes() == b"{}"


def test_a_directory_above_made_by_another_run_meanwhile_is_written_into(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    made = os.mkdir

    def raced(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        if Path(path).name == "ransomware":  # another run made it first, its own way
            made(path, 0o700, dir_fd=dir_fd)
            raise FileExistsError(17, "File exists")
        made(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", raced)

    _write(tmp_path, {"scenario.json": b"{}"}, new=True)

    assert (tmp_path / ENTRY / "scenario.json").read_bytes() == b"{}"
    assert oct((tmp_path / ENTRY).parent.stat().st_mode & 0o777) == oct(0o700)  # not ours


def _descriptors(monkeypatch: pytest.MonkeyPatch) -> tuple[list[int], list[int]]:
    """The descriptors opened and closed from now on."""
    opened: list[int] = []
    closed: list[int] = []
    real_open, real_close = os.open, os.close

    def spied_open(*arguments: Any, **options: Any) -> int:
        descriptor = real_open(*arguments, **options)
        opened.append(descriptor)
        return descriptor

    def spied_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "open", spied_open)
    monkeypatch.setattr(os, "close", spied_close)
    return opened, closed


@pytest.mark.parametrize("new", [True, False], ids=["new", "update"])
def test_a_write_leaves_no_directory_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, new: bool
) -> None:
    if not new:
        _entry(tmp_path)
    opened, closed = _descriptors(monkeypatch)

    _write(tmp_path, {"scenario.json": b"{}"}, new=new)

    assert opened
    assert sorted(opened) == sorted(closed)


def test_a_refused_write_leaves_no_directory_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "scenarios").symlink_to(tmp_path / "elsewhere")
    opened, closed = _descriptors(monkeypatch)

    with pytest.raises(UnsafeInputError):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    assert opened
    assert sorted(opened) == sorted(closed)


def test_a_file_of_an_entry_that_is_a_link_is_never_replaced(tmp_path: Path) -> None:
    directory = _entry(tmp_path)
    (tmp_path / "elsewhere.json").write_text("kept")
    (directory / "scenario.json").unlink()
    (directory / "scenario.json").symlink_to(tmp_path / "elsewhere.json")

    with pytest.raises(UnsafeInputError):
        _write(tmp_path, {"scenario.json": b"{}\n"}, new=False)
    assert (directory / "scenario.json").is_symlink()  # put back as it was
    assert (tmp_path / "elsewhere.json").read_text() == "kept"
    names = sorted(path.name for path in directory.iterdir())
    assert names == ["README.md", "scenario.json", "scenario.yaml"]


def test_a_repository_that_cannot_be_opened_is_the_environment_s_fault(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError, match="cannot read"):
        _write(tmp_path / "missing", {"scenario.json": b"{}"}, new=True)


def test_an_entry_to_update_that_is_missing_is_the_environment_s_fault(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError, match="cannot read scenarios: it is missing"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=False)
    assert not (tmp_path / ENTRY).exists()  # never made for an update


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_directory_that_cannot_be_made_is_the_environment_s_fault(tmp_path: Path) -> None:
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "scenarios").chmod(0o555)
    try:
        with pytest.raises(EnvironmentProblemError, match="cannot make scenarios/ransomware"):
            _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    finally:
        (tmp_path / "scenarios").chmod(0o755)


def test_nothing_is_where_a_directory_above_is_missing(tmp_path: Path) -> None:
    assert not RepositoryEntries(tmp_path).exists("scenarios/ransomware/akira")


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_directory_that_cannot_be_searched_cannot_be_written_into(tmp_path: Path) -> None:
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "scenarios").chmod(0o644)  # listed, but nothing in it can be looked at
    try:
        with pytest.raises(EnvironmentProblemError, match="cannot read"):
            _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    finally:
        (tmp_path / "scenarios").chmod(0o755)


def test_a_new_entry_appears_whole(tmp_path: Path) -> None:
    umask = os.umask(0o077)  # the modes hold whatever the umask
    try:
        _write(tmp_path, {"scenario.yaml": b"a: 1\n", "scenario.json": b"{}"}, new=True)
    finally:
        os.umask(umask)

    entry = tmp_path / ENTRY
    assert sorted(path.name for path in entry.iterdir()) == ["scenario.json", "scenario.yaml"]
    assert (entry / "scenario.yaml").read_bytes() == b"a: 1\n"
    for directory in (entry, entry.parent, entry.parent.parent):  # those made by the run too
        assert oct(directory.stat().st_mode & 0o777) == oct(0o755), directory
    assert [path.name for path in entry.parent.iterdir()] == ["akira"]  # nothing else left


def test_nothing_to_write_writes_nothing(tmp_path: Path) -> None:
    _write(tmp_path, {}, new=True)

    assert list(tmp_path.iterdir()) == []


def test_a_new_entry_that_cannot_be_written_whole_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    written = data_files.write_in

    def failing(directory: int, path: Path, data: bytes, *, create: bool = False) -> None:
        calls.append(path.name)
        if len(calls) == 2:
            raise EnvironmentProblemError("disk full")
        written(directory, path, data, create=create)

    monkeypatch.setattr("scenario_tools.adapters.repository.write_in", failing)

    with pytest.raises(EnvironmentProblemError):
        _write(tmp_path, {"scenario.yaml": b"a", "scenario.json": b"b"}, new=True)
    assert list((tmp_path / "scenarios" / "ransomware").iterdir()) == []


def test_a_new_entry_is_removed_when_the_run_does_not_end(tmp_path: Path) -> None:
    assert _interrupted(tmp_path, {"scenario.json": b"{}"}, new=True) == b"{}"

    assert list((tmp_path / "scenarios" / "ransomware").iterdir()) == []


def test_a_new_entry_never_replaces_what_appeared_at_its_place(tmp_path: Path) -> None:
    (tmp_path / ENTRY).mkdir(parents=True)

    with pytest.raises(EnvironmentProblemError, match="already exists"):
        _write(tmp_path, {"scenario.json": b"b"}, new=True)
    assert list((tmp_path / ENTRY).iterdir()) == []
    assert [path.name for path in (tmp_path / ENTRY).parent.iterdir()] == ["akira"]


def test_a_place_that_cannot_be_reserved_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    made = os.mkdir

    def failing(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        if Path(path).name == "akira":
            raise OSError(28, "No space left on device")
        made(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot write"):
        _write(tmp_path, {"scenario.json": b"b"}, new=True)
    assert list((tmp_path / "scenarios" / "ransomware").iterdir()) == []


def test_an_update_replaces_the_files_given(tmp_path: Path) -> None:
    directory = _entry(tmp_path)

    _write(tmp_path, {"scenario.json": b"{}\n"}, new=False)

    assert (directory / "scenario.json").read_bytes() == b"{}\n"
    assert (directory / "scenario.yaml").read_text() == "external_id: one\n"
    names = sorted(path.name for path in directory.iterdir())
    assert names == ["README.md", "scenario.json", "scenario.yaml"]  # nothing kept aside


def test_an_update_is_put_back_when_the_run_does_not_end(tmp_path: Path) -> None:
    directory = _entry(tmp_path)

    assert _interrupted(tmp_path, {"scenario.json": b"{}\n"}, new=False) == b"{}\n"

    assert (directory / "scenario.json").read_text() == '{"a": 1}'
    names = sorted(path.name for path in directory.iterdir())
    assert names == ["README.md", "scenario.json", "scenario.yaml"]


def test_an_update_of_a_file_that_cannot_be_kept_aside_is_the_environment_s_fault(
    tmp_path: Path,
) -> None:
    directory = _entry(tmp_path)
    (directory / "scenario.json").unlink()

    with pytest.raises(EnvironmentProblemError, match="cannot write"):
        _write(tmp_path, {"scenario.json": b"{}\n"}, new=False)
    assert sorted(path.name for path in directory.iterdir()) == ["README.md", "scenario.yaml"]


def test_a_hidden_directory_left_by_an_interrupted_write_is_no_entry(tmp_path: Path) -> None:
    _entry(tmp_path, "scenarios/ransomware/.akira.k3j9", "one")

    assert RepositoryEntries(tmp_path).entries() == ()


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


def test_an_update_that_cannot_be_put_back_keeps_the_previous_file_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _entry(tmp_path)
    renamed = os.rename

    def failing(source: str, target: str, **options: Any) -> None:
        if source.endswith(".previous"):
            raise OSError(5, "Input/output error")
        renamed(source, target, **options)

    monkeypatch.setattr(os, "rename", failing)

    with pytest.raises(EnvironmentProblemError, match="kept as") as error:
        _interrupted(tmp_path, {"scenario.json": b"{}\n"}, new=False)
    assert isinstance(error.value.__cause__, RuntimeError)  # the run's own failure
    kept = [path for path in directory.iterdir() if path.name.endswith(".previous")]
    assert [path.read_text() for path in kept] == ['{"a": 1}']
    assert kept[0].name in str(error.value)


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_new_entry_that_cannot_be_removed_says_so(tmp_path: Path) -> None:
    parent = tmp_path / "scenarios" / "ransomware"

    def run() -> None:
        with RepositoryEntries(tmp_path).writing(ENTRY, {"scenario.json": b"{}"}, new=True):
            parent.chmod(0o555)  # the entry can no longer be removed from it
            raise RuntimeError("the plan cannot be written")

    try:
        with pytest.raises(EnvironmentProblemError, match=f"cannot remove {ENTRY}") as error:
            run()
    finally:
        parent.chmod(0o755)
    assert isinstance(error.value.__cause__, RuntimeError)
    assert (tmp_path / ENTRY).is_dir()  # left, and said so


def test_a_directory_made_whose_mode_cannot_be_set_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(descriptor: int, mode: int) -> None:
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot make scenarios"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)


def _unremovable_copies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A previous file kept aside can no longer be removed."""
    removed = os.unlink

    def failing(path: str, **options: Any) -> None:
        if str(path).endswith(".previous"):
            raise OSError(5, "Input/output error")
        removed(path, **options)

    monkeypatch.setattr(os, "unlink", failing)


def test_a_copy_that_cannot_be_removed_once_written_is_said_and_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _entry(tmp_path)
    _unremovable_copies(monkeypatch)

    with pytest.raises(LeftAsideError, match="remove it by hand") as error:
        _write(tmp_path, {"scenario.json": b"{}\n"}, new=False)
    assert (directory / "scenario.json").read_bytes() == b"{}\n"  # the update stands
    kept = [path.name for path in directory.iterdir() if path.name.endswith(".previous")]
    assert len(kept) == 1
    assert kept[0] in str(error.value)


def test_a_copy_left_while_putting_a_file_back_is_said(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _entry(tmp_path)
    (tmp_path / "elsewhere.json").write_text("kept")
    (directory / "scenario.json").unlink()
    (directory / "scenario.json").symlink_to(tmp_path / "elsewhere.json")
    _unremovable_copies(monkeypatch)

    with pytest.raises(EnvironmentProblemError, match="a copy is left as"):
        _write(tmp_path, {"scenario.json": b"{}\n"}, new=False)
    assert (directory / "scenario.json").is_symlink()


def test_a_new_entry_whose_place_another_took_meanwhile_is_never_removed(
    tmp_path: Path,
) -> None:
    entry = tmp_path / ENTRY
    moved = entry.parent / "moved"

    def run() -> None:
        with RepositoryEntries(tmp_path).writing(ENTRY, {"scenario.json": b"{}"}, new=True):
            entry.rename(moved)
            entry.mkdir()
            (entry / "theirs").write_text("another run's")
            raise RuntimeError("the plan cannot be written")

    with pytest.raises(EnvironmentProblemError, match="another was put at its place") as error:
        run()
    assert isinstance(error.value.__cause__, RuntimeError)
    [kept] = [path for path in entry.parent.iterdir() if path.name.startswith(".akira.")]
    assert (kept / "theirs").read_text() == "another run's"
    assert kept.name in str(error.value)
    assert (moved / "scenario.json").read_bytes() == b"{}"  # ours, never confused with theirs


def test_a_new_entry_moved_away_meanwhile_is_said_left(tmp_path: Path) -> None:
    entry = tmp_path / ENTRY
    moved = entry.parent / "moved"

    def run() -> None:
        with RepositoryEntries(tmp_path).writing(ENTRY, {"scenario.json": b"{}"}, new=True):
            entry.rename(moved)
            raise RuntimeError("the plan cannot be written")

    with pytest.raises(EnvironmentProblemError, match="moved meanwhile") as error:
        run()
    assert isinstance(error.value.__cause__, RuntimeError)
    assert (moved / "scenario.json").read_bytes() == b"{}"


def test_a_held_repository_is_written_in_even_once_its_path_names_another(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    source = RepositoryEntries(root)

    with source.locked():
        root.rename(tmp_path / "held")
        (tmp_path / "other").mkdir()
        root.symlink_to(tmp_path / "other")  # the path now names another checkout
        _write(root, {"scenario.json": b"{}"}, new=True, source=source)
        with pytest.raises(EnvironmentProblemError, match="no longer names"):
            source.check_held()

    assert (tmp_path / "held" / ENTRY / "scenario.json").read_bytes() == b"{}"
    assert list((tmp_path / "other").iterdir()) == []


def test_a_held_repository_whose_path_is_gone_is_said(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    source = RepositoryEntries(root)

    with source.locked():
        source.check_held()  # still the one held
        root.rename(tmp_path / "held")
        with pytest.raises(EnvironmentProblemError, match="no longer names"):
            source.check_held()


def test_a_repository_once_released_is_written_by_its_path_again(tmp_path: Path) -> None:
    source = RepositoryEntries(tmp_path)
    with source.locked():
        pass

    _write(tmp_path, {"scenario.json": b"{}"}, new=True, source=source)

    assert (tmp_path / ENTRY / "scenario.json").read_bytes() == b"{}"
