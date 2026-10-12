"""Writing an entry in the repository: never through a link, from the repository held, only
where nothing is or over what was read, and taking back only what the run wrote when it cannot
be kept."""

import os
import signal
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters import places
from scenario_tools.adapters.entry_writer import RepositoryWriter
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError
from scenario_tools.ports.repository import WrittenEntry
from tests.adapters.spies import descriptors

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


def _write(
    root: Path,
    files: dict[str, bytes],
    *,
    new: bool,
    source: RepositoryEntries | None = None,
    previous: dict[str, bytes] | None = None,
) -> None:
    with _writing(root, files, new=new, source=source, previous=previous):
        pass


def _writing(
    root: Path,
    files: dict[str, bytes],
    *,
    new: bool,
    source: RepositoryEntries | None = None,
    previous: dict[str, bytes] | None = None,
) -> AbstractContextManager[WrittenEntry]:
    """Write as intake does: an update with the bytes each file holds now, as read."""
    if previous is None and not new:
        directory = root / ENTRY
        previous = {name: (directory / name).read_bytes() for name in files}
    return RepositoryWriter(source or RepositoryEntries(root)).writing(
        ENTRY, files, previous=None if new else previous
    )


def _interrupted(
    root: Path, files: dict[str, bytes], *, new: bool, during: Callable[[], object] = lambda: None
) -> bytes:
    """Write ``files``, do ``during``, then fail before the block ends: what ``scenario.json``
    was meanwhile."""
    seen: list[bytes] = []

    def run() -> None:
        with _writing(root, files, new=new):
            seen.append((root / ENTRY / "scenario.json").read_bytes())
            during()
            raise RuntimeError("the plan cannot be written")

    with pytest.raises(RuntimeError):
        run()
    return seen[0]


def _failing_block(
    root: Path, files: dict[str, bytes], *, new: bool, during: Callable[[], object]
) -> pytest.ExceptionInfo[EnvironmentProblemError]:
    """Like ``_interrupted``, when taking back what was written fails, and is said."""

    def run() -> None:
        with _writing(root, files, new=new):
            during()
            raise RuntimeError("the plan cannot be written")

    with pytest.raises(EnvironmentProblemError) as error:
        run()
    assert isinstance(error.value.__cause__, RuntimeError)
    assert "the plan cannot be written" in str(error.value)  # what led to it, seen
    return error


def _names(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir())


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
        _write(tmp_path, {"scenario.json": b"{}"}, new=False, previous={"scenario.json": b""})
    assert _refusal(error) == ("IO-013", ENTRY)
    assert (real / "scenario.json").read_text() == '{"a": 1}'


def test_a_file_of_an_entry_that_is_a_link_is_never_replaced(tmp_path: Path) -> None:
    directory = _entry(tmp_path)
    (tmp_path / "elsewhere.json").write_text('{"a": 1}')
    (directory / "scenario.json").unlink()
    (directory / "scenario.json").symlink_to(tmp_path / "elsewhere.json")

    with pytest.raises(UnsafeInputError) as error:
        _write(
            tmp_path, {"scenario.json": b"{}"}, new=False, previous={"scenario.json": b'{"a": 1}'}
        )
    assert _refusal(error) == ("IO-013", f"{ENTRY}/scenario.json")
    assert (directory / "scenario.json").is_symlink()
    assert (tmp_path / "elsewhere.json").read_text() == '{"a": 1}'


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


@pytest.mark.parametrize("name", ["akira", "ransomware"], ids=["entry", "above"])
def test_a_directory_replaced_as_it_is_made_is_never_written_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    (tmp_path / "scenarios").mkdir()
    made = os.mkdir
    theirs = tmp_path / "theirs"
    place = tmp_path / ENTRY if name == "akira" else tmp_path / "scenarios" / name

    def replaced(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        made(path, mode, dir_fd=dir_fd)
        if Path(path).name == name:  # swapped before the run opens it
            place.rename(tmp_path / "ours")
            made(str(theirs))
            (theirs / "kept").write_text("another's")
            theirs.rename(place)

    monkeypatch.setattr(os, "mkdir", replaced)
    opened, closed = descriptors(monkeypatch)

    with pytest.raises(EnvironmentProblemError, match="put at its place meanwhile"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    assert sorted(opened) == sorted(closed)
    assert _names(place) == ["kept"]  # never written in


def test_an_empty_directory_put_as_it_is_made_is_as_good_as_the_one_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "scenarios" / "ransomware").mkdir(parents=True)
    made = os.mkdir

    def replaced(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        made(path, mode, dir_fd=dir_fd)
        if Path(path).name == "akira":
            (tmp_path / ENTRY).rename(tmp_path / "ours")
            made(str(tmp_path / ENTRY))

    monkeypatch.setattr(os, "mkdir", replaced)

    _write(tmp_path, {"scenario.json": b"{}"}, new=True)

    assert (tmp_path / ENTRY / "scenario.json").read_bytes() == b"{}"


def test_a_new_entry_appears_whole(tmp_path: Path) -> None:
    umask = os.umask(0o077)  # the modes hold whatever the umask
    try:
        _write(tmp_path, {"scenario.yaml": b"a: 1\n", "scenario.json": b"{}"}, new=True)
    finally:
        os.umask(umask)

    entry = tmp_path / ENTRY
    assert _names(entry) == ["scenario.json", "scenario.yaml"]
    assert (entry / "scenario.yaml").read_bytes() == b"a: 1\n"
    for directory in (entry, entry.parent, entry.parent.parent):  # those made by the run too
        assert oct(directory.stat().st_mode & 0o777) == oct(0o755), directory
    assert oct((entry / "scenario.json").stat().st_mode & 0o777) == oct(0o644)
    assert _names(entry.parent) == ["akira"]  # nothing else left


def test_nothing_to_write_writes_nothing(tmp_path: Path) -> None:
    with RepositoryWriter(RepositoryEntries(tmp_path)).writing(ENTRY, {}, previous=None) as written:
        written.check()

    assert list(tmp_path.iterdir()) == []


def test_nothing_written_still_checks_the_repository_held(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    source = RepositoryEntries(root)

    with source.locked(), RepositoryWriter(source).writing(ENTRY, {}, previous={}) as written:
        root.rename(tmp_path / "held")
        with pytest.raises(EnvironmentProblemError, match="no longer names"):
            written.check()
        (tmp_path / "held").rename(root)


def test_a_new_entry_that_cannot_be_written_whole_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    created = places.create_in

    def failing(directory: int, path: Path, data: bytes) -> tuple[int, int]:
        calls.append(path.name)
        if len(calls) == 2:
            raise EnvironmentProblemError("disk full")
        return created(directory, path, data)

    monkeypatch.setattr("scenario_tools.adapters.entry_writer.create_in", failing)

    with pytest.raises(EnvironmentProblemError, match="disk full"):
        _write(tmp_path, {"scenario.yaml": b"a", "scenario.json": b"b"}, new=True)
    assert list(tmp_path.iterdir()) == []  # the directories made for it too


def test_a_new_entry_and_the_directories_made_for_it_go_when_the_run_does_not_end(
    tmp_path: Path,
) -> None:
    assert _interrupted(tmp_path, {"scenario.json": b"{}"}, new=True) == b"{}"

    assert list(tmp_path.iterdir()) == []


def test_directories_already_there_stay_when_a_new_entry_goes(tmp_path: Path) -> None:
    _entry(tmp_path, "scenarios/ransomware/other")

    _interrupted(tmp_path, {"scenario.json": b"{}"}, new=True)

    assert _names(tmp_path / "scenarios" / "ransomware") == ["other"]


def test_a_new_entry_never_replaces_what_appeared_at_its_place(tmp_path: Path) -> None:
    (tmp_path / ENTRY).mkdir(parents=True)

    with pytest.raises(EnvironmentProblemError, match="already exists"):
        _write(tmp_path, {"scenario.json": b"b"}, new=True)
    assert list((tmp_path / ENTRY).iterdir()) == []
    assert _names((tmp_path / ENTRY).parent) == ["akira"]


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
    assert list(tmp_path.iterdir()) == []  # the directories made for it go too


def test_a_directory_made_whose_mode_cannot_be_set_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(descriptor: int, mode: int) -> None:
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot make scenarios"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)


def test_a_new_entry_whose_mode_cannot_be_set_goes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "scenarios" / "ransomware").mkdir(parents=True)

    def failing(descriptor: int, mode: int) -> None:
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", failing)

    with pytest.raises(EnvironmentProblemError, match=f"cannot make {ENTRY}"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    assert list((tmp_path / "scenarios" / "ransomware").iterdir()) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_new_entry_that_cannot_be_taken_back_says_so(tmp_path: Path) -> None:
    parent = tmp_path / "scenarios" / "ransomware"

    def lock() -> None:
        parent.chmod(0o555)  # the entry can no longer be set aside nor removed from it

    try:
        error = _failing_block(tmp_path, {"scenario.json": b"{}"}, new=True, during=lock)
    finally:
        parent.chmod(0o755)
    assert f"cannot take back {ENTRY}" in str(error.value)
    assert "remove by hand what this run wrote" in str(error.value)
    assert (tmp_path / ENTRY).is_dir()  # left, and said so


def test_a_new_entry_whose_place_another_took_meanwhile_is_never_removed(
    tmp_path: Path,
) -> None:
    entry = tmp_path / ENTRY

    def taken() -> None:
        entry.rename(entry.parent / "moved")
        entry.mkdir()
        (entry / "theirs").write_text("another run's")

    error = _failing_block(tmp_path, {"scenario.json": b"{}"}, new=True, during=taken)

    assert "another was put at its place meanwhile" in str(error.value)
    assert (entry / "theirs").read_text() == "another run's"  # put back as it was
    assert (entry.parent / "moved" / "scenario.json").read_bytes() == b"{}"


def test_a_new_entry_moved_away_meanwhile_is_said(tmp_path: Path) -> None:
    entry = tmp_path / ENTRY

    error = _failing_block(
        tmp_path,
        {"scenario.json": b"{}"},
        new=True,
        during=lambda: entry.rename(entry.parent / "moved"),
    )

    assert "moved meanwhile" in str(error.value)
    assert (entry.parent / "moved" / "scenario.json").read_bytes() == b"{}"


def test_an_update_replaces_the_files_given(tmp_path: Path) -> None:
    directory = _entry(tmp_path)

    _write(tmp_path, {"scenario.json": b"{}\n"}, new=False)

    assert (directory / "scenario.json").read_bytes() == b"{}\n"
    assert (directory / "scenario.yaml").read_text() == "external_id: one\n"
    assert _names(directory) == ["README.md", "scenario.json", "scenario.yaml"]


def test_an_update_is_put_back_when_the_run_does_not_end(tmp_path: Path) -> None:
    directory = _entry(tmp_path)

    assert _interrupted(tmp_path, {"scenario.json": b"{}\n"}, new=False) == b"{}\n"

    assert (directory / "scenario.json").read_text() == '{"a": 1}'
    assert _names(directory) == ["README.md", "scenario.json", "scenario.yaml"]


def test_an_update_of_a_file_changed_since_it_was_read_writes_nothing(tmp_path: Path) -> None:
    directory = _entry(tmp_path)

    with pytest.raises(EnvironmentProblemError, match="changed since it was read"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=False, previous={"scenario.json": b"{}"})
    assert (directory / "scenario.json").read_text() == '{"a": 1}'


def test_an_update_of_a_file_gone_since_it_was_read_writes_nothing(tmp_path: Path) -> None:
    directory = _entry(tmp_path)
    (directory / "scenario.json").unlink()

    with pytest.raises(EnvironmentProblemError, match="changed since it was read"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=False, previous={"scenario.json": b"{}"})
    assert _names(directory) == ["README.md", "scenario.yaml"]


def test_an_update_that_cannot_be_put_back_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _entry(tmp_path)

    def failing(directory: int, path: Path, data: bytes) -> tuple[int, int]:
        raise EnvironmentProblemError(f"cannot write {path}: No space left on device")

    # Putting the previous bytes back is creating them where the run's version was.
    monkeypatch.setattr("scenario_tools.adapters.entry_writer.create_in", failing)

    error = _failing_block(tmp_path, {"scenario.json": b"{}\n"}, new=False, during=lambda: None)

    assert f"cannot take back {ENTRY}/scenario.json" in str(error.value)
    assert "restore it by hand" in str(error.value)
    assert (directory / "scenario.json").read_bytes() == b"{}\n"  # where it is looked for
    assert _names(directory) == ["README.md", "scenario.json", "scenario.yaml"]


def test_an_updated_file_another_changed_meanwhile_is_left_as_it_is_and_said(
    tmp_path: Path,
) -> None:
    directory = _entry(tmp_path)

    def changed() -> None:
        (directory / "scenario.json").unlink()
        (directory / "scenario.json").write_text("another's")

    error = _failing_block(tmp_path, {"scenario.json": b"{}\n"}, new=False, during=changed)

    assert "changed meanwhile" in str(error.value)
    assert (directory / "scenario.json").read_text() == "another's"


@pytest.mark.parametrize("new", [True, False], ids=["new", "update"])
def test_an_entry_is_known_to_be_still_where_it_was_written(tmp_path: Path, new: bool) -> None:
    if not new:
        _entry(tmp_path)

    with _writing(tmp_path, {"scenario.json": b"{}"}, new=new) as written:
        written.check()  # nothing moved: nothing said


@pytest.mark.parametrize("new", [True, False], ids=["new", "update"])
def test_an_entry_swapped_once_written_is_said(tmp_path: Path, new: bool) -> None:
    if not new:
        _entry(tmp_path)
    entry = tmp_path / ENTRY
    said: list[str] = []

    with _writing(tmp_path, {"scenario.json": b"{}"}, new=new) as written:
        entry.rename(entry.parent / "moved")
        with pytest.raises(EnvironmentProblemError, match="no longer names") as error:
            written.check()  # gone
        said.append(str(error.value))
        entry.mkdir()
        with pytest.raises(EnvironmentProblemError, match="no longer names") as error:
            written.check()  # another in its place
        said.append(str(error.value))
        entry.rmdir()
        (entry.parent / "moved").rename(entry)  # put back, so that the block ends cleanly

    assert len(said) == 2


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
        with _writing(root, {"scenario.json": b"{}"}, new=True, source=source) as written:
            with pytest.raises(EnvironmentProblemError, match="no longer names"):
                written.check()
            (tmp_path / "other").rmdir()
            root.unlink()
            (tmp_path / "held").rename(root)  # back, so that the block ends cleanly

    assert (root / ENTRY / "scenario.json").read_bytes() == b"{}"


def test_a_held_repository_whose_path_is_gone_is_said(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    source = RepositoryEntries(root)

    with (
        source.locked(),
        _writing(root, {"scenario.json": b"{}"}, new=True, source=source) as written,
    ):
        written.check()  # still the one held
        root.rename(tmp_path / "held")
        with pytest.raises(EnvironmentProblemError, match="no longer names"):
            written.check()
        (tmp_path / "held").rename(root)


def test_a_repository_once_released_is_written_by_its_path_again(tmp_path: Path) -> None:
    source = RepositoryEntries(tmp_path)
    with source.locked():
        pass

    _write(tmp_path, {"scenario.json": b"{}"}, new=True, source=source)

    assert (tmp_path / ENTRY / "scenario.json").read_bytes() == b"{}"


def test_a_held_repository_that_cannot_be_reached_again_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = RepositoryEntries(tmp_path)

    def failing(descriptor: int) -> int:
        raise OSError(24, "Too many open files")

    with source.locked():
        monkeypatch.setattr(os, "dup", failing)
        with pytest.raises(EnvironmentProblemError, match="Too many open files"):
            _write(tmp_path, {"scenario.json": b"{}"}, new=True, source=source)


@pytest.mark.parametrize("new", [True, False], ids=["new", "update"])
def test_a_write_leaves_no_directory_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, new: bool
) -> None:
    if not new:
        _entry(tmp_path)
    opened, closed = descriptors(monkeypatch)

    with _writing(tmp_path, {"scenario.json": b"{}"}, new=new) as written:
        written.check()
    _interrupted(tmp_path, {"scenario.json": b"[]"}, new=False)  # and when taken back

    assert opened
    assert sorted(opened) == sorted(closed)


def test_a_refused_write_leaves_no_directory_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "scenarios").symlink_to(tmp_path / "elsewhere")
    opened, closed = descriptors(monkeypatch)

    with pytest.raises(UnsafeInputError):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    assert opened
    assert sorted(opened) == sorted(closed)


def test_a_repository_that_cannot_be_opened_is_the_environment_s_fault(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError, match="cannot read"):
        _write(tmp_path / "missing", {"scenario.json": b"{}"}, new=True)


def test_an_entry_to_update_that_is_missing_is_the_environment_s_fault(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError, match="cannot read scenarios: it is missing"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=False, previous={"scenario.json": b""})
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


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_file_to_update_that_cannot_be_read_is_the_environment_s_fault(tmp_path: Path) -> None:
    directory = _entry(tmp_path)
    (directory / "scenario.json").chmod(0o000)
    try:
        with pytest.raises(EnvironmentProblemError, match=f"cannot read {ENTRY}/scenario.json"):
            _write(tmp_path, {"scenario.json": b"{}"}, new=False, previous={"scenario.json": b""})
    finally:
        (directory / "scenario.json").chmod(0o644)


def test_a_file_to_update_whose_bytes_cannot_be_read_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _entry(tmp_path)

    class Failing:
        def __enter__(self) -> "Failing":
            return self

        def __exit__(self, *arguments: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "fdopen", lambda *arguments, **options: Failing())

    with pytest.raises(EnvironmentProblemError, match="Input/output error"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=False, previous={"scenario.json": b""})


def test_directories_made_go_when_a_deeper_one_cannot_be_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    made = os.mkdir

    def failing(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        if Path(path).name == "ransomware":
            raise OSError(28, "No space left on device")
        made(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot make scenarios/ransomware"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    assert list(tmp_path.iterdir()) == []  # scenarios, made by the run, went too


def test_a_new_entry_whose_identity_cannot_be_read_is_not_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    told = places.identity

    def failing(descriptor: int, where: str) -> tuple[int, int]:
        if where == ENTRY:
            raise EnvironmentProblemError(f"cannot read {where}: Input/output error")
        return told(descriptor, where)

    monkeypatch.setattr("scenario_tools.adapters.entry_writer.identity", failing)

    with pytest.raises(EnvironmentProblemError, match="Input/output error"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)
    assert list(tmp_path.iterdir()) == []


def test_files_another_put_in_a_new_entry_meanwhile_stay(tmp_path: Path) -> None:
    entry = tmp_path / ENTRY

    error = _failing_block(
        tmp_path,
        {"scenario.json": b"{}"},
        new=True,
        during=lambda: (entry / "notes.txt").write_text("another's"),
    )

    assert "meanwhile stays" in str(error.value)
    assert _names(entry) == ["notes.txt"]  # this run's file went, theirs stayed
    assert (entry / "notes.txt").read_text() == "another's"


@pytest.mark.parametrize("new", [True, False], ids=["new", "update"])
@pytest.mark.parametrize("how", ["in place", "renamed over"])
def test_a_file_changed_once_written_is_said_by_the_check(
    tmp_path: Path, new: bool, how: str
) -> None:
    if not new:
        _entry(tmp_path)
    written_file = tmp_path / ENTRY / "scenario.json"

    with _writing(tmp_path, {"scenario.json": b"{}"}, new=new) as written:
        if how == "in place":
            written_file.write_bytes(b"[]")
        else:
            (tmp_path / ENTRY / "other").write_bytes(b"{}")  # the same bytes, another file
            (tmp_path / ENTRY / "other").rename(written_file)
        with pytest.raises(EnvironmentProblemError, match="changed since this run wrote it"):
            written.check()


def test_an_updated_file_gone_meanwhile_is_said(tmp_path: Path) -> None:
    directory = _entry(tmp_path)

    error = _failing_block(
        tmp_path,
        {"scenario.json": b"{}\n"},
        new=False,
        during=lambda: (directory / "scenario.json").unlink(),
    )

    assert "gone meanwhile" in str(error.value)


def test_an_update_put_back_whose_copy_cannot_be_removed_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _entry(tmp_path)
    removed = os.unlink

    def failing(path: str, **options: Any) -> None:
        if places.is_hidden_name(path):
            raise OSError(13, "Permission denied")
        removed(path, **options)

    def lock() -> None:
        monkeypatch.setattr(os, "unlink", failing)

    error = _failing_block(tmp_path, {"scenario.json": b"{}\n"}, new=False, during=lock)

    assert "given its previous bytes back" in str(error.value)
    assert (directory / "scenario.json").read_text() == '{"a": 1}'  # put back all the same
    [left] = [name for name in _names(directory) if places.is_hidden_name(name)]
    assert left in str(error.value)


def test_a_file_written_then_removed_is_said_by_the_check(tmp_path: Path) -> None:
    with _writing(tmp_path, {"scenario.json": b"{}"}, new=True) as written:
        (tmp_path / ENTRY / "scenario.json").unlink()
        with pytest.raises(EnvironmentProblemError, match="changed since this run wrote it"):
            written.check()


def test_a_file_written_that_cannot_be_read_again_is_said_by_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Failing:
        def __enter__(self) -> "Failing":
            return self

        def __exit__(self, *arguments: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            raise OSError(5, "Input/output error")

    with _writing(tmp_path, {"scenario.json": b"{}"}, new=True) as written:
        monkeypatch.setattr(os, "fdopen", lambda *arguments, **options: Failing())
        with pytest.raises(EnvironmentProblemError, match="changed since this run wrote it"):
            written.check()
        monkeypatch.undo()


def test_a_file_another_put_over_one_of_a_new_entry_stays(tmp_path: Path) -> None:
    entry = tmp_path / ENTRY

    def replaced() -> None:
        (entry / "theirs").write_text("another's")
        (entry / "theirs").rename(entry / "scenario.json")

    error = _failing_block(tmp_path, {"scenario.json": b"{}"}, new=True, during=replaced)

    assert "meanwhile stays" in str(error.value)
    assert (entry / "scenario.json").read_text() == "another's"


def test_a_new_entry_whose_directory_cannot_be_removed_is_put_back_and_said(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    removed = os.rmdir

    def failing(path: str, **options: Any) -> None:
        if places.is_hidden_name(path):
            raise OSError(5, "Input/output error")
        removed(path, **options)

    def lock() -> None:
        monkeypatch.setattr(os, "rmdir", failing)

    error = _failing_block(tmp_path, {"scenario.json": b"{}"}, new=True, during=lock)

    assert "Input/output error" in str(error.value)
    assert (tmp_path / ENTRY).is_dir()  # put back where it is looked for


class Hung(BaseException):
    """A wait that should never be: no handler of the code under test may take it for an I/O
    error, as it would a TimeoutError."""


@pytest.fixture
def bounded() -> Iterator[None]:
    """Never wait more than a few seconds: a test that would hang fails instead."""

    def expired(signal_number: int, frame: object) -> None:
        raise Hung("the run waits on something it should never wait on")

    before = signal.signal(signal.SIGALRM, expired)
    signal.alarm(5)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, before)


@pytest.mark.usefixtures("bounded")
def test_a_pipe_put_in_place_of_a_file_to_update_is_never_waited_on(tmp_path: Path) -> None:
    directory = _entry(tmp_path)
    (directory / "scenario.json").unlink()
    os.mkfifo(directory / "scenario.json")

    with pytest.raises(UnsafeInputError) as error:
        _write(tmp_path, {"scenario.json": b"{}"}, new=False, previous={"scenario.json": b"{}"})
    assert _refusal(error) == ("IO-013", f"{ENTRY}/scenario.json")


@pytest.mark.usefixtures("bounded")
def test_a_pipe_put_in_place_of_a_file_written_is_never_waited_on(tmp_path: Path) -> None:
    written_file = tmp_path / ENTRY / "scenario.json"

    with _writing(tmp_path, {"scenario.json": b"{}"}, new=True) as written:
        written_file.unlink()
        os.mkfifo(written_file)
        with pytest.raises(EnvironmentProblemError, match="changed since this run wrote it"):
            written.check()
        written_file.unlink()
        written_file.write_bytes(b"{}")


@pytest.mark.parametrize("new", [True, False], ids=["new", "update"])
def test_a_file_written_that_another_changed_in_place_is_never_taken_back(
    tmp_path: Path, new: bool
) -> None:
    if not new:
        _entry(tmp_path)
    written_file = tmp_path / ENTRY / "scenario.json"

    def edited() -> None:
        with written_file.open("ab") as file:  # the same file, another's bytes added
            file.write(b" edited")

    error = _failing_block(tmp_path, {"scenario.json": b"{}"}, new=new, during=edited)

    assert "meanwhile" in str(error.value)
    assert written_file.read_bytes() == b"{} edited"  # never lost


def test_an_update_without_the_bytes_it_replaces_is_a_mistake(tmp_path: Path) -> None:
    _entry(tmp_path)

    with pytest.raises(ValueError, match="bytes it was read with"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=False, previous={"other.json": b""})


def test_a_directory_another_made_then_removed_meanwhile_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raced(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        raise FileExistsError(17, "File exists")  # made by another, and gone by now

    monkeypatch.setattr(os, "mkdir", raced)

    with pytest.raises(EnvironmentProblemError, match="cannot make scenarios"):
        _write(tmp_path, {"scenario.json": b"{}"}, new=True)
