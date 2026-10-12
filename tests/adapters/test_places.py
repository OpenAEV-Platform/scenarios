"""Places in a directory held open by its descriptor: opened never through a link, taken back
only when they hold what the run made, and written only where nothing was."""

import errno
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from scenario_tools.adapters.places import (
    ABSENT,
    FOREIGN,
    REMOVED,
    PlaceTakenError,
    create_in,
    described,
    hidden_name,
    identity,
    is_hidden_name,
    made_directory,
    open_directory,
    place_back,
    take_back,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError


@pytest.fixture
def held(tmp_path: Path) -> Iterator[int]:
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _names(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir())


def test_a_hidden_name_is_the_tool_s_own_and_short() -> None:
    name = hidden_name()

    assert is_hidden_name(name)
    assert len(name) < 40  # whatever the name it stands for
    assert hidden_name() != name
    assert not is_hidden_name(".akira")
    assert not is_hidden_name(".scenario-tools-xyz")


def test_a_directory_is_opened_never_through_a_link_nor_a_file(tmp_path: Path, held: int) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    (tmp_path / "file").write_text("x")

    os.close(open_directory(held, "real", "real"))
    for name in ("link", "file"):
        with pytest.raises(UnsafeInputError) as error:
            open_directory(held, name, f"shown/{name}")
        assert (error.value.code, error.value.path) == ("IO-013", f"shown/{name}")
    with pytest.raises(FileNotFoundError):
        open_directory(held, "missing", "missing")


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_directory_that_cannot_be_opened_is_the_environment_s_fault(
    tmp_path: Path, held: int
) -> None:
    (tmp_path / "locked").mkdir(mode=0o000)
    try:
        with pytest.raises(EnvironmentProblemError, match="cannot read shown"):
            open_directory(held, "locked", "shown")
    finally:
        (tmp_path / "locked").chmod(0o755)


def test_a_directory_just_made_is_opened_only_when_empty(tmp_path: Path, held: int) -> None:
    (tmp_path / "made").mkdir()
    (tmp_path / "taken").mkdir()
    (tmp_path / "taken" / "theirs").write_text("x")

    os.close(made_directory(held, "made", "made"))
    with pytest.raises(EnvironmentProblemError, match="put at its place meanwhile"):
        made_directory(held, "taken", "taken")
    assert _names(tmp_path / "taken") == ["theirs"]


def test_an_identity_is_the_device_and_inode(tmp_path: Path, held: int) -> None:
    status = tmp_path.stat()

    assert identity(held, "shown") == (status.st_dev, status.st_ino)


def test_an_identity_that_cannot_be_read_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, held: int
) -> None:
    def failing(descriptor: int) -> os.stat_result:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "fstat", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot read shown: Input/output error"):
        identity(held, "shown")


def test_a_file_is_created_only_where_nothing_is(tmp_path: Path, held: int) -> None:
    written = create_in(held, tmp_path / "scenario.json", b"{}")

    assert (tmp_path / "scenario.json").read_bytes() == b"{}"
    assert oct((tmp_path / "scenario.json").stat().st_mode & 0o777) == oct(0o644)
    status = (tmp_path / "scenario.json").stat()
    assert written == (status.st_dev, status.st_ino)
    with pytest.raises(EnvironmentProblemError, match="already exists"):
        create_in(held, tmp_path / "scenario.json", b"other")
    assert (tmp_path / "scenario.json").read_bytes() == b"{}"
    (tmp_path / "link.json").symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(EnvironmentProblemError, match="already exists"):
        create_in(held, tmp_path / "link.json", b"x")
    assert not (tmp_path / "elsewhere.json").exists()


def test_a_file_that_cannot_be_written_whole_is_not_left(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(descriptor: int) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", failing)

    with pytest.raises(EnvironmentProblemError, match="No space left on device"):
        create_in(held, tmp_path / "scenario.json", b"{}")
    assert _names(tmp_path) == []


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_what_the_run_made_is_taken_back(tmp_path: Path, held: int, kind: str) -> None:
    place = tmp_path / "made"
    if kind == "file":
        place.write_text("x")
    else:
        place.mkdir()
        (place / "inside").write_text("x")
    made = identity_of(place)

    outcome = take_back(held, "made", made, _remove(held), where="shown", failure=None)

    assert outcome == REMOVED
    assert _names(tmp_path) == []


def identity_of(path: Path) -> tuple[int, int]:
    status = path.lstat()
    return status.st_dev, status.st_ino


def _remove(held: int) -> "_Remover":
    return _Remover(held)


class _Remover:
    def __init__(self, held: int) -> None:
        self.held = held

    def __call__(self, aside: str) -> None:
        try:
            os.unlink(aside, dir_fd=self.held)
        except IsADirectoryError:
            shutil.rmtree(aside, dir_fd=self.held)


def test_nothing_at_the_place_is_nothing_to_take_back(tmp_path: Path, held: int) -> None:
    assert take_back(held, "made", (0, 0), _remove(held), where="shown", failure=None) == ABSENT


def test_what_another_put_at_the_place_is_put_back_as_it_was(tmp_path: Path, held: int) -> None:
    (tmp_path / "made").symlink_to(tmp_path / "theirs")

    outcome = take_back(held, "made", (0, 0), _remove(held), where="shown", failure=None)

    assert outcome == FOREIGN
    assert (tmp_path / "made").is_symlink()
    assert _names(tmp_path) == ["made"]


def test_what_cannot_be_removed_is_put_back_and_said_with_the_run_s_failure(
    tmp_path: Path, held: int
) -> None:
    (tmp_path / "made").write_text("x")
    failure = RuntimeError("the plan cannot be written")

    def failing(aside: str) -> None:
        raise OSError(errno.EACCES, "Permission denied")

    with pytest.raises(EnvironmentProblemError) as error:
        take_back(
            held, "made", identity_of(tmp_path / "made"), failing, where="shown", failure=failure
        )

    said = str(error.value)
    assert "cannot take back shown: Permission denied; remove it by hand" in said
    assert "the plan cannot be written" in said  # the failure that led to it, seen
    assert error.value.__cause__ is failure
    assert _names(tmp_path) == ["made"]  # put back where it is looked for


def test_what_can_neither_be_removed_nor_put_back_is_said_where_it_is(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "made").write_text("x")

    def no_way_back(*arguments: object, **options: object) -> None:
        raise OSError(errno.EIO, "Input/output error")  # the way back

    def failing(aside: str) -> None:
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "link", no_way_back)

    with pytest.raises(EnvironmentProblemError, match="it is left as shown-dir/") as error:
        take_back(
            held,
            "made",
            identity_of(tmp_path / "made"),
            failing,
            where="shown-dir/made",
            failure=None,
        )
    [left] = _names(tmp_path)
    assert is_hidden_name(left)
    assert left in str(error.value)


def test_what_another_put_that_cannot_be_put_back_is_said_where_it_is(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "made").write_text("theirs")

    def no_way_back(*arguments: object, **options: object) -> None:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "link", no_way_back)

    with pytest.raises(EnvironmentProblemError, match="put at shown meanwhile") as error:
        take_back(held, "made", (0, 0), _remove(held), where="shown", failure=None)
    [kept] = _names(tmp_path)
    assert (tmp_path / kept).read_text() == "theirs"
    assert kept in str(error.value)


def test_a_place_that_cannot_be_set_aside_is_said(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "made").write_text("x")

    def failing(source: str, target: str, **options: object) -> None:
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "rename", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot take back shown: Permission denied"):
        take_back(
            held, "made", identity_of(tmp_path / "made"), _remove(held), where="shown", failure=None
        )
    assert _names(tmp_path) == ["made"]


def test_a_failure_is_described_for_a_reader() -> None:
    assert described(None) == ""
    assert described(KeyboardInterrupt()) == " (after an interruption)"
    assert described(RuntimeError("disk full")) == " (after: disk full)"
    assert described(RuntimeError()) == " (after: RuntimeError)"


def test_a_directory_just_made_that_cannot_be_listed_is_the_environment_s_fault(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "made").mkdir()

    def failing(descriptor: int) -> Iterator[os.DirEntry[str]]:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "scandir", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot read made: Input/output error"):
        made_directory(held, "made", "made")


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_a_file_in_a_directory_that_cannot_be_written_is_the_environment_s_fault(
    tmp_path: Path,
) -> None:
    (tmp_path / "locked").mkdir(mode=0o555)
    descriptor = os.open(tmp_path / "locked", os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(EnvironmentProblemError, match="Permission denied"):
            create_in(descriptor, tmp_path / "locked" / "scenario.json", b"{}")
    finally:
        os.close(descriptor)
        (tmp_path / "locked").chmod(0o755)


def test_a_file_interrupted_while_written_is_not_left(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(descriptor: int, data: memoryview) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "write", interrupted)

    with pytest.raises(KeyboardInterrupt):
        create_in(held, tmp_path / "scenario.json", b"{}")
    assert _names(tmp_path) == []


def test_a_file_whose_identity_cannot_be_read_is_left_and_said(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(descriptor: int) -> os.stat_result:
        (tmp_path / "scenario.json").rename(tmp_path / "ours")  # another takes the name
        (tmp_path / "scenario.json").write_text("another's")
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "fstat", failing)

    with pytest.raises(EnvironmentProblemError, match="remove it by hand") as error:
        create_in(held, tmp_path / "scenario.json", b"{}")
    assert "Input/output error" in str(error.value)
    assert (tmp_path / "scenario.json").read_text() == "another's"  # never removed


def test_a_file_that_cannot_be_written_whole_never_takes_another_with_it(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def swapped_then_failing(descriptor: int) -> None:
        (tmp_path / "scenario.json").rename(tmp_path / "ours")  # another takes the name
        (tmp_path / "scenario.json").write_text("another's")
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", swapped_then_failing)

    with pytest.raises(EnvironmentProblemError, match="No space left on device"):
        create_in(held, tmp_path / "scenario.json", b"{}")
    assert (tmp_path / "scenario.json").read_text() == "another's"


def test_a_file_set_aside_is_put_back_only_where_nothing_is(tmp_path: Path, held: int) -> None:
    (tmp_path / "aside").write_text("ours")

    place_back(held, "aside", "name")

    assert _names(tmp_path) == ["name"]
    assert (tmp_path / "name").read_text() == "ours"
    (tmp_path / "aside").write_text("ours again")
    with pytest.raises(PlaceTakenError):
        place_back(held, "aside", "name")  # another's is there: never replaced
    assert (tmp_path / "name").read_text() == "ours"
    assert (tmp_path / "aside").read_text() == "ours again"


def test_a_directory_set_aside_is_put_back_by_its_name(tmp_path: Path, held: int) -> None:
    (tmp_path / "aside").mkdir()

    place_back(held, "aside", "name")

    assert _names(tmp_path) == ["name"]


def test_a_file_is_put_back_by_its_name_where_links_cannot_be_made(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "aside").write_text("ours")

    def unlinkable(*arguments: object, **options: object) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", unlinkable)

    place_back(held, "aside", "name")

    assert (tmp_path / "name").read_text() == "ours"


def test_a_place_taken_is_said_apart_from_other_failures(tmp_path: Path, held: int) -> None:
    (tmp_path / "scenario.json").write_text("there")

    with pytest.raises(PlaceTakenError, match="already exists"):
        create_in(held, tmp_path / "scenario.json", b"{}")
    assert issubclass(PlaceTakenError, EnvironmentProblemError)


def test_a_file_put_back_whose_hidden_name_stays_is_said_so(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "aside").write_text("ours")

    def failing(path: str, **options: object) -> None:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "unlink", failing)

    assert place_back(held, "aside", "name") is False  # put back, but the hidden name stays
    assert (tmp_path / "name").read_text() == "ours"


def test_what_another_put_back_with_a_second_name_left_is_said(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "made").write_text("theirs")
    removed = os.unlink

    def failing(path: str, **options: object) -> None:
        if is_hidden_name(path):
            raise OSError(errno.EIO, "Input/output error")
        removed(path, **options)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "unlink", failing)

    with pytest.raises(EnvironmentProblemError, match="is put back, but a second name") as error:
        take_back(held, "made", (0, 0), _remove(held), where="shown", failure=None)
    assert (tmp_path / "made").read_text() == "theirs"
    [second] = [name for name in _names(tmp_path) if is_hidden_name(name)]
    assert second in str(error.value)


def test_a_file_interrupted_before_it_is_known_is_never_removed(
    tmp_path: Path, held: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(descriptor: int) -> os.stat_result:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "fstat", interrupted)

    with pytest.raises(EnvironmentProblemError, match="remove it by hand") as error:
        create_in(held, tmp_path / "scenario.json", b"{}")
    assert isinstance(error.value.__cause__, KeyboardInterrupt)
    assert _names(tmp_path) == ["scenario.json"]  # cannot be told from another's: left, said
