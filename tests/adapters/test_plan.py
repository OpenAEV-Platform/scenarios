"""The plan's place: reserved as an empty file held open, the plan written in that file and
published only while the place is still the one reserved, and given back otherwise, never
another file."""

import errno
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import write_output
from scenario_tools.adapters.places import is_hidden_name
from scenario_tools.adapters.plan import Reservation, reserve_plan
from scenario_tools.ports.errors import EnvironmentProblemError
from tests.adapters.spies import descriptors


def _reserve(path: Path) -> None:
    with reserve_plan(path):
        pass


def _failing(path: Path, during: Callable[[Reservation], None] = lambda reservation: None) -> None:
    """Reserve ``path``, do ``during``, then fail before the block ends."""
    with reserve_plan(path) as reservation:
        during(reservation)
        raise RuntimeError("the run cannot end")


def test_an_output_is_published_in_the_place_reserved_for_it(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"

    with reserve_plan(plan) as reservation:
        assert plan.read_bytes() == b""  # empty, until it is published
        assert oct(plan.stat().st_mode & 0o777) == oct(0o644)
        reservation.publish(b"{}\n")

    assert plan.read_bytes() == b"{}\n"
    assert oct(plan.stat().st_mode & 0o777) == oct(0o644)
    assert [path.name for path in tmp_path.iterdir()] == ["plan.json"]


def test_a_place_is_never_reserved_over_anything_nor_through_a_link(tmp_path: Path) -> None:
    (tmp_path / "plan.json").write_text("there")
    with pytest.raises(EnvironmentProblemError, match="already exists"):
        _reserve(tmp_path / "plan.json")
    assert (tmp_path / "plan.json").read_text() == "there"
    (tmp_path / "link.json").symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(EnvironmentProblemError, match="already exists"):
        _reserve(tmp_path / "link.json")  # a link is something there, never followed
    assert not (tmp_path / "elsewhere.json").exists()
    with pytest.raises(EnvironmentProblemError):
        _reserve(tmp_path / "missing" / "plan.json")
    (tmp_path / "linked").symlink_to(tmp_path)
    with pytest.raises(EnvironmentProblemError, match="symbolic link"):
        _reserve(tmp_path / "linked" / "other.json")  # the place's own directory: never
    assert not (tmp_path / "other.json").exists()


def test_a_place_the_block_ends_without_publishing_is_given_back(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        _failing(tmp_path / "plan.json")
    _reserve(tmp_path / "plan.json")  # ended without a failure, and without an output

    assert list(tmp_path.iterdir()) == []


def test_a_published_output_stays_whatever_follows(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        _failing(tmp_path / "plan.json", lambda reservation: reservation.publish(b"x"))

    assert (tmp_path / "plan.json").read_bytes() == b"x"


def test_an_output_is_never_published_in_a_directory_moved_meanwhile(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()

    def moved(reservation: Reservation) -> None:
        out.rename(tmp_path / "moved")
        out.mkdir()
        (out / "plan.json").write_text("another run's")
        reservation.publish(b"x")

    with pytest.raises(EnvironmentProblemError, match="taken meanwhile"):
        _failing(out / "plan.json", moved)
    assert (out / "plan.json").read_text() == "another run's"
    assert list((tmp_path / "moved").iterdir()) == []


def test_a_place_taken_meanwhile_is_never_written_over_nor_removed(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"

    def taken(reservation: Reservation) -> None:
        plan.unlink()
        plan.write_text("another run's")
        reservation.publish(b"x")

    with pytest.raises(EnvironmentProblemError, match="taken meanwhile"):
        _failing(plan, taken)
    assert plan.read_text() == "another run's"
    assert [path.name for path in tmp_path.iterdir()] == ["plan.json"]  # nothing else left


def test_a_place_removed_meanwhile_is_never_written(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"

    def removed(reservation: Reservation) -> None:
        plan.unlink()
        reservation.publish(b"x")

    with pytest.raises(EnvironmentProblemError, match="taken meanwhile"):
        _failing(plan, removed)
    assert list(tmp_path.iterdir()) == []


def _unremovable(monkeypatch: pytest.MonkeyPatch) -> None:
    removed = os.unlink

    def failing(path: str, **options: Any) -> None:
        if path == "plan.json" or is_hidden_name(path):  # under its name or set aside
            raise OSError(errno.EACCES, "Permission denied")
        removed(path, **options)

    monkeypatch.setattr(os, "unlink", failing)


def test_a_place_that_cannot_be_given_back_is_said_with_the_block_s_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _unremovable(monkeypatch)

    with pytest.raises(EnvironmentProblemError, match="remove it by hand") as error:
        _failing(tmp_path / "plan.json")
    assert isinstance(error.value.__cause__, RuntimeError)
    [left] = [path for path in tmp_path.iterdir() if is_hidden_name(path.name)]
    assert left.name in str(error.value)  # left, and said so
    assert (tmp_path / "plan.json").exists()  # back where it is looked for


def test_a_place_whose_state_cannot_be_read_is_never_said_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(*arguments: Any, **options: Any) -> os.stat_result:
        raise OSError(errno.EACCES, "Permission denied")

    def unreadable(reservation: Reservation) -> None:
        monkeypatch.setattr(os, "stat", failing)
        reservation.publish(b"x")

    with pytest.raises(EnvironmentProblemError, match="remove it by hand") as error:
        _failing(tmp_path / "plan.json", unreadable)
    assert "cannot write" in str(error.value.__cause__)
    [left] = list(tmp_path.iterdir())
    assert left.name in str(error.value)


def test_an_output_published_is_on_disk_before_it_is_said_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[int] = []
    real_fsync = os.fsync

    def spied(descriptor: int) -> None:
        synced.append(descriptor)
        real_fsync(descriptor)

    with reserve_plan(tmp_path / "plan.json") as reservation:
        monkeypatch.setattr(os, "fsync", spied)
        reservation.publish(b"x")

    assert synced


def test_a_link_put_at_the_place_meanwhile_is_put_back_as_a_link(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    (tmp_path / "theirs.json").write_text("another run's")

    def linked(reservation: Reservation) -> None:
        plan.unlink()
        plan.symlink_to(tmp_path / "theirs.json")

    with pytest.raises(RuntimeError):
        _failing(plan, linked)
    assert plan.is_symlink()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["plan.json", "theirs.json"]


def test_a_file_put_at_the_place_meanwhile_is_never_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = tmp_path / "plan.json"

    def failing(*arguments: Any, **options: Any) -> None:
        raise FileExistsError(errno.EEXIST, "File exists")  # the way back is taken by a third

    def taken(reservation: Reservation) -> None:
        plan.unlink()
        plan.write_text("another run's")
        monkeypatch.setattr(os, "link", failing)

    with pytest.raises(EnvironmentProblemError, match="is kept as") as error:
        _failing(plan, taken)
    assert isinstance(error.value.__cause__, RuntimeError)
    [kept] = [path for path in tmp_path.iterdir() if path.name != "plan.json"]
    assert kept.read_text() == "another run's"
    assert kept.name in str(error.value)


def test_an_output_is_written_in_the_file_reserved_never_in_another(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"

    def swapped(reservation: Reservation) -> None:
        plan.rename(tmp_path / "ours.json")  # the reserved file, under another name
        plan.write_text("another run's")
        reservation.publish(b"x")

    with pytest.raises(EnvironmentProblemError, match="taken meanwhile"):
        _failing(plan, swapped)
    assert plan.read_text() == "another run's"
    assert (tmp_path / "ours.json").read_bytes() == b"x"  # written where it was reserved


def test_an_output_leaves_nothing_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened, closed = descriptors(monkeypatch)

    write_output(tmp_path / "scenario.json", b"x")
    with reserve_plan(tmp_path / "plan.json") as reservation:
        reservation.publish(b"x")
    with pytest.raises(RuntimeError):
        _failing(tmp_path / "other.json")

    assert opened
    assert sorted(opened) == sorted(closed)


def test_a_reservation_that_cannot_end_leaves_nothing_open_nor_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(descriptor: int, mode: int) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    opened, closed = descriptors(monkeypatch)
    monkeypatch.setattr(os, "fchmod", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot write"):
        _reserve(tmp_path / "plan.json")
    assert sorted(opened) == sorted(closed)
    assert list(tmp_path.iterdir()) == []


def test_a_reservation_that_can_neither_end_nor_be_removed_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(descriptor: int, mode: int) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", failing)
    _unremovable(monkeypatch)

    with pytest.raises(EnvironmentProblemError, match="remove it by hand") as error:
        _reserve(tmp_path / "plan.json")
    assert "cannot write" in str(error.value.__cause__)


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_an_output_in_a_directory_that_cannot_be_written_is_the_environment_s_fault(
    tmp_path: Path,
) -> None:
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked").chmod(0o555)
    try:
        with pytest.raises(EnvironmentProblemError, match="cannot write"):
            _reserve(tmp_path / "locked" / "plan.json")
    finally:
        (tmp_path / "locked").chmod(0o755)
    assert list((tmp_path / "locked").iterdir()) == []


def test_a_reservation_whose_identity_cannot_be_read_is_left_and_said(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = tmp_path / "plan.json"

    def failing(descriptor: int) -> os.stat_result:
        plan.rename(tmp_path / "ours")  # another takes the place
        plan.write_text("another run's")
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "fstat", failing)

    with pytest.raises(EnvironmentProblemError, match="remove it by hand"):
        _reserve(plan)
    assert plan.read_text() == "another run's"  # never removed


def test_a_plan_whose_directory_another_put_in_its_place_is_never_published(
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    out.mkdir()

    def moved(reservation: Reservation) -> None:
        out.rename(tmp_path / "moved")
        out.mkdir()
        reservation.publish(b"x")

    with pytest.raises(EnvironmentProblemError, match="taken meanwhile"):
        _failing(out / "plan.json", moved)
    assert list(out.iterdir()) == []
    assert list((tmp_path / "moved").iterdir()) == []  # the reservation given back


def test_a_plan_whose_directory_is_gone_meanwhile_is_never_published(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()

    def gone(reservation: Reservation) -> None:
        out.rename(tmp_path / "moved")
        reservation.publish(b"x")

    with pytest.raises(EnvironmentProblemError, match="taken meanwhile"):
        _failing(out / "plan.json", gone)
    assert list((tmp_path / "moved").iterdir()) == []
