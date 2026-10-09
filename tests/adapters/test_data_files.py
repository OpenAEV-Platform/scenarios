"""Policy data and export files: read safely, written without following a link."""

import errno
import io
import os
import secrets
import stat
import zipfile
from pathlib import Path

import pytest

from scenario_tools.adapters.data_files import (
    YamlDataLoader,
    read_export,
    read_mapping,
    write_output,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

ROOT = Path(__file__).parents[2]
GOLDEN = ROOT / "tests" / "golden" / "exports"


def test_policy_data_is_read_by_name() -> None:
    rules = YamlDataLoader(ROOT / "policy" / "data").load("volatile-fields")

    assert set(rules) == {"removed", "removed_suffixes", "sorted"}


@pytest.mark.parametrize("name", ["../secrets", "a/b", "", "Volatile"])
def test_a_data_name_is_a_plain_name(name: str) -> None:
    with pytest.raises(ValueError, match="data name"):
        YamlDataLoader(ROOT / "policy" / "data").load(name)


def test_an_exported_archive_gives_its_scenario() -> None:
    export = read_export(GOLDEN / "easm-scenario.zip")

    assert export["scenario_information"]["scenario_name"] == "EASM Scenario"


def test_an_exported_json_file_gives_its_scenario(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text('{"scenario_information": {"scenario_name": "x"}}', encoding="utf-8")

    assert read_export(path) == {"scenario_information": {"scenario_name": "x"}}


@pytest.mark.parametrize("names", [[], ["a.json", "b.json"]], ids=["none", "two"])
def test_an_archive_needs_exactly_one_scenario_entry(tmp_path: Path, names: list[str]) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", b"x")
        for name in names:
            archive.writestr(name, b"{}")
    path = tmp_path / "export.zip"
    path.write_bytes(buffer.getvalue())

    with pytest.raises(UnsafeInputError) as error:
        read_export(path)
    assert error.value.code == "IO-014"


def test_an_output_is_written_and_replaced(tmp_path: Path) -> None:
    path = tmp_path / "scenario.json"
    write_output(path, b"a first, longer content\n")
    write_output(path, b"second\n")  # shorter: nothing of the first may remain

    assert path.read_bytes() == b"second\n"


def test_an_output_is_never_written_through_a_link(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_bytes(b"keep\n")
    (tmp_path / "scenario.json").symlink_to(target)

    with pytest.raises(UnsafeInputError) as error:
        write_output(tmp_path / "scenario.json", b"new\n")
    assert error.value.code == "IO-013"
    assert target.read_bytes() == b"keep\n"


def test_a_mapping_file_gives_source_to_stable_identifiers(tmp_path: Path) -> None:
    path = tmp_path / "map.yaml"
    path.write_text(
        "- {source_inject_id: a, stable_id: b}\n- {source_inject_id: c, stable_id: d}\n",
        encoding="utf-8",
    )

    assert read_mapping(path) == {"a": "b", "c": "d"}


@pytest.mark.parametrize(
    "content",
    ["a: b", "- [a, b]", "- {source_inject_id: a}", "- {source_inject_id: a, stable_id: 1}",
     "- {source_inject_id: a, stable_id: b}\n- {source_inject_id: a, stable_id: c}"],
    ids=["not a list", "not objects", "missing stable id", "not text", "source twice"],
)  # fmt: skip
def test_a_malformed_mapping_is_refused(tmp_path: Path, content: str) -> None:
    path = tmp_path / "map.yaml"
    path.write_text(content + "\n", encoding="utf-8")

    with pytest.raises(UnsafeInputError) as error:
        read_mapping(path)
    assert error.value.code == "VER-011"


def test_an_empty_mapping_maps_nothing(tmp_path: Path) -> None:
    path = tmp_path / "map.yaml"
    path.write_text("[]\n", encoding="utf-8")

    assert read_mapping(path) == {}


def test_an_output_that_cannot_be_created_is_an_environment_problem(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError):
        write_output(tmp_path / "missing" / "scenario.json", b"x")


def test_a_failed_write_keeps_the_previous_output_and_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "scenario.json"
    target.write_bytes(b"previous\n")

    def full_disk(descriptor: int, data: bytes) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "write", full_disk)

    with pytest.raises(EnvironmentProblemError, match="No space left"):
        write_output(target, b"new\n")
    assert target.read_bytes() == b"previous\n"
    assert [path.name for path in tmp_path.iterdir()] == ["scenario.json"]


def test_a_hard_linked_output_is_replaced_without_touching_the_other_file(tmp_path: Path) -> None:
    target, other = tmp_path / "scenario.json", tmp_path / "other.json"
    other.write_bytes(b"other\n")
    os.link(other, target)

    write_output(target, b"new\n")

    assert target.read_bytes() == b"new\n"
    assert other.read_bytes() == b"other\n"


def test_the_output_mode_is_the_same_whatever_the_umask_or_the_previous_mode(
    tmp_path: Path,
) -> None:
    target = tmp_path / "scenario.json"
    target.write_bytes(b"previous\n")
    target.chmod(0o666)
    mask = os.umask(0o077)
    try:
        write_output(target, b"new\n")
    finally:
        os.umask(mask)

    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_an_output_directory_that_is_a_link_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "entry").symlink_to(real)

    with pytest.raises(UnsafeInputError) as error:
        write_output(tmp_path / "entry" / "scenario.json", b"x")
    assert error.value.code == "IO-013"
    assert list(real.iterdir()) == []


@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_an_output_that_is_not_a_regular_file_is_refused_without_blocking(
    tmp_path: Path, kind: str
) -> None:
    target = tmp_path / "scenario.json"
    if kind == "fifo":
        os.mkfifo(target)
    else:
        target.mkdir()

    with pytest.raises(UnsafeInputError) as error:
        write_output(target, b"x")
    assert error.value.code == "IO-013"


def test_a_fifo_with_a_reader_is_refused_too(tmp_path: Path) -> None:
    target = tmp_path / "scenario.json"
    os.mkfifo(target)
    reader = os.open(target, os.O_RDONLY | os.O_NONBLOCK)  # the open now succeeds
    try:
        with pytest.raises(UnsafeInputError) as error:
            write_output(target, b"x")
        assert error.value.code == "IO-013"
    finally:
        os.close(reader)


def test_an_output_whose_status_cannot_be_read_is_an_environment_problem(tmp_path: Path) -> None:
    entry = tmp_path / "entry"
    entry.mkdir()
    entry.chmod(0o400)  # readable, but nothing in it can be looked up
    try:
        with pytest.raises(EnvironmentProblemError, match="Permission denied"):
            write_output(entry / "scenario.json", b"x")
    finally:
        entry.chmod(0o700)


def test_a_planted_temporary_file_is_never_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = tmp_path / ".scenario.json.0123456789abcdef"
    planted.write_bytes(b"planted\n")
    monkeypatch.setattr(secrets, "token_hex", lambda size: "0123456789abcdef")

    with pytest.raises(EnvironmentProblemError):
        write_output(tmp_path / "scenario.json", b"new\n")
    assert planted.read_bytes() == b"planted\n"
    assert not (tmp_path / "scenario.json").exists()


def test_a_write_cut_short_is_resumed_until_everything_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = os.write
    monkeypatch.setattr(os, "write", lambda descriptor, data: real_write(descriptor, data[:3]))

    write_output(tmp_path / "scenario.json", b"a longer content\n")

    assert (tmp_path / "scenario.json").read_bytes() == b"a longer content\n"


def test_an_interrupted_write_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(descriptor: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "fsync", interrupted)

    with pytest.raises(KeyboardInterrupt):
        write_output(tmp_path / "scenario.json", b"new\n")
    assert list(tmp_path.iterdir()) == []


def test_an_empty_mapping_file_is_refused(tmp_path: Path) -> None:
    mapping = tmp_path / "map.yaml"
    mapping.write_text("", encoding="utf-8")

    with pytest.raises(UnsafeInputError) as error:
        read_mapping(mapping)
    assert error.value.code == "VER-011"
