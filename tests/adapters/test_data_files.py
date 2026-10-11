"""Policy data and export files: read safely, written without following a link."""

import base64
import errno
import io
import os
import secrets
import stat
import zipfile
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import (
    YamlDataLoader,
    check_export_archive,
    read_attachments,
    read_export,
    read_export_archive,
    read_mapping,
    read_stored_scenario,
    reserve_output,
    write_output,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError
from tests.adapters.test_safe_zip import ENCRYPTED

ROOT = Path(__file__).parents[2]
GOLDEN = ROOT / "tests" / "golden" / "exports"
ATTACHMENTS = ENCRYPTED  # one entry, encrypted with the conventional password "infected"
# The same entry, made with `zip -P other`: an archive the importer could not open.
OTHER_PASSWORD = base64.b64decode(
    "UEsDBAoACQAAAAo7Sl2MsuviEwAAAAcAAAAFAAAAcy50eHTWN1T4MN5xv8YduY2BwrtUhn5+UEsHCIyy6+ITAAAABw"
    "AAAFBLAQIeAwoACQAAAAo7Sl2MsuviEwAAAAcAAAAFAAAAAAAAAAEAAAC0gQAAAABzLnR4dFBLBQYAAAAAAQABADMA"
    "AABGAAAAAAA="
)


def test_policy_data_is_read_by_name() -> None:
    rules = YamlDataLoader(ROOT / "policy" / "data").load("volatile-fields")

    assert set(rules) == {"removed", "removed_suffixes", "sorted", "emptied_in_builtin_contracts"}
    assert rules["emptied_in_builtin_contracts"] == ["injector_contract_attack_patterns"]


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


def _export_zip(*entries: tuple[str, bytes, bytes]) -> bytes:
    """An archive of (name, comment, data) entries, as the platform writes an export."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, comment, data in entries:
            entry = zipfile.ZipInfo(name)
            entry.comment = comment
            archive.writestr(entry, data)
    return buffer.getvalue()


@pytest.mark.parametrize(
    "entries",
    [
        [("readme.txt", b"", b"x")],
        [("a.json", b"Scenario", b"{}"), ("b.json", b"Scenario", b"{}")],
        [("a.json", b"", b"{}")],
    ],
    ids=["none", "two", "a json entry without the comment"],
)
def test_an_archive_needs_exactly_one_scenario_entry(
    tmp_path: Path, entries: list[tuple[str, bytes, bytes]]
) -> None:
    path = tmp_path / "export.zip"
    path.write_bytes(_export_zip(*entries))

    with pytest.raises(UnsafeInputError) as error:
        read_export(path)
    assert error.value.code == "IO-014"


def test_the_scenario_entry_is_the_one_whose_comment_says_so(tmp_path: Path) -> None:
    # As the importer reads it: by its comment, whatever its name.
    path = tmp_path / "export.zip"
    path.write_bytes(_export_zip(("notes.json", b"", b"[]"), ("EASM", b"Scenario", b"{}")))

    assert read_export(path) == {}


@pytest.mark.parametrize("name", ["report.pdf", "data.json"])
def test_an_export_carrying_documents_is_refused_until_they_are_supported(
    tmp_path: Path, name: str
) -> None:
    path = tmp_path / "export.zip"
    path.write_bytes(_export_zip(("EASM.json", b"Scenario", b"{}"), (name, b"Attachment", b"x")))

    with pytest.raises(UnsafeInputError) as error:
        read_export(path)
    assert (error.value.code, error.value.message) == (
        "IO-014",
        "documents are not supported yet: the export carries 1 document",
    )


def test_an_export_archive_in_memory_passes_the_same_checks() -> None:
    data = (GOLDEN / "easm-scenario.zip").read_bytes()
    check_export_archive(data, "export.zip")

    with pytest.raises(UnsafeInputError) as error:
        check_export_archive(b"not a zip", "out/export.zip")
    assert (error.value.code, error.value.path) == ("IO-007", "out/export.zip")


def test_an_export_archive_file_gives_its_bytes_once_checked(tmp_path: Path) -> None:
    assert (
        read_export_archive(GOLDEN / "easm-scenario.zip")
        == (GOLDEN / "easm-scenario.zip").read_bytes()
    )
    path = tmp_path / "export.zip"
    path.write_bytes(b"x" * (20 * 1024 * 1024 + 1))

    with pytest.raises(UnsafeInputError) as error:
        read_export_archive(path)
    assert (error.value.code, error.value.path) == ("IO-001", str(path))


@pytest.mark.parametrize("names", [[], ["a.json", "b.json"]], ids=["none", "two"])
def test_an_export_archive_file_needs_exactly_one_scenario_entry(
    tmp_path: Path, names: list[str]
) -> None:
    path = tmp_path / "export.zip"
    path.write_bytes(_export_zip(*((name, b"Scenario", b"{}") for name in names)))

    with pytest.raises(UnsafeInputError) as error:
        read_export_archive(path)
    assert (error.value.code, error.value.path) == ("IO-014", str(path))


def test_a_stored_scenario_gives_its_bytes_and_document(tmp_path: Path) -> None:
    path = tmp_path / "scenario.json"
    path.write_bytes(b'{"scenario_information": {}}\n')

    assert read_stored_scenario(path) == (
        b'{"scenario_information": {}}\n',
        {"scenario_information": {}},
    )


def test_a_stored_scenario_that_is_not_json_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "scenario.json"
    path.write_bytes(b"{")

    with pytest.raises(UnsafeInputError) as error:
        read_stored_scenario(path)
    assert error.value.path == str(path)


def test_no_attachments_file_means_no_attachments(tmp_path: Path) -> None:
    assert read_attachments(tmp_path / "attachments.zip") is None


def test_attachments_given_as_a_link_are_refused_even_dangling(tmp_path: Path) -> None:
    path = tmp_path / "attachments.zip"
    path.symlink_to(tmp_path / "nowhere.zip")

    with pytest.raises(UnsafeInputError) as error:
        read_attachments(path)
    assert error.value.code == "IO-013"


def test_attachments_that_open_with_the_shared_password_are_read(tmp_path: Path) -> None:
    path = tmp_path / "attachments.zip"
    path.write_bytes(ATTACHMENTS)

    assert read_attachments(path) == ATTACHMENTS


@pytest.mark.parametrize(
    ("content", "code"),
    [(b"not a zip", "IO-007"), (OTHER_PASSWORD, "IO-007")],
    ids=["not a zip", "another password"],
)
def test_attachments_the_importer_could_not_open_are_refused(
    tmp_path: Path, content: bytes, code: str
) -> None:
    path = tmp_path / "attachments.zip"
    path.write_bytes(content)

    with pytest.raises(UnsafeInputError) as error:
        read_attachments(path)
    assert (error.value.code, error.value.path) == (code, str(path))


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


def test_the_documents_refusal_counts_them(tmp_path: Path) -> None:
    path = tmp_path / "export.zip"
    documents = [(f"{n}.pdf", b"Attachment", b"x") for n in range(2)]
    path.write_bytes(_export_zip(("EASM.json", b"Scenario", b"{}"), *documents))

    with pytest.raises(UnsafeInputError) as error:
        read_export(path)
    assert error.value.message.endswith("the export carries 2 documents")


def test_a_file_written_only_if_new_is_created(tmp_path: Path) -> None:
    write_output(tmp_path / "scenario.yaml", b"name: x\n", create=True)

    assert (tmp_path / "scenario.yaml").read_bytes() == b"name: x\n"
    assert (tmp_path / "scenario.yaml").stat().st_mode & 0o777 == 0o644
    assert sorted(path.name for path in tmp_path.iterdir()) == ["scenario.yaml"]


def test_a_file_written_only_if_new_never_replaces_one_that_appeared(tmp_path: Path) -> None:
    # Created in between, by a person or another run: it is theirs and stays.
    (tmp_path / "scenario.yaml").write_bytes(b"completed: by hand\n")

    with pytest.raises(EnvironmentProblemError, match="already exists"):
        write_output(tmp_path / "scenario.yaml", b"name: x\n", create=True)

    assert (tmp_path / "scenario.yaml").read_bytes() == b"completed: by hand\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["scenario.yaml"]


def test_an_output_is_reserved_before_anything_is_written(tmp_path: Path) -> None:
    reserve_output(tmp_path / "plan.json")

    assert (tmp_path / "plan.json").read_bytes() == b""  # empty, until it is written
    assert oct((tmp_path / "plan.json").stat().st_mode & 0o777) == oct(0o644)
    with pytest.raises(EnvironmentProblemError, match="already exists"):
        reserve_output(tmp_path / "plan.json")  # never over anything there
    (tmp_path / "link.json").symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(EnvironmentProblemError, match="already exists"):
        reserve_output(tmp_path / "link.json")  # a link is something there, never followed
    assert not (tmp_path / "elsewhere.json").exists()
    with pytest.raises(EnvironmentProblemError):
        reserve_output(tmp_path / "missing" / "plan.json")
    (tmp_path / "linked").symlink_to(tmp_path)
    with pytest.raises(UnsafeInputError):
        reserve_output(tmp_path / "linked" / "other.json")


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


def test_an_output_leaves_nothing_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened, closed = _descriptors(monkeypatch)

    write_output(tmp_path / "scenario.json", b"x")

    assert opened
    assert sorted(opened) == sorted(closed)


def test_a_reservation_that_cannot_end_leaves_nothing_open_nor_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(descriptor: int, mode: int) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    opened, closed = _descriptors(monkeypatch)
    monkeypatch.setattr(os, "fchmod", failing)

    with pytest.raises(EnvironmentProblemError, match="cannot write"):
        reserve_output(tmp_path / "plan.json")
    assert sorted(opened) == sorted(closed)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_an_output_in_a_directory_that_cannot_be_written_is_the_environment_s_fault(
    tmp_path: Path,
) -> None:
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked").chmod(0o555)
    try:
        with pytest.raises(EnvironmentProblemError, match="cannot write"):
            reserve_output(tmp_path / "locked" / "plan.json")
    finally:
        (tmp_path / "locked").chmod(0o755)
    assert list((tmp_path / "locked").iterdir()) == []
