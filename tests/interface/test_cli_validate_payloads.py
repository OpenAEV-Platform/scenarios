"""validate-payloads on a copy of the hand-built catalogue: it passes, and each defect of a
catalogue, made by one change, fails on the expected check only, at its file and field."""

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.domain.verification.payload_catalogue import (
    BASE_NAME_DIFFERS,
    BASE_NAME_TAKEN,
    ENTRY_NOT_FOLDER,
    ENTRY_NOT_VERSION_FILE,
    ENTRY_SPECIAL,
    FOLDER_NOT_SLUG,
    ID_TWICE,
    OUT_OF_SCHEMA,
    OVER_SIZE,
)
from scenario_tools.domain.verification.payload_version import (
    ID_NOT_ITS_CONTENT,
    NAME_NO_SUFFIX,
    NAME_SUFFIX_ON_FIRST,
    NOT_STORED_FORM,
    SET_NOT_SORTED,
    VERSION_FILE_LIMIT,
)
from scenario_tools.interface.cli import main
from tests.support.payload_tree import PS, PS_FIRST, PS_LATER, ROOT, WHOAMI, edit, repository


def _run(catalogue: Path) -> tuple[int, list[tuple[str, str, str, str]]]:
    result = CliRunner().invoke(main, ["--format", "json", "validate-payloads", str(catalogue)])
    document = json.loads(result.output)
    found = [(f["code"], f["path"], f["field"], f["message"]) for f in document["findings"]]
    return result.exit_code, found


def test_the_hand_built_catalogue_passes(tmp_path: Path) -> None:
    assert _run(repository(tmp_path)) == (0, [])


def _set(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    return lambda document: document.__setitem__(key, value)


def _drop(key: str) -> Callable[[dict[str, Any]], None]:
    return lambda document: document.pop(key)


@pytest.mark.parametrize(
    ("file", "change", "expected"),
    [
        (PS_FIRST, _set("payload_tags", ["t"]), ("PAY-009", "", OUT_OF_SCHEMA)),
        (PS_FIRST, _set("file_drop_file", "x"), ("PAY-009", "", OUT_OF_SCHEMA)),
        (
            PS_FIRST,
            _set("payload_cleanup_command", ""),
            ("PAY-009", "/payload_cleanup_command", OUT_OF_SCHEMA),
        ),
        (PS_FIRST, _set("payload_arguments", []), ("PAY-009", "/payload_arguments", OUT_OF_SCHEMA)),
        (PS_FIRST, _set("payload_type", "Executable"), ("PAY-009", "/payload_type", OUT_OF_SCHEMA)),
        (
            PS_LATER,
            _set("payload_name", "Process Discovery - ps"),
            ("PAY-009", "/payload_name", NAME_NO_SUFFIX),
        ),
        (
            PS_FIRST,
            _set("payload_name", "Process Discovery - ps (1.0.0)"),
            ("PAY-009", "/payload_name", NAME_SUFFIX_ON_FIRST),
        ),
        (
            PS_LATER,
            _set("payload_name", "Other name (1.1.0)"),
            ("PAY-009", "/payload_name", BASE_NAME_DIFFERS),
        ),
        (
            WHOAMI,
            _set("payload_attack_patterns", ["T1033", "T1007"]),
            ("PAY-009", "/payload_attack_patterns", SET_NOT_SORTED),
        ),
        (
            WHOAMI,
            lambda d: d["payload_domains"].reverse(),
            ("PAY-009", "/payload_domains", SET_NOT_SORTED),
        ),
    ],
)
def test_each_defect_of_a_version_file_fails_on_its_check_only(
    tmp_path: Path,
    file: str,
    change: Callable[[dict[str, Any]], None],
    expected: tuple[str, str, str],
) -> None:
    catalogue = repository(tmp_path)
    edit(catalogue, file, change)
    code, found = _run(catalogue)
    assert code == 1
    assert {(c, message) for c, _, _, message in found} == {(expected[0], expected[2])}
    assert expected[1] in {field for _, _, field, _ in found}  # a schema may also say so at ""
    assert {path for _, path, _, _ in found} == {f"payloads/{file}"}


def test_an_id_that_is_not_the_one_its_content_has_fails(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    path = catalogue / PS_FIRST
    document = json.loads(path.read_text("utf-8"))
    document["payload_external_id"] = "not-its-id"
    path.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    assert _run(catalogue) == (
        1,
        [("PAY-003", f"payloads/{PS_FIRST}", "/payload_external_id", ID_NOT_ITS_CONTENT)],
    )


@pytest.mark.parametrize(
    "rewrite",
    [
        lambda data: data.replace(b"\n", b"\r\n"),
        lambda data: b"\xef\xbb\xbf" + data,
        lambda data: data.rstrip(b"\n"),
        lambda data: json.dumps(json.loads(data), indent=4, sort_keys=True).encode() + b"\n",
    ],
)
def test_a_file_not_in_the_stored_form_fails(
    tmp_path: Path, rewrite: Callable[[bytes], bytes]
) -> None:
    catalogue = repository(tmp_path)
    path = catalogue / PS_FIRST
    path.write_bytes(rewrite(path.read_bytes()))
    code, found = _run(catalogue)
    assert (code, found) == (1, [("PAY-009", f"payloads/{PS_FIRST}", "", NOT_STORED_FORM)])


@pytest.mark.parametrize(
    ("make", "where", "message"),
    [
        (lambda c: (c / "README.md").write_text("x"), "payloads/README.md", ENTRY_NOT_FOLDER),
        (
            lambda c: (c / "Process_Discovery").mkdir(),
            "payloads/Process_Discovery",
            FOLDER_NOT_SLUG,
        ),
        (
            lambda c: (c / PS / "1.2.json").write_text("{}"),
            f"payloads/{PS}/1.2.json",
            ENTRY_NOT_VERSION_FILE,
        ),
        (lambda c: (c / PS / "notes").mkdir(), f"payloads/{PS}/notes", ENTRY_NOT_VERSION_FILE),
        (lambda c: (c / "linked").symlink_to(c / PS), "payloads/linked", ENTRY_SPECIAL),
        (
            lambda c: (c / PS / "2.0.0.json").symlink_to(c / PS_FIRST),
            f"payloads/{PS}/2.0.0.json",
            ENTRY_SPECIAL,
        ),
        (
            lambda c: (c / PS / "2.0.0.json").write_bytes(b" " * (VERSION_FILE_LIMIT + 1)),
            f"payloads/{PS}/2.0.0.json",
            OVER_SIZE,
        ),
    ],
)
def test_each_defect_of_the_layout_fails_on_its_check_only(
    tmp_path: Path, make: Callable[[Path], object], where: str, message: str
) -> None:
    catalogue = repository(tmp_path)
    make(catalogue)
    assert _run(catalogue) == (1, [("PAY-009", where, "", message)])


def test_a_payload_whose_base_name_another_has_fails(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    shutil.copytree(catalogue / PS, catalogue / "zz-copy")
    (catalogue / "zz-copy" / "1.1.0.json").unlink()
    edit(catalogue, "zz-copy/1.0.0.json", _set("command_content", "ps -e"))
    assert _run(catalogue) == (
        1,
        [("PAY-009", "payloads/zz-copy/1.0.0.json", "/payload_name", BASE_NAME_TAKEN)],
    )


def test_an_id_two_versions_share_fails(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    shutil.copytree(catalogue / PS, catalogue / "zz-copy")
    (catalogue / "zz-copy" / "1.1.0.json").unlink()
    path = catalogue / "zz-copy" / "1.0.0.json"
    document = json.loads(path.read_text("utf-8"))
    document["payload_name"] = "Another"
    path.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    code, found = _run(catalogue)
    assert ("PAY-009", "payloads/zz-copy/1.0.0.json", "/payload_external_id", ID_TWICE) in found
    assert code == 1


def test_a_file_that_is_not_strict_json_is_refused_input(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    (catalogue / PS_FIRST).write_text('{"payload_name": "a", "payload_name": "b"}\n')
    assert _run(catalogue) == (
        1,
        [("IO-005", f"payloads/{PS_FIRST}", "", "duplicate key 'payload_name'")],
    )


def test_the_findings_are_the_same_on_a_second_run(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    edit(catalogue, PS_LATER, _set("payload_name", "Process Discovery - ps"))
    (catalogue / "README.md").write_text("x")
    assert _run(catalogue) == _run(catalogue)


def test_a_directory_without_policy_data_above_is_the_environment(tmp_path: Path) -> None:
    catalogue = tmp_path / "payloads"
    shutil.copytree(ROOT / "tests" / "golden" / "payloads", catalogue)
    result = CliRunner().invoke(main, ["validate-payloads", str(catalogue)])
    assert result.exit_code == 3


def test_a_repository_without_the_payload_schema_is_the_environment(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    (catalogue.parent / "schemas" / "payload.schema.json").unlink()
    result = CliRunner().invoke(main, ["validate-payloads", str(catalogue)])
    assert result.exit_code == 3


def test_the_repository_s_own_catalogue_passes() -> None:
    catalogue = ROOT / "payloads"
    if not catalogue.exists():
        pytest.skip("the repository holds no payload catalogue yet")
    result = CliRunner().invoke(main, ["validate-payloads", str(catalogue)])
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["payload_output_parsers"].append({}),
        lambda d: d["payload_output_parsers"][0]["output_parser_contract_output_elements"].append(
            {}
        ),
        lambda d: d["payload_output_parsers"][0]["output_parser_contract_output_elements"][0][
            "contract_output_element_regex_groups"
        ].append({}),
    ],
)
def test_an_empty_object_in_the_output_parsers_fails_the_schema(
    tmp_path: Path, change: Callable[[dict[str, Any]], None]
) -> None:
    catalogue = repository(tmp_path)
    edit(catalogue, PS_FIRST, change)
    code, found = _run(catalogue)
    assert code == 1
    assert {(c, message) for c, _, _, message in found} == {("PAY-009", OUT_OF_SCHEMA)}


@pytest.mark.parametrize("part", ["schemas", "policy", "policy/data"])
def test_rules_reached_through_a_link_are_the_environment_never_followed(
    tmp_path: Path, part: str
) -> None:
    catalogue = repository(tmp_path)
    root = catalogue.parent
    moved = tmp_path / "outside"
    (root / part).rename(moved)
    (root / part).symlink_to(moved)
    result = CliRunner().invoke(main, ["validate-payloads", str(catalogue)])
    assert result.exit_code == 3


def test_a_catalogue_reached_through_a_link_in_the_repository_is_refused(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    root = catalogue.parent
    (root / "copies").mkdir()
    (root / "copies" / "real").mkdir()
    catalogue.rename(root / "copies" / "real" / "payloads")
    (root / "linked").symlink_to(root / "copies" / "real")
    code, found = _run(root / "linked" / "payloads")
    assert code == 1
    assert [c for c, *_ in found] == ["IO-013"]


def _against(catalogue: Path, base: Path) -> tuple[int, list[tuple[str, str]]]:
    arguments = [
        "--format",
        "json",
        "validate-payloads",
        str(catalogue),
        "--previous-root",
        str(base),
    ]
    result = CliRunner().invoke(main, arguments)
    document = json.loads(result.output)
    return result.exit_code, [(f["code"], f["path"]) for f in document["findings"]]


def _base(tmp_path: Path) -> Path:
    """A checkout of the base branch holding the hand-built catalogue."""
    base = tmp_path / "base"
    shutil.copytree(ROOT / "tests" / "golden" / "payloads", base / "payloads")
    return base


def test_a_catalogue_that_keeps_the_base_passes_against_it(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)

    assert _against(catalogue, _base(tmp_path)) == (0, [])


def test_a_version_the_base_holds_edited_or_removed_fails_against_it(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    base = _base(tmp_path)
    edit(catalogue, PS_LATER, lambda document: document.update(payload_description="Changed."))
    (catalogue / WHOAMI).unlink()
    (catalogue / WHOAMI).parent.rmdir()

    code, found = _against(catalogue, base)

    assert code == 1
    assert found == [
        ("VER-022", f"payloads/{PS_LATER}"),
        ("VER-022", f"payloads/{WHOAMI}"),
    ]


def test_a_new_version_below_the_base_s_highest_fails_against_it(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    base = _base(tmp_path)
    shutil.copyfile(catalogue / PS_LATER, catalogue / PS / "1.0.5.json")
    edit(
        catalogue,
        f"{PS}/1.0.5.json",
        lambda document: document.update(payload_name="Process Discovery - ps (1.0.5)"),
    )

    code, found = _against(catalogue, base)

    assert code == 1
    assert ("VER-023", f"payloads/{PS}/1.0.5.json") in found


def test_a_base_without_a_catalogue_is_an_empty_base(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    (tmp_path / "empty").mkdir()

    assert _against(catalogue, tmp_path / "empty") == (0, [])


def test_a_copy_of_the_catalogue_is_checked_against_the_base_s_payloads(tmp_path: Path) -> None:
    catalogue = repository(tmp_path)
    copy = catalogue.parent / "copies" / "payloads"
    shutil.copytree(catalogue, copy)
    edit(copy, PS_LATER, lambda document: document.update(payload_description="Changed."))

    assert _against(copy, _base(tmp_path)) == (1, [("VER-022", f"copies/payloads/{PS_LATER}")])


@pytest.mark.parametrize("kind", ["link", "file"])
def test_a_base_whose_payloads_is_no_directory_is_the_environment(
    tmp_path: Path, kind: str
) -> None:
    catalogue = repository(tmp_path)
    base = tmp_path / "base"
    base.mkdir()
    if kind == "link":
        (base / "payloads").symlink_to(_base(tmp_path / "elsewhere") / "payloads")
    else:
        (base / "payloads").write_text("x")

    result = CliRunner().invoke(
        main,
        ["--format", "json", "validate-payloads", str(catalogue), "--previous-root", str(base)],
    )

    assert result.exit_code == 3, result.output
    assert "the base checkout's payloads is no directory" in result.output
