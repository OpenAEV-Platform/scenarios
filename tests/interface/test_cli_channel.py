"""The ``channel`` commands: the previous release checked against the channel's pointer, and
the pointer that moves the channel to the release just published."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.interface.cli import main

REPOSITORY = "OpenAEV-Platform/scenarios"


def _manifest(tmp_path: Path, release: str, name: str = "manifest.json", **extra: Any) -> Path:
    document = {
        "repository": REPOSITORY,
        "channel": "edge",
        "release": release,
        "release_approver": "laugiov",
        **extra,
    }
    path = tmp_path / name
    path.write_bytes(jcs(document))
    return path


def _pointer(tmp_path: Path, manifest: Path, release: str, name: str = "edge.json") -> Path:
    path = tmp_path / name
    path.write_bytes(
        jcs(
            {
                "schema_version": 1,
                "repository": REPOSITORY,
                "channel": "edge",
                "release": release,
                "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            }
        )
    )
    return path


def _run(*arguments: str) -> Any:
    return CliRunner().invoke(main, ["--format", "json", "channel", *arguments])


def test_the_previous_release_is_the_one_the_pointer_names(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    pointer = _pointer(tmp_path, manifest, "2026.10.27.1")

    result = _run(
        "previous", "--pointer", str(pointer), "--manifest", str(manifest), "--channel", "edge"
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["ok"] is True


def test_a_manifest_the_pointer_does_not_name_is_refused(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    pointer = _pointer(tmp_path, manifest, "2026.10.27.1")
    other = _manifest(tmp_path, "2026.10.27.1", "other.json", items=[])

    result = _run(
        "previous", "--pointer", str(pointer), "--manifest", str(other), "--channel", "edge"
    )

    assert result.exit_code == 3, result.output
    assert "not the release the channel's pointer names" in result.output


def test_a_pointer_of_another_channel_or_out_of_shape_is_refused(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    pointer = _pointer(tmp_path, manifest, "2026.10.27.1")
    broken = tmp_path / "broken.json"
    broken.write_bytes(b'{"schema_version": 1}')

    stable = _run(
        "previous", "--pointer", str(pointer), "--manifest", str(manifest), "--channel", "stable"
    )
    shaped = _run(
        "previous", "--pointer", str(broken), "--manifest", str(manifest), "--channel", "edge"
    )

    assert stable.exit_code == 3, stable.output
    assert "is the pointer of edge, not stable" in stable.output
    assert shaped.exit_code == 3, shaped.output
    assert "channel pointer: it holds another field than its five" in shaped.output


def test_the_first_pointer_of_a_channel_names_its_release(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    out = tmp_path / "out" / "edge.json"
    out.parent.mkdir()

    result = _run("pointer", str(manifest), "--previous", "none", "--out", str(out))

    assert result.exit_code == 0, result.output
    assert json.loads(out.read_bytes()) == {
        "schema_version": 1,
        "repository": REPOSITORY,
        "channel": "edge",
        "release": "2026.10.27.1",
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
    }
    assert out.read_bytes() == jcs(json.loads(out.read_bytes()))


def test_the_next_pointer_moves_the_channel_forward(tmp_path: Path) -> None:
    first = _manifest(tmp_path, "2026.10.27.1")
    previous = _pointer(tmp_path, first, "2026.10.27.1")
    second = _manifest(tmp_path, "2026.10.28.1", "second.json")
    out = tmp_path / "next.json"

    result = _run("pointer", str(second), "--previous", str(previous), "--out", str(out))

    assert result.exit_code == 0, result.output
    assert json.loads(out.read_bytes())["release"] == "2026.10.28.1"


def test_a_pointer_that_would_move_the_channel_back_is_never_written(tmp_path: Path) -> None:
    later = _manifest(tmp_path, "2026.10.28.1")
    previous = _pointer(tmp_path, later, "2026.10.28.1")
    earlier = _manifest(tmp_path, "2026.10.27.1", "earlier.json")
    out = tmp_path / "next.json"

    result = _run("pointer", str(earlier), "--previous", str(previous), "--out", str(out))

    assert result.exit_code == 3, result.output
    assert "edge would go back from 2026.10.28.1 to 2026.10.27.1" in result.output
    assert not out.exists()


def test_a_pointer_to_a_manifest_not_approved_is_never_written(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(
        jcs({"repository": REPOSITORY, "channel": "edge", "release": "2026.10.27.1"})
    )
    out = tmp_path / "edge.json"

    result = _run("pointer", str(manifest), "--previous", "none", "--out", str(out))

    assert result.exit_code == 3, result.output
    assert "a channel names an approved release only" in result.output
    assert not out.exists()


def test_the_pointer_goes_to_a_new_file(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    out = tmp_path / "edge.json"
    out.write_text("taken")

    result = _run("pointer", str(manifest), "--previous", "none", "--out", str(out))

    assert result.exit_code == 2, result.output
    assert out.read_text() == "taken"


def test_an_unreadable_pointer_is_an_input_refused(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    hostile = tmp_path / "edge.json"
    hostile.write_bytes(b'{"release": "2026.10.27.1", "release": "2099.01.01.1"}')
    large = tmp_path / "large.json"
    large.write_bytes(b'{"a": "' + b"x" * 5000 + b'"}')

    for pointer in (hostile, large):
        result = _run(
            "previous", "--pointer", str(pointer), "--manifest", str(manifest), "--channel", "edge"
        )
        assert result.exit_code == 1, result.output
        assert [f["code"][:3] for f in json.loads(result.output)["findings"]] == ["IO-"]


@pytest.mark.parametrize("change", [{"release": "2026.10.28.1"}, {"repository": "someone/else"}])
def test_a_manifest_of_another_release_or_repository_is_not_the_previous(
    tmp_path: Path, change: dict[str, str]
) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    named = _pointer(tmp_path, manifest, "2026.10.27.1")
    manifest.write_bytes(jcs({**json.loads(manifest.read_bytes()), **change}))
    pointer = tmp_path / "rehashed.json"
    pointer.write_bytes(
        jcs(
            {
                **json.loads(named.read_bytes()),
                "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            }
        )
    )

    result = _run(
        "previous", "--pointer", str(pointer), "--manifest", str(manifest), "--channel", "edge"
    )

    assert result.exit_code == 3, result.output
    assert "not the release the channel's pointer names" in result.output


def test_the_same_release_with_the_same_manifest_keeps_the_channel_where_it_is(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    previous = _pointer(tmp_path, manifest, "2026.10.27.1")
    out = tmp_path / "next.json"

    result = _run("pointer", str(manifest), "--previous", str(previous), "--out", str(out))

    assert result.exit_code == 0, result.output
    assert out.read_bytes() == previous.read_bytes()


@pytest.mark.parametrize(
    ("channel", "why"),
    [
        ("edge", "edge already names 2026.10.27.1 with another manifest"),
        ("stable", "a pointer of edge cannot follow one of stable"),
    ],
)
def test_a_pointer_that_does_not_follow_the_previous_is_never_written(
    tmp_path: Path, channel: str, why: str
) -> None:
    first = _manifest(tmp_path, "2026.10.27.1")
    previous = _pointer(tmp_path, first, "2026.10.27.1")
    previous.write_bytes(jcs({**json.loads(previous.read_bytes()), "channel": channel}))
    other = _manifest(tmp_path, "2026.10.27.1", "other.json", items=[])
    out = tmp_path / "next.json"

    result = _run("pointer", str(other), "--previous", str(previous), "--out", str(out))

    assert result.exit_code == 3, result.output
    assert why in result.output
    assert not out.exists()


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ([], "channel pointer: the manifest must be an object"),
        (
            {"repository": "someone/else", "channel": "edge", "release": "2026.10.27.1"},
            "channel pointer: the manifest is of another repository",
        ),
    ],
)
def test_a_document_that_is_no_manifest_of_this_repository_gets_no_pointer(
    tmp_path: Path, document: Any, why: str
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(jcs(document))
    out = tmp_path / "edge.json"

    result = _run("pointer", str(manifest), "--previous", "none", "--out", str(out))

    assert result.exit_code == 3, result.output
    assert why in result.output
    assert not out.exists()


def test_a_previous_pointer_out_of_shape_is_refused(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, "2026.10.27.1")
    broken = tmp_path / "previous.json"
    broken.write_bytes(b'{"schema_version": 1}')
    out = tmp_path / "next.json"

    result = _run("pointer", str(manifest), "--previous", str(broken), "--out", str(out))

    assert result.exit_code == 3, result.output
    assert "it holds another field than its five" in result.output
    assert not out.exists()
