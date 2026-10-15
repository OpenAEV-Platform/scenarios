"""The ``verify`` command: a release checked as its consumers will, before it is published."""

import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.interface.cli import main
from tests.interface.test_cli_build import ARCHIVE, ROOT, _approvals, _build, _repository


def _release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A release built by build, as the release workflow builds it."""
    root = _repository(tmp_path, monkeypatch)
    out = tmp_path / "release"
    assert _build(root, _approvals(tmp_path), out).exit_code == 0
    return out


def _verify(manifest: Path, *options: str) -> Any:
    arguments = ["--format", "json", "verify", str(manifest), "--schemas", str(ROOT / "schemas")]
    return CliRunner().invoke(main, [*arguments, *options])


def _findings(result: Any) -> list[tuple[str, str]]:
    return [(f["code"], f["path"]) for f in json.loads(result.output)["findings"]]


def _manifest(release: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((release / "manifest.json").read_bytes())
    return document


def _rewrite(release: Path, document: dict[str, Any]) -> None:
    (release / "manifest.json").write_bytes(jcs(document))


def test_a_release_built_by_build_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)

    result = _verify(release / "manifest.json")

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["ok"] is True


def test_the_archives_may_be_elsewhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release = _release(tmp_path, monkeypatch)
    (tmp_path / "archives").mkdir()
    (release / ARCHIVE).rename(tmp_path / "archives" / ARCHIVE)

    result = _verify(release / "manifest.json", "--archives", str(tmp_path / "archives"))

    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("change", ["missing", "altered"])
def test_an_archive_missing_or_altered_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    release = _release(tmp_path, monkeypatch)
    if change == "missing":
        (release / ARCHIVE).unlink()
    else:
        data = bytearray((release / ARCHIVE).read_bytes())
        data[-1] ^= 1
        (release / ARCHIVE).write_bytes(bytes(data))

    result = _verify(release / "manifest.json")

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("VRF-006", ARCHIVE)]


def test_an_archive_unsafe_to_extract_is_refused_even_listed_with_its_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../escape.json", "{}")
    evil = buffer.getvalue()
    (release / ARCHIVE).write_bytes(evil)
    document = _manifest(release)
    document["items"][0]["archive"].update(sha256=hashlib.sha256(evil).hexdigest(), size=len(evil))
    _rewrite(release, document)

    result = _verify(release / "manifest.json")

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("VRF-007", ARCHIVE)]


def test_a_payload_listed_but_not_embedded_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    document = _manifest(release)
    document["items"][0]["payloads"] = [{"id": "ghost", "version": "1.0.0", "sha256": "0" * 64}]
    _rewrite(release, document)

    result = _verify(release / "manifest.json")

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("VRF-008", ARCHIVE)]


def test_a_manifest_out_of_its_schema_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    document = _manifest(release)
    document["channel"] = "beta"
    _rewrite(release, document)

    result = _verify(release / "manifest.json")

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("VRF-009", "manifest.json")]


def test_an_approved_release_names_its_approver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)

    refused = _verify(release / "manifest.json", "--approved")
    _rewrite(release, dict(_manifest(release), release_approver="alice"))
    accepted = _verify(release / "manifest.json", "--approved")

    assert refused.exit_code == 1, refused.output
    assert _findings(refused) == [("VRF-009", "manifest.json")]
    assert accepted.exit_code == 0, accepted.output


def test_a_release_with_a_payload_built_into_its_archive_is_verified_by_its_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What build lists is what verify recomputes, payload by payload."""
    from scenario_tools.adapters.zip_archive import ZipArchiveBuilder
    from tests.domain.verification.test_release_output import PAYLOAD, PAYLOAD_ID, VECTOR, _stored

    release = _release(tmp_path, monkeypatch)

    def with_payload(payload: dict[str, Any]) -> None:
        data = ZipArchiveBuilder().build(json.dumps(_stored(payload)).encode(), None)
        (release / ARCHIVE).write_bytes(data)
        document = _manifest(release)
        item = document["items"][0]
        item["archive"].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        item["payloads"] = [{"id": PAYLOAD_ID, "version": "1.0.0", "sha256": VECTOR["sha256"]}]
        _rewrite(release, document)

    with_payload(PAYLOAD)
    accepted = _verify(release / "manifest.json")
    with_payload(dict(PAYLOAD, command_content="Write-Output changed"))
    refused = _verify(release / "manifest.json")

    assert accepted.exit_code == 0, accepted.output
    assert refused.exit_code == 1, refused.output
    assert _findings(refused) == [("VRF-008", ARCHIVE)]


def test_a_file_beside_the_archives_that_the_manifest_does_not_list_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    (release / "extra.zip").write_bytes(b"x")

    result = _verify(release / "manifest.json")

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("VRF-006", "extra.zip")]


@pytest.mark.parametrize("schemas", ["missing", "empty"])
def test_schemas_that_cannot_be_used_are_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, schemas: str
) -> None:
    release = _release(tmp_path, monkeypatch)
    place = tmp_path / "schemas"
    if schemas == "empty":
        place.mkdir()

    result = CliRunner().invoke(
        main,
        ["--format", "json", "verify", str(release / "manifest.json"), "--schemas", str(place)],
    )

    assert result.exit_code == 3, result.output
    assert "holds no manifest.schema.json" in result.output


@pytest.mark.parametrize("beside", ["hidden", "directory", "link"])
def test_anything_beside_the_archives_that_the_manifest_does_not_list_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, beside: str
) -> None:
    release = _release(tmp_path, monkeypatch)
    name = {"hidden": ".notes", "directory": "more", "link": "elsewhere.zip"}[beside]
    if beside == "hidden":
        (release / name).write_text("x")
    elif beside == "directory":
        (release / name).mkdir()
    else:
        (release / name).symlink_to(tmp_path / "missing")

    result = _verify(release / "manifest.json")

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("VRF-006", name)]


def test_a_listed_archive_that_is_a_directory_is_unsafe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    (release / ARCHIVE).unlink()
    (release / ARCHIVE).mkdir()

    result = _verify(release / "manifest.json")

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("VRF-007", ARCHIVE)]


def test_a_manifest_of_another_name_is_not_taken_for_a_file_to_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)
    (release / "manifest.json").rename(release / "edge.json")

    result = _verify(release / "edge.json")

    assert result.exit_code == 0, result.output


def test_an_archives_directory_that_is_missing_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = _release(tmp_path, monkeypatch)

    result = _verify(release / "manifest.json", "--archives", str(tmp_path / "missing"))

    assert result.exit_code == 3, result.output
    assert "cannot read the release" in result.output
