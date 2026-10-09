"""The ``openaev export`` and ``openaev import`` commands against a stand-in platform."""

import io
import json
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner

from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, Report
from scenario_tools.interface.cli import execute, main
from scenario_tools.ports.errors import EnvironmentProblemError
from tests.platform_server import Platform, platform_server

TOKEN = "0b6c6f0e-token-secret"  # noqa: S105 - a test value, never a real token
SCENARIO = "0a64b5ab-2016-426b-813f-9051d32e88b3"


def _archive(*entries: tuple[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


EXPORT = _archive(("EASM Scenario.json", b'{"export_version": 1}'))


@pytest.fixture
def platform() -> Iterator[Platform]:
    with platform_server() as server:
        yield server


def _run(platform: Platform, *arguments: str) -> tuple[int, str, str]:
    result = CliRunner().invoke(
        main, list(arguments), env={"OPENAEV_URL": platform.url, "OPENAEV_TOKEN": TOKEN}
    )
    return result.exit_code, result.stdout, result.stderr


# Export


def test_export_writes_the_archive(platform: Platform, tmp_path: Path) -> None:
    platform.answer(200, EXPORT)
    out = tmp_path / "export.zip"

    code, stdout, _ = _run(platform, "openaev", "export", SCENARIO, "--out", str(out))

    assert (code, stdout.strip()) == (0, "openaev export: ok")
    assert out.read_bytes() == EXPORT
    assert out.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize(
    ("answer", "code"),
    [
        (b"not an archive", "IO-007"),
        (_archive(("a.json", b"{}"), ("b.json", b"{}")), "IO-014"),
        (_archive(("export.txt", b"{}")), "IO-014"),
        (_archive(("export.json", b"{")), "IO-002"),
        (_archive(("../export.json", b"{}")), "IO-010"),
    ],
    ids=["not a zip", "two json entries", "no json entry", "bad json", "unsafe name"],
)
def test_a_refused_export_is_never_written(
    platform: Platform, tmp_path: Path, answer: bytes, code: str
) -> None:
    platform.answer(200, answer)
    out = tmp_path / "export.zip"

    exit_code, stdout, _ = _run(
        platform, "--format", "json", "openaev", "export", SCENARIO, "--out", str(out)
    )

    assert exit_code == 1
    assert [finding["code"] for finding in json.loads(stdout)["findings"]] == [code]
    assert list(tmp_path.iterdir()) == []


def test_a_refused_export_leaves_the_previous_file_as_it_was(
    platform: Platform, tmp_path: Path
) -> None:
    out = tmp_path / "export.zip"
    out.write_bytes(EXPORT)
    platform.answer(200, b"not an archive")

    code, _, _ = _run(platform, "openaev", "export", SCENARIO, "--out", str(out))

    assert code == 1
    assert out.read_bytes() == EXPORT
    assert [path.name for path in tmp_path.iterdir()] == ["export.zip"]


def test_an_export_over_the_archive_limit_is_reported_on_the_output(
    platform: Platform, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "build").mkdir()
    platform.answer(200, b"x" * (20 * 1024 * 1024 + 1))

    code, stdout, _ = _run(
        platform, "--format", "json", "openaev", "export", SCENARIO, "--out", "build/x/../e.zip"
    )

    assert code == 1
    [finding] = json.loads(stdout)["findings"]
    assert (finding["code"], finding["path"]) == ("IO-001", "build/e.zip")
    assert list((tmp_path / "build").iterdir()) == []


def test_a_refused_export_is_reported_on_the_output_path(
    platform: Platform, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "build").mkdir()
    platform.answer(200, b"not an archive")

    _, stdout, _ = _run(
        platform, "--format", "json", "openaev", "export", SCENARIO, "--out", "build/e.zip"
    )

    assert json.loads(stdout)["findings"][0]["path"] == "build/e.zip"


@pytest.mark.parametrize("token", [TOKEN, "a'\"\\b-secret"], ids=["plain", "quotes"])
def test_a_refused_export_never_shows_what_the_platform_chose(
    platform: Platform, tmp_path: Path, token: str
) -> None:
    # The platform has seen the token and chooses what the archive holds: the refusal gives the
    # check that failed, never the content, whichever way the content would be written.
    platform.answer(200, _archive((f"../{token}.json", b"{}")))

    result = CliRunner().invoke(
        main,
        ["--format", "json", "openaev", "export", SCENARIO, "--out", str(tmp_path / "e")],
        env={"OPENAEV_URL": platform.url, "OPENAEV_TOKEN": token},
    )

    assert result.exit_code == 1
    [finding] = json.loads(result.stdout)["findings"]
    assert (finding["code"], finding["message"]) == (
        "IO-010",
        "the archive the platform exported fails this check",
    )
    assert "secret" not in result.stdout


@pytest.mark.parametrize("scenario", ["../../api/users", SCENARIO.upper(), "x"])
def test_export_needs_a_scenario_uuid(platform: Platform, tmp_path: Path, scenario: str) -> None:
    code, stdout, stderr = _run(
        platform, "openaev", "export", scenario, "--out", str(tmp_path / "e.zip")
    )

    assert code == 2
    assert stdout == ""
    assert "a UUID in lower case with hyphens" in stderr
    assert platform.received == []


def test_export_needs_the_platform_in_the_environment(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main,
        ["--format", "json", "openaev", "export", SCENARIO, "--out", str(tmp_path / "e.zip")],
        env={"OPENAEV_URL": None, "OPENAEV_TOKEN": None},
    )

    assert result.exit_code == 3
    assert json.loads(result.stdout) == {
        "command": "openaev export",
        "ok": False,
        "findings": [],
        "error": "OPENAEV_URL is not set",
    }


def test_an_unusable_platform_url_exits_with_an_environment_problem(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main,
        ["openaev", "export", SCENARIO, "--out", str(tmp_path / "e.zip")],
        env={"OPENAEV_URL": "http://platform.example.org", "OPENAEV_TOKEN": TOKEN},
    )

    assert result.exit_code == 3
    assert "https, or http to the local machine only" in result.stdout


def test_a_long_environment_error_is_shortened() -> None:
    def produce() -> Report:
        raise EnvironmentProblemError("the platform cannot be reached: " + "x" * 1000)

    for output_format in ("text", "json"):
        output, code = execute("openaev export", produce, output_format)
        assert code == 3
        message = json.loads(output)["error"] if output_format == "json" else output
        assert len(message) <= MESSAGE_LIMIT
        assert message.endswith("…") or message.endswith("\\u2026")


def test_a_platform_error_exits_with_an_environment_problem(
    platform: Platform, tmp_path: Path
) -> None:
    platform.answer(401)

    code, stdout, _ = _run(platform, "openaev", "export", SCENARIO, "--out", str(tmp_path / "e"))

    assert code == 3
    assert stdout.strip() == (
        "openaev export: environment error: the platform refused the token (HTTP 401)"
    )
    assert TOKEN not in stdout


# Import


def test_a_complete_import_is_ok(platform: Platform, tmp_path: Path) -> None:
    archive = tmp_path / "scenario.zip"
    archive.write_bytes(EXPORT)
    platform.answer(200, b'{"missingActions": []}')

    code, stdout, _ = _run(platform, "openaev", "import", str(archive))

    assert (code, stdout.strip()) == (0, "openaev import: ok")
    assert EXPORT in platform.received[0].body


def test_import_findings_are_relative_to_the_working_directory(
    platform: Platform, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "scenario.zip").write_bytes(EXPORT)
    platform.answer(200, b'{"missingActions": [{"type": "Injector", "name": "Scan"}]}')

    code, stdout, _ = _run(platform, "openaev", "import", "build/x/../scenario.zip")

    assert code == 1
    assert stdout.splitlines() == [
        "BLOCKING OAV-001 build/scenario.zip: the platform skipped inject 'Scan': its Injector "
        "is missing on the instance",
        "openaev import: 1 blocking finding",
    ]


def test_a_missing_archive_is_an_environment_problem(platform: Platform, tmp_path: Path) -> None:
    code, stdout, _ = _run(platform, "openaev", "import", str(tmp_path / "missing.zip"))

    assert code == 3
    assert "cannot read" in stdout
    assert platform.received == []


def test_skipped_injects_fail_the_import(platform: Platform, tmp_path: Path) -> None:
    archive = tmp_path / "scenario.zip"
    archive.write_bytes(EXPORT)
    platform.answer(200, b'{"missingActions": [{"type": "Injector", "name": "Scan"}]}')

    code, stdout, _ = _run(platform, "--format", "json", "openaev", "import", str(archive))

    assert code == 1
    assert json.loads(stdout)["findings"] == [
        {
            "code": "OAV-001",
            "severity": "blocking",
            "path": "scenario.zip",
            "field": "",
            "message": (
                "the platform skipped inject 'Scan': its Injector is missing on the instance"
            ),
        }
    ]


def test_a_refused_archive_is_never_sent(platform: Platform, tmp_path: Path) -> None:
    archive = tmp_path / "scenario.zip"
    archive.write_bytes(_archive(("a.json", b"{}"), ("b.json", b"{}")))

    code, stdout, _ = _run(platform, "--format", "json", "openaev", "import", str(archive))

    assert code == 1
    assert [finding["code"] for finding in json.loads(stdout)["findings"]] == ["IO-014"]
    assert platform.received == []


def test_import_needs_the_platform_in_the_environment(tmp_path: Path) -> None:
    archive = tmp_path / "scenario.zip"
    archive.write_bytes(EXPORT)

    result = CliRunner().invoke(
        main, ["openaev", "import", str(archive)], env={"OPENAEV_URL": None, "OPENAEV_TOKEN": None}
    )

    assert result.exit_code == 3
    assert "OPENAEV_URL is not set" in result.stdout
