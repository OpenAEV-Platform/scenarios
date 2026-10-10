"""The ``openaev export`` and ``openaev import`` commands against a stand-in platform."""

import io
import json
import time
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner

from scenario_tools.adapters.openaev_http import TOKEN_LENGTH
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, Finding, Report, Severity
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


@pytest.mark.parametrize("token", [TOKEN, "Ab+c~d.secret-value=="], ids=["plain", "symbols"])
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


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize(
    ("token", "name"),
    [
        (TOKEN, f"x {TOKEN} x"),
        ("nb-secret-value-1", "a\nb-secret-value-1"),
        ("u00e9-secret-value", "\u00e9-secret-value"),
        (TOKEN, "y" * 262 + TOKEN),
    ],
    ids=["as it is", "made by the message", "made by the JSON output", "cut short"],
)
def test_the_output_never_shows_the_token(
    platform: Platform, tmp_path: Path, output_format: str, token: str, name: str
) -> None:
    # The platform has seen the token and names the skipped injects: whatever it sends, and
    # however the output writes it, the token never shows.
    archive = tmp_path / "scenario.zip"
    archive.write_bytes(EXPORT)
    platform.answer(200, json.dumps({"missingActions": [{"type": "x", "name": name}]}).encode())

    result = CliRunner().invoke(
        main,
        ["--format", output_format, "openaev", "import", str(archive)],
        env={"OPENAEV_URL": platform.url, "OPENAEV_TOKEN": token},
    )

    assert result.exit_code == 1
    assert token[:4] not in result.stdout  # not even the start of it, where a message is cut
    if output_format == "json":
        [finding] = json.loads(result.stdout)["findings"]
        assert finding["message"] == "withheld: it would show a secret"
        assert finding["path"] == "scenario.zip"  # only what would show the token is withheld


@pytest.mark.parametrize("token", [TOKEN, "Ab+c~d.secret-value=="], ids=["plain", "symbols"])
def test_a_path_that_would_show_the_token_is_withheld(
    platform: Platform, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / f"{token}.zip").write_bytes(EXPORT)
    platform.answer(200, b'{"missingActions": [{"type": "Injector", "name": "Scan"}]}')

    result = CliRunner().invoke(
        main,
        ["--format", "json", "openaev", "import", f"{token}.zip"],
        env={"OPENAEV_URL": platform.url, "OPENAEV_TOKEN": token},
    )
    code, stdout = result.exit_code, result.stdout

    assert code == 1
    assert token not in stdout
    [finding] = json.loads(stdout)["findings"]
    assert (finding["code"], finding["path"]) == ("OAV-001", "")


def test_an_export_output_never_shows_the_token(
    platform: Platform, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    platform.answer(200, b"not an archive")

    code, stdout, _ = _run(platform, "openaev", "export", SCENARIO, "--out", f"{TOKEN}.zip")

    assert code == 1
    assert TOKEN not in stdout
    assert "withheld: it would show a secret" in stdout


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize(
    ("token", "name"),
    [
        (TOKEN, TOKEN),
        ("nb-secret-value-1", "a\nb-secret-value-1"),
        (TOKEN, "cut short"),
    ],
    ids=["plain", "made by escaping", "cut short"],
)
def test_an_environment_error_never_shows_the_token(
    platform: Platform, tmp_path: Path, output_format: str, token: str, name: str
) -> None:
    if name == "cut short":  # the token starts just before the 300th character of the output
        start = len(f"openaev import: environment error: cannot read {tmp_path}/")
        name = "d" * (290 - start) + token
    missing = tmp_path / f"{name}.zip"

    result = CliRunner().invoke(
        main,
        ["--format", output_format, "openaev", "import", str(missing)],
        env={"OPENAEV_URL": platform.url, "OPENAEV_TOKEN": token},
    )

    assert result.exit_code == 3
    assert token[:4] not in result.stdout  # not even the start of it, where a message is cut
    if output_format == "json":
        assert json.loads(result.stdout)["error"] == "withheld: it would show a secret"
    else:
        assert result.stdout.strip() == (
            "openaev import: environment error: withheld: it would show a secret"
        )


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize("part", ["path", "field"])
def test_a_path_or_field_cut_in_the_token_never_shows_its_start(
    output_format: str, part: str
) -> None:
    # Cut to the limit, a path or a field can end with the start of the token.
    long = {"path": "d" * 290 + TOKEN, "field": "/" + "k" * 289 + TOKEN}[part]
    finding = Finding("OAV-001", Severity.BLOCKING, "", "", "skipped")
    finding = Finding(**{**finding.__dict__, part: long})

    output, code = execute(
        "openaev import", lambda: Report("openaev import", (finding,)), output_format, hidden=TOKEN
    )

    assert code == 1
    assert TOKEN[:4] not in output


def test_a_long_report_is_withheld_without_losing_its_count() -> None:
    findings = tuple(
        Finding("OAV-001", Severity.BLOCKING, "", f"/{n:03}", f"skipped near {TOKEN}")
        for n in range(250)
    )

    output, code = execute(
        "openaev import", lambda: Report("openaev import", findings), "json", hidden=TOKEN
    )

    shown = json.loads(output)["findings"]
    assert code == 1
    assert TOKEN not in output
    assert len(shown) == 101
    assert [f["code"] for f in shown].count("IO-016") == 1
    assert shown[-1]["message"] == "150 more findings not shown"


def test_an_internal_error_never_shows_the_token() -> None:
    def produce() -> Report:
        raise RuntimeError(f"failed near {TOKEN}")

    output, code = execute("openaev import", produce, "text", hidden=TOKEN)

    assert code == 4
    assert TOKEN not in output
    assert output == "openaev import: internal error: withheld: it would show a secret"


@pytest.mark.parametrize("command", ["export", "import"])
def test_a_directory_given_as_a_file_never_shows_the_token(
    platform: Platform, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    # Checked by the guarded command, not by the argument parser, whose usage error would
    # repeat the path.
    monkeypatch.chdir(tmp_path)
    (tmp_path / TOKEN).mkdir()
    platform.answer(200, EXPORT)
    arguments = [SCENARIO, "--out", TOKEN] if command == "export" else [TOKEN]

    code, stdout, stderr = _run(platform, "openaev", command, *arguments)

    assert code == 1
    assert TOKEN not in stdout + stderr
    assert "IO-013" in stdout


def test_what_is_left_once_withheld_could_never_hold_a_token() -> None:
    # A token has at least TOKEN_LENGTH characters and no whitespace: the tools' own text, all
    # that is left once everything that would show it is withheld, has no such run.
    def finding() -> Report:
        return Report("openaev import", (Finding("OAV-001", Severity.BLOCKING, TOKEN, "", TOKEN),))

    def environment() -> Report:
        raise EnvironmentProblemError(TOKEN)

    def internal() -> Report:
        raise RuntimeError(TOKEN)

    for produce in (finding, environment, internal):
        for output_format in ("text", "json"):
            output, _ = execute("openaev import", produce, output_format, hidden=TOKEN)
            assert TOKEN not in output
            assert max(len(run) for run in output.split()) < TOKEN_LENGTH


def _finding(message: str) -> Callable[[], Report]:
    return lambda: Report(
        "openaev import", (Finding("OAV-001", Severity.BLOCKING, "", "", message),)
    )


def test_a_message_cut_after_one_character_of_the_token_is_withheld() -> None:
    output, _ = execute("openaev import", _finding("a" * 298 + TOKEN), "text", hidden=TOKEN)

    assert output.splitlines()[0] == "BLOCKING OAV-001: withheld: it would show a secret"


def test_a_long_token_keeps_the_guard_quick() -> None:
    token = "t" * 1_000_000  # no maximum length: the guard must not grow with it

    start = time.monotonic()
    output, _ = execute("openaev import", _finding("a" * 400), "text", hidden=token)

    assert time.monotonic() - start < 0.5
    assert output.splitlines()[0].startswith("BLOCKING OAV-001: aaa")


def test_a_message_made_only_of_the_start_of_a_long_token_is_withheld() -> None:
    token = "a" + "t" * 399  # longer than a message: only its start can show

    output, _ = execute("openaev import", _finding(token), "text", hidden=token)

    assert output.splitlines()[0] == "BLOCKING OAV-001: withheld: it would show a secret"


def test_a_message_ending_like_the_token_starts_but_not_cut_is_left_as_it_is() -> None:
    message = f"value {TOKEN[0]}."  # as if cut, but without the ellipsis

    output, _ = execute("openaev import", _finding(message), "text", hidden=TOKEN)

    assert output.splitlines()[0] == f"BLOCKING OAV-001: {message}"


def test_an_environment_error_cut_in_the_token_is_withheld_in_json() -> None:
    def produce() -> Report:
        raise EnvironmentProblemError("a" * 290 + TOKEN)

    output, code = execute("openaev import", produce, "json", hidden=TOKEN)

    assert code == 3
    assert json.loads(output)["error"] == "withheld: it would show a secret"


@pytest.mark.parametrize("command", ["export", "import"])
@pytest.mark.parametrize(
    ("token", "reason"),
    [
        ("e", "at least 16 characters"),
        ("OPENAEV", "at least 16 characters"),
        ("a b c d e f g h i", "letters, digits and -._~+/ only, then = signs"),
        ("OPENAEV_TOKEN is not", "letters, digits and -._~+/ only, then = signs"),
    ],
)
def test_a_token_that_is_not_one_is_reported_as_such(
    tmp_path: Path, command: str, token: str, reason: str
) -> None:
    # The guard protects a token the platform could have seen: an invalid one is never sent,
    # and hiding it would hide what is wrong with it.
    archive = tmp_path / "scenario.zip"
    archive.write_bytes(EXPORT)
    arguments = (
        [SCENARIO, "--out", str(tmp_path / "e.zip")] if command == "export" else [str(archive)]
    )

    result = CliRunner().invoke(
        main,
        ["openaev", command, *arguments],
        env={"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": token},
    )

    assert result.exit_code == 3
    assert result.stdout.strip() == (
        f"openaev {command}: environment error: OPENAEV_TOKEN is not a token: {reason}"
    )


@pytest.mark.parametrize(("status", "told"), [(500, True), (401, False)])
def test_a_failed_import_tells_whether_the_scenario_may_exist(
    platform: Platform, tmp_path: Path, status: int, told: bool
) -> None:
    archive = tmp_path / "scenario.zip"
    archive.write_bytes(EXPORT)
    platform.answer(status)

    code, stdout, _ = _run(platform, "--format", "json", "openaev", "import", str(archive))

    assert code == 3
    error = json.loads(stdout)["error"]
    assert ("the scenario may have been created all the same" in error) is told


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize(
    ("token", "end"),
    [
        ("u00e9-secret-value", "\u00e9-secret-value"),
        ("x1bsec-secret-value", "\x1bsec-secret-value"),
    ],
    ids=["JSON escape", "text escape"],
)
@pytest.mark.parametrize("where", ["finding", "error"])
def test_the_start_of_the_token_never_shows_where_escaping_writes_it(
    output_format: str, token: str, end: str, where: str
) -> None:
    # Cut short just after the escaped character: the escape writes the start of the token.
    message = "a" * 294 + end

    def produce() -> Report:
        if where == "error":
            raise EnvironmentProblemError(message)
        return _finding(message)()

    output, _ = execute("openaev import", produce, output_format, hidden=token)

    assert token[:7] not in output


def test_an_output_without_the_token_is_left_as_it_is(platform: Platform, tmp_path: Path) -> None:
    archive = tmp_path / "scenario.zip"
    archive.write_bytes(EXPORT)
    platform.answer(200, b'{"missingActions": [{"type": "Injector", "name": "Scan"}]}')

    _, stdout, _ = _run(platform, "openaev", "import", str(archive))

    assert "the platform skipped inject 'Scan'" in stdout


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
