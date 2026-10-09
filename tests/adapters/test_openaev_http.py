"""The OpenAEV client over HTTP: credentials from the environment, fixed export options, local
or encrypted transport, no redirect, bounded answers, and errors that never carry the token."""

import json
import socket
import ssl
import time
from collections.abc import Iterator

import pytest

from scenario_tools.adapters.openaev_http import (
    EXPORT_OPTIONS,
    HttpOpenAEV,
    _HTTPSHandler,
    _Watchdog,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError
from scenario_tools.ports.openaev import ImportResult, SkippedInject
from tests.platform_server import Platform, platform_server

TOKEN = "0b6c6f0e-token-secret"  # noqa: S105 - a test value, never a real token
SCENARIO = "0a64b5ab-2016-426b-813f-9051d32e88b3"


@pytest.fixture
def platform() -> Iterator[Platform]:
    with platform_server() as server:
        yield server


def _client(
    platform: Platform, *, timeout: float = 5.0, archive_limit: int = 20 * 1024 * 1024
) -> HttpOpenAEV:
    return HttpOpenAEV.from_environment(
        {"OPENAEV_URL": platform.url, "OPENAEV_TOKEN": TOKEN},
        timeout=timeout,
        archive_limit=archive_limit,
    )


# Credentials and transport


@pytest.mark.parametrize(
    "url",
    [
        "https://platform.example.org",
        "https://platform.example.org:8443/openaev/",
        "https://xn--bcher-kva.example",
        "https://a-b.example",
        "https://192.0.2.10",
        "https://[2001:db8::1]:8443",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
    ],
)
def test_an_encrypted_or_local_url_is_accepted(url: str) -> None:
    HttpOpenAEV.from_environment({"OPENAEV_URL": url, "OPENAEV_TOKEN": TOKEN})


@pytest.mark.parametrize(
    ("environment", "reason"),
    [
        ({"OPENAEV_TOKEN": TOKEN}, "OPENAEV_URL is not set"),
        ({"OPENAEV_URL": "", "OPENAEV_TOKEN": TOKEN}, "OPENAEV_URL is not set"),
        ({"OPENAEV_URL": "https://platform.example.org"}, "OPENAEV_TOKEN is not set"),
        (
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": ""},
            "OPENAEV_TOKEN is not set",
        ),
        (
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": "a b"},
            "OPENAEV_TOKEN is not a token",
        ),
        (
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": "a\r\nX-Other: 1"},
            "OPENAEV_TOKEN is not a token",
        ),
        (
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": "jeton-é"},
            "OPENAEV_TOKEN is not a token",
        ),
        ({"OPENAEV_URL": "http://platform.example.org", "OPENAEV_TOKEN": TOKEN}, "https"),
        ({"OPENAEV_URL": "http://10.0.0.1:8080", "OPENAEV_TOKEN": TOKEN}, "https"),
        ({"OPENAEV_URL": "ftp://platform.example.org", "OPENAEV_TOKEN": TOKEN}, "https"),
        ({"OPENAEV_URL": "ftp://localhost", "OPENAEV_TOKEN": TOKEN}, "https"),
        ({"OPENAEV_URL": "platform.example.org", "OPENAEV_TOKEN": TOKEN}, "https"),
        ({"OPENAEV_URL": "https://", "OPENAEV_TOKEN": TOKEN}, "no host"),
        (
            {"OPENAEV_URL": "https://user:pass@platform.example.org", "OPENAEV_TOKEN": TOKEN},
            "user information",
        ),
        (
            {"OPENAEV_URL": "https://user@platform.example.org", "OPENAEV_TOKEN": TOKEN},
            "user information",
        ),
        (
            {"OPENAEV_URL": "https://platform.example.org/?tenant=1", "OPENAEV_TOKEN": TOKEN},
            "query or fragment",
        ),
        (
            {"OPENAEV_URL": "https://platform.example.org/#top", "OPENAEV_TOKEN": TOKEN},
            "query or fragment",
        ),
        (
            {"OPENAEV_URL": "https://platform.example.org:99999", "OPENAEV_TOKEN": TOKEN},
            "not a URL",
        ),
        ({"OPENAEV_URL": "http://local\thost:8080", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "http://localhost\n:8080", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://platform.example.org/a b", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://" + "a" * 70 + ".com", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://a..b", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://-bad.example", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://bad-.example", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://a_b.example", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://%65xample.com", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://example.com.", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
        ({"OPENAEV_URL": "https://" + "a." * 127 + "com", "OPENAEV_TOKEN": TOKEN}, "not a URL"),
    ],
)
def test_an_unusable_environment_is_an_environment_problem(
    environment: dict[str, str], reason: str
) -> None:
    with pytest.raises(EnvironmentProblemError, match=reason) as error:
        HttpOpenAEV.from_environment(environment)
    assert TOKEN not in str(error.value)
    assert "pass" not in str(error.value)


# Export


def test_export_asks_for_the_scenario_with_the_fixed_options_and_the_token(
    platform: Platform,
) -> None:
    platform.answer(200, b"PK archive", {"Content-Type": "application/zip"})

    assert _client(platform).export_scenario(SCENARIO) == b"PK archive"

    [request] = platform.received
    assert request.method == "GET"
    assert request.path == (
        f"/api/scenarios/{SCENARIO}/export?isWithTeams=true&isWithPlayers=false"
        "&isWithVariableValues=false&isWithScopeDefinition=true"
    )
    assert request.headers["authorization"] == f"Bearer {TOKEN}"


def test_the_export_options_keep_teams_and_scope_and_leave_out_players_and_values() -> None:
    assert dict(EXPORT_OPTIONS) == {
        "isWithTeams": "true",
        "isWithPlayers": "false",
        "isWithVariableValues": "false",
        "isWithScopeDefinition": "true",
    }


def test_the_path_of_the_platform_url_is_kept(platform: Platform) -> None:
    client = HttpOpenAEV.from_environment(
        {"OPENAEV_URL": f"{platform.url}/openaev/", "OPENAEV_TOKEN": TOKEN}
    )

    client.export_scenario(SCENARIO)

    assert platform.received[0].path.startswith(f"/openaev/api/scenarios/{SCENARIO}/export?")


def test_the_scenario_identifier_is_encoded_in_the_path(platform: Platform) -> None:
    _client(platform).export_scenario("a/../b")

    assert platform.received[0].path.startswith("/api/scenarios/a%2F..%2Fb/export?")


def test_an_export_larger_than_the_archive_limit_is_refused(platform: Platform) -> None:
    platform.answer(200, b"x" * 101)

    with pytest.raises(UnsafeInputError) as error:
        _client(platform, archive_limit=100).export_scenario(SCENARIO)
    assert (error.value.code, error.value.message) == ("IO-001", "larger than 100 bytes")


def test_an_export_at_the_archive_limit_is_returned(platform: Platform) -> None:
    platform.answer(200, b"x" * 100)

    assert _client(platform, archive_limit=100).export_scenario(SCENARIO) == b"x" * 100


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (401, "the platform refused the token \\(HTTP 401\\)"),
        (403, "the platform refused the token \\(HTTP 403\\)"),
        (404, f"scenario {SCENARIO} not found on the platform \\(HTTP 404\\)"),
        (500, "the platform answered HTTP 500"),
        (204, "the platform answered HTTP 204"),
    ],
)
def test_an_error_of_the_platform_is_an_environment_problem(
    platform: Platform, status: int, reason: str
) -> None:
    platform.answer(status, b'{"token": "echo"}' if status != 204 else b"")

    with pytest.raises(EnvironmentProblemError, match=f"^{reason}$") as error:
        _client(platform).export_scenario(SCENARIO)
    assert TOKEN not in str(error.value)


def test_a_redirect_is_never_followed(platform: Platform) -> None:
    with platform_server() as elsewhere:
        platform.answer(302, b"", {"Location": f"{elsewhere.url}/steal"})

        with pytest.raises(
            EnvironmentProblemError, match=r"^the platform answered a redirect \(HTTP 302\)"
        ):
            _client(platform).export_scenario(SCENARIO)
        assert elsewhere.received == []


def test_an_unreachable_platform_is_an_environment_problem() -> None:
    with socket.socket() as bound:  # bound but not listening: the connection is refused
        bound.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{bound.getsockname()[1]}"
        client = HttpOpenAEV.from_environment({"OPENAEV_URL": url, "OPENAEV_TOKEN": TOKEN})

        with pytest.raises(
            EnvironmentProblemError,
            match=r"^the platform cannot be reached \(ConnectionRefusedError\)$",
        ) as error:
            client.export_scenario(SCENARIO)
    assert "127.0.0.1" not in str(error.value)


def test_a_platform_that_does_not_answer_in_time_is_an_environment_problem(
    platform: Platform,
) -> None:
    platform.delay = 0.5

    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.1 seconds$"
    ):
        _client(platform, timeout=0.1).export_scenario(SCENARIO)


def test_a_platform_that_answers_byte_by_byte_is_cut_at_the_deadline(platform: Platform) -> None:
    platform.answer(200, b"x" * 100)
    platform.drip = 0.02  # two seconds for the whole body, each byte well within the timeout

    start = time.monotonic()
    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.3 seconds$"
    ):
        _client(platform, timeout=0.3).export_scenario(SCENARIO)
    assert time.monotonic() - start < 1.0


def test_a_read_that_stalls_near_the_deadline_is_cut_at_the_deadline(platform: Platform) -> None:
    # Each byte comes within the timeout of one network operation, but the third would come
    # after the total deadline: the read waiting for it must stop at the deadline.
    platform.answer(200, b"xyz")
    platform.drip = 0.35

    start = time.monotonic()
    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.5 seconds$"
    ):
        _client(platform, timeout=0.5).export_scenario(SCENARIO)
    assert time.monotonic() - start < 0.65


def test_an_answer_whose_headers_crawl_is_cut_at_the_deadline(platform: Platform) -> None:
    platform.raw = b"HTTP/1.1 200 OK\r\nX-Padding: " + b"a" * 200 + b"\r\n\r\n"
    platform.drip = 0.02  # four seconds of headers, each byte well within the timeout

    start = time.monotonic()
    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.3 seconds$"
    ):
        _client(platform, timeout=0.3).export_scenario(SCENARIO)
    assert time.monotonic() - start < 0.6


def test_a_connection_opened_after_the_deadline_is_cut_at_once(platform: Platform) -> None:
    host, port = platform.url.removeprefix("http://").split(":")
    with _Watchdog(0.01) as watchdog:
        while not watchdog.expired:
            time.sleep(0.005)

        with watchdog.create_connection((host, int(port)), 5) as connection:
            assert connection.recv(1) == b""  # shut down: nothing more can come


def test_an_encrypted_call_whose_tunnel_crawls_is_cut_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with platform_server() as proxy:
        proxy.raw = b"HTTP/1.1 200 Connection established\r\nX-Padding: " + b"a" * 200
        proxy.drip = 0.02  # four seconds for the proxy's answer, each byte within the timeout
        for name in ("HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(name, proxy.url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        client = HttpOpenAEV.from_environment(
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": TOKEN},
            timeout=0.3,
        )

        start = time.monotonic()
        with pytest.raises(
            EnvironmentProblemError, match=r"^the platform did not answer within 0.3 seconds$"
        ):
            client.export_scenario(SCENARIO)
        assert time.monotonic() - start < 0.6


def test_an_encrypted_call_verifies_the_certificate_and_the_host_name() -> None:
    tls = _HTTPSHandler(_Watchdog(1))._tls

    assert tls.verify_mode is ssl.CERT_REQUIRED
    assert tls.check_hostname


def test_a_transport_failure_is_named_by_its_kind_only(platform: Platform) -> None:
    platform.raw = f"Bearer {TOKEN} from platform.example.org\r\n\r\n".encode()

    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform cannot be reached \(BadStatusLine\)$"
    ):
        _client(platform).export_scenario(SCENARIO)


def test_a_local_call_never_goes_through_a_proxy(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    with platform_server() as proxy:
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(name, proxy.url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)

        _client(platform).export_scenario(SCENARIO)

        assert proxy.received == []
    assert len(platform.received) == 1


def test_an_encrypted_call_may_go_through_the_proxy_tunnel_without_the_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with platform_server() as proxy:
        proxy.answer(502)
        for name in ("HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(name, proxy.url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        client = HttpOpenAEV.from_environment(
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": TOKEN}
        )

        with pytest.raises(EnvironmentProblemError, match=r"^the platform cannot be reached"):
            client.export_scenario(SCENARIO)

        [request] = proxy.received
    assert (request.method, request.path) == ("CONNECT", "platform.example.org:443")
    assert "authorization" not in request.headers


# Import

ARCHIVE = b"PK\x03\x04 archive bytes \r\n--not-a-boundary"


def _multipart(request_body: bytes, content_type: str) -> tuple[str, bytes]:
    """The headers and the content of the single part of a multipart body."""
    boundary = content_type.split("boundary=", 1)[1].encode()
    parts = request_body.split(b"--" + boundary)
    assert parts[0] == b""
    assert parts[-1] == b"--\r\n"
    [part] = parts[1:-1]
    headers, content = part.split(b"\r\n\r\n", 1)
    assert content.endswith(b"\r\n")
    return headers.decode(), content[:-2]


def test_import_sends_the_archive_as_the_file_field(platform: Platform) -> None:
    platform.answer(200, b'{"missingActions": []}')

    assert _client(platform).import_scenario(ARCHIVE) == ImportResult(())

    [request] = platform.received
    assert (request.method, request.path) == ("POST", "/api/scenarios/import")
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    assert request.headers["content-type"].startswith("multipart/form-data; boundary=")
    headers, content = _multipart(request.body, request.headers["content-type"])
    assert content == ARCHIVE
    assert 'Content-Disposition: form-data; name="file"; filename="scenario.zip"' in headers
    assert "Content-Type: application/zip" in headers


def test_the_boundary_never_occurs_in_the_archive(platform: Platform) -> None:
    platform.answer(200, b'{"missingActions": []}')

    _client(platform).import_scenario(ARCHIVE)
    _client(platform).import_scenario(ARCHIVE)

    boundaries = {request.headers["content-type"].split("=", 1)[1] for request in platform.received}
    assert len(boundaries) == 2
    assert all(boundary.encode() not in ARCHIVE for boundary in boundaries)


def test_a_boundary_found_in_the_archive_is_drawn_again(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    draws = iter(["not-a-boundary", "f" * 32])
    monkeypatch.setattr(
        "scenario_tools.adapters.openaev_http.secrets.token_hex", lambda size: next(draws)
    )
    platform.answer(200, b'{"missingActions": []}')

    _client(platform).import_scenario(ARCHIVE)

    assert platform.received[0].headers["content-type"].endswith("boundary=" + "f" * 32)


def test_import_returns_the_injects_the_platform_skipped(platform: Platform) -> None:
    platform.answer(
        200,
        json.dumps(
            {
                "missingActions": [
                    {"type": "InjectorContract/Payload", "name": "Dump credentials"},
                    {"type": "Injector", "name": "Scan"},
                ]
            }
        ).encode(),
    )

    assert _client(platform).import_scenario(ARCHIVE) == ImportResult(
        (
            SkippedInject("InjectorContract/Payload", "Dump credentials"),
            SkippedInject("Injector", "Scan"),
        )
    )


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b"{}",
        b'{"missingActions": {}}',
        b'{"missingActions": ["Scan"]}',
        b'{"missingActions": [{"type": "Injector"}]}',
        b'{"missingActions": [{"type": 1, "name": "Scan"}]}',
        b"[" * 10_000,
        b'{"missingActions": [], "padding": "' + b"x" * (1024 * 1024) + b'"}',
        b'{"missingActions": []}' + b" " * (1024 * 1024),
    ],
    ids=[
        "not json",
        "not an object",
        "no missing actions",
        "missing actions not a list",
        "action not an object",
        "action without name",
        "type not text",
        "too deep",
        "too large",
        "padded beyond the limit",
    ],
)
def test_an_unexpected_import_answer_is_an_environment_problem(
    platform: Platform, body: bytes
) -> None:
    platform.answer(200, body)

    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform's answer to the import is not the expected"
    ):
        _client(platform).import_scenario(ARCHIVE)


def test_an_import_error_names_the_import(platform: Platform) -> None:
    platform.answer(500, b"{}")

    with pytest.raises(EnvironmentProblemError, match=r"^the platform answered HTTP 500$"):
        _client(platform).import_scenario(ARCHIVE)
