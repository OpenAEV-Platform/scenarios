"""The OpenAEV client over HTTP: credentials from the environment, fixed export options, local
or encrypted transport, no redirect, bounded answers, and errors that never carry the token."""

import http.client
import json
import socket
import ssl
import time
from collections.abc import Callable, Iterator

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.adapters.openaev_http import (
    EXPORT_OPTIONS,
    HttpOpenAEV,
    _HTTPConnection,
    _HTTPSConnection,
    _HTTPSHandler,
    _Watchdog,
    usable_token,
)
from scenario_tools.domain.verification.held_payloads import HeldContract
from scenario_tools.ports.errors import (
    EnvironmentProblemError,
    OutcomeUnknownError,
    UnsafeInputError,
)
from scenario_tools.ports.openaev import ImportResult, SkippedInject
from tests.platform_server import Platform, platform_server

TOKEN = "0b6c6f0e-token-secret"  # noqa: S105 - a test value, never a real token
SCENARIO = "0a64b5ab-2016-426b-813f-9051d32e88b3"
NOT_LOCAL = r"^OPENAEV_URL uses http, but the connection did not reach the local machine$"


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


@pytest.mark.parametrize("token", ["x" * 16, "Ab0-._~+/secret==", SCENARIO])
def test_a_bearer_token_of_16_characters_or_more_is_accepted(token: str) -> None:
    HttpOpenAEV.from_environment({"OPENAEV_URL": "https://a.example", "OPENAEV_TOKEN": token})


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
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": "x" * 15},
            "OPENAEV_TOKEN is not a token: at least 16 characters",
        ),
        (
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": 'quote"-secret-value'},
            "OPENAEV_TOKEN is not a token",
        ),
        (
            {
                "OPENAEV_URL": "https://platform.example.org",
                "OPENAEV_TOKEN": "back\\slash-secret-value",
            },
            "OPENAEV_TOKEN is not a token",
        ),
        (
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": "a=b-secret-value"},
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
        ({"OPENAEV_URL": "https://platform.example.org?", "OPENAEV_TOKEN": TOKEN}, "query"),
        ({"OPENAEV_URL": "https://platform.example.org/#", "OPENAEV_TOKEN": TOKEN}, "query"),
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
        (404, "the scenario was not found on the platform \\(HTTP 404\\)"),
        (400, "the platform answered HTTP 400"),
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


def test_an_unknown_scenario_is_not_named_back(platform: Platform) -> None:
    # The identifier is the caller's, and could be anything, the token included.
    platform.answer(404)
    client = HttpOpenAEV.from_environment({"OPENAEV_URL": platform.url, "OPENAEV_TOKEN": SCENARIO})

    with pytest.raises(EnvironmentProblemError) as error:
        client.export_scenario(SCENARIO)
    assert SCENARIO not in str(error.value)


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


@pytest.mark.timing
def test_a_platform_that_does_not_answer_in_time_is_an_environment_problem(
    platform: Platform,
) -> None:
    platform.delay = 0.5

    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.1 seconds$"
    ):
        _client(platform, timeout=0.1).export_scenario(SCENARIO)


@pytest.mark.timing
def test_a_platform_that_answers_byte_by_byte_is_cut_at_the_deadline(platform: Platform) -> None:
    platform.answer(200, b"x" * 100)
    platform.drip = 0.02  # two seconds for the whole body, each byte well within the timeout

    start = time.monotonic()
    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.3 seconds$"
    ):
        _client(platform, timeout=0.3).export_scenario(SCENARIO)
    assert time.monotonic() - start < 1.0


@pytest.mark.timing
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


@pytest.mark.timing
def test_an_answer_whose_headers_crawl_is_cut_at_the_deadline(platform: Platform) -> None:
    platform.raw = b"HTTP/1.1 200 OK\r\nX-Padding: " + b"a" * 200 + b"\r\n\r\n"
    platform.drip = 0.02  # four seconds of headers, each byte well within the timeout

    start = time.monotonic()
    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.3 seconds$"
    ):
        _client(platform, timeout=0.3).export_scenario(SCENARIO)
    assert time.monotonic() - start < 0.6


def _address(platform: Platform) -> tuple[str, int]:
    host, port = platform.url.removeprefix("http://").split(":")
    return host, int(port)


def test_no_connection_is_attempted_after_the_deadline(platform: Platform) -> None:
    with _Watchdog(0.01) as watchdog:
        while not watchdog.expired:
            time.sleep(0.005)

        with pytest.raises(TimeoutError):
            watchdog.create_connection(_address(platform), 5)
    assert platform.received == []


@pytest.mark.timing
def test_no_attempt_starts_once_the_deadline_has_passed(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter([0.0, 0.0])  # deadline set and name resolved in time; then always too late
    monkeypatch.setattr(
        "scenario_tools.adapters.openaev_http.time.monotonic", lambda: next(clock, 100.0)
    )

    with pytest.raises(TimeoutError, match="before the connection"):
        _Watchdog(5).create_connection(_address(platform), 5)
    assert platform.received == []


@pytest.mark.timing
def test_a_connection_completed_after_the_deadline_is_closed(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deadline set, name resolved and attempt started in time, connection made too late.
    clock = iter([0.0, 0.0, 0.0, 100.0])
    monkeypatch.setattr(
        "scenario_tools.adapters.openaev_http.time.monotonic", lambda: next(clock, 100.0)
    )
    watchdog = _Watchdog(5)

    with pytest.raises(TimeoutError):
        watchdog.create_connection(_address(platform), 5)


def test_a_connection_made_while_the_watchdog_expires_is_closed(platform: Platform) -> None:
    # The watchdog fires between the last check of the clock and the registration of the
    # socket: it found nothing to cut, so the socket must not be handed over.
    watchdog = _Watchdog(5)
    watchdog._expire()

    with pytest.raises(TimeoutError):
        watchdog.create_connection(_address(platform), 5)


@pytest.mark.timing
def test_the_watchdog_cuts_a_connection_wrapped_for_encryption() -> None:
    # Wrapping for encryption detaches the socket the watchdog made: the encrypted socket is the
    # one to watch, and the cut must reach it.
    with socket.create_server(("127.0.0.1", 0)) as server:  # accepts, never answers
        watchdog = _Watchdog(5)
        raw = watchdog.create_connection(server.getsockname(), 5)
        tls = ssl.create_default_context()
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        with tls.wrap_socket(
            raw, server_hostname="platform.example.org", do_handshake_on_connect=False
        ) as encrypted:
            watchdog.watch(encrypted)
            watchdog._expire()

            start = time.monotonic()
            with pytest.raises(ConnectionError):  # the hello cannot even be sent
                encrypted.do_handshake()
            assert time.monotonic() - start < 1


class _Encrypted:
    def __init__(self, events: list[tuple[object, ...]], failure: Exception | None) -> None:
        self.events, self.failure = events, failure

    def settimeout(self, value: float) -> None:
        self.events.append(("timeout", value))

    def do_handshake(self) -> None:
        self.events.append(("handshake",))
        if self.failure:
            raise self.failure

    def close(self) -> None:
        self.events.append(("close",))


def _encrypted_connection(
    monkeypatch: pytest.MonkeyPatch, failure: Exception | None = None
) -> tuple[_HTTPSConnection, _Encrypted, list[tuple[object, ...]]]:
    """An encrypted connection whose network, encryption and watchdog are stand-ins that
    record what the connection does, in order."""
    events: list[tuple[object, ...]] = []
    encrypted = _Encrypted(events, failure)

    class Context:
        def wrap_socket(self, sock: object, **options: object) -> _Encrypted:
            events.append(("wrap", options["server_hostname"], options["do_handshake_on_connect"]))
            return encrypted

    class Watchdog:
        create_connection = None
        reached = False

        def watch(self, connection: object) -> None:
            events.append(("watch", connection is encrypted))

        def left(self) -> float:
            return 2.5

    monkeypatch.setattr(
        http.client.HTTPConnection, "connect", lambda self: setattr(self, "sock", object())
    )
    connection = _HTTPSConnection(
        "platform.example.org",
        watchdog=Watchdog(),  # type: ignore[arg-type]
        context=Context(),  # type: ignore[arg-type]
    )
    return connection, encrypted, events


def test_the_encrypted_socket_is_watched_before_its_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, encrypted, events = _encrypted_connection(monkeypatch)

    connection.connect()

    assert events == [
        ("wrap", "platform.example.org", False),
        ("watch", True),
        ("timeout", 2.5),
        ("handshake",),
    ]
    assert connection.sock is encrypted
    assert connection._watchdog.reached  # the request may now be sent


def test_through_a_proxy_the_handshake_names_the_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, _, events = _encrypted_connection(monkeypatch)
    connection.set_tunnel("tunnel.example.org", 443)

    connection.connect()

    assert events[0] == ("wrap", "tunnel.example.org", False)


def test_a_failed_handshake_closes_the_encrypted_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    connection, _, events = _encrypted_connection(monkeypatch, TimeoutError("late"))

    with pytest.raises(TimeoutError):
        connection.connect()
    assert events[-1] == ("close",)
    assert not connection._watchdog.reached


def test_a_watched_socket_that_expires_late_is_cut_at_once(platform: Platform) -> None:
    watchdog = _Watchdog(5)
    watchdog._expire()

    with socket.create_connection(_address(platform), 2) as connection:
        watchdog.watch(connection)
        assert connection.recv(1) == b""


def test_a_closed_socket_is_never_cut_through_a_reused_descriptor() -> None:
    watchdog = _Watchdog(5)
    first, peer = socket.socketpair()
    watchdog.watch(first)
    descriptor = first.fileno()
    first.close()
    peer.close()

    other, other_peer = socket.socketpair()
    with other, other_peer:
        assert descriptor in (other.fileno(), other_peer.fileno())  # the lowest free one
        watchdog._expire()
        other.sendall(b"x")
        other_peer.sendall(b"y")
        assert (other_peer.recv(1), other.recv(1)) == (b"x", b"y")


LOOPBACK = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9))
ELSEWHERE = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 8080))


@pytest.mark.timing
@pytest.mark.parametrize("addresses", [[ELSEWHERE], [LOOPBACK, ELSEWHERE]], ids=["one", "mixed"])
def test_localhost_must_resolve_to_the_local_machine(
    monkeypatch: pytest.MonkeyPatch, addresses: list[object]
) -> None:
    monkeypatch.setattr(
        "scenario_tools.adapters.openaev_http.socket.getaddrinfo",
        lambda *args, **kwargs: addresses,
    )
    client = HttpOpenAEV.from_environment(
        {"OPENAEV_URL": "http://localhost:8080", "OPENAEV_TOKEN": TOKEN}, timeout=0.5
    )

    with pytest.raises(
        EnvironmentProblemError,
        match=r"^OPENAEV_URL uses http, but localhost does not resolve to the local machine$",
    ):
        client.export_scenario(SCENARIO)


def test_a_connection_attempt_gets_only_the_time_left(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    timeouts: list[float | None] = []

    class Recording(socket.socket):
        def settimeout(self, value: float | None) -> None:
            timeouts.append(value)
            super().settimeout(value)

    monkeypatch.setattr("scenario_tools.adapters.openaev_http.socket.socket", Recording)

    with _Watchdog(5).create_connection(_address(platform), 120):
        pass
    assert timeouts
    assert 0 < (timeouts[0] or 0) <= 5


@pytest.mark.timing
def test_a_name_resolution_that_outlives_the_deadline_is_abandoned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow(*args: object, **kwargs: object) -> list[object]:
        time.sleep(2)
        return []

    monkeypatch.setattr("scenario_tools.adapters.openaev_http.socket.getaddrinfo", slow)
    client = HttpOpenAEV.from_environment(
        {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": TOKEN}, timeout=0.2
    )

    start = time.monotonic()
    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.2 seconds$"
    ):
        client.export_scenario(SCENARIO)
    assert time.monotonic() - start < 0.5


def test_a_name_that_does_not_resolve_is_named_by_its_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unknown(*args: object, **kwargs: object) -> list[object]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr("scenario_tools.adapters.openaev_http.socket.getaddrinfo", unknown)
    client = HttpOpenAEV.from_environment(
        {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": TOKEN}
    )

    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform cannot be reached \(gaierror\)$"
    ):
        client.export_scenario(SCENARIO)


def test_each_resolved_address_is_tried_in_turn(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, port = _address(platform)
    with socket.socket() as refused:  # bound but not listening: refuses the first attempt
        refused.bind(("127.0.0.1", 0))
        addresses = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", refused.getsockname()),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port)),
        ]
        monkeypatch.setattr(
            "scenario_tools.adapters.openaev_http.socket.getaddrinfo",
            lambda *args, **kwargs: addresses,
        )
        platform.answer(200, b"archive")

        assert _client(platform).export_scenario(SCENARIO) == b"archive"


@pytest.mark.timing
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


@pytest.mark.timing
def test_the_handshake_after_a_slow_tunnel_ends_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with platform_server() as proxy:
        proxy.raw = b"HTTP/1.1 200 Connection established\r\n\r\n"
        proxy.drip = 0.008  # a third of a second for the tunnel
        proxy.hold = 1.0  # then no answer to the client's hello
        for name in ("HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(name, proxy.url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        client = HttpOpenAEV.from_environment(
            {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": TOKEN},
            timeout=0.6,
        )

        start = time.monotonic()
        with pytest.raises(
            EnvironmentProblemError, match=r"^the platform did not answer within 0.6 seconds$"
        ):
            client.export_scenario(SCENARIO)
        assert time.monotonic() - start < 0.8


def test_an_encrypted_call_verifies_the_certificate_and_the_host_name() -> None:
    tls = _HTTPSHandler(_Watchdog(1))._tls

    assert tls.verify_mode is ssl.CERT_REQUIRED
    assert tls.check_hostname


def test_an_encrypted_call_refuses_protocols_older_than_tls_1_2() -> None:
    # The default context leaves the floor to the local OpenSSL configuration, which may still
    # accept TLS 1.0 and 1.1; the client sets it itself.
    tls = _HTTPSHandler(_Watchdog(1))._tls

    assert tls.minimum_version is ssl.TLSVersion.TLSv1_2


def test_a_transport_failure_is_named_by_its_kind_only(platform: Platform) -> None:
    platform.raw = f"Bearer {TOKEN} from platform.example.org\r\n\r\n".encode()

    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform cannot be reached \(BadStatusLine\)$"
    ):
        _client(platform).export_scenario(SCENARIO)


@pytest.mark.timing
def test_an_answer_finished_after_the_deadline_is_late_even_if_the_timer_lags(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Lagging:  # a timer whose thread is never scheduled in time
        daemon = False

        def __init__(self, *args: object) -> None:
            pass

        def start(self) -> None:
            pass

        def cancel(self) -> None:
            pass

    monkeypatch.setattr("scenario_tools.adapters.openaev_http.threading.Timer", Lagging)
    platform.answer(200, b"xyz")
    platform.drip = 0.12  # each byte within the timeout, the whole answer past the deadline

    with pytest.raises(
        EnvironmentProblemError, match=r"^the platform did not answer within 0.2 seconds$"
    ):
        _client(platform, timeout=0.2).export_scenario(SCENARIO)


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


def test_a_skipped_inject_without_a_name_or_type_is_returned_as_such(platform: Platform) -> None:
    # The platform names an inject by its title, else its resource, either of which may be empty.
    platform.answer(
        200, b'{"missingActions": [{"type": null, "name": null}, {"type": "Injector"}]}'
    )

    assert _client(platform).import_scenario(ARCHIVE) == ImportResult(
        (SkippedInject(None, None), SkippedInject("Injector", None))
    )


class _Connected:
    def __init__(self, address: tuple[object, ...]) -> None:
        self.address, self.closed = address, False

    def getpeername(self) -> tuple[object, ...]:
        return self.address

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("address", "local"),
    [
        (("127.0.0.1", 80), True),
        (("127.0.0.2", 80), True),
        (("::1", 80, 0, 0), True),
        (("192.0.2.10", 80), False),
        (("::ffff:127.0.0.1", 80, 0, 0), False),  # not loopback for Python 3.12, which is pinned
    ],
)
def test_a_plain_http_connection_must_reach_the_local_machine(
    monkeypatch: pytest.MonkeyPatch, address: tuple[object, ...], local: bool
) -> None:
    # Checked on the connection itself, whatever resolved the name: the token goes in clear.
    connected = _Connected(address)
    monkeypatch.setattr(
        http.client.HTTPConnection, "connect", lambda self: setattr(self, "sock", connected)
    )
    connection = _HTTPConnection("localhost", watchdog=_Watchdog(5))

    if local:
        connection.connect()
    else:
        with pytest.raises(EnvironmentProblemError, match=NOT_LOCAL):
            connection.connect()
    assert connected.closed is not local
    assert connection._watchdog.reached is local  # only then may the request be sent


def _import(platform: Platform) -> None:
    _client(platform, timeout=0.3).import_scenario(ARCHIVE)


def _export(platform: Platform) -> None:
    _client(platform, timeout=0.3).export_scenario(SCENARIO)


def _answer(status: int) -> Callable[[Platform], None]:
    return lambda platform: platform.answer(status)


def _raw(answer: bytes) -> Callable[[Platform], None]:
    return lambda platform: setattr(platform, "raw", answer)


def _late(platform: Platform) -> None:
    platform.delay = 0.6  # the request is in: the platform takes too long to answer


def _silent(platform: Platform) -> None:
    platform.silent = True


def _odd(platform: Platform) -> None:
    platform.answer(200, b"[]")


SHORT = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}"
CHUNK_CUT = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nab"


@pytest.mark.timing
@pytest.mark.parametrize(
    ("setup", "call", "may_have_acted"),
    [
        pytest.param(_late, _import, True, id="import late"),
        pytest.param(_raw(SHORT), _import, True, id="import cut short"),
        pytest.param(_raw(CHUNK_CUT), _import, True, id="import chunk cut"),
        pytest.param(_raw(b"garbled\r\n\r\n"), _import, True, id="import garbled"),
        pytest.param(_odd, _import, True, id="import unexpected"),
        pytest.param(_silent, _import, True, id="import no answer"),
        pytest.param(_answer(500), _import, True, id="import 500"),
        pytest.param(_answer(503), _import, True, id="import 503"),
        pytest.param(_answer(201), _import, True, id="import 201"),
        pytest.param(_answer(401), _import, False, id="import 401"),
        pytest.param(_answer(403), _import, False, id="import 403"),
        pytest.param(_answer(400), _import, False, id="import 400"),
        pytest.param(_answer(404), _import, False, id="import 404"),
        pytest.param(_answer(302), _import, False, id="import redirect"),
        pytest.param(_answer(500), _export, False, id="export 500"),
        pytest.param(_raw(SHORT), _export, False, id="export cut short"),
        pytest.param(_late, _export, False, id="export late"),
    ],
)
def test_a_failure_says_whether_the_platform_may_have_acted(
    platform: Platform,
    setup: Callable[[Platform], None],
    call: Callable[[Platform], None],
    may_have_acted: bool,
) -> None:
    # Only an import can change the platform, and only once its request may have reached it.
    setup(platform)

    with pytest.raises(EnvironmentProblemError) as error:
        call(platform)
    assert isinstance(error.value, OutcomeUnknownError) is may_have_acted


def test_an_import_refused_before_it_could_reach_the_platform_did_nothing() -> None:
    with socket.socket() as bound:  # bound but not listening: refused before anything is sent
        bound.bind(("127.0.0.1", 0))
        client = HttpOpenAEV.from_environment(
            {"OPENAEV_URL": f"http://127.0.0.1:{bound.getsockname()[1]}", "OPENAEV_TOKEN": TOKEN}
        )

        with pytest.raises(EnvironmentProblemError) as error:
            client.import_scenario(ARCHIVE)
    assert not isinstance(error.value, OutcomeUnknownError)


@pytest.mark.timing
def test_an_import_late_before_any_connection_did_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow(*args: object, **kwargs: object) -> list[object]:
        time.sleep(1)
        return []

    monkeypatch.setattr("scenario_tools.adapters.openaev_http.socket.getaddrinfo", slow)
    client = HttpOpenAEV.from_environment(
        {"OPENAEV_URL": "https://platform.example.org", "OPENAEV_TOKEN": TOKEN}, timeout=0.2
    )

    with pytest.raises(EnvironmentProblemError, match="did not answer within") as error:
        client.import_scenario(ARCHIVE)
    assert not isinstance(error.value, OutcomeUnknownError)


@given(
    st.one_of(
        st.text(max_size=40),
        st.from_regex(r"[A-Za-z0-9._~+/-]{10,30}=*", fullmatch=True),
        st.from_regex(r"[A-Za-z0-9 =]{14,18}", fullmatch=True),
    )
)
def test_the_guard_hides_exactly_the_tokens_a_call_would_send(value: str) -> None:
    try:
        HttpOpenAEV.from_environment({"OPENAEV_URL": "https://a.example", "OPENAEV_TOKEN": value})
    except EnvironmentProblemError:
        sent = False
    else:
        sent = True

    assert (usable_token(value) == value != "") is sent


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


def test_skipped_injects_are_returned_as_the_platform_names_them(platform: Platform) -> None:
    # Whatever they hold: the commands decide what their output may show.
    action = {"type": "Injector", "name": f"x {TOKEN} x"}
    platform.answer(200, json.dumps({"missingActions": [action]}).encode())

    assert _client(platform).import_scenario(ARCHIVE) == ImportResult(
        (SkippedInject("Injector", f"x {TOKEN} x"),)
    )


@pytest.mark.parametrize("call", ["export", "import"])
def test_an_answer_shorter_than_it_declared_is_refused(platform: Platform, call: str) -> None:
    # The platform closes the connection before the length it announced: what came is a prefix,
    # however valid it looks.
    platform.raw = b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"missingActions": []}'
    client = _client(platform)
    calls: dict[str, Callable[[], object]] = {
        "export": lambda: client.export_scenario(SCENARIO),
        "import": lambda: client.import_scenario(ARCHIVE),
    }

    with pytest.raises(EnvironmentProblemError, match=r"^the platform's answer was cut short$"):
        calls[call]()


def test_an_export_cut_short_exactly_at_the_limit_is_refused(platform: Platform) -> None:
    platform.raw = b"HTTP/1.1 200 OK\r\nContent-Length: 150\r\n\r\n" + b"x" * 100

    with pytest.raises(EnvironmentProblemError, match=r"^the platform's answer was cut short$"):
        _client(platform, archive_limit=100).export_scenario(SCENARIO)


def test_an_import_error_names_the_import(platform: Platform) -> None:
    platform.answer(500, b"{}")

    with pytest.raises(EnvironmentProblemError, match=r"^the platform answered HTTP 500$"):
        _client(platform).import_scenario(ARCHIVE)


# What the platform holds, read before an import


CONTRACT = "6d0d3c1e-3f5a-4c9b-9d0e-1f2a3b4c5d6e"


def _page(payloads: list[dict[str, object]], last: object, total: object = None) -> bytes:
    return json.dumps(
        {
            "content": payloads,
            "last": last,
            "totalElements": len(payloads) if total is None else total,
        }
    ).encode()


def _payload(number: int, external_id: str | None = None) -> dict[str, object]:
    payload: dict[str, object] = {"payload_id": f"p-{number}", "payload_name": str(number)}
    if external_id is not None:
        payload["payload_external_id"] = external_id
    return payload


def test_a_contract_the_platform_holds_is_read_with_its_payload(platform: Platform) -> None:
    payload = {"payload_type": "Command", "command_content": "whoami"}
    platform.answer(200, json.dumps({"injector_contract_payload": payload}).encode())

    assert _client(platform).held_contract(CONTRACT) == HeldContract(payload)
    request = platform.received[0]
    assert (request.method, request.path) == ("GET", f"/api/injector_contracts/{CONTRACT}")
    assert request.headers["authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("payload", [None, {}], ids=["null", "empty"])
def test_a_contract_without_a_payload_is_held_without_one(
    platform: Platform, payload: object
) -> None:
    platform.answer(200, json.dumps({"injector_contract_payload": payload}).encode())

    assert _client(platform).held_contract(CONTRACT) == HeldContract(None)


def test_a_contract_the_platform_does_not_hold_is_none(platform: Platform) -> None:
    platform.answer(404, b'{"message": "not found"}')

    assert _client(platform).held_contract(CONTRACT) is None


def test_the_contract_identifier_is_encoded_in_the_path(platform: Platform) -> None:
    platform.answer(404)

    _client(platform).held_contract("a/../b c")

    assert platform.received[0].path == "/api/injector_contracts/a%2F..%2Fb%20c"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        # what a platform sends when it cannot write the whole contract: two documents
        (b'{"injector_contract_payload": {"payload_collector_type"}}{"message": "x"}', "not JSON"),
        (b"[]", "not a JSON object"),
    ],
    ids=["broken", "not an object"],
)
def test_a_contract_answer_that_cannot_be_read_is_an_environment_problem(
    platform: Platform, body: bytes, message: str
) -> None:
    platform.answer(200, body)

    with pytest.raises(EnvironmentProblemError, match=message) as error:
        _client(platform).held_contract(CONTRACT)

    assert TOKEN not in str(error.value)


def test_a_contract_larger_than_its_limit_is_refused(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("scenario_tools.adapters.openaev_http.CONTRACT_LIMIT", 16)
    platform.answer(200, b'{"injector_contract_payload": null}')

    with pytest.raises(EnvironmentProblemError, match="larger than 16 bytes"):
        _client(platform).held_contract(CONTRACT)


@pytest.mark.parametrize("status", [401, 500])
def test_a_contract_the_platform_fails_to_give_is_an_environment_problem(
    platform: Platform, status: int
) -> None:
    platform.answer(status)

    with pytest.raises(EnvironmentProblemError):
        _client(platform).held_contract(CONTRACT)


def test_the_payloads_are_read_page_by_page_and_kept_by_the_external_ids_asked(
    platform: Platform,
) -> None:
    first, other, second = _payload(1, "ext-1"), _payload(2, "ext-9"), _payload(4, "ext-2")
    pages = [_page([first, other, _payload(3)], False, 4), _page([second], True, 4)]
    platform.routes.append(
        (
            "POST",
            "/api/payloads/search",
            lambda received: (200, pages[json.loads(received.body)["page"]]),
        )
    )

    held = _client(platform).held_payloads(frozenset({"ext-1", "ext-2"}))

    assert held == {"ext-1": first, "ext-2": second}
    assert [json.loads(r.body) for r in platform.received] == [
        {"page": 0, "size": 200},
        {"page": 1, "size": 200},
    ]
    assert platform.received[0].headers["content-type"] == "application/json"


def test_no_payload_is_read_when_none_is_asked(platform: Platform) -> None:
    assert _client(platform).held_payloads(frozenset()) == {}
    assert platform.received == []


@pytest.mark.parametrize(
    "body",
    [_page([_payload(1, "ext-1")], True), _page([], True)],
    ids=["last", "an empty platform"],
)
def test_the_reading_stops_at_the_last_page(platform: Platform, body: bytes) -> None:
    platform.answer(200, body)

    _client(platform).held_payloads(frozenset({"ext-1"}))

    assert len(platform.received) == 1


@pytest.mark.parametrize(
    "body",
    [
        _page([_payload(1), _payload(2)], True, 3),  # one payload of the count never seen
        _page([_payload(1), _payload(1)], True, 2),  # one seen twice, as a shifted page gives
        _page([_payload(1), _payload(1), _payload(2)], True, 2),  # twice, yet the count agrees
        _page([], False, 1),  # no payload, and yet not the last page
        _page([{"payload_name": "no ID"}], True, 1),
    ],
    ids=[
        "one missed",
        "one seen twice",
        "twice, the count agreeing",
        "empty page",
        "no payload ID",
    ],
)
def test_a_reading_that_may_have_missed_a_payload_is_an_environment_problem(
    platform: Platform, body: bytes
) -> None:
    platform.answer(200, body)

    with pytest.raises(EnvironmentProblemError, match="changed while they were read"):
        _client(platform).held_payloads(frozenset({"ext-1"}))


def test_a_count_that_changes_between_pages_is_an_environment_problem(
    platform: Platform,
) -> None:
    pages = [_page([_payload(1)], False, 2), _page([_payload(2)], True, 3)]
    platform.routes.append(
        (
            "POST",
            "/api/payloads/search",
            lambda received: (200, pages[json.loads(received.body)["page"]]),
        )
    )

    with pytest.raises(EnvironmentProblemError, match="changed while they were read"):
        _client(platform).held_payloads(frozenset({"ext-1"}))


def test_two_payloads_under_one_external_id_are_an_environment_problem(
    platform: Platform,
) -> None:
    platform.answer(200, _page([_payload(1, "ext-1"), _payload(2, "ext-1")], True))

    with pytest.raises(EnvironmentProblemError, match="two payloads under one external ID"):
        _client(platform).held_payloads(frozenset({"ext-1"}))


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        json.dumps({"content": {}, "last": True, "totalElements": 0}).encode(),
        json.dumps({"content": [], "totalElements": 0}).encode(),
        json.dumps({"content": [], "last": None, "totalElements": 0}).encode(),
        json.dumps({"content": [], "last": True}).encode(),
        json.dumps({"content": [], "last": True, "totalElements": True}).encode(),
        json.dumps({"content": ["x"], "last": True, "totalElements": 1}).encode(),
    ],
    ids=["a list", "content", "last missing", "last null", "count missing", "count", "item"],
)
def test_a_page_of_another_shape_is_an_environment_problem(platform: Platform, body: bytes) -> None:
    platform.answer(200, body)

    with pytest.raises(EnvironmentProblemError, match="the platform's page of payloads"):
        _client(platform).held_payloads(frozenset({"ext-1"}))


def test_a_page_that_is_not_json_is_an_environment_problem(platform: Platform) -> None:
    platform.answer(200, b"not json")

    with pytest.raises(EnvironmentProblemError, match="not JSON"):
        _client(platform).held_payloads(frozenset({"ext-1"}))


def test_a_page_larger_than_its_limit_is_refused(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("scenario_tools.adapters.openaev_http.PAGE_LIMIT", 16)
    platform.answer(200, _page([], True))

    with pytest.raises(EnvironmentProblemError, match="larger than 16 bytes"):
        _client(platform).held_payloads(frozenset({"ext-1"}))


def test_a_platform_with_more_pages_than_the_limit_is_an_environment_problem(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("scenario_tools.adapters.openaev_http.PAGES", 3)
    platform.routes.append(
        (
            "POST",
            "/api/payloads/search",
            lambda received: (200, _page([_payload(json.loads(received.body)["page"])], False, 9)),
        )
    )

    with pytest.raises(EnvironmentProblemError, match="more than 600 payloads"):
        _client(platform).held_payloads(frozenset({"ext-1"}))

    assert len(platform.received) == 3


@pytest.mark.parametrize("contract_id", ["", ".", ".."])
def test_a_contract_id_that_names_no_contract_is_never_asked(
    platform: Platform, contract_id: str
) -> None:
    with pytest.raises(EnvironmentProblemError, match="is not a contract ID"):
        _client(platform).held_contract(contract_id)

    assert platform.received == []
