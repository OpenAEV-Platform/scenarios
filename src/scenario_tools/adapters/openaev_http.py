"""The OpenAEV platform over HTTP, with the standard library.

The URL and a tenant-scoped token come from the environment only. The transport is HTTPS, or
plain HTTP to the local machine, and a redirect is never followed: the token would go with it.
A local call never goes through a proxy, which would see the token in clear. Answers are read
within limits and a total deadline, and an error message names a failure by its kind only: the
text of a transport error may carry the host, or what the platform sent.
"""

import contextlib
import functools
import http.client
import ipaddress
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from types import TracebackType
from typing import Any

from scenario_tools.adapters.safe_readers import parse_json
from scenario_tools.adapters.safe_zip import ARCHIVE_LIMIT
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError
from scenario_tools.ports.openaev import ImportResult, SkippedInject

# Teams are kept, as the policy checks their names; players and variable values are internal.
EXPORT_OPTIONS = (
    ("isWithTeams", "true"),
    ("isWithPlayers", "false"),
    ("isWithVariableValues", "false"),
    ("isWithScopeDefinition", "true"),
)
TIMEOUT = 120.0
ANSWER_LIMIT = 1024 * 1024
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# A bearer token (RFC 6750): no output of the tools escapes these characters, so a token that
# shows anywhere shows as it is, where the guard of the commands finds it.
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+=*")
# Long enough never to be a part of the tools' own text, which has no run of 16 characters
# without a space: a guard that withholds what would show the token can always fall back on it.
TOKEN_LENGTH = 16
_URL = re.compile(r"[\x21-\x7e]+")  # visible ASCII: nothing urlsplit would silently drop
# A DNS label: letters, digits and inner hyphens; an internationalised name is written in its
# ASCII form (xn--).
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # the redirect answer then comes back as an error


class _Watchdog:
    """One deadline for a whole call, whatever the call waits for: the name resolution, the
    connection, the tunnel, the encryption, the headers or the body. The timeout of each network
    operation alone would let a platform that answers byte by byte hold the call for ever. The
    connections are made here, within the time left, and cut when the deadline passes."""

    def __init__(self, seconds: float, *, loopback_only: bool = False) -> None:
        self.expired = False
        self._deadline = time.monotonic() + seconds
        self._loopback_only = loopback_only
        self._lock = threading.Lock()
        # Socket objects, never bare descriptors: once closed, a socket has none left to cut,
        # whereas its former descriptor may already serve another file.
        self._sockets: list[socket.socket] = []
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def left(self) -> float:
        return self._deadline - time.monotonic()

    def _resolve(self, host: str, port: int) -> list[Any]:
        """The addresses of ``host``, or ``TimeoutError`` at the deadline: the resolution runs
        in a thread of its own, as nothing else can bound it."""
        found: list[Any] = []
        failed: list[OSError] = []

        def resolve() -> None:
            try:
                found.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
            except OSError as error:
                failed.append(error)

        worker = threading.Thread(target=resolve, daemon=True)
        worker.start()
        worker.join(max(self.left(), 0))
        if worker.is_alive():
            raise TimeoutError("the name resolution outlived the deadline")
        if failed:
            raise failed[0]
        return found

    def create_connection(
        self, address: tuple[str, int], timeout: float, source_address: object = None
    ) -> socket.socket:
        """In place of ``socket.create_connection``: each address in turn, each attempt within
        the time left, and none once the deadline has passed. The calls bind no local address,
        so ``source_address`` is always empty."""
        error = OSError("no address")  # getaddrinfo gives at least one, or fails
        addresses = self._resolve(*address)
        if self._loopback_only and not all(
            ipaddress.ip_address(target[0]).is_loopback for *_, target in addresses
        ):
            raise EnvironmentProblemError(
                f"OPENAEV_URL uses http, but {address[0]} does not resolve to the local machine"
            )
        for family, kind, protocol, _, target in addresses:
            left = self.left()
            if left <= 0:
                raise TimeoutError("the deadline passed before the connection")
            connection = socket.socket(family, kind, protocol)
            try:
                connection.settimeout(min(timeout, left))
                connection.connect(target)
            except OSError as failure:
                connection.close()
                error = failure
                continue
            with self._lock:  # the same lock as the watchdog: it cannot fire in between
                if self.expired or self.left() <= 0:
                    connection.close()
                    raise TimeoutError("the connection completed after the deadline")
                self._sockets.append(connection)
            return connection
        raise error

    def watch(self, connection: socket.socket) -> None:
        """Watch a socket made from one of ours, such as the one wrapped for encryption: the
        wrapping detaches the first. Cut at once when the deadline has already passed."""
        with self._lock:
            self._sockets.append(connection)
            if self.expired:
                _cut(connection)

    def _expire(self) -> None:
        with self._lock:
            self.expired = True
            for connection in self._sockets:
                _cut(connection)

    def __enter__(self) -> "_Watchdog":
        self._timer.start()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self._timer.cancel()


def _cut(connection: socket.socket) -> None:
    """Shut the connection down, at the socket level: the encrypted socket's own shutdown would
    also drop its encryption state under the thread still reading from it."""
    with contextlib.suppress(OSError):  # already closed: nothing left to cut
        socket.socket.shutdown(connection, socket.SHUT_RDWR)


class _HTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, watchdog: _Watchdog, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = watchdog.create_connection


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self, *args: Any, watchdog: _Watchdog, context: ssl.SSLContext, **kwargs: Any
    ) -> None:
        super().__init__(*args, context=context, **kwargs)
        self._watchdog = watchdog
        self._tls = context
        self._create_connection = watchdog.create_connection

    def connect(self) -> None:
        """The connection of the standard library, with the handshake watched: the wrapping
        detaches the first socket, so the encrypted one is handed to the watchdog before the
        handshake starts, with the time left as its timeout, a slow tunnel included."""
        http.client.HTTPConnection.connect(self)  # the connection, and the proxy tunnel if any
        encrypted = self._tls.wrap_socket(
            self.sock,
            # Through a proxy, the platform is the tunnel's host (set by the standard library).
            server_hostname=getattr(self, "_tunnel_host", None) or self.host,
            do_handshake_on_connect=False,
        )
        self._watchdog.watch(encrypted)
        try:
            encrypted.settimeout(max(self._watchdog.left(), 0.001))  # past it: already cut
            encrypted.do_handshake()
        except BaseException:
            encrypted.close()
            raise
        self.sock = encrypted


class _HTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, watchdog: _Watchdog) -> None:
        super().__init__()
        self._watchdog = watchdog

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(functools.partial(_HTTPConnection, watchdog=self._watchdog), req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, watchdog: _Watchdog) -> None:
        self._tls = ssl.create_default_context()  # certificate and host name verified
        super().__init__(context=self._tls)
        self._watchdog = watchdog

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        connection = functools.partial(_HTTPSConnection, watchdog=self._watchdog)
        return self.do_open(connection, req, context=self._tls)


def _is_host(host: str) -> bool:
    """An IP address, or a host name made of DNS labels."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        return len(host) <= 253 and all(_LABEL.fullmatch(label) for label in labels)
    return True


def _base_url(url: str) -> tuple[str, bool]:
    """The URL without its trailing slash, and whether it names the local machine."""
    try:
        if not _URL.fullmatch(url):
            raise ValueError("whitespace or a character out of printable ASCII")
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError for a port out of range
        if host and not _is_host(host):
            raise ValueError("a malformed host")
    except ValueError as error:
        raise EnvironmentProblemError("OPENAEV_URL is not a URL") from error
    local = parts.scheme == "http" and host in _LOCAL_HOSTS
    if parts.scheme != "https" and not local:
        raise EnvironmentProblemError(
            "OPENAEV_URL must use https, or http to the local machine only"
        )
    if not host:
        raise EnvironmentProblemError("OPENAEV_URL has no host")
    if parts.username is not None or parts.password is not None:
        raise EnvironmentProblemError("OPENAEV_URL must not carry user information")
    if "?" in url or "#" in url:  # an empty query or fragment too: the path would follow it
        raise EnvironmentProblemError("OPENAEV_URL must not carry a query or fragment")
    return url.rstrip("/"), local


class HttpOpenAEV:
    """The two platform endpoints the tools call: scenario export and scenario import."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        timeout: float = TIMEOUT,
        archive_limit: int = ARCHIVE_LIMIT,
    ) -> None:
        self._url, self._local = _base_url(url)
        self._token = token
        self._timeout = timeout
        self._archive_limit = archive_limit

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str],
        *,
        timeout: float = TIMEOUT,
        archive_limit: int = ARCHIVE_LIMIT,
    ) -> "HttpOpenAEV":
        url = environment.get("OPENAEV_URL")
        if not url:
            raise EnvironmentProblemError("OPENAEV_URL is not set")
        token = environment.get("OPENAEV_TOKEN")
        if not token:
            raise EnvironmentProblemError("OPENAEV_TOKEN is not set")
        if not _TOKEN.fullmatch(token):
            raise EnvironmentProblemError(
                "OPENAEV_TOKEN is not a token: letters, digits and -._~+/ only, then = signs"
            )
        if len(token) < TOKEN_LENGTH:
            raise EnvironmentProblemError(
                f"OPENAEV_TOKEN is not a token: at least {TOKEN_LENGTH} characters"
            )
        return cls(url, token, timeout=timeout, archive_limit=archive_limit)

    def _call(
        self,
        method: str,
        path: str,
        limit: int,
        *,
        body: bytes | None = None,
        content_type: str | None = None,
        not_found: str = "",
    ) -> bytes:
        """The body of a 200 answer, at most ``limit + 1`` bytes of it."""
        headers = {"Authorization": f"Bearer {self._token}"}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(  # noqa: S310 - the scheme is checked in _base_url
            self._url + path, data=body, headers=headers, method=method
        )
        late = EnvironmentProblemError(
            f"the platform did not answer within {self._timeout:g} seconds"
        )
        with _Watchdog(self._timeout, loopback_only=self._local) as watchdog:
            handlers: list[urllib.request.BaseHandler] = [
                _NoRedirect(),
                _HTTPHandler(watchdog),
                _HTTPSHandler(watchdog),
            ]
            if self._local:
                handlers.append(urllib.request.ProxyHandler({}))
            opener = urllib.request.build_opener(*handlers)
            try:
                # The timeout of each operation also bounds the connection itself, before a
                # socket exists for the watchdog to cut.
                with opener.open(request, timeout=self._timeout) as answer:
                    status = answer.status
                    data: bytes = answer.read(limit + 1)
            except urllib.error.HTTPError as error:
                error.close()
                raise EnvironmentProblemError(_problem(error.code, not_found)) from None
            except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
                reason = getattr(error, "reason", error)
                # A timed-out operation and the watchdog share one deadline: either means late.
                if watchdog.expired or isinstance(reason, TimeoutError):
                    raise late from None
                kind = type(reason if isinstance(reason, BaseException) else error).__name__
                raise EnvironmentProblemError(f"the platform cannot be reached ({kind})") from None
        # The clock decides, not the timer, whose thread may run late; a body cut at the
        # deadline reads as a short one.
        if watchdog.left() <= 0:
            raise late
        if status != 200:
            raise EnvironmentProblemError(_problem(status, not_found))
        return data

    def export_scenario(self, scenario_id: str) -> bytes:
        path = f"/api/scenarios/{urllib.parse.quote(scenario_id, safe='')}/export?"
        data = self._call(
            "GET",
            path + urllib.parse.urlencode(EXPORT_OPTIONS),
            self._archive_limit,
            not_found="the scenario was not found on the platform",
        )
        if len(data) > self._archive_limit:
            raise UnsafeInputError("IO-001", f"larger than {self._archive_limit} bytes")
        return data

    def import_scenario(self, archive: bytes) -> ImportResult:
        boundary = secrets.token_hex(16)
        while boundary.encode() in archive:
            boundary = secrets.token_hex(16)
        body = b"".join(
            (
                f"--{boundary}\r\n".encode(),
                b'Content-Disposition: form-data; name="file"; filename="scenario.zip"\r\n',
                b"Content-Type: application/zip\r\n\r\n",
                archive,
                f"\r\n--{boundary}--\r\n".encode(),
            )
        )
        data = self._call(
            "POST",
            "/api/scenarios/import",
            ANSWER_LIMIT,
            body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )
        return _import_result(data)


def _problem(status: int, not_found: str) -> str:
    if status in (401, 403):
        return f"the platform refused the token (HTTP {status})"
    if status == 404 and not_found:
        return f"{not_found} (HTTP 404)"
    if 300 <= status < 400:
        return f"the platform answered a redirect (HTTP {status}), which is never followed"
    return f"the platform answered HTTP {status}"


def _import_result(data: bytes) -> ImportResult:
    unexpected = EnvironmentProblemError(
        "the platform's answer to the import is not the expected JSON object"
    )
    try:
        document = parse_json(data, limit=ANSWER_LIMIT)
    except UnsafeInputError as error:
        raise unexpected from error
    actions = document.get("missingActions") if isinstance(document, dict) else None
    if not isinstance(actions, list):
        raise unexpected
    skipped = []
    for action in actions:
        if not isinstance(action, dict):
            raise unexpected
        kind, name = action.get("type"), action.get("name")
        if not isinstance(kind, str) or not isinstance(name, str):
            raise unexpected
        skipped.append(SkippedInject(kind, name))
    return ImportResult(tuple(skipped))
