"""The OpenAEV platform over HTTP, with the standard library.

The URL and a tenant-scoped token come from the environment only. The transport is HTTPS, or
plain HTTP to the local machine, and a redirect is never followed: the token would go with it.
A local call never goes through a proxy, which would see the token in clear. Answers are read
within limits and a total deadline, and no error message carries the token or the URL.
"""

import http.client
import ipaddress
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
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
_TOKEN = re.compile(r"[\x21-\x7e]+")
_URL = _TOKEN  # printable ASCII, with no whitespace: nothing urlsplit would silently drop
# A DNS label: letters, digits and inner hyphens; an internationalised name is written in its
# ASCII form (xn--).
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_CHUNK = 64 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # the redirect answer then comes back as an error


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
    if parts.query or parts.fragment:
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
        self._url, local = _base_url(url)
        self._token = token
        self._timeout = timeout
        self._archive_limit = archive_limit
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        if local:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

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
            raise EnvironmentProblemError("OPENAEV_TOKEN is not a token: printable ASCII only")
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
        deadline = time.monotonic() + self._timeout
        try:
            with self._opener.open(request, timeout=self._timeout) as answer:
                status = answer.status
                data = self._read(answer, limit + 1, deadline)
        except urllib.error.HTTPError as error:
            error.close()
            raise EnvironmentProblemError(_problem(error.code, not_found)) from None
        except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
            reason = getattr(error, "reason", error)
            raise EnvironmentProblemError(f"the platform cannot be reached: {reason}") from None
        if status != 200:
            raise EnvironmentProblemError(_problem(status, not_found))
        return data

    def _read(self, answer: http.client.HTTPResponse, wanted: int, deadline: float) -> bytes:
        """The answer until ``wanted`` bytes are in, one chunk at most beyond them, within the
        total deadline: the timeout of each network operation alone would let a platform crawl
        for ever."""
        late = EnvironmentProblemError(
            f"the platform did not answer within {self._timeout:g} seconds"
        )
        # The answer's socket: each read waits no longer than the time left, so that the total
        # deadline holds even when a read blocks.
        connection = answer.fp.raw._sock  # type: ignore[attr-defined]
        chunks: list[bytes] = []
        size = 0
        while size < wanted and not answer.isclosed():  # closed once the whole body is in
            left = deadline - time.monotonic()
            if left <= 0:
                raise late
            connection.settimeout(left)
            try:
                chunk = answer.read1(_CHUNK)
            except TimeoutError:
                raise late from None
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)

    def export_scenario(self, scenario_id: str) -> bytes:
        path = f"/api/scenarios/{urllib.parse.quote(scenario_id, safe='')}/export?"
        data = self._call(
            "GET",
            path + urllib.parse.urlencode(EXPORT_OPTIONS),
            self._archive_limit,
            not_found=f"scenario {scenario_id} not found on the platform",
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
