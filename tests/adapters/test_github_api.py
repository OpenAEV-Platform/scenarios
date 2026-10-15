"""GitHub's API, read with the standard library: what the release workflow asks of it."""

import http.client
import http.server
import io
import json
import threading
import urllib.error
import urllib.request
from typing import Any

import pytest

from scenario_tools.adapters import github_api
from scenario_tools.adapters.github_api import ANSWER_LIMIT, HttpGitHub
from scenario_tools.ports.errors import EnvironmentProblemError

TOKEN = "test-token-0123456789"  # noqa: S105 - the tests' own, never a real one
REPOSITORY = "OpenAEV-Platform/scenarios"
COMMIT = "a" * 40


class _Answer(io.BytesIO):
    status = 200

    def __enter__(self) -> "_Answer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _api(pages: dict[str, Any], asked: list[urllib.request.Request] | None = None) -> HttpGitHub:
    def open_url(request: urllib.request.Request, timeout: float) -> _Answer:
        assert timeout > 0
        if asked is not None:
            asked.append(request)
        answer = pages[request.full_url]
        if isinstance(answer, Exception):
            raise answer
        return _Answer(answer if isinstance(answer, bytes) else json.dumps(answer).encode())

    return HttpGitHub(TOKEN, REPOSITORY, open_url=open_url)


def test_the_pull_requests_of_a_commit_are_asked_with_the_token_as_github_wants() -> None:
    url = f"https://api.github.com/repos/{REPOSITORY}/commits/{COMMIT}/pulls?per_page=100"
    asked: list[urllib.request.Request] = []

    pulls = _api({url: [{"number": 9}]}, asked).pulls_of(COMMIT)

    assert pulls == [{"number": 9}]
    [request] = asked
    assert request.get_header("Authorization") == f"Bearer {TOKEN}"
    assert request.get_header("Accept") == "application/vnd.github+json"
    assert request.get_header("X-github-api-version") == "2022-11-28"
    assert request.get_method() == "GET"


def test_the_reviews_of_a_pull_request_are_read_page_after_page() -> None:
    base = f"https://api.github.com/repos/{REPOSITORY}/pulls/9/reviews?per_page=100&page="
    first = [{"id": n} for n in range(100)]
    pages = {f"{base}1": first, f"{base}2": [{"id": 100}]}

    assert _api(pages).reviews_of(9) == [*first, {"id": 100}]


def test_a_pull_request_with_too_many_reviews_is_refused() -> None:
    base = f"https://api.github.com/repos/{REPOSITORY}/pulls/9/reviews?per_page=100&page="
    pages = {f"{base}{page}": [{"id": n} for n in range(100)] for page in range(1, 12)}

    with pytest.raises(EnvironmentProblemError, match="more than 1000 reviews"):
        _api(pages).reviews_of(9)


@pytest.mark.parametrize(
    ("answer", "said"),
    [
        (urllib.error.HTTPError("u", 403, "Forbidden", None, None), "HTTP 403"),  # type: ignore[arg-type]
        (urllib.error.URLError("no route"), "cannot reach GitHub"),
        (TimeoutError(), "cannot reach GitHub"),
        (http.client.BadStatusLine("secret status line"), "cannot reach GitHub"),
        (http.client.IncompleteRead(b"partial"), "cannot reach GitHub"),
        (b"not json", "not JSON"),
        (b"[" * 200 + b"]" * 200, "not JSON"),
        (b" " * (ANSWER_LIMIT + 1), f"larger than {ANSWER_LIMIT} bytes"),
        ({"not": "a list"}, "not a list"),
    ],
)
def test_what_github_cannot_give_is_the_environment_s_fault_and_never_shows_the_token(
    answer: Any, said: str
) -> None:
    url = f"https://api.github.com/repos/{REPOSITORY}/commits/{COMMIT}/pulls?per_page=100"

    with pytest.raises(EnvironmentProblemError, match=said) as error:
        _api({url: answer}).pulls_of(COMMIT)
    assert TOKEN not in str(error.value)
    assert "secret status line" not in str(error.value)


@pytest.mark.parametrize(
    ("token", "repository"),
    [("", REPOSITORY), ("a b", REPOSITORY), ("x\n", REPOSITORY), (TOKEN, "scenarios"),
     (TOKEN, "a/b/c"), (TOKEN, "../x"), (TOKEN, "a b/c"), (TOKEN, "a/."), (TOKEN, "a/..")],
)  # fmt: skip
def test_a_token_or_a_repository_unfit_to_ask_with_is_refused(token: str, repository: str) -> None:
    with pytest.raises(EnvironmentProblemError) as error:
        HttpGitHub(token, repository)
    if token:
        assert token not in str(error.value)


@pytest.mark.parametrize("commit", ["HEAD", "a" * 39, "../x", "A" * 40])
def test_a_commit_that_is_no_commit_id_is_never_asked(commit: str) -> None:
    with pytest.raises(EnvironmentProblemError, match="not a commit"):
        _api({}).pulls_of(commit)


@pytest.mark.parametrize("number", [0, -1, True])
def test_a_pull_request_that_is_no_number_is_never_asked(number: int) -> None:
    with pytest.raises(EnvironmentProblemError, match="not a pull request number"):
        _api({}).reviews_of(number)


def test_a_commit_with_a_page_full_of_pull_requests_is_refused() -> None:
    url = f"https://api.github.com/repos/{REPOSITORY}/commits/{COMMIT}/pulls?per_page=100"

    with pytest.raises(EnvironmentProblemError, match="100 pull requests or more"):
        _api({url: [{"number": n} for n in range(100)]}).pulls_of(COMMIT)


def test_a_redirect_comes_back_as_an_error_and_the_token_never_goes_further(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real answer over the loopback: the redirect is said, never followed."""
    followed: list[str] = []

    class Redirecting(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith("/elsewhere"):
                followed.append(self.headers.get("Authorization", ""))
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()

        def log_message(self, *arguments: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Redirecting)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(github_api, "API", f"http://127.0.0.1:{server.server_port}")
    try:
        with pytest.raises(EnvironmentProblemError, match="HTTP 302"):
            HttpGitHub(TOKEN, REPOSITORY).pulls_of(COMMIT)
    finally:
        server.shutdown()
        server.server_close()
    assert followed == []
