"""GitHub's API, read with the standard library, for what the release workflow asks of it: the
pull requests a commit was merged by, and the reviews of a pull request.

Only ``api.github.com``, over HTTPS, with the token the workflow gives; a redirect is never
followed, as the token would go with it. Answers are read within a limit, each read within a
timeout, and an error is named by its kind: never the token, never what GitHub sent.
"""

import re
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from scenario_tools.adapters.openaev_http import NoRedirect
from scenario_tools.adapters.safe_readers import parse_json
from scenario_tools.domain.shared.commits import is_commit_id
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

API = "https://api.github.com"
ANSWER_LIMIT = 4 * 1024 * 1024
TIMEOUT = 30.0
_PAGE = 100
_PAGES = 10  # a pull request with more reviews than this is no pull request of this catalogue
_REPOSITORY = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
_TOKEN = re.compile(r"[A-Za-z0-9_.-]+")

OpenUrl = Callable[[urllib.request.Request, float], Any]


def _opened(request: urllib.request.Request, timeout: float) -> Any:
    opener = urllib.request.build_opener(NoRedirect())
    return opener.open(request, timeout=timeout)  # nosec B310 - the URL is API's, over HTTPS


class HttpGitHub:
    """The repository ``repository`` (``owner/name``) on GitHub, read with ``token``."""

    def __init__(self, token: str, repository: str, *, open_url: OpenUrl = _opened) -> None:
        if not _TOKEN.fullmatch(token):
            raise EnvironmentProblemError("the GitHub token is missing or is not one")
        if not _REPOSITORY.fullmatch(repository) or repository.endswith(("/.", "/..")):
            raise EnvironmentProblemError(f"{repository!r} is not a GitHub repository name")
        self._token = token
        self._repository = repository
        self._open = open_url

    def _get(self, path: str, what: str) -> list[Any]:
        request = urllib.request.Request(  # noqa: S310 - the URL is API's, over HTTPS
            f"{API}/repos/{self._repository}/{path}",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "scenario-tools",
            },
            method="GET",
        )
        try:
            with self._open(request, TIMEOUT) as answer:
                data = answer.read(ANSWER_LIMIT + 1)
        except urllib.error.HTTPError as error:
            raise EnvironmentProblemError(
                f"cannot read {what} from GitHub: HTTP {error.code}"
            ) from None
        except (urllib.error.URLError, OSError) as error:
            raise EnvironmentProblemError(f"cannot reach GitHub to read {what}") from error
        if len(data) > ANSWER_LIMIT:
            raise EnvironmentProblemError(
                f"GitHub's answer for {what} is larger than {ANSWER_LIMIT} bytes"
            )
        try:
            found = parse_json(data, path=what)
        except UnsafeInputError as error:
            raise EnvironmentProblemError(f"GitHub's answer for {what} is not JSON") from error
        if not isinstance(found, list):
            raise EnvironmentProblemError(f"GitHub's answer for {what} is not a list")
        return found

    def pulls_of(self, commit: str) -> list[Any]:
        """The pull requests GitHub associates with ``commit``, a full commit ID."""
        if not is_commit_id(commit):
            raise EnvironmentProblemError(f"{commit!r} is not a commit ID")
        pulls = self._get(
            f"commits/{commit}/pulls?per_page={_PAGE}", f"the pull requests of {commit}"
        )
        if len(pulls) >= _PAGE:  # a page full: more may follow, which are never guessed
            raise EnvironmentProblemError(
                f"{commit} has {_PAGE} pull requests or more: they cannot be read"
            )
        return pulls

    def reviews_of(self, number: int) -> list[Any]:
        """The reviews of the pull request ``number``, oldest first, every page of them."""
        if type(number) is not int or number < 1:
            raise EnvironmentProblemError(f"{number!r} is not a pull request number")
        reviews: list[Any] = []
        what = f"the reviews of pull request #{number}"
        for page in range(1, _PAGES + 1):
            found = self._get(f"pulls/{number}/reviews?per_page={_PAGE}&page={page}", what)
            reviews += found
            if len(found) < _PAGE:
                return reviews
        raise EnvironmentProblemError(
            f"pull request #{number} has more than {_PAGE * _PAGES} reviews: it cannot be read"
        )
