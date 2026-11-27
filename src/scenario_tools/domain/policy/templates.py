"""The repositories a Nuclei template may be fetched from, read from the maintainers' data, and
what keeps a template's link from naming one of them at a commit.

A repository is a GitHub one, named ``<owner>/<repository>`` in lower case. A template of it is
fetched in its raw form, at a commit: ``https://raw.githubusercontent.com/<owner>/<repository>/
<commit>/<path>``, or ``https://github.com/<owner>/<repository>/raw/<commit>/<path>``, which
leads there. A commit is its full hash, 40 hexadecimal characters in lower case: a branch or a
tag can be moved after the review, a commit cannot. A link is compared as written, never decoded
nor folded, and its path holds only letters, digits and ``. _ ~ + -`` between single slashes,
with no ``.`` or ``..`` segment, no query and no fragment: what passes is what the platform
fetches, and nothing a client or a server reads otherwise.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass

TEMPLATE_URL = "template_url"  # the field of an inject's content that holds a template's link

_KEYS = ("github_repositories",)
_SCHEME = "https://"
# A GitHub account, 39 characters at most whose hyphens are single and inside, and one of its
# repositories, in lower case; never "." nor "..".
_REPOSITORY = re.compile(
    r"(?=[a-z0-9-]{1,39}/)[a-z0-9]+(?:-[a-z0-9]+)*/(?!\.\.?\Z)[a-z0-9._-]{1,100}"
)
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SEGMENT = re.compile(r"[A-Za-z0-9._~+-]+")
_DOTS = frozenset({".", ".."})


@dataclass(frozen=True)
class PinnedTemplate:
    """An allowed repository, as ``<owner>/<repository>``, and a commit's full hash a template
    link names."""

    repository: str
    commit: str


@dataclass(frozen=True)
class TemplateSources:
    """The GitHub repositories, as ``<owner>/<repository>``, a Nuclei template may come from."""

    repositories: tuple[str, ...]

    @classmethod
    def from_document(cls, document: object) -> "TemplateSources":
        """Read the nuclei-templates data document: one list of distinct repositories, each
        ``<owner>/<repository>`` in lower case, so that a typo never allows another one."""
        if not isinstance(document, Mapping):
            raise ValueError("nuclei-templates: the document must be a mapping")
        unknown = sorted(str(key) for key in document if key not in _KEYS)
        if unknown:
            raise ValueError(f"nuclei-templates: unknown keys {', '.join(unknown)}")
        listed = document.get("github_repositories")
        if (
            not isinstance(listed, list)
            or not all(isinstance(item, str) for item in listed)
            or len(set(listed)) != len(listed)
        ):
            raise ValueError(
                "nuclei-templates: github_repositories must be a list of distinct texts"
            )
        if not all(_REPOSITORY.fullmatch(repository) for repository in listed):
            raise ValueError(
                "nuclei-templates: github_repositories must hold <owner>/<repository> names "
                "in lower case"
            )
        return cls(tuple(listed))

    def _commit_and_path(self, rest: str) -> tuple[str, str] | None:
        """The allowed repository ``rest``, a link without its scheme, leads to, and what
        follows it: its commit and the path after it; ``None`` when it leads to none."""
        for repository in self.repositories:
            for prefix in (
                f"raw.githubusercontent.com/{repository}/",
                f"github.com/{repository}/raw/",
            ):
                if rest.startswith(prefix):
                    return repository, rest[len(prefix) :]
        return None

    def _read(self, link: str) -> tuple[str | None, PinnedTemplate | None]:
        """What keeps ``link`` from naming a template of an allowed repository at a commit, if
        anything, else the repository and the commit it names."""
        if not link.startswith(_SCHEME):
            return "does not start with https://", None
        found = self._commit_and_path(link[len(_SCHEME) :])
        if found is None:
            return (
                "does not lead to a repository that policy/data/nuclei-templates.yaml allows",
                None,
            )
        repository, rest = found
        commit, _, path = rest.partition("/")
        if not _COMMIT.fullmatch(commit):
            return (
                "is not pinned to a commit's full hash, 40 hexadecimal characters in lower case: a "
                "branch or a tag can move after the review"
            ), None
        if not all(
            _SEGMENT.fullmatch(segment) and segment not in _DOTS for segment in path.split("/")
        ):
            return (
                "has a path that is not plain (only letters, digits and . _ ~ + - between single "
                "slashes, no . or .. segment, no query nor fragment)"
            ), None
        return None, PinnedTemplate(repository, commit)

    def problem(self, link: str) -> str | None:
        """What keeps ``link`` from naming a template of an allowed repository at a commit,
        said as the end of a sentence about the link, if anything."""
        return self._read(link)[0]

    def pinned(self, link: str) -> PinnedTemplate | None:
        """The allowed repository and the commit ``link`` names, when nothing keeps it from
        naming a template of that repository at that commit; ``None`` otherwise. The link alone
        does not show that the repository holds the commit: GitHub serves a commit of any fork
        of a repository under the repository's own link, so whoever can ask GitHub checks that
        the commit is on the repository's default branch."""
        return self._read(link)[1]
