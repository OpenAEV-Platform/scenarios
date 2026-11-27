"""Check that each Nuclei template the entries fetch is on its repository's default branch.

POL-012 lets a template link name a commit of an allowed repository only, and reads the link
alone. GitHub serves a commit of any fork of a repository under the repository's own link, the
head of an unmerged pull request from a fork among them: such a link passes POL-012 while the
repository never held what it names. So GitHub is asked, once for each repository and commit,
how the commit compares with the repository's default branch: the branch must hold it. A link
POL-012 refuses is left to it, and a scenario that cannot be read to the checks of validate.
"""

from collections.abc import Callable, Iterable, Mapping

from scenario_tools.domain.policy.templates import TEMPLATE_URL, PinnedTemplate, TemplateSources
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.stored import injects

CODE = "POL-012"
_CONTENT = "inject_content"
HELD = frozenset({"identical", "behind"})  # the commit is the branch's head, or one before it


def _message(pinned: PinnedTemplate, branch: str, status: str | None) -> str:
    if status is None:
        found = f"names a commit that no repository of {pinned.repository}'s network holds"
    else:
        found = (
            f"names a commit that is not on {pinned.repository}'s default branch, {branch} "
            f"(GitHub compares it as {status}): a commit of a fork, or of a pull request not "
            "merged, is served under the repository's link too"
        )
    return f"this Nuclei template link {found}; use a commit of {branch}"


def template_commit_findings(
    scenarios: Iterable[tuple[str, object]],
    sources: TemplateSources,
    *,
    default_branch: Callable[[str], str],
    compared: Callable[[str, str, str], str | None],
) -> tuple[Finding, ...]:
    """A blocking POL-012 finding for each template link of ``scenarios``, pairs of the path of
    a stored ``scenario.json`` and its document, that names a commit of an allowed repository of
    ``sources`` its default branch does not hold. ``default_branch`` gives the name of a
    repository's default branch, and ``compared`` how a commit compares with a branch of a
    repository, as GitHub says it, ``None`` for a commit no repository of its network holds."""
    branches: dict[str, str] = {}
    statuses: dict[PinnedTemplate, str | None] = {}
    findings: list[Finding] = []
    for path, stored in scenarios:
        for found in injects(stored):
            held = found.inject.get(_CONTENT)
            link = held.get(TEMPLATE_URL) if isinstance(held, Mapping) else None
            pinned = sources.pinned(link) if isinstance(link, str) else None
            if pinned is None:
                continue  # a template the platform holds, or a link POL-012 refuses
            if pinned.repository not in branches:
                branches[pinned.repository] = default_branch(pinned.repository)
            branch = branches[pinned.repository]
            if pinned not in statuses:
                statuses[pinned] = compared(pinned.repository, branch, pinned.commit)
            status = statuses[pinned]
            if status in HELD:
                continue
            findings.append(
                Finding(
                    CODE,
                    Severity.BLOCKING,
                    path,
                    f"{found.pointer}/{_CONTENT}/{TEMPLATE_URL}",
                    _message(pinned, branch, status),
                )
            )
    return tuple(findings)
