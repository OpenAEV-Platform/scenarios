"""Pinned Nuclei templates: an inject that fetches its Nuclei template from a link fetches it over
https, from a repository the maintainers allow, at a commit. The platform fetches the template
and runs it itself, so the template the reviewers read must be the one it runs: a branch or a
tag can be moved after the merge, and a repository nobody vouches for can hold anything.

The link is the ``template_url`` of the content of every inject, those of a workflow's steps
included. A link left empty, or no link at all, is fine: the template is then one the platform
holds, chosen by its identifier. A value that is not text is refused, since nothing can vouch
for it. The link is read as written, as ``domain/policy/templates.py`` says, and the allowed
targets (POL-003) leave it to this rule: it names where a template comes from, never a target.
A refused link is never quoted.
"""

from collections.abc import Iterator, Mapping

from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.policy.templates import TEMPLATE_URL
from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.shared.stored import injects

_CONTENT = "inject_content"
_WHAT_TO_DO = (
    "use a template of an allowed repository, pinned to a commit: "
    "https://raw.githubusercontent.com/<owner>/<repository>/<commit>/<path>"
)


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    path = f"{content.directory}/scenario.json"
    for found in injects(content.stored):
        held = found.inject.get(_CONTENT)
        link = held.get(TEMPLATE_URL) if isinstance(held, Mapping) else None
        if link is None or link == "":
            continue  # a template the platform holds
        problem = data.templates.problem(link) if isinstance(link, str) else "is not a text"
        if problem is not None:
            yield Violation(
                path,
                f"{found.pointer}/{_CONTENT}/{TEMPLATE_URL}",
                f"this Nuclei template link {problem}; {_WHAT_TO_DO}",
            )


RULE = Rule(
    "POL-012",
    Severity.BLOCKING,
    "A Nuclei template fetched from a link comes over https from a repository the maintainers "
    "allow, pinned to a commit, never a branch or a tag.",
    _check,
)
