"""The checks of an entry that its schema cannot express: where it sits in the repository, a
description still cut to fit, an external ID another entry has, and a minimum platform version
older than the one its built-in contracts were recorded on."""

import re
from collections.abc import Iterable, Mapping

from scenario_tools.domain.catalogue.metadata import TRUNCATION_MARK, clean
from scenario_tools.domain.shared.finding import Finding, Severity

REQUIRED = ("scenario.yaml", "scenario.json")
SLUG_LIMIT = 64
_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_CONSTRAINT = re.compile(r"(?:>=|>|==|~=)([0-9]+(?:\.[0-9]+)*)")
_NAMED = 3  # entries a duplicate finding names, so that none is cut out of its message


def domains_from_document(document: object) -> tuple[str, ...]:
    """The domains of the catalogue, from the domains data document: a non-empty list of
    kebab-case names."""
    domains = document.get("domains") if isinstance(document, Mapping) else None
    if (
        not isinstance(domains, list)
        or not domains
        or not all(isinstance(domain, str) and _SLUG.fullmatch(domain) for domain in domains)
    ):
        raise ValueError("domains: must list the catalogue's domains in kebab-case")
    return tuple(domains)


def layout_findings(
    path: str, present: Iterable[str], domains: Iterable[str]
) -> tuple[Finding, ...]:
    """An ``SCH-008`` finding when the entry at ``path``, relative to the repository, is not at
    ``scenarios/<domain>/<slug>/`` with one of ``domains``, and one for each required file it
    lacks among ``present``."""
    domains = tuple(domains)
    parts = path.split("/")
    whys = []
    if len(parts) != 3 or parts[0] != "scenarios":
        whys.append("an entry is a directory scenarios/<domain>/<slug>/ of the repository")
    else:
        if parts[1] not in domains:
            whys.append(f"the domain {parts[1]} is not one of {', '.join(domains)}")
        if len(parts[2]) > SLUG_LIMIT or not _SLUG.fullmatch(parts[2]):
            whys.append(
                f"the slug is not kebab-case of at most {SLUG_LIMIT} characters: lower-case "
                "letters and digits, single hyphens between them"
            )
    findings = [Finding("SCH-008", Severity.BLOCKING, path, "", why) for why in whys]
    findings += [
        Finding("SCH-008", Severity.BLOCKING, f"{path}/{name}", "", f"the entry has no {name}")
        for name in REQUIRED
        if name not in set(present)
    ]
    return tuple(findings)


def truncation_findings(description: str, path: str) -> tuple[Finding, ...]:
    """An ``SCH-009`` finding when the description still ends with the truncation mark once its
    blanks are cleaned: it was cut to fit its bound, and no one has reviewed the cut."""
    if not clean(description).text.endswith(TRUNCATION_MARK):
        return ()
    message = (
        f"the description ends with the truncation mark {TRUNCATION_MARK}: it was cut to fit; "
        "review its end and remove the mark"
    )
    return (Finding("SCH-009", Severity.BLOCKING, path, "/description", message),)


def _version(text: str) -> tuple[tuple[int, str], ...]:
    """A version that compares as its numbers do, however many digits they have: each as its
    length and digits, leading zeros dropped; without the zeros ending it, so that 3.2 and
    3.2.0 are equal."""
    numbers = [part.lstrip("0") for part in text.split(".")]
    while numbers and not numbers[-1]:
        numbers.pop()
    return tuple((len(number), number) for number in numbers)


def version_findings(constraint: str, recorded: str, path: str) -> tuple[Finding, ...]:
    """An ``SCH-011`` information when the minimum of ``constraint``, a ``requires.openaev``
    the schema accepted, is older than ``recorded``, the version the built-in contracts were
    recorded on: they were checked on that version only."""
    match = _CONSTRAINT.fullmatch(constraint)
    if match is None or _version(match.group(1)) >= _version(recorded):
        return ()
    message = (
        f"requires.openaev allows versions older than {recorded}, where the built-in contracts "
        "were recorded: they were checked on that version only; raise the minimum to it, or "
        "check the scenario on the older versions"
    )
    return (Finding("SCH-011", Severity.INFO, path, "/requires/openaev", message),)


def duplicate_findings(
    external_id: str, path: str, others: Mapping[str, Iterable[str]]
) -> tuple[Finding, ...]:
    """An ``SCH-010`` finding when other entries, ``others`` mapping each external ID to their
    directories, have ``external_id`` too; the message names them."""
    named = sorted(others.get(external_id, ()))
    if not named:
        return ()
    who = "another entry has" if len(named) == 1 else "other entries have"
    shown = ", ".join(named[:_NAMED])
    more = f" and {len(named) - _NAMED} more" if len(named) > _NAMED else ""
    message = f"{who} this external_id: {shown}{more}"
    return (Finding("SCH-010", Severity.BLOCKING, path, "/external_id", message),)
