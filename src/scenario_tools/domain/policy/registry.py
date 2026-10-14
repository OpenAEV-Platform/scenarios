"""Every policy rule, once, in code order, and the findings they give for an entry."""

from collections.abc import Iterable, Mapping

from scenario_tools.domain.policy.exceptions import REGISTRY, PolicyException
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.policy.rules import (
    actions,
    cleanup,
    elevation,
    internal,
    recurrence,
    sources,
    spacing,
    targets,
    vendors,
)
from scenario_tools.domain.shared.finding import Finding, Severity

RULES: tuple[Rule, ...] = (
    sources.RULE,
    recurrence.RULE,
    targets.RULE,
    actions.RULE,
    cleanup.RULE,
    vendors.RULE,
    elevation.RULE,
    spacing.RULE,
    internal.RULE,
)


def findings_of(rule: Rule, violations: Iterable[Violation]) -> tuple[Finding, ...]:
    """The findings of ``violations``, with the code of ``rule`` and its severity, unless a
    violation gives its own, which only lowers it (an informative breach of a blocking rule),
    so that a finding never says another rule's code."""
    return tuple(
        Finding(
            rule.code,
            # A violation severity only lowers the rule's, never raises it: only info takes over.
            Severity.INFO if violation.severity is Severity.INFO else rule.severity,
            violation.path,
            violation.field,
            violation.message,
        )
        for violation in violations
    )


def rule_findings(code: str, data: PolicyData, content: EntryContent) -> tuple[Finding, ...]:
    """The findings of the rule ``code`` alone for the entry ``content`` holds, for a command
    that asks one rule, as the archive asks for the recurrence."""
    (rule,) = (rule for rule in RULES if rule.code == code)
    return findings_of(rule, rule.check(data, content))


def _excepted(
    code: str,
    violation: Violation,
    own: list[tuple[int, PolicyException]],
    content: EntryContent,
    used: set[int],
) -> Violation:
    """``violation``, when blocking, as information if an exception of its entry covers it, for
    this version of ``scenario.json``; its reason comes first, so that a shortened message keeps
    it, and the exception counts as used."""
    if violation.severity is Severity.INFO:
        return violation
    for index, exception in own:
        if (
            exception.code,
            f"{content.directory}/scenario.json",
            exception.field,
            exception.sha256,
        ) == (code, violation.path, violation.field, content.stored_sha256):
            used.add(index)
            message = f"excepted by the maintainers ({exception.justification}): "
            return Violation(
                violation.path, violation.field, message + violation.message, Severity.INFO
            )
    return violation


def policy_findings(data: PolicyData, content: EntryContent) -> tuple[Finding, ...]:
    """The findings of every rule for the entry ``content`` holds, rule after rule, with the
    maintainers' ``data``: a finding an exception of the entry covers is information, and an
    exception of the entry that covers none blocks, so that none outlives its breach."""
    declared = content.declared  # of any shape: its schema's check reports it
    external_id = declared.get("external_id") if isinstance(declared, Mapping) else None
    own = [
        (index, exception)
        for index, exception in enumerate(data.exceptions)
        if exception.entry == external_id
    ]
    used: set[int] = set()
    found = tuple(
        finding
        for rule in RULES
        for finding in findings_of(
            rule,
            [
                _excepted(rule.code, violation, own, content, used)
                for violation in rule.check(data, content)
            ],
        )
    )
    unused = tuple(
        Finding(
            "POL-011",
            Severity.BLOCKING,
            REGISTRY,
            f"/exceptions/{index}",
            f"this exception of {exception.code} for {content.directory} covers no finding: its "
            f"scenario.json changed (sha256 now {content.stored_sha256 or 'unknown'}), or the "
            "breach is gone or moved; review the change and give the exception that hash, or "
            "remove it",
        )
        for index, exception in own
        if index not in used
    )
    return found + unused
