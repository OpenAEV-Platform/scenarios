"""Every policy rule, once, in code order, and the findings they give for an entry."""

from collections.abc import Iterable

from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.policy.rules import (
    actions,
    cleanup,
    elevation,
    recurrence,
    sources,
    targets,
    vendors,
)
from scenario_tools.domain.shared.finding import Finding

RULES: tuple[Rule, ...] = (
    sources.RULE,
    recurrence.RULE,
    targets.RULE,
    actions.RULE,
    cleanup.RULE,
    vendors.RULE,
    elevation.RULE,
)


def findings_of(rule: Rule, violations: Iterable[Violation]) -> tuple[Finding, ...]:
    """The findings of ``violations``, with the code and severity of ``rule``, so that a finding
    never says another rule's code or severity."""
    return tuple(
        Finding(rule.code, rule.severity, violation.path, violation.field, violation.message)
        for violation in violations
    )


def rule_findings(code: str, data: PolicyData, content: EntryContent) -> tuple[Finding, ...]:
    """The findings of the rule ``code`` alone for the entry ``content`` holds, for a command
    that asks one rule, as the archive asks for the recurrence."""
    (rule,) = (rule for rule in RULES if rule.code == code)
    return findings_of(rule, rule.check(data, content))


def policy_findings(data: PolicyData, content: EntryContent) -> tuple[Finding, ...]:
    """The findings of every rule for the entry ``content`` holds, rule after rule, with the
    maintainers' ``data``."""
    return tuple(
        finding for rule in RULES for finding in findings_of(rule, rule.check(data, content))
    )
