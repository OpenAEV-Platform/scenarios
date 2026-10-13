"""A policy rule, the entry it reads and the violations it gives."""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.policy.targets import AllowedTargets
from scenario_tools.domain.shared.finding import Severity


@dataclass(frozen=True)
class EntryContent:
    """What the rules read of one entry: its directory, relative to the repository, the names
    it holds, what ``scenario.yaml`` declares once it meets its schema, and the stored
    ``scenario.json`` once read, whatever its shape; ``None`` when missing or refused, which
    their own checks report. A rule never relies on a shape it has not checked."""

    directory: str
    files: frozenset[str]
    declared: Mapping[str, Any] | None
    stored: object


@dataclass(frozen=True)
class PolicyData:
    """The maintainers' data the rules read, from ``policy/data``."""

    targets: AllowedTargets


@dataclass(frozen=True)
class Violation:
    """One breach of a rule: the file relative to the repository, the JSON pointer of the field,
    empty for the whole file, and what is wrong."""

    path: str
    field: str
    message: str


@dataclass(frozen=True)
class Rule:
    """A rule: its code, its severity, what it refuses, and the check that finds each breach."""

    code: str
    severity: Severity
    statement: str
    check: Callable[[PolicyData, EntryContent], Iterable[Violation]]
