"""How large a module and its functions are: its lines, and the cyclomatic complexity of each of
its functions, methods and classes as radon ranks it, A for the simplest to F."""

from collections.abc import Iterator
from typing import Any

from radon.complexity import cc_rank, cc_visit  # type: ignore[import-untyped]

MAX_RANK = "C"  # a complexity of 20 at most
MAX_LINES = 600


def _blocks(found: list[Any]) -> Iterator[Any]:
    """Every block radon read, the methods of a class and the functions inside a function too."""
    for block in found:
        yield block
        yield from _blocks(getattr(block, "methods", []))
        yield from _blocks(getattr(block, "closures", []))


def too_complex(source: str) -> list[str]:
    """The blocks of ``source`` ranked beyond ``MAX_RANK``, each with its rank and complexity."""
    return [
        f"{block.fullname} {cc_rank(block.complexity)} ({block.complexity})"
        for block in _blocks(cc_visit(source))
        if cc_rank(block.complexity) > MAX_RANK
    ]


def too_long(source: str) -> bool:
    """Whether ``source`` holds more than ``MAX_LINES`` lines."""
    return len(source.splitlines()) > MAX_LINES
