"""Only the walk reads the parts of a stored scenario that hold injects.

The checker is tested on synthetic sources first, so that a silent pass on the real package
cannot hide a broken checker. The modules that read a part on purpose are listed, each with its
reason, and each must still read one: a module that no longer does leaves the list.
"""

from pathlib import Path

import pytest

from tests.architecture.stored_parts import direct_reads

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "scenario_tools"

# Where the parts are defined, produced or refused when misshapen.
EXEMPT = {
    "domain/shared/stored.py": "defines the walk",
    "domain/catalogue/structure.py": (
        "refuses a part that is not a list, or an item that is not an object"
    ),
    "domain/catalogue/normalisation.py": "produces the parts from an export",
}
# Modules that read a part on purpose.
ALLOWED = {
    "domain/verification/versioning.py": (
        "compares the raw inject lists of two versions, where an item of another shape is itself "
        "a change"
    ),
    "application/build_fixtures.py": "writes the parts of test exports",
}


@pytest.mark.parametrize(
    ("source", "read"),
    [
        ("stored.get(INJECTS)", "stored.get(INJECTS)"),
        ("stored.get(INJECTS, [])", "stored.get(INJECTS, [])"),
        ("stored.get(key=INJECTS)", "stored.get(key=INJECTS)"),
        ("dict.get(stored, INJECTS)", "dict.get(stored, INJECTS)"),
        ("stored.pop(INJECTS)", "stored.pop(INJECTS)"),
        ("stored.setdefault(INJECTS, [])", "stored.setdefault(INJECTS, [])"),
        ("stored[INJECTS]", "stored[INJECTS]"),
        ("found = INJECTS in stored", "INJECTS in stored"),
        ("found = INJECTS not in stored", "INJECTS not in stored"),
        ("found = key == INJECTS in stored", "key == INJECTS in stored"),
        ("from m import INJECTS as PART\nstored.get(PART)", "stored.get(PART)"),
        ("import m\nstored.get(m.INJECTS)", "stored.get(m.INJECTS)"),
        ("stored.get('scenario_injects')", "'scenario_injects'"),
        ("stored['scenario_workflow']", "'scenario_workflow'"),
    ],
)
def test_direct_reads_are_reported(source: str, read: str) -> None:
    assert read in direct_reads(source)


@pytest.mark.parametrize(
    "source",
    [
        "for found in injects(stored):\n    pass",
        "from scenario_tools.domain.shared.stored import INJECTS\nPARTS = {INJECTS}",
        "pointer = f'/{INJECTS}/0'",
        "from m import INJECTS as PART\npointer = f'/{PART}/0'",
        "'''Reads scenario_injects through the walk.'''",
        "stored.get(OTHER)",
        "stored.get()",
        "stored.get(PART)",
        "found = OTHER in stored",
        "found = INJECTS == part",
        "found = INJECTS == key in stored",
    ],
)
def test_naming_a_part_or_walking_it_is_not_a_read(source: str) -> None:
    assert direct_reads(source) == []


def test_only_the_walk_reads_the_parts() -> None:
    offenders = {
        name: found
        for path in sorted(PACKAGE.rglob("*.py"))
        if (name := path.relative_to(PACKAGE).as_posix()) not in EXEMPT | ALLOWED
        and (found := direct_reads(path.read_text(encoding="utf-8")))
    }
    assert offenders == {}


@pytest.mark.parametrize("name", sorted(EXEMPT | ALLOWED))
def test_each_listed_module_still_reads_a_part(name: str) -> None:
    assert direct_reads((PACKAGE / name).read_text(encoding="utf-8"))
