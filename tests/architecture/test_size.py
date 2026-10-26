"""No function of the tools is beyond complexity C, and no module beyond 600 lines.

A function that grows past C is split into named rules, a module past 600 lines by its
responsibilities. An exception needs its reason written here, next to it, and leaves the list
once it is no longer one. The checker is tested on synthetic sources first, so that a silent pass
on the real package cannot hide a broken checker.
"""

from pathlib import Path

from tests.architecture.size import MAX_LINES, too_complex, too_long

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "scenario_tools"

# Modules or blocks allowed beyond the bounds, each with its reason: none today.
EXCEPTIONS: dict[str, str] = {}


def _branching(name: str, branches: int, indent: str = "") -> str:
    """A function of complexity ``branches + 1``: one branch per ``if``."""
    body = "".join(
        f"{indent}    if value == {index}:\n{indent}        return {index}\n"
        for index in range(branches)
    )
    return f"{indent}def {name}(value):\n{body}{indent}    return -1\n"


def test_a_function_of_complexity_c_passes() -> None:
    assert too_complex(_branching("simple", 19)) == []


def test_a_function_beyond_c_is_reported() -> None:
    assert too_complex(_branching("tangled", 20)) == ["tangled D (21)"]


def test_a_method_beyond_c_is_reported() -> None:
    source = "class Holder:\n" + _branching("tangled", 20, "    ")
    assert "Holder.tangled D (21)" in too_complex(source)


def test_a_method_of_a_class_inside_a_class_beyond_c_is_reported() -> None:
    source = "class Outer:\n    class Inner:\n" + _branching("tangled", 20, "        ")
    assert any(found.endswith("tangled D (21)") for found in too_complex(source))


def test_a_function_inside_a_function_beyond_c_is_reported() -> None:
    source = "def outer():\n" + _branching("tangled", 20, "    ") + "    return tangled\n"
    assert any(found.startswith("tangled D") for found in too_complex(source))


def test_a_module_of_the_bound_passes_and_one_line_more_does_not() -> None:
    assert not too_long("x = 1\n" * MAX_LINES)
    assert too_long("x = 1\n" * (MAX_LINES + 1))


def _modules() -> list[tuple[str, str]]:
    return [
        (path.relative_to(PACKAGE).as_posix(), path.read_text(encoding="utf-8"))
        for path in sorted(PACKAGE.rglob("*.py"))
    ]


def test_no_function_is_beyond_complexity_c() -> None:
    offenders = {
        name: found
        for name, source in _modules()
        if (
            found := [block for block in too_complex(source) if f"{name}:{block}" not in EXCEPTIONS]
        )
    }
    assert offenders == {}


def test_no_module_is_beyond_600_lines() -> None:
    offenders = [name for name, source in _modules() if too_long(source) and name not in EXCEPTIONS]
    assert offenders == []


def test_each_exception_has_its_reason_and_is_still_one() -> None:
    for name, reason in EXCEPTIONS.items():
        assert reason.strip(), name
        module, _, block = name.partition(":")
        source = (PACKAGE / module).read_text(encoding="utf-8")
        assert block in too_complex(source) if block else too_long(source), name
