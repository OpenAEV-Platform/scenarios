"""Static check that the parts of a stored scenario that hold injects are read through one walk.

A module that reads ``scenario_injects`` itself would miss the injects other parts hold, so every
check reads them through the walk. A read is the part's name written as a string, or its constant
used to look the part up: as an argument of ``get``, ``pop`` or ``setdefault``, as a subscript, or
in a membership test. The constant is recognised under an import alias and as a module
attribute. Naming the part in a set, or building a pointer from it, is not a read.
"""

import ast

PART_NAMES = frozenset({"scenario_injects", "scenario_workflow"})
PART_CONSTANTS = frozenset({"INJECTS"})
_LOOKUPS = frozenset({"get", "pop", "setdefault"})


def _constant_names(tree: ast.Module) -> frozenset[str]:
    """The names a part constant goes by in ``tree``: its own, and any import alias."""
    names = set(PART_CONSTANTS)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(
                alias.asname
                for alias in node.names
                if alias.name in PART_CONSTANTS and alias.asname is not None
            )
    return frozenset(names)


def _is_part_constant(node: ast.expr, names: frozenset[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in names
    return isinstance(node, ast.Attribute) and node.attr in PART_CONSTANTS


def direct_reads(source: str) -> list[str]:
    """Return the direct reads of an inject-holding part in ``source``, in order of appearance."""
    tree = ast.parse(source)
    names = _constant_names(tree)
    reads: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value in PART_NAMES:
            reads.append(repr(node.value))
        elif (
            (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _LOOKUPS
                and any(
                    _is_part_constant(argument, names)
                    for argument in (*node.args, *(keyword.value for keyword in node.keywords))
                )
            )
            or (isinstance(node, ast.Subscript) and _is_part_constant(node.slice, names))
            or (
                isinstance(node, ast.Compare)
                and _is_part_constant(node.left, names)
                and any(isinstance(operator, ast.In | ast.NotIn) for operator in node.ops)
            )
        ):
            reads.append(ast.unparse(node))
    return reads
