"""Static check that the domain layer stays pure: no I/O, no outer layer.

Only an explicit allow-list of side-effect-free standard-library modules may be imported,
plus the allowed pure third-party libraries and the domain itself. Built-in calls that
perform I/O or execute code dynamically are reported too.
"""

import ast

ALLOWED_STDLIB = frozenset(
    {
        "__future__",
        "abc",
        "base64",
        "binascii",
        "bisect",
        "collections",
        "copy",
        "dataclasses",
        "datetime",
        "decimal",
        "difflib",
        "enum",
        "fnmatch",
        "fractions",
        "functools",
        "hashlib",
        "heapq",
        "ipaddress",
        "itertools",
        "json",
        "math",
        "numbers",
        "operator",
        "re",
        "statistics",
        "string",
        "textwrap",
        "types",
        "typing",
        "unicodedata",
        "uuid",
    }
)
ALLOWED_THIRD_PARTY = frozenset({"rfc8785"})
FORBIDDEN_BUILTINS = frozenset(
    {"open", "print", "input", "eval", "exec", "compile", "__import__", "breakpoint"}
)
# Calls that read the clock or random state: the domain receives them through ports.
NON_DETERMINISTIC_CALLS = frozenset({"now", "utcnow", "today", "uuid1", "uuid4"})
DOMAIN_PACKAGE = "scenario_tools.domain"


def _is_allowed(module: str) -> bool:
    if module == DOMAIN_PACKAGE or module.startswith(DOMAIN_PACKAGE + "."):
        return True
    root = module.split(".", 1)[0]
    return root in ALLOWED_STDLIB or root in ALLOWED_THIRD_PARTY


def _called_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def forbidden_uses(source: str) -> list[str]:
    """Return what a domain source file must not use, in order of appearance.

    Modules are reported by name, relative imports as ``relative import``, forbidden or
    non-deterministic calls as ``name()`` and any access to ``__builtins__`` by that name.
    """
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            offenders.extend(alias.name for alias in node.names if not _is_allowed(alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                offenders.append("relative import")
            elif node.module is not None and not _is_allowed(node.module):
                offenders.append(node.module)
        elif isinstance(node, ast.Call):
            name = _called_name(node.func)
            is_builtin_call = isinstance(node.func, ast.Name) and name in FORBIDDEN_BUILTINS
            if is_builtin_call or name in NON_DETERMINISTIC_CALLS:
                offenders.append(f"{name}()")
        elif isinstance(node, ast.Name) and node.id == "__builtins__":
            offenders.append("__builtins__")
    return offenders
