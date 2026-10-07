"""Static check of the imports allowed in the domain layer."""

import ast
import sys

ALLOWED_THIRD_PARTY = frozenset({"rfc8785"})
DOMAIN_PACKAGE = "scenario_tools.domain"


def _is_allowed(module: str) -> bool:
    root = module.split(".", 1)[0]
    if module == DOMAIN_PACKAGE or module.startswith(DOMAIN_PACKAGE + "."):
        return True
    if root == "scenario_tools":
        return False
    return root in sys.stdlib_module_names or root in ALLOWED_THIRD_PARTY


def forbidden_imports(source: str) -> list[str]:
    """Return the modules a domain source file must not import, in order of appearance."""
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            offenders.extend(alias.name for alias in node.names if not _is_allowed(alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                offenders.append("relative import")
            elif node.module is not None and not _is_allowed(node.module):
                offenders.append(node.module)
    return offenders
