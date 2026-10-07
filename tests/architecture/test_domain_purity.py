"""The domain layer imports only the standard library, allowed pure libraries and itself.

Keeps the domain free of I/O and of outer layers. The checker is tested on synthetic sources first,
so that a silent pass on the real package cannot hide a broken checker.
"""

from pathlib import Path

import pytest

from tests.architecture.purity import forbidden_imports

DOMAIN = Path(__file__).resolve().parents[2] / "src" / "scenario_tools" / "domain"


@pytest.mark.parametrize(
    "source",
    [
        "import json\nimport hashlib",
        "from dataclasses import dataclass",
        "import rfc8785",
        "from scenario_tools.domain.shared import canonical",
    ],
)
def test_allowed_imports_pass(source: str) -> None:
    assert forbidden_imports(source) == []


@pytest.mark.parametrize(
    ("source", "offender"),
    [
        ("import yaml", "yaml"),
        ("from jsonschema import validate", "jsonschema"),
        ("import httpx", "httpx"),
        ("from scenario_tools.adapters import zip_archive", "scenario_tools.adapters"),
        (
            "from scenario_tools.application.prepare_entry import run",
            "scenario_tools.application.prepare_entry",
        ),
        ("import scenario_tools.ports.openaev", "scenario_tools.ports.openaev"),
        ("from scenario_tools.interface.cli import main", "scenario_tools.interface.cli"),
        ("def f():\n    import click", "click"),
        ("from . import sibling", "relative import"),
        ("from ...adapters import zip_archive", "relative import"),
    ],
)
def test_forbidden_imports_are_reported(source: str, offender: str) -> None:
    assert offender in forbidden_imports(source)


def test_domain_package_is_pure() -> None:
    offenders = {
        str(path.relative_to(DOMAIN)): found
        for path in sorted(DOMAIN.rglob("*.py"))
        if (found := forbidden_imports(path.read_text(encoding="utf-8")))
    }
    assert offenders == {}
