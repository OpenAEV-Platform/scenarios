"""The domain layer imports only the standard library, allowed pure libraries and itself.

Keeps the domain free of I/O and of outer layers. The checker is tested on synthetic sources first,
so that a silent pass on the real package cannot hide a broken checker.
"""

from pathlib import Path

import pytest

from tests.architecture.purity import forbidden_uses

DOMAIN = Path(__file__).resolve().parents[2] / "src" / "scenario_tools" / "domain"


@pytest.mark.parametrize(
    "source",
    [
        "import json\nimport hashlib",
        "from dataclasses import dataclass",
        "from collections.abc import Mapping",
        "import uuid",
        "import rfc8785",
        "from scenario_tools.domain.shared import canonical",
    ],
)
def test_allowed_imports_pass(source: str) -> None:
    assert forbidden_uses(source) == []


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
        ("import os", "os"),
        ("import socket", "socket"),
        ("import subprocess", "subprocess"),
        ("from pathlib import Path", "pathlib"),
        ("import importlib", "importlib"),
        ("import urllib.request", "urllib.request"),
        ("from . import sibling", "relative import"),
        ("from ...adapters import zip_archive", "relative import"),
    ],
)
def test_forbidden_uses_are_reported(source: str, offender: str) -> None:
    assert offender in forbidden_uses(source)


def test_domain_package_is_pure() -> None:
    offenders = {
        str(path.relative_to(DOMAIN)): found
        for path in sorted(DOMAIN.rglob("*.py"))
        if (found := forbidden_uses(path.read_text(encoding="utf-8")))
    }
    assert offenders == {}


@pytest.mark.parametrize(
    ("source", "offender"),
    [
        ("open('report.txt')", "open()"),
        ("with open('x') as f:\n    pass", "open()"),
        ("print('debug')", "print()"),
        ("eval('1 + 1')", "eval()"),
        ("exec('x = 1')", "exec()"),
        ("compile('1', '<s>', 'eval')", "compile()"),
        ("__import__('os')", "__import__()"),
        ("input()", "input()"),
        ("breakpoint()", "breakpoint()"),
    ],
)
def test_io_and_dynamic_builtins_are_reported(source: str, offender: str) -> None:
    assert offender in forbidden_uses(source)


def test_a_local_name_shadowing_nothing_is_allowed() -> None:
    assert forbidden_uses("def render(value: str) -> str:\n    return value.strip()") == []


@pytest.mark.parametrize(
    ("source", "offender"),
    [
        ("import datetime\ndatetime.datetime.now()", "now()"),
        ("from datetime import datetime\ndatetime.utcnow()", "utcnow()"),
        ("from datetime import date\ndate.today()", "today()"),
        ("import uuid\nuuid.uuid4()", "uuid4()"),
        ("import uuid\nuuid.uuid1()", "uuid1()"),
        ("__builtins__['open']('x')", "__builtins__"),
    ],
)
def test_hidden_inputs_and_builtins_access_are_reported(source: str, offender: str) -> None:
    assert offender in forbidden_uses(source)


def test_deterministic_uuid_is_allowed() -> None:
    assert forbidden_uses("import uuid\nuuid.uuid5(uuid.NAMESPACE_URL, 'x')") == []
