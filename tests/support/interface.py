"""Patching a name the command-line modules read, wherever they read it.

The commands are split by group into the modules of ``scenario_tools.interface``: a name a test
replaces is replaced in every one of them that holds it, as it was in the single module before."""

from types import ModuleType
from typing import Any

import pytest

from scenario_tools.interface import base, entries, intake, openaev, payloads, release

MODULES: tuple[ModuleType, ...] = (base, entries, intake, release, payloads, openaev)


def patch_interface(monkeypatch: pytest.MonkeyPatch, name: str, value: object) -> None:
    """Replace ``name`` with ``value`` in every command-line module that holds it."""
    holders = [module for module in MODULES if hasattr(module, name)]
    assert holders, name
    for module in holders:
        monkeypatch.setattr(module, name, value)


def interface_attribute(name: str) -> Any:
    """The object a command-line module holds under ``name``, the same in every one of them."""
    found = {
        id(getattr(module, name)): getattr(module, name)
        for module in MODULES
        if hasattr(module, name)
    }
    assert len(found) == 1, name
    return next(iter(found.values()))
