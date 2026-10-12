"""Spies the adapters' tests share."""

import os
from typing import Any

import pytest


def descriptors(monkeypatch: pytest.MonkeyPatch) -> tuple[list[int], list[int]]:
    """The descriptors opened, or duplicated, and those closed from now on."""
    opened: list[int] = []
    closed: list[int] = []
    real_open, real_close, real_dup = os.open, os.close, os.dup

    def spied_open(*arguments: Any, **options: Any) -> int:
        descriptor = real_open(*arguments, **options)
        opened.append(descriptor)
        return descriptor

    def spied_dup(descriptor: int) -> int:
        duplicate = real_dup(descriptor)
        opened.append(duplicate)
        return duplicate

    def spied_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "open", spied_open)
    monkeypatch.setattr(os, "dup", spied_dup)
    monkeypatch.setattr(os, "close", spied_close)
    return opened, closed
