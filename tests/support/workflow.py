"""Closed lists of keys of an export, for the tests: those of the repository's data file."""

from pathlib import Path
from typing import Any

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.shared.workflow import ExportKeys

_DATA = Path(__file__).resolve().parents[2] / "policy" / "data"
KEYS_DOCUMENT: dict[str, Any] = YamlDataLoader(_DATA).load("export-keys")
KEYS = ExportKeys.from_document(KEYS_DOCUMENT)
