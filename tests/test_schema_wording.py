"""The published schemas describe a scenario in chaining: what its type means, the edition it
needs, and that its steps count where its injects do."""

import json
from pathlib import Path

import pytest

SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"


def _descriptions(value: object) -> list[str]:
    if isinstance(value, dict):
        found = [value["description"]] if isinstance(value.get("description"), str) else []
        return found + [text for child in value.values() for text in _descriptions(child)]
    if isinstance(value, list):
        return [text for child in value for text in _descriptions(child)]
    return []


@pytest.mark.parametrize("name", ["scenario.schema.json", "manifest.schema.json"])
def test_the_schema_describes_chaining(name: str) -> None:
    texts = _descriptions(json.loads((SCHEMAS / name).read_text(encoding="utf-8")))
    assert any("chained: the scenario is a workflow of steps" in text for text in texts)
    assert any(text.endswith("A chaining scenario needs EE.") for text in texts)
    assert not [text for text in texts if "the injects " in text and "or steps" not in text]
