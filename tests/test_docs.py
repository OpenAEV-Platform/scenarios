"""The documentation's examples stay what the tools accept."""

import re
from pathlib import Path

from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.safe_readers import parse_yaml

ROOT = Path(__file__).parents[1]


def test_the_intake_requests_shown_are_valid_requests() -> None:
    text = (ROOT / "docs" / "intake.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(.*?)```", text, flags=re.DOTALL)
    validator = JsonSchemaValidator(ROOT / "schemas")

    assert len(blocks) == 2
    for block in blocks:
        assert validator.validate("intake-request", parse_yaml(block.encode())) == ()
