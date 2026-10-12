"""The documentation's examples stay what the tools accept."""

import re
from pathlib import Path

import pytest

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


# What the platform embeds: its starter-pack exports carry these identifiers, which the catalogue
# takes as the external identifiers of the same content. Once published, none ever changes.
STARTER_PACK_SCENARIOS = {
    ("EASM Scenario", "scenarios/techniques/easm/"): "3e2aa79f-9d73-48fd-839e-ccf1525b42e7",
    (
        "Tabletop Exercise - Akira Ransomware Crisis",
        "scenarios/ransomware/akira-ransomware-crisis/",
    ): "90bf7bde-7f50-4b2b-ac78-a7617960d509",
    (
        "[SALT TYPHOON] CVE & TTPs validation",
        "scenarios/intrusion-sets/cve-ttps-validation/",
    ): "8c7511d2-9ca9-4236-8cf9-be3b10f8cd8e",
}
STARTER_PACK_PAYLOADS = {
    "BAT script execution with WMIC - Salt Typhoon": "11de5aa3-4615-402f-afb7-1459dd5851ef",
    "Cleanup artifacts": "b0ab8632-2ea2-4b44-81e7-04289245de03",
    "Copy beacon cab file to remote target with some masquerading - Salt Typhoon": (
        "e38425d8-fef7-48a2-bf1f-217cdd08642a"
    ),
    'Create a New Service "Crowdoor" - Salt Typhoon': "13973155-b166-4bbf-a34a-6b74c0d92957",
    "Create a new Registry Key for Autorun of cmd.exe - Salt Typhoon": (
        "3bb212f8-84ac-4e21-bffe-eaee2afe43b0"
    ),
    "Deploy cab file containing beacon to target - Salt Typhoon Style": (
        "f3cf1f92-54dc-497e-8d0e-10c0edacf285"
    ),
    "Enumerate Local and Remote System Info - Salt Typhoon": "e66243d7-14ac-41c3-98db-e262169180ce",
    "Execute a remote BAT Script via PSExec - Salt Typhoon": "03874f13-ab7c-4616-b3ec-4274c3205644",
    "Expand cab file to remote target with some masquerading - Salt Typhoon": (
        "abf89316-e585-4863-9458-57c71fcc98dc"
    ),
    "Exfiltrate data HTTPS using curl windows": "1f0f9adf-4c16-42ce-bfb6-1ff2134bd8fc",
    "TrillClient\u2019s user credential discovery - Salt Typhoon": (
        "a2a29122-1033-4b4b-8581-b57a3ed0f75f"
    ),
}
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _table(text: str, section: str) -> list[list[str]]:
    """The cells of each data row of the table under the heading ``section``, without
    backticks; a row whose last cell is not an identifier fails, never left out."""
    found = re.search(rf"^## {re.escape(section)}[ \t]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert found, f"the section {section!r} is missing from docs/starter-pack-ids.md"
    lines = [line.strip() for line in found[1].splitlines() if line.strip().startswith("|")]
    rows = [[cell.strip().strip("`") for cell in line.strip("|").split("|")] for line in lines[2:]]
    for row in rows:  # past the header and its separator
        assert re.fullmatch(_UUID, row[-1]), f"no identifier in the row {row!r}"
    return rows


def _rows(section: str) -> list[list[str]]:
    text = (ROOT / "docs" / "starter-pack-ids.md").read_text(encoding="utf-8")
    return _table(text, section)


@pytest.mark.parametrize("row", ["| Extra | `not-an-id` |", "| Extra | |", "| Extra |"])
def test_a_row_without_an_identifier_fails_rather_than_being_left_out(row: str) -> None:
    valid = f"| A | `{'0' * 8}-0000-0000-0000-{'0' * 12}` |"
    text = f"## Payloads\n\n| Payload | ID |\n|---|---|\n{valid}\n{row}\n"

    with pytest.raises(AssertionError, match="Extra"):
        _table(text, "Payloads")


def test_the_starter_pack_page_lists_each_scenario_with_its_identifier_once() -> None:
    rows = _rows("Scenarios")

    assert len(rows) == len(STARTER_PACK_SCENARIOS)
    assert {(name, entry): identifier for name, entry, identifier in rows} == STARTER_PACK_SCENARIOS


def test_the_starter_pack_page_lists_each_payload_with_its_identifier_once() -> None:
    rows = _rows("Payloads")

    assert len(rows) == len(STARTER_PACK_PAYLOADS)
    assert dict(rows) == STARTER_PACK_PAYLOADS
    identifiers = [*STARTER_PACK_SCENARIOS.values(), *STARTER_PACK_PAYLOADS.values()]
    assert len(set(identifiers)) == len(identifiers)  # none names two things


@pytest.mark.parametrize(
    ("page", "least"), [("README.md", 5), ("CONTRIBUTING.md", 4), ("SECURITY.md", 0)]
)
def test_every_relative_link_of_a_front_page_leads_to_a_file_of_the_repository(
    page: str, least: int
) -> None:
    text = (ROOT / page).read_text(encoding="utf-8")
    links = re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text)
    relative = [link for link in links if not re.match(r"[a-z]+:", link)]

    assert len(relative) >= least
    for link in relative:
        target = (ROOT / link).resolve()
        assert target.is_relative_to(ROOT.resolve()), link  # never a place outside the repository
        assert target.exists(), link
