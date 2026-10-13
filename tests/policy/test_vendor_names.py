"""The security products a scenario never names, kept as data the maintainers own."""

from pathlib import Path

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.policy.actions import as_command
from scenario_tools.domain.policy.vendors import vendors_from_document

VENDORS = vendors_from_document(
    YamlDataLoader(Path(__file__).parents[2] / "policy" / "data").load("vendor-names")
)


@pytest.mark.parametrize(
    "text",
    ["Get-Service CSFalconService # CrowdStrike", "SentinelOne agent", "Trend Micro Apex One"],
)
def test_security_products_are_named_in_the_list(text: str) -> None:
    assert VENDORS.search(as_command(text))


@pytest.mark.parametrize(
    "text",
    [
        "Set-MpPreference -DisableRealtimeMonitoring $false",  # built into the system
        "sc query WinDefend",
        "reset the password",  # "eset" inside a word
        "titanium",  # "tanium" inside a word
    ],
)
def test_system_components_and_words_are_not(text: str) -> None:
    assert not VENDORS.search(as_command(text))
