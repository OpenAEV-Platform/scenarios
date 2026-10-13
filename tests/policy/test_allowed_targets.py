"""The allowed targets, kept as data the maintainers own: the example names, loopback and the
test ranges, and nothing else until the test environment exists."""

import ipaddress
from pathlib import Path

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.policy.targets import AllowedTargets

ROOT = Path(__file__).parents[2]


def test_the_repository_allows_the_standard_names_and_ranges_only() -> None:
    allowed = AllowedTargets.from_document(
        YamlDataLoader(ROOT / "policy" / "data").load("allowed-targets")
    )

    assert allowed.domains == (
        "example",
        "example.com",
        "example.net",
        "example.org",
        "test",
        "invalid",
        "localhost",
    )
    assert allowed.networks == tuple(
        ipaddress.ip_network(network)
        for network in (
            "127.0.0.0/8",
            "::1/128",
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "2001:db8::/32",
        )
    )
    assert allowed.external == frozenset()
