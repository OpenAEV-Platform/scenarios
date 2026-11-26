"""The repositories a Nuclei template may come from, kept as data the maintainers own: the
templates ProjectDiscovery publishes, and nothing else until the maintainers vouch for another."""

from pathlib import Path

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.policy.templates import TemplateSources

ROOT = Path(__file__).parents[2]


def test_the_repository_allows_projectdiscovery_s_templates_only() -> None:
    sources = TemplateSources.from_document(
        YamlDataLoader(ROOT / "policy" / "data").load("nuclei-templates")
    )

    assert sources.repositories == ("projectdiscovery/nuclei-templates",)


def test_the_snapshots_read_the_same_list() -> None:
    """The frozen corpus of the snapshots holds its own copy of the policy data."""
    corpus = ROOT / "tests" / "snapshots" / "corpus" / "policy" / "data"

    assert YamlDataLoader(corpus).load("nuclei-templates") == YamlDataLoader(
        ROOT / "policy" / "data"
    ).load("nuclei-templates")
