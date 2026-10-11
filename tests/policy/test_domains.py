"""The domains of the catalogue, kept as data the maintainers own."""

from pathlib import Path

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.catalogue.entry import domains_from_document

ROOT = Path(__file__).parents[2]


def test_the_catalogue_has_its_four_domains() -> None:
    document = YamlDataLoader(ROOT / "policy" / "data").load("domains")

    assert domains_from_document(document) == (
        "vulnerabilities",
        "intrusion-sets",
        "ransomware",
        "techniques",
    )
