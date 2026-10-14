"""The payload IDs agreed outside the repository, kept as data the maintainers own."""

from pathlib import Path

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.verification.payload_references import AgreedIds


def test_the_registry_reads() -> None:
    document = YamlDataLoader(Path(__file__).parents[2] / "policy" / "data").load("payload-ids")

    assert isinstance(AgreedIds.from_document(document), AgreedIds)
